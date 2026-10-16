package api

// services/status_notices.rs — status-page subscriber fan-out (s251).
//
// One worker owns every email sent to status_page_subscribers, for both
// producers: monitor transitions (uptime) and incident updates (incidents).
// Neither may fan out itself. Inline is wrong: uptime's caller holds one of
// only 10 check slots and the tick drains them all before advancing (a long
// fan-out stalls ALL monitoring); incidents' caller is an HTTP handler. A
// detached goroutine per event is also wrong: it loses ordering (subscribers
// told "recovered" before "down") and backpressure (a fleet-wide blip spawns
// hundreds of fan-outs that exhaust the pool and the relay). One worker
// draining a bounded FIFO restores both.
//
// s427: every notice carries its producer's tenant, and the fan-out only
// reaches subscribers stamped with that owner_id — the list used to be global,
// so every tenant's subscribers got every tenant's notices.

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// statusNoticesMaxSubscriberFanout caps one notice's fan-out. The public
// subscribe endpoint is unauthenticated, so the list is attacker-growable.
const statusNoticesMaxSubscriberFanout int64 = 1000

// statusNoticesQueueDepth bounds pending notices so a flapping fleet cannot
// grow the queue without limit.
const statusNoticesQueueDepth = 256

type StatusNoticesStatusNotice struct {
	// What the notice is about (monitor/incident name), for logging only.
	Source  string
	Subject string
	Message string
	// The tenant this notice belongs to (s427).
	OwnerID uuid.UUID
}

var (
	statusNoticesOnce sync.Once
	statusNoticesTx   chan StatusNoticesStatusNotice
	statusNoticesMu   sync.RWMutex
)

// StatusNoticesStartWorker starts the worker. Idempotent.
func StatusNoticesStartWorker(db *pgxpool.Pool) {
	statusNoticesOnce.Do(func() {
		ch := make(chan StatusNoticesStatusNotice, statusNoticesQueueDepth)
		statusNoticesMu.Lock()
		statusNoticesTx = ch
		statusNoticesMu.Unlock()
		go statusNoticesWorker(db, ch)
	})
}

func statusNoticesWorker(db *pgxpool.Pool, rx <-chan StatusNoticesStatusNotice) {
	ctx := context.Background()
	for notice := range rx {
		// Bail before the fan-out without a mail transport. The public
		// subscribe endpoint auto-verifies, so verified subscribers exist on
		// installs that never configured SMTP — otherwise each notice would
		// walk the list emitting a failed-send warning per subscriber.
		smtp, err := queryScalarOpt[string](ctx, db, "SELECT value FROM settings WHERE key = 'smtp_host'")
		if err != nil || smtp == nil {
			slog.Debug(fmt.Sprintf("No SMTP configured — skipping subscriber notices for '%s'", notice.Source))
			continue
		}
		emails, err := queryAll[string](ctx, db,
			"SELECT email FROM status_page_subscribers WHERE owner_id = $1 AND verified = TRUE AND notify_incidents = TRUE ORDER BY created_at ASC LIMIT $2",
			notice.OwnerID, statusNoticesMaxSubscriberFanout)
		if err != nil || len(emails) == 0 {
			continue
		}
		if int64(len(emails)) == statusNoticesMaxSubscriberFanout {
			slog.Warn(fmt.Sprintf("Status notice for '%s' capped at %d subscribers — later subscribers were not emailed", notice.Source, statusNoticesMaxSubscriberFanout))
		}
		for _, email := range emails {
			NotificationsSendNotification(ctx, db, &NotificationsNotifyChannels{Email: &email}, notice.Subject, notice.Message, notice.Message)
		}
	}
}

// StatusNoticesEnqueue queues a notice and returns immediately. A full queue
// drops it with a warning rather than back-pressuring a monitor check or an
// HTTP handler: a status email is worth less than timely checks.
func StatusNoticesEnqueue(source, subject, message string, ownerID uuid.UUID) {
	statusNoticesMu.RLock()
	tx := statusNoticesTx
	statusNoticesMu.RUnlock()
	if tx == nil {
		slog.Warn(fmt.Sprintf("Status-notice worker not started; dropping '%s' notification", source))
		return
	}
	select {
	case tx <- StatusNoticesStatusNotice{Source: source, Subject: subject, Message: message, OwnerID: ownerID}:
	default:
		slog.Warn(fmt.Sprintf("Status-notice queue full (%d) — dropped notification for '%s'", statusNoticesQueueDepth, source))
	}
}
