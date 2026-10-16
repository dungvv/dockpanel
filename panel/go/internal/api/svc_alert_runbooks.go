package api

// Port of panel/backend/src/services/alert_runbooks.rs.
//
// Lookup helper for alert runbooks. Resolution order: DB row first
// (operator-edited or seeded), then fall back to the compile-time defaults.
// This keeps fresh installs producing useful notification payloads even
// before the operator clicks "Seed missing default runbooks."
//
// Notification payloads use excerpt(280) to keep mobile previews readable
// across slack/discord/pagerduty. The full markdown is rendered in email and
// in the in-panel incident detail view.

import (
	"context"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
)

// AlertRunbooksRunbookView is the Rust RunbookView.
type AlertRunbooksRunbookView struct {
	AlertType       string     `json:"alert_type"`
	RunbookMd       string     `json:"runbook_md"`
	SeverityDefault string     `json:"severity_default"`
	IsDefault       bool       `json:"is_default"`
	UpdatedAt       *time.Time `json:"updated_at"`
	UpdatedBy       *uuid.UUID `json:"updated_by"`
}

func alertRunbooksFromDefault(d *AlertRunbookDefaultsDefaultRunbook) AlertRunbooksRunbookView {
	return AlertRunbooksRunbookView{
		AlertType:       d.AlertType,
		RunbookMd:       d.RunbookMd,
		SeverityDefault: d.Severity,
		IsDefault:       true,
	}
}

// AlertRunbooksGetRunbook resolves a runbook by alert_type: the DB row if
// present, otherwise the compile-time default, otherwise nil for unknown
// alert types.
func AlertRunbooksGetRunbook(ctx context.Context, db Querier, alertType string) *AlertRunbooksRunbookView {
	row, err := queryOpt[Tup4[string, string, time.Time, *uuid.UUID]](ctx, db,
		"SELECT runbook_md, severity_default, updated_at, updated_by "+
			"FROM alert_runbooks WHERE alert_type = $1", alertType)
	if err == nil && row != nil {
		return &AlertRunbooksRunbookView{
			AlertType:       alertType,
			RunbookMd:       row.A,
			SeverityDefault: row.B,
			IsDefault:       false,
			UpdatedAt:       &row.C,
			UpdatedBy:       row.D,
		}
	}
	if d := AlertRunbookDefaultsFindDefault(alertType); d != nil {
		v := alertRunbooksFromDefault(d)
		return &v
	}
	return nil
}

// AlertRunbooksListRunbooks lists every known runbook — DB rows merged over
// the defaults. DB rows win on collision; defaults with no DB row are
// returned with IsDefault = true.
func AlertRunbooksListRunbooks(ctx context.Context, db Querier) []AlertRunbooksRunbookView {
	out := make([]AlertRunbooksRunbookView, 0, len(AlertRunbookDefaultsDefaults)+4)

	rows, err := queryAll[Tup5[string, string, string, time.Time, *uuid.UUID]](ctx, db,
		"SELECT alert_type, runbook_md, severity_default, updated_at, updated_by "+
			"FROM alert_runbooks")
	if err != nil {
		rows = nil
	}
	for _, r := range rows {
		out = append(out, AlertRunbooksRunbookView{
			AlertType:       r.A,
			RunbookMd:       r.B,
			SeverityDefault: r.C,
			IsDefault:       false,
			UpdatedAt:       &r.D,
			UpdatedBy:       r.E,
		})
	}

	for i := range AlertRunbookDefaultsDefaults {
		d := &AlertRunbookDefaultsDefaults[i]
		found := false
		for _, r := range out {
			if r.AlertType == d.AlertType {
				found = true
				break
			}
		}
		if !found {
			out = append(out, alertRunbooksFromDefault(d))
		}
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].AlertType < out[j].AlertType })
	return out
}

// AlertRunbooksExcerpt truncates markdown to ~max chars at a sentence
// boundary for notification payloads (slack/discord/pagerduty mobile
// preview). Strips `#` heading lines so the excerpt starts with prose.
func AlertRunbooksExcerpt(md string, max int) string {
	// str::lines: split on \n, drop a trailing \r, no final empty line.
	lines := strings.Split(md, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	kept := make([]string, 0, len(lines))
	for _, l := range lines {
		l = strings.TrimSuffix(l, "\r")
		if strings.HasPrefix(strings.TrimLeftFunc(l, unicode.IsSpace), "#") {
			continue
		}
		kept = append(kept, l)
	}
	trimmed := strings.TrimSpace(strings.Join(kept, " "))

	runes := []rune(trimmed)
	if len(runes) <= max {
		return trimmed
	}

	head := string(runes[:max])
	if idx := strings.LastIndex(head, ". "); idx >= 0 {
		return strings.TrimRightFunc(head[:idx+1], unicode.IsSpace) + "…"
	}
	if idx := strings.LastIndex(head, " "); idx >= 0 {
		return head[:idx] + "…"
	}
	return head + "…"
}
