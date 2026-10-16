package api

// Port of panel/backend/src/models.rs. JSON tags mirror serde (Option → null,
// never omitempty; #[serde(skip_serializing)] → `json:"-"`); db tags mirror
// sqlx FromRow column names.

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// User is a `users` row. Read it with an explicit column list or SELECT *;
// prior_role is deliberately NOT a field (see unsuspendAccount): a database
// restored from a snapshot older than that migration then degrades that one
// call instead of failing every login.
type User struct {
	ID            uuid.UUID  `json:"id" db:"id"`
	Email         string     `json:"email" db:"email"`
	PasswordHash  string     `json:"-" db:"password_hash"`
	Role          string     `json:"role" db:"role"`
	EmailVerified bool       `json:"email_verified" db:"email_verified"`
	EmailToken    *string    `json:"-" db:"email_token"`
	ResetToken    *string    `json:"-" db:"reset_token"`
	ResetExpires  *time.Time `json:"-" db:"reset_expires"`
	TotpSecret    *string    `json:"-" db:"totp_secret"`
	TotpEnabled   bool       `json:"totp_enabled" db:"totp_enabled"`
	RecoveryCodes *string    `json:"-" db:"recovery_codes"`
	OAuthProvider *string    `json:"oauth_provider" db:"oauth_provider"`
	OAuthID       *string    `json:"-" db:"oauth_id"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at" db:"updated_at"`
}

// OnCallSchedule (Phase 4 W3): rotation = ordered user ids × cadence_days;
// who is on call at T is cadence math against anchor_at.
type OnCallSchedule struct {
	ID          uuid.UUID   `json:"id" db:"id"`
	Name        string      `json:"name" db:"name"`
	Members     []uuid.UUID `json:"members" db:"members"`
	CadenceDays int32       `json:"cadence_days" db:"cadence_days"`
	AnchorAt    time.Time   `json:"anchor_at" db:"anchor_at"`
	CreatedAt   time.Time   `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at" db:"updated_at"`
}

// EscalationPolicy (Phase 4 W3): ordered JSONB array of EscalationStep,
// referenced from alert_rules.escalation_policy_id (NULL = pre-W3 15/30-min).
type EscalationPolicy struct {
	ID        uuid.UUID       `json:"id" db:"id"`
	Name      string          `json:"name" db:"name"`
	Steps     json.RawMessage `json:"steps" db:"steps"`
	CreatedAt time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt time.Time       `json:"updated_at" db:"updated_at"`
}

// EscalationStep is one entry of escalation_policies.steps. Route is one of
// "on_call_schedule:<uuid>", "user:<uuid>", "all_channels", "webhook:<url>".
type EscalationStep struct {
	AfterMinutes int32  `json:"after_minutes"`
	Route        string `json:"route"`
}

// Site is a `sites` row.
type Site struct {
	ID                  uuid.UUID  `json:"id" db:"id"`
	UserID              uuid.UUID  `json:"user_id" db:"user_id"`
	ServerID            *uuid.UUID `json:"server_id" db:"server_id"`
	Domain              string     `json:"domain" db:"domain"`
	Runtime             string     `json:"runtime" db:"runtime"`
	Status              string     `json:"status" db:"status"`
	ProxyPort           *int32     `json:"proxy_port" db:"proxy_port"`
	PHPVersion          *string    `json:"php_version" db:"php_version"`
	RootPath            *string    `json:"root_path" db:"root_path"`
	SSLEnabled          bool       `json:"ssl_enabled" db:"ssl_enabled"`
	SSLCertPath         *string    `json:"ssl_cert_path" db:"ssl_cert_path"`
	SSLKeyPath          *string    `json:"ssl_key_path" db:"ssl_key_path"`
	SSLExpiry           *time.Time `json:"ssl_expiry" db:"ssl_expiry"`
	SSLProfile          *string    `json:"ssl_profile" db:"ssl_profile"`
	SSLRenewalAt        *time.Time `json:"ssl_renewal_at" db:"ssl_renewal_at"`
	SSLRenewalCheckedAt *time.Time `json:"ssl_renewal_checked_at" db:"ssl_renewal_checked_at"`
	// Which ACME challenge issued the installed certificate: http-01 or
	// dns-01. NULL = not recorded (predates the provenance migration and the
	// backfill could not prove it). Renewal treats NULL as unknown, never as
	// http-01; see renewalPlan.
	SSLChallenge *string `json:"ssl_challenge" db:"ssl_challenge"`
	// The name the certificate was actually ORDERED for: the domain, except
	// for a wildcard where it is the Cloudflare zone (covers {subject} and
	// *.{subject}, never *.{domain}).
	SSLCertSubject *string `json:"ssl_cert_subject" db:"ssl_cert_subject"`
	// Three-state on purpose: a default false would assert "not a wildcard"
	// over every legacy apex wildcard, exactly the row that cannot be identified.
	SSLWildcard *bool `json:"ssl_wildcard" db:"ssl_wildcard"`
	// The dns_zones row whose Cloudflare credential issued this certificate —
	// renewal uses THIS row, so no text match can select another tenant's token.
	SSLDNSZoneID      *uuid.UUID `json:"ssl_dns_zone_id" db:"ssl_dns_zone_id"`
	RateLimit         *int32     `json:"rate_limit" db:"rate_limit"`
	MaxUploadMB       int32      `json:"max_upload_mb" db:"max_upload_mb"`
	PHPMemoryMB       int32      `json:"php_memory_mb" db:"php_memory_mb"`
	PHPMaxWorkers     int32      `json:"php_max_workers" db:"php_max_workers"`
	CustomNginx       *string    `json:"custom_nginx" db:"custom_nginx"`
	PHPPreset         *string    `json:"php_preset" db:"php_preset"`
	AppCommand        *string    `json:"app_command" db:"app_command"`
	ParentSiteID      *uuid.UUID `json:"parent_site_id" db:"parent_site_id"`
	SyncedAt          *time.Time `json:"synced_at" db:"synced_at"`
	Enabled           bool       `json:"enabled" db:"enabled"`
	FastCGICache      bool       `json:"fastcgi_cache" db:"fastcgi_cache"`
	RedisCache        bool       `json:"redis_cache" db:"redis_cache"`
	RedisDB           int32      `json:"redis_db" db:"redis_db"`
	WAFEnabled        bool       `json:"waf_enabled" db:"waf_enabled"`
	WAFMode           string     `json:"waf_mode" db:"waf_mode"`
	CSPPolicy         *string    `json:"csp_policy" db:"csp_policy"`
	PermissionsPolicy *string    `json:"permissions_policy" db:"permissions_policy"`
	BotProtection     string     `json:"bot_protection" db:"bot_protection"`
	// Monthly bandwidth cap in MB, NULL = unlimited; read by the traffic
	// accounting scheduler against the month's site_traffic_usage row.
	BandwidthQuotaMB *int32 `json:"bandwidth_quota_mb" db:"bandwidth_quota_mb"`
	// Set the instant the scheduler auto-disables this site for exceeding its
	// quota — the only thing distinguishing that from a manual disable.
	BandwidthSuspendedAt *time.Time `json:"bandwidth_suspended_at" db:"bandwidth_suspended_at"`
	// Opt-in per site: enabling it is the one moment the docroot is
	// restructured (content moves under a writable subdir so the OpenSSH
	// chroot boundary can stay root-owned).
	SFTPEnabled bool      `json:"sftp_enabled" db:"sftp_enabled"`
	SFTPUID     *int32    `json:"sftp_uid" db:"sftp_uid"`
	SFTPGID     *int32    `json:"sftp_gid" db:"sftp_gid"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// PanelSnapshot (Phase 4 W4): binaries + DB dump + /etc/dockpanel, kept past
// update.sh's .bak files so an operator can roll back hours later.
type PanelSnapshot struct {
	ID           uuid.UUID  `json:"id" db:"id"`
	FilePath     string     `json:"file_path" db:"file_path"`
	FromVersion  string     `json:"from_version" db:"from_version"`
	ToVersion    *string    `json:"to_version" db:"to_version"`
	Trigger      string     `json:"trigger" db:"trigger"`
	Operator     *string    `json:"operator" db:"operator"`
	SizeBytes    int64      `json:"size_bytes" db:"size_bytes"`
	SHA256       string     `json:"sha256" db:"sha256"`
	RolledBackAt *time.Time `json:"rolled_back_at" db:"rolled_back_at"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
}

// FleetUpdateRun (Phase 4 W4): Plan is the ordered server list, Progress is
// updated incrementally as the orchestrator walks it.
type FleetUpdateRun struct {
	ID            uuid.UUID       `json:"id" db:"id"`
	TargetVersion string          `json:"target_version" db:"target_version"`
	Plan          json.RawMessage `json:"plan" db:"plan"`
	Progress      json.RawMessage `json:"progress" db:"progress"`
	HaltOnFailure bool            `json:"halt_on_failure" db:"halt_on_failure"`
	IncludePanel  bool            `json:"include_panel" db:"include_panel"`
	StartedBy     *uuid.UUID      `json:"started_by" db:"started_by"`
	StartedAt     time.Time       `json:"started_at" db:"started_at"`
	FinishedAt    *time.Time      `json:"finished_at" db:"finished_at"`
	Outcome       *string         `json:"outcome" db:"outcome"`
}

// UpdateChannel (Phase 4 W4) validates settings.update_channel.
type UpdateChannel string

// UpdateChannelValidate accepts exactly stable | candidate | hold.
func UpdateChannelValidate(s string) error {
	switch s {
	case "stable", "candidate", "hold":
		return nil
	}
	return fmt.Errorf("invalid channel '%s' (must be one of: stable, candidate, hold)", s)
}
