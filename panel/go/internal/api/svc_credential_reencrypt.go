package api

// Port of panel/backend/src/services/credential_reencrypt.rs — re-encrypt
// every stored credential under the CURRENT primary key.
//
// ## Why this exists
//
// secrets_crypto decrypts through a UNION of candidate keys, so adding,
// changing or removing SECRETS_ENCRYPTION_KEY no longer strands data. That
// makes the variable *survivable*. It does not make it *finished*: until every
// row is rewritten under the new primary key, the whole install depends on a
// fallback arm, and the old derivation can never be retired. This is the
// missing migration half.
//
// ## The registry is a CENSUS, and its completeness is pinned
//
// credentialReencryptSimpleSubjects plus the three special shapes below must
// cover every module that calls SecretsCryptoEncryptCredential. A registry
// that merely *lists* what someone remembered is a changelog: the next
// feature to encrypt a column joins the install silently and is then the one
// row this sweep skips. TestEveryCredentialWriterIsCovered asserts that every
// module containing an encrypt call appears in CredentialReencryptCoveredModules.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
)

// credentialReencryptSubject is a credential column this sweep rewrites:
// (table, id column, value column). The id column is compared and returned as
// text so one code path serves both uuid ids and settings' text key.
type credentialReencryptSubject struct{ Table, IDCol, ValueCol string }

var credentialReencryptSimpleSubjects = []credentialReencryptSubject{
	{"databases", "id", "db_password_enc"},
	{"mail_domains", "id", "dkim_private_key"},
	{"dns_zones", "id", "cf_api_token"},
	{"users", "id", "totp_secret"},
	{"whmcs_config", "id", "api_secret_encrypted"},
	{"cdn_zones", "id", "api_key"},
	{"git_deploys", "id", "github_token"},
	{"servers", "id", "agent_token"},
	{"alert_rules", "id", "notify_pagerduty_key"},
	{"alert_rules", "id", "notify_webhook_url"},
	{"alert_rules", "id", "notify_slack_url"},
	{"alert_rules", "id", "notify_discord_url"},
	{"monitors", "id", "alert_slack_url"},
	{"monitors", "id", "alert_discord_url"},
	{"webhook_endpoints", "id", "verify_secret"},
	{"extensions", "id", "webhook_secret"},
	{"whmcs_config", "id", "webhook_secret"},
	{"deploy_configs", "id", "webhook_secret"},
	{"git_deploys", "id", "webhook_secret"},
}

// credentialReencryptSpecialSubjects are visited through a hand-written arm
// rather than the simple list, because their ciphertext is not one row-one
// column. TestSubjectTokensMatchTheSweep asserts each is really passed to a
// credentialReencryptNewReport(..) call in this file.
var credentialReencryptSpecialSubjects = []string{
	"settings.value",
	"backup_destinations.config",
	"secrets.encrypted_value",
}

// CredentialReencryptCoveredModules: modules known to write an encrypted
// credential, each paired with **the subject that re-keys it**.
//
// ⚠ The pairing is the point. It was previously a bare list of module names,
// so a new encrypting module could pass the census by adding its NAME here
// while its column was never added to the simple subjects and was silently
// skipped by every re-key — the exact failure this file's header warns about,
// reproduced inside the mechanism meant to prevent it. Naming the subject
// makes the two halves one edit: TestSubjectTokensMatchTheSweep rejects a
// subject the sweep does not actually visit.
var CredentialReencryptCoveredModules = [][2]string{
	{"settings", "settings.value"},
	{"databases", "databases.db_password_enc"},
	{"whmcs", "whmcs_config.api_secret_encrypted"},
	{"system", "settings.value"},
	{"sites", "databases.db_password_enc"},
	{"migration", "databases.db_password_enc"},
	{"mail", "mail_domains.dkim_private_key"},
	{"dns", "dns_zones.cf_api_token"},
	{"backup_destinations", "backup_destinations.config"},
	{"auth", "users.totp_secret"},
	{"cdn", "cdn_zones.api_key"},
	{"git_deploys", "git_deploys.github_token"},
	{"servers", "servers.agent_token"},
	{"agent", "servers.agent_token"},
	{"alerts", "alert_rules.notify_pagerduty_key"},
	{"alerts", "alert_rules.notify_webhook_url"},
	{"alerts", "alert_rules.notify_slack_url"},
	{"alerts", "alert_rules.notify_discord_url"},
	{"monitors", "monitors.alert_slack_url"},
	{"monitors", "monitors.alert_discord_url"},
	{"webhook_gateway", "webhook_endpoints.verify_secret"},
	{"extensions", "extensions.webhook_secret"},
	{"whmcs", "whmcs_config.webhook_secret"},
	{"deploy", "deploy_configs.webhook_secret"},
	{"git_deploys", "git_deploys.webhook_secret"},
}

// CredentialReencryptCoveredModuleNames is the module names alone, for the
// operator-facing settings endpoint.
func CredentialReencryptCoveredModuleNames() []string {
	out := make([]string, 0, len(CredentialReencryptCoveredModules))
	for _, m := range CredentialReencryptCoveredModules {
		out = append(out, m[0])
	}
	return out
}

// CredentialReencryptSweptSubjects is every subject this sweep re-keys, as
// `table.column`. Reported beside the module list so the endpoint answers
// "did it touch my X?" about COLUMNS and not only about modules.
func CredentialReencryptSweptSubjects() []string {
	out := make([]string, 0, len(credentialReencryptSimpleSubjects)+len(credentialReencryptSpecialSubjects))
	for _, s := range credentialReencryptSimpleSubjects {
		out = append(out, s.Table+"."+s.ValueCol)
	}
	return append(out, credentialReencryptSpecialSubjects...)
}

// credentialReencryptSensitiveSettingsSQL: settings rows whose value is
// ciphertext. Mirrors the predicate the writers in rt_settings apply
// (rtSettingsSensitiveKeys plus the _client_secret suffix). The IN (...) list
// is SQL text, so TestSensitiveSettingsSQLCoversSettingsSensitiveKeys keeps it
// from drifting from rtSettingsSensitiveKeys.
const credentialReencryptSensitiveSettingsSQL = "SELECT key::text AS id, value FROM settings " +
	"WHERE (key IN ('smtp_password', 'pdns_api_key', 'ai_diagnosis_api_key') OR key LIKE '%\\_client\\_secret') " +
	"AND value IS NOT NULL AND value <> ''"

// CredentialReencryptSubjectReport is one subject's outcome.
type CredentialReencryptSubjectReport struct {
	Subject string `json:"subject"`
	// Rows carrying a non-empty value that we examined.
	Examined int64 `json:"examined"`
	// Rows rewritten under the current primary key.
	Rewritten int64 `json:"rewritten"`
	// Rows already under the primary key — nothing to do.
	AlreadyCurrent int64 `json:"already_current"`
	// Rows no candidate key could open. NOT rewritten; a failed re-encrypt
	// must never overwrite the only copy of the ciphertext.
	Unreadable int64 `json:"unreadable"`
	// Rows a normal write changed between our SELECT and our UPDATE. The CAS
	// guard on every UPDATE here skips rather than overwrites the newer value;
	// they are re-keyed on the NEXT run.
	Raced int64 `json:"raced"`
}

func credentialReencryptNewReport(subject string) *CredentialReencryptSubjectReport {
	return &CredentialReencryptSubjectReport{Subject: subject}
}

// CredentialReencryptAll sweeps every subject. Never fails the whole run
// because one subject failed — a missing optional table must not stop the
// rest, and a partially-completed sweep is safe to re-run.
func CredentialReencryptAll(ctx context.Context, db *pgxpool.Pool, jwtSecret string) []*CredentialReencryptSubjectReport {
	var reports []*CredentialReencryptSubjectReport
	for _, s := range credentialReencryptSimpleSubjects {
		reports = append(reports, credentialReencryptColumn(ctx, db, jwtSecret, s.Table, s.IDCol, s.ValueCol))
	}
	reports = append(reports, credentialReencryptSettings(ctx, db, jwtSecret))
	reports = append(reports, credentialReencryptDestinations(ctx, db, jwtSecret))
	reports = append(reports, credentialReencryptVaultSecrets(ctx, db, jwtSecret))
	return reports
}

// credentialReencryptRewrite runs one CAS update and books its outcome.
func credentialReencryptRewrite(ctx context.Context, db *pgxpool.Pool, report *CredentialReencryptSubjectReport, addr, sql string, args ...any) {
	n, err := execSQL(ctx, db, sql, args...)
	switch {
	case err != nil:
		report.Unreadable++
		slog.Error(fmt.Sprintf("re-encrypt: %s write failed: %v", addr, err))
	case n > 0:
		report.Rewritten++
	default:
		report.Raced++
		slog.Warn(fmt.Sprintf("re-encrypt: %s changed concurrently — skipped this run, will be picked up by the next one", addr))
	}
}

func credentialReencryptColumn(ctx context.Context, db *pgxpool.Pool, jwtSecret, table, idCol, valueCol string) *CredentialReencryptSubjectReport {
	report := credentialReencryptNewReport(table + "." + valueCol)

	// Table/column names come from the const registry above, never from input.
	sel := fmt.Sprintf("SELECT %s::text AS id, %s AS value FROM %s WHERE %s IS NOT NULL AND %s <> ''",
		idCol, valueCol, table, valueCol, valueCol)
	rows, err := queryAll[Tup2[string, string]](ctx, db, sel)
	if err != nil {
		slog.Warn(fmt.Sprintf("re-encrypt: skipping %s.%s: %v", table, valueCol, err))
		return report
	}

	// CAS on the value read: a normal write landing between our SELECT and
	// this UPDATE makes the UPDATE affect 0 rows instead of clobbering the
	// newer plaintext's ciphertext with a re-encrypted copy of what we read.
	update := fmt.Sprintf("UPDATE %s SET %s = $1 WHERE %s::text = $2 AND %s = $3", table, valueCol, idCol, valueCol)
	for _, row := range rows {
		id, value := row.A, row.B
		report.Examined++
		fresh, err := SecretsCryptoReencryptCredential(value, jwtSecret)
		switch {
		case err != nil:
			report.Unreadable++
			// The VALUE is never logged, only its address.
			slog.Error(fmt.Sprintf("re-encrypt: %s.%s id=%s unreadable: %v", table, valueCol, id, err))
		case fresh == nil:
			report.AlreadyCurrent++
		default:
			credentialReencryptRewrite(ctx, db, report, fmt.Sprintf("%s.%s id=%s", table, valueCol, id), update, *fresh, id, value)
		}
	}
	return report
}

func credentialReencryptSettings(ctx context.Context, db *pgxpool.Pool, jwtSecret string) *CredentialReencryptSubjectReport {
	report := credentialReencryptNewReport("settings.value")

	rows, err := queryAll[Tup2[string, string]](ctx, db, credentialReencryptSensitiveSettingsSQL)
	if err != nil {
		slog.Warn(fmt.Sprintf("re-encrypt: skipping settings.value: %v", err))
		return report
	}
	for _, row := range rows {
		key, value := row.A, row.B
		report.Examined++
		fresh, err := SecretsCryptoReencryptCredential(value, jwtSecret)
		switch {
		case err != nil:
			report.Unreadable++
			slog.Error(fmt.Sprintf("re-encrypt: settings[%s] unreadable: %v", key, err))
		case fresh == nil:
			report.AlreadyCurrent++
		default:
			credentialReencryptRewrite(ctx, db, report, "settings["+key+"]",
				"UPDATE settings SET value = $1, updated_at = NOW() WHERE key = $2 AND value = $3", *fresh, key, value)
		}
	}
	return report
}

// credentialReencryptDestinations: backup_destinations.config is JSON with
// ciphertext at known keys, so the unit of work is a key inside a document
// rather than a column.
func credentialReencryptDestinations(ctx context.Context, db *pgxpool.Pool, jwtSecret string) *CredentialReencryptSubjectReport {
	report := credentialReencryptNewReport("backup_destinations.config")

	rows, err := queryAll[Tup2[string, json.RawMessage]](ctx, db, "SELECT id::text AS id, config FROM backup_destinations")
	if err != nil {
		slog.Warn(fmt.Sprintf("re-encrypt: skipping backup_destinations.config: %v", err))
		return report
	}

	for _, row := range rows {
		id, original := row.A, row.B
		dec := json.NewDecoder(bytes.NewReader(original))
		dec.UseNumber()
		var config any
		_ = dec.Decode(&config)
		obj, _ := config.(map[string]any)
		changed, rowFailed, rowExamined := false, false, false

		for _, key := range rtBackupDestinationsConfigSensitiveKeys {
			value, ok := obj[key].(string)
			if !ok || value == "" {
				continue
			}
			rowExamined = true
			fresh, err := SecretsCryptoReencryptCredential(value, jwtSecret)
			switch {
			case err != nil:
				rowFailed = true
				slog.Error(fmt.Sprintf("re-encrypt: backup_destinations[%s].%s unreadable: %v", id, key, err))
			case fresh != nil:
				obj[key] = *fresh
				changed = true
			}
		}

		if rowExamined {
			report.Examined++
		}
		if rowFailed {
			report.Unreadable++
			// Never write back a document we could only partly re-encrypt.
			continue
		}
		if !changed {
			if rowExamined {
				report.AlreadyCurrent++
			}
			continue
		}

		next, err := json.Marshal(obj)
		if err != nil {
			report.Unreadable++
			continue
		}
		// CAS on the config read at the top of this iteration, before any key
		// was rewritten — a concurrent edit to this destination between our
		// SELECT and this UPDATE makes the guard fail instead of clobbering it.
		credentialReencryptRewrite(ctx, db, report, "backup_destinations["+id+"]",
			"UPDATE backup_destinations SET config = $1 WHERE id::text = $2 AND config = $3",
			json.RawMessage(next), id, original)
	}
	return report
}

// credentialReencryptVaultSecrets: the Secrets Manager vault. Different key
// ladder from the credential path (SecretsCryptoVaultKeySources), so it needs
// its own arm rather than sharing ReencryptCredential.
func credentialReencryptVaultSecrets(ctx context.Context, db *pgxpool.Pool, jwtSecret string) *CredentialReencryptSubjectReport {
	report := credentialReencryptNewReport("secrets.encrypted_value")

	rows, err := queryAll[Tup2[string, string]](ctx, db,
		"SELECT id::text AS id, encrypted_value FROM secrets "+
			"WHERE encrypted_value IS NOT NULL AND encrypted_value <> ''")
	if err != nil {
		slog.Warn(fmt.Sprintf("re-encrypt: skipping secrets.encrypted_value: %v", err))
		return report
	}
	for _, row := range rows {
		id, value := row.A, row.B
		report.Examined++
		fresh, err := SecretsCryptoReencryptVault(value, jwtSecret)
		switch {
		case err != nil:
			report.Unreadable++
			slog.Error(fmt.Sprintf("re-encrypt: secrets[%s] unreadable: %v", id, err))
		case fresh == nil:
			report.AlreadyCurrent++
		default:
			// No `version` bump: the plaintext is unchanged, only its wrapper.
			// rt_secrets pairs every version increment with an INSERT into
			// secret_versions under that number — bumping it here without one
			// would desync the two on every successful re-key.
			credentialReencryptRewrite(ctx, db, report, "secrets["+id+"]",
				"UPDATE secrets SET encrypted_value = $1, updated_at = NOW() WHERE id::text = $2 AND encrypted_value = $3",
				*fresh, id, value)
		}
	}
	return report
}
