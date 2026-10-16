-- Second loose-ends audit: canary_files (Feature 12, 20260324000000) has zero
-- application-code readers or writers — the shipped canary-file feature
-- (auto_healer.rs::security_check_canary_files, routes/security.rs::canary_arm)
-- persists atime/trigger state via `settings` rows keyed `canary_atime_<path>`
-- instead, and its watch-path list is a hardcoded Rust const, not rows from
-- this table. Its sibling detection table from the same migration
-- (suspicious_events) is fully wired end-to-end; this one never was. Dead
-- schema, never written, never read; drop it.
DROP TABLE IF EXISTS canary_files;
