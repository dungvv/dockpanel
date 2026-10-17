#!/usr/bin/env bash
# nginx-clone-env-backup-path-pin-e2e.sh — s438
#
# Pins the two remaining defense-in-depth findings from the s436
# `dockpanel-fanout` round ([[project_dockpanel_tech_debt_p173]], Findings 1
# and 2). Both were confirmed NOT reachable via the panel API today — every
# current caller sources its domain/filepath from a DB-validated column, not
# straight from an admin-supplied field — but the handlers themselves had no
# validation of their own, so a future caller (or a future backend change
# that trusts them) would inherit the gap silently.
#
#   §A  nginx.go (agent routes): cloneSite/getEnv/setEnv (were clone_site/get_env/set_env in the retired Rust nginx.rs) were 3 of ~28 domain-taking
#       handlers that skipped `isValidDomain` while every sibling calls it
#       first. The live systemd unit's `ReadWritePaths` allowlist includes
#       `/etc/systemd/system` and `/var/spool/cron` — so an unvalidated
#       domain segment (`../../etc/systemd/system`) is root code execution
#       via cron/systemd-unit overwrite, not merely a stray file write.
#   §B  remote_backup.go's remoteBackupUpload() (Rust: upload()) gated the backup filepath with a lexical
#       `strings.HasPrefix()` check that "/var/backups/dockpanel/../../etc/shadow"
#       satisfies — the OS resolves the `..` on open. ProtectSystem=strict
#       blocks writes outside the allowlist but not READS, so an unguarded
#       path here is arbitrary root-readable-file exfiltration (shadow,
#       Let's Encrypt private keys, .env secrets) to an attacker-supplied
#       S3/SFTP destination.
#
# Pure source analysis: no box, no network, no build.

set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

echo
echo "=============================================="
echo "  nginx clone/env + remote-backup path validation — source pins (s438)"
echo "=============================================="
echo

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[31m✗\033[0m %s\n' "$1"; }

# Strip comments before matching (per [[feedback_source_pin_prose_trap]] — this
# file's own header spells the tokens the arms grep for).
code() {
  perl -0777 -pe '
    s{/\*.*?\*/}{}gs;
    s{^\s*//.*$}{}gm;
  ' "$1"
}

has()  { grep -qE -- "$2" <<< "$1"; }
flat() { tr '\n\t' '  ' <<< "$1" | tr -s ' '; }

# A function body, bounded on ITS OWN braces (s323 fix — a window ending at
# the successor's match position swallows the next function's declaration).
fnbody() {
  awk -v fn="$2" '
    (index($0, "func " fn "(") || $0 ~ ("^func \\([^)]*\\) " fn "\\(")) && !started { started=1 }
    started {
      n=gsub(/\{/,"{"); m=gsub(/\}/,"}"); depth += n - m; print
      if (opened || n>0) opened=1
      if (opened && depth<=0) exit
    }
  ' <<< "$1"
}

NGINX=panel/go/internal/agent/routes/nginx.go
BACKUP=panel/go/internal/agent/routes/remote_backup.go

for f in "$NGINX" "$BACKUP"; do
  [ -f "$f" ] || { bad "SETUP subject missing: $f"; exit 1; }
done

NGINX_SRC=$(code "$NGINX")
BACKUP_SRC=$(code "$BACKUP")

# ── §A  nginx.go: cloneSite/getEnv/setEnv now validate their domain(s) ────

CLONE=$(flat "$(fnbody "$NGINX_SRC" "cloneSite")")
if [ -z "$CLONE" ]; then
  bad "A0 could not extract nginx.go cloneSite"
else
  ok "A0 nginx.go cloneSite extracted"
  if has "$CLONE" '!isValidDomain\(b\.SourceDomain\)' && has "$CLONE" '!isValidDomain\(b\.TargetDomain\)'; then
    ok "A1 cloneSite validates BOTH source_domain and target_domain"
  else
    bad "A1 cloneSite is missing domain validation on one or both fields — rsync --delete runs on an unvalidated path"
  fi
  CHK_AT=$(grep -boE 'isValidDomain\(b\.(Source|Target)Domain\)' <<< "$CLONE" | head -1 | cut -d: -f1)
  # s459: clone_site no longer runs rsync inline — it delegates the whole
  # copy (rsync included) to staging::clone_files, so the thing validation
  # must precede is now that delegated call, not a `safe_command("rsync")`
  # literal that no longer exists in this function's body at all.
  # (Go: services.StagingCloneFiles.)
  RSYNC_AT=$(grep -bo 'services\.StagingCloneFiles(' <<< "$CLONE" | head -1 | cut -d: -f1)
  if [ -n "$CHK_AT" ] && [ -n "$RSYNC_AT" ] && [ "$CHK_AT" -lt "$RSYNC_AT" ]; then
    ok "A2 the validation precedes the delegated StagingCloneFiles call"
  else
    bad "A2 the validation does not precede the delegated StagingCloneFiles call (check@${CHK_AT:-none} delegate@${RSYNC_AT:-none})"
  fi
fi

GETENV=$(flat "$(fnbody "$NGINX_SRC" "getEnv")")
if [ -z "$GETENV" ]; then
  bad "A3 could not extract nginx.go getEnv"
else
  ok "A3 nginx.go getEnv extracted"
  if has "$GETENV" '!isValidDomain\(domain\)'; then
    ok "A4 getEnv validates domain before building the .env path"
  else
    bad "A4 getEnv has no domain validation — reads an arbitrary root-readable file via a crafted domain segment"
  fi
  # Go handlers have no Result return type to widen — the Rust-era intent
  # ("it can actually reject") is that a bad domain answers 400 and returns
  # BEFORE the .env path is read.
  if has "$GETENV" 'if !isValidDomain\(domain\) \{ writeErr\(w, http\.StatusBadRequest, [^)]*\) return \}' \
     && [ "$(grep -bo 'isValidDomain(domain)' <<< "$GETENV" | head -1 | cut -d: -f1)" -lt "$(grep -bo 'os\.ReadFile(' <<< "$GETENV" | head -1 | cut -d: -f1)" ]; then
    ok "A5 getEnv actually rejects a bad domain (400 + return) before reading the .env path"
  else
    bad "A5 getEnv's validation does not reject (400 + return) before os.ReadFile — it cannot refuse anything, regardless of what A4 found"
  fi
fi

SETENV=$(flat "$(fnbody "$NGINX_SRC" "setEnv")")
if [ -z "$SETENV" ]; then
  bad "A6 could not extract nginx.go setEnv"
else
  ok "A6 nginx.go setEnv extracted"
  if has "$SETENV" '!isValidDomain\(domain\)'; then
    ok "A7 setEnv validates domain before writing the .env path"
  else
    bad "A7 setEnv has no domain validation — writes an arbitrary path via a crafted domain segment"
  fi
fi

# A8 — the census floor. 25 sibling handlers already called is_valid_domain (Go: isValidDomain)
# before this fix (finder- and skeptic-verified at s436); this fix adds 4 new
# call sites (clone_site x2, get_env, set_env). A future removal of any of
# these checks drops the total below this floor; a future ADDITION does not
# break it, so this is deliberately a floor, not an exact-equality census
# (the heavier enumeration [[project_dockpanel_lessons_p60]] describes is not
# proportionate to a DiD-only, not-currently-reachable finding).
N_CALLS=$(grep -oF 'isValidDomain(' <<< "$NGINX_SRC" | wc -l | tr -d ' ')
if [ "$N_CALLS" -ge 31 ]; then
  ok "A8 nginx.go calls isValidDomain at least 31 times (found $N_CALLS) — the 4 new call sites are present"
else
  bad "A8 nginx.go calls isValidDomain only $N_CALLS times, expected >= 31 — a validation call site was lost"
fi

# ── §B  remote_backup.go: remoteBackupUpload() rejects '..' in the filepath ──────────────

UPLOAD=$(flat "$(fnbody "$BACKUP_SRC" "remoteBackupUpload")")
if [ -z "$UPLOAD" ]; then
  bad "B0 could not extract remote_backup.go remoteBackupUpload"
else
  ok "B0 remote_backup.go remoteBackupUpload extracted"
  if has "$UPLOAD" 'strings\.HasPrefix\(body\.Filepath, "/var/backups/dockpanel/"\)' && has "$UPLOAD" 'strings\.Contains\(body\.Filepath, "\.\."\)'; then
    ok "B1 upload rejects BOTH a non-prefixed path AND a lexical '..' traversal"
  else
    bad "B1 upload is missing the prefix check, the '..' rejection, or both — a crafted filepath can read outside /var/backups/dockpanel/"
  fi
  # B2 — the two conditions must be OR'd together in one guard, not two
  # separate ifs where an early return on the first could let a later
  # "and only if that passed" mutation quietly drop the second (both must
  # gate the SAME single rejection).
  if has "$UPLOAD" '!strings\.HasPrefix\(body\.Filepath, "/var/backups/dockpanel/"\) \|\| strings\.Contains\(body\.Filepath, "\.\."\)'; then
    ok "B2 both conditions are OR'd into a single rejection guard"
  else
    bad "B2 the prefix check and the '..' rejection are not combined into one guard — re-read remoteBackupUpload(), a mutation may have split them"
  fi
fi

echo
echo "----------------------------------------------"
printf '  PASS %d  FAIL %d\n' "$PASS" "$FAIL"
echo "----------------------------------------------"
echo

[ "$FAIL" -eq 0 ] || exit 1
exit 0
