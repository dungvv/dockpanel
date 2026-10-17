#!/usr/bin/env bash
# upgrade-reach-pin-e2e.sh — s331 / v2.89.0
#
# Pins the defects this release fixes, all of which share one shape: a fix from
# the PREVIOUS release whose reach fell short of its claim.
#
#   A. v2.88.0 hardened the pre-upgrade dump by setting `umask 077` — but set it
#      at TOP-LEVEL scope in an 1100-line script, so it governed every `mkdir`
#      and `>` for the rest of the upgrade. `/opt/dockpanel/frontend` (nginx
#      serves the SPA from it as www-data) and `/var/www/acme/.well-known/
#      acme-challenge` (HTTP-01) would be created 0700 on any install that
#      creates them fresh: panel assets 403, certificates stop renewing.
#   B. v2.88.0 hardened the backup cron setup.sh EMITS, but nothing rewrote an
#      existing install's crontab, which carries the dump INLINE with a bare `>`
#      (0644). setup.sh deduped on the new script's path, which the inline line
#      never contains, so re-running it kept the old line AND added a second.
#   C. /volume-backups/{id}/restore has never once succeeded — the panel sent no
#      body, so the agent's required `Json` extractor answered 415 before any
#      handler ran. Fixing only that ARMS an unscoped restore, because the row
#      is fetched by id alone and the agent comes from the row's own server_id.
#      Body fix and scope MUST be pinned together.
#   D. The cleanup task evicted the webhook rate-limit counter on a 5-minute
#      window while both webhook handlers roll an hour, so a caller got a fresh
#      allowance every ~15 minutes.
#
# Pure source analysis: no box, no network, no build.
#
# ⚠ SHELL COMMENTS ARE STRIPPED BEFORE EVERY SHELL ARM, and that is not
# optional here. The fix for A is DOCUMENTED in update.sh in prose that spells
# `umask 077` several times, so an arm grepping raw source would match the
# comment describing the fix and stay green on a tree where the fix was
# reverted. Same family as the arm that matched the sentence NARRATING a check
# (lesson #149) and the pinned-decl prose trap.
#
# ⚠ NO PIPES INTO `grep -q`: under pipefail the upstream dies of SIGPIPE and the
# pipeline reports failure, turning an arm red on correct code. Here-strings only.
#
# ⚠ Go arms are scoped to their subject's OWN function body, never file-wide —
# an s330 arm grepped setup.sh file-wide for `umask 077` and printed GREEN at the
# previous tag off three unrelated mktemp calls (lesson #330).

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[31m✗\033[0m %s\n' "$1"; }

UPD=scripts/update.sh
SET=scripts/setup.sh
ORCH=panel/go/internal/api/rt_backup_orchestrator.go
RMOD=panel/go/internal/api/core_router.go
GITD=panel/go/internal/api/rt_git_deploys.go
DEPL=panel/go/internal/api/rt_deploy.go

for f in "$UPD" "$SET" "$ORCH" "$RMOD" "$GITD" "$DEPL"; do
  [ -f "$f" ] || bad "MISSING SUBJECT FILE: $f"
done

# Shell comment stripper. Removes whole-line and trailing `#` comments while
# leaving `#` inside single/double quotes alone (the crontab line carries
# `+\%Y\%m\%d`, and sed addresses here use `#` as the delimiter).
shcode() {
  perl -0777 -pe '
    my @out;
    for my $l (split /\n/, $_) {
      my ($q, $r) = ("", "");
      for my $i (0 .. length($l) - 1) {
        my $c = substr($l, $i, 1);
        my $p = $i ? substr($l, $i - 1, 1) : "";
        if ($q) { $q = "" if $c eq $q && $p ne "\\"; }
        elsif ($c eq q{'"'"'} || $c eq q{"}) { $q = $c; }
        elsif ($c eq "#") { last; }
        $r .= $c;
      }
      push @out, $r;
    }
    $_ = join("\n", @out) . "\n";
  ' "$1"
}

# Go/TSX comment stripper — the FIXED one (a `/*` mid-line is data, not the
# start of a block comment; the naive version deleted real code in four suites).
code() {
  perl -0777 -pe '
    s{\{/\*.*?\*/\}}{}gs;
    s{^[ \t]*/\*.*?\*/[ \t]*$}{}gms;
    s{^\s*//.*$}{}gm;
  ' "$1"
}

# An arm whose subject could not be extracted must SKIP, never print a green.
subj()   { local t; t=$("$1" "$2"); [ -n "$t" ] || return 1; printf '%s' "$t"; }
has()    { grep -qE -- "$2" <<< "$1"; }
count()  { grep -cE -- "$2" <<< "$1" || true; }

# Extract one top-level Go func body, bounded by its OWN closing brace in
# column 0 — not a fixed -A window, which bleeds into the next function and can
# match the very token it searches for (lesson #172).
fnbody() { sed -n "/^func $2(/,/^}/p" <<< "$1"; }

echo "== §A  update.sh: the umask is scoped to the dump, not to the rest of the upgrade =="
if S=$(subj shcode "$UPD"); then
  # A1 — the regression itself: a bare top-level `umask` statement. At v2.88.0
  # this is line 258 and this arm is RED.
  TOP=$(count "$S" '^[[:space:]]*umask[[:space:]]')
  if [ "$TOP" -eq 0 ]; then
    ok "no top-level umask statement in update.sh"
  else
    bad "$TOP top-level umask statement(s) in update.sh — governs every later mkdir and redirect"
  fi

  # A2 — and the protection is still THERE, in the subshell that performs the
  # dump redirect. A1 alone would pass on a tree that simply deleted the umask,
  # which would put the token-bearing dump back at 0644.
  # ⚠ Keyed on `pre-upgrade-`, which is unique to THIS dump's filename — not on
  # `pg_dump`. A mutation sweep caught the broader form: §B's migration line also
  # contains `umask 077; docker exec … pg_dump`, so an arm grepping every pg_dump
  # line stayed GREEN with the subshell's umask deleted, satisfied by an unrelated
  # match in the same file (the #310/#330 scope class).
  DUMP=$(grep -E 'pre-upgrade-' <<< "$S" || true)
  if [ -z "$DUMP" ]; then
    bad "no pre-upgrade dump line found in update.sh — this section is measuring nothing"
  elif has "$DUMP" 'umask 077;'; then
    ok "the pre-upgrade dump still runs under umask 077, inside its own subshell"
  else
    bad "the pre-upgrade dump no longer sets umask — it carries agent_token in cleartext"
  fi

  # A3 — control that A1 is not passing because the file was truncated: the two
  # directories the regression breaks must still be created by this script.
  FE=$(count "$S" 'mkdir -p "\$FE_DIR"')
  ACME=$(count "$S" 'mkdir -p /var/www/acme/\.well-known/acme-challenge')
  if [ "$FE" -ge 1 ] && [ "$ACME" -ge 1 ]; then
    ok "control: the frontend and ACME mkdir sites are present ($FE, $ACME)"
  else
    bad "control failed — mkdir sites missing (fe=$FE acme=$ACME); §A may be vacuous"
  fi
else
  echo "  - skipped §A (subject unreadable)"
fi

echo "== §B  the legacy inline backup cron is reached, and cannot be duplicated =="
if S=$(subj shcode "$UPD"); then
  # B1 — v2.88.0's update.sh referenced crontab ZERO times, so no upgrade could
  # ever repair an existing install's 0644 dump. RED at the previous tag.
  CRON=$(count "$S" 'crontab')
  if [ "$CRON" -ge 1 ]; then
    ok "update.sh reaches the crontab ($CRON reference(s))"
  else
    bad "update.sh never touches crontab — an existing install keeps writing 0644 dumps for ever"
  fi

  # B2 — and it must specifically harden the INLINE form, keyed on the operation
  # rather than on a comment about it.
  if has "$S" 'umask 077; docker exec dockpanel-postgres pg_dump'; then
    ok "update.sh rewrites the legacy inline dump line to run under umask 077"
  else
    bad "update.sh does not harden the legacy inline dump line"
  fi
else
  echo "  - skipped §B/update (subject unreadable)"
fi

if S=$(subj shcode "$SET"); then
  # B3 — setup.sh's dedupe must drop the inline form too. Keyed on the crontab
  # install pipeline's own line so an unrelated grep elsewhere cannot satisfy it.
  # The install is a multi-line pipeline, so the window is bounded by the
  # pipeline's OWN terminator (`| crontab -`) rather than by a fixed -A count.
  INSTALL=$(awk '/crontab -l/{inside=1} inside{print} inside && /\| crontab -/{exit}' <<< "$S")
  if [ -z "$INSTALL" ]; then
    bad "no crontab install line in setup.sh — B3 is measuring nothing"
  elif has "$INSTALL" 'pg_dump -U dockpanel'; then
    ok "setup.sh's cron dedupe also removes the legacy inline dump line"
  else
    bad "setup.sh dedupes only on the script path — re-running it leaves TWO daily dumps"
  fi
else
  echo "  - skipped §B/setup (subject unreadable)"
fi

echo "== §C  volume restore: the body, and the scope that body arms =="
if S=$(subj code "$ORCH"); then
  BODY=$(fnbody "$S" rtBackupOrchestratorRestoreVolumeBackup)
  POSTCALL=$(awk '/result, err := agent\.Post\(/{inside=1} inside && /^[[:space:]]*if err != nil/{exit} inside{print}' <<< "$BODY")
  if [ -z "$BODY" ]; then
    bad "rtBackupOrchestratorRestoreVolumeBackup not found — §C is measuring nothing"
  else
    # C1 — the call must carry a body. A nil body is a guaranteed 415 at the
    # agent's required Json extractor, which is why this route never worked.
    if [ -z "$POSTCALL" ]; then
      bad "the volume restore POST call was not found — C1 is measuring nothing"
    elif has "$(tr '\n' ' ' <<< "$POSTCALL")" ',[[:space:]]*nil\)[[:space:]]*$'; then
      bad "the volume restore still posts None — the agent answers 415 before any handler runs"
    else
      ok "the volume restore no longer posts an empty body"
    fi

    # C2 — and it must send the field the agent actually requires. C1 alone
    # passes on any non-None body, including one missing volume_name (400).
    #
    # ⚠ Scoped to the POST CALL, not to the function. The first draft grepped the
    # whole fn body for `volume_name` and printed GREEN at v2.88.0 — because the
    # function already spells `backup.volume_name` in the label it passes to
    # `agent_for_site_server` (Go: agentForSiteServer), an unrelated use. That
    # false green sat inside a batch of twelve reds, which is precisely where
    # one hides (lesson #330).
    if [ -z "$POSTCALL" ]; then
      bad "the volume restore POST call was not found — C2 is measuring nothing"
    elif has "$POSTCALL" '"volume_name":'; then
      ok "the restore body carries volume_name, the agent's required field"
    else
      bad "the restore body omits volume_name — the agent rejects it"
    fi

    # C3 — the paired half. volume_backups has NO owner column, so the scope is
    # server-based: this machine, or a server this operator registered. Without
    # it, fixing C1 lets any admin unpack a backup over another operator's volume.
    if has "$BODY" 'sv\.is_local OR sv\.user_id = u\.id'; then
      ok "the row fetch is scoped to servers this operator runs"
    else
      bad "the volume backup row is fetched by id alone — C1 arms a cross-server restore"
    fi

    # C4 — the role is read from the DATABASE, not from the JWT claim, so a
    # demoted account stops qualifying immediately.
    if has "$BODY" "u\.role = 'admin'"; then
      ok "the scope reads the role from the database, not from claims"
    else
      bad "the scope does not consult users.role — a demoted token keeps restoring"
    fi
  fi
else
  echo "  - skipped §C (subject unreadable)"
fi

# §D (webhook janitor window) — the cleanup is st.cleanupOnce in
# panel/go/internal/api/core_state.go, which a test can call directly:
# D1 retired: covered by TestPinUpgradeReachWebhookJanitorWindow (panel/go/internal/api/pin_upgrade_reach_test.go)
# D2 retired: covered by TestPinUpgradeReachWebhookJanitorCap (panel/go/internal/api/pin_upgrade_reach_test.go)
# D3 retired: covered by TestPinUpgradeReachWebhookJanitorWindow (panel/go/internal/api/pin_upgrade_reach_test.go)

echo "== §E  the attempt limit has ONE definition, not three literals =="
if S=$(subj code "$RMOD"); then
  if has "$S" '^const WebhookAttemptLimit '; then
    ok "WebhookAttemptLimit is defined once in core_router.go"
  else
    bad "WebhookAttemptLimit is gone — the limit is a literal again"
  fi
else
  echo "  - skipped §E/def (subject unreadable)"
fi

# Both webhook handlers must READ that constant. A literal repeated per file is
# how the janitor and the handlers came to disagree in the first place.
READERS=0
for f in "$GITD" "$DEPL"; do
  if T=$(subj code "$f"); then
    has "$T" 'Count >= WebhookAttemptLimit' && READERS=$((READERS+1))
  fi
done
if [ "$READERS" -eq 2 ]; then
  ok "both webhook handlers read the shared constant ($READERS/2)"
else
  bad "only $READERS/2 webhook handlers read WebhookAttemptLimit — the literal has drifted back"
fi

echo
echo "upgrade-reach: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
