# Git hooks

These are the repository's checked-in hooks. They used to live only in
`.git/hooks/`, which meant they protected exactly one working copy — a fresh
clone, CI, or a second machine got nothing.

| Hook | Gates |
|---|---|
| `pre-commit` | Infrastructure-leak scan (real IPs, hostnames, tokens) |
| `pre-push` | Secrets scan, stale `panel/frontend/dist`, version consistency (`VERSION` vs the frontend `package.json`), and `npm audit` + `govulncheck` |

## Install

```bash
git config core.hooksPath scripts/hooks
```

That points git at this directory instead of `.git/hooks`, so the hooks are
versioned with the code and every clone gets the same gates.

`govulncheck` is the part of the pre-push gate that catches what Dependabot
misses: it reports Go vulnerabilities (stdlib included, so an outdated
toolchain shows up too) only on call paths the binaries actually reach. The
hook installs it on first use; it needs `go` on PATH, and without it the gate
degrades to a yellow warning rather than failing.

## Design notes

- No gate ever early-exits; each sets `FOUND=1` and the hook drains at the end,
  so one push reports every problem instead of one per attempt.
- The audit gate **fails open** on network errors. `npm audit` and `govulncheck`
  both exit non-zero when they cannot reach their advisory source, which is
  indistinguishable from a real finding by exit code — a gate that blocks on a
  DNS blip is a gate that gets disabled with `--no-verify`.
- `govulncheck` analyses for `GOOS=linux`, the only platform DockPanel ships
  for; the tool itself is built for the host.
