# SSL certificate expiring

A TLS certificate is approaching its expiry date.

## Why this fired

The agent reads each managed cert and the panel fires at the configured ladder (default 30/14/7d warning, 3/1d critical). With ARI-driven renewal (RFC 9773) the panel auto-renews based on CA hints; this alert means automatic renewal has not yet succeeded, not that imminent expiry is guaranteed.

## First check

1. From the panel: **SSL → click the cert → "Renew now"**. Watch the result.
2. If renewal fails, click **"Logs"** on the cert and read the last attempt.
3. From the host:
   ```
   openssl s_client -connect <domain>:443 -servername <domain> </dev/null 2>/dev/null | openssl x509 -noout -dates
   journalctl -u dockpanel-agent --since "24 hours ago" | grep -i acme
   ```

## Common causes

- DNS-01 challenge failed (Cloudflare API token revoked or scoped wrong)
- HTTP-01 challenge blocked (firewall change blocked port 80, or nginx config broke `.well-known/acme-challenge` path)
- Rate limit hit at the CA (Let's Encrypt: 5 duplicate certs per week per domain)
- Domain ownership changed (DNS now points elsewhere)
- ACME profile mismatch (CA dropped the profile the panel is configured for — check **Settings → SSL → ACME Profile**)
- Cert is for a domain that's been removed but the cert object lingered

## Escalation

Wake a human at 3 days remaining if "Renew now" fails twice. Beyond that, customer-facing TLS warnings start showing up in browsers. If the CA is rate-limiting, wait the window out — forcing more attempts compounds the problem.
