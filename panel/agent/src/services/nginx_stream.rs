//! TCP proxying through nginx's `stream` context.
//!
//! `stream` is a top-level sibling of `http` — managed proxies are one file
//! each under [`STREAM_DIR`], included by the `stream {}` block setup.sh /
//! update.sh wire into `nginx.conf`. Two consumers use this:
//!
//!   * database remote access — `proxy_pass` to a managed DB container's
//!     existing loopback-only port binding (the container is never
//!     republished on a public interface), and
//!   * generic TCP proxies — a validated operator-supplied `host:port`.
//!
//! The write lifecycle is the same contract the vhost writers keep:
//! validate everything, write temp+rename, `nginx -t`, reload, and roll the
//! file back with `restore_or_remove` when the test rejects it.

use crate::services::nginx::{restore_or_remove, restore_note, test_config};

/// Where the top-level `stream { include … }` block points. Created by
/// setup.sh/update.sh; the agent refuses to write when the include is not
/// wired, because a dropped file would otherwise sit inert and the panel
/// would report a proxy that does not exist.
pub const STREAM_DIR: &str = "/etc/nginx/dockpanel-streams";

/// Public TCP listen ports come only from this range, allocated per server
/// by the backend and verified free here before a file is written. Kept
/// clear of the Docker ephemeral range and of anything the panel itself
/// listens on.
pub const LISTEN_PORT_MIN: u16 = 40000;
pub const LISTEN_PORT_MAX: u16 = 44999;

/// Certificate/key paths resolved from the certificate registry, referenced
/// in place — key material is never copied into the stream directory.
pub struct TlsPaths {
    pub cert: String,
    pub key: String,
}

/// Whether this box's nginx has the managed stream include wired. Split from
/// the filesystem read so the decision is testable without `/etc/nginx`.
pub fn stream_available_at(nginx_conf: &std::path::Path) -> bool {
    std::fs::read_to_string(nginx_conf)
        .map(|body| body.contains("dockpanel-streams"))
        .unwrap_or(false)
}

/// Whether stream proxies can be written on THIS box.
pub fn stream_available() -> bool {
    stream_available_at(std::path::Path::new("/etc/nginx/nginx.conf"))
}

/// Proxy names double as filenames inside [`STREAM_DIR`], so the alphabet is
/// deliberately narrower than nginx's: lowercase slug, no separators, no
/// dots — `../evil` and `a b` never reach the filesystem.
pub fn validate_proxy_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 48 {
        return Err("proxy name must be 1-48 characters".to_string());
    }
    let ok = name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !name.starts_with('-')
        && !name.ends_with('-');
    if ok {
        Ok(())
    } else {
        Err(format!(
            "invalid proxy name '{name}' — use lowercase letters, digits and '-'"
        ))
    }
}

/// Public listen ports are confined to the managed range so a proxy can
/// never shadow an HTTP listener, the panel port, or a Docker ephemeral
/// binding.
pub fn validate_listen_port(port: u16) -> Result<(), String> {
    if (LISTEN_PORT_MIN..=LISTEN_PORT_MAX).contains(&port) {
        Ok(())
    } else {
        Err(format!(
            "listen port {port} is outside the managed TCP proxy range \
             {LISTEN_PORT_MIN}-{LISTEN_PORT_MAX}"
        ))
    }
}

/// Normalize and validate an upstream host for `proxy_pass`.
///
/// Anything nginx would read as more than one token — whitespace, `;`, `{`,
/// `}` — is an injection into a file nginx runs as root, so the accepted
/// shape is deliberately small: an IP literal (IPv6 in brackets), or a
/// hostname of letters, digits, dots and hyphens.
pub fn normalize_upstream_host(host: &str) -> Result<String, String> {
    let h = host.trim();
    if let Some(inner) = h.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        return inner
            .parse::<std::net::Ipv6Addr>()
            .map(|_| format!("[{inner}]"))
            .map_err(|_| format!("invalid IPv6 upstream '{h}'"));
    }
    if h.parse::<std::net::Ipv4Addr>().is_ok() {
        return Ok(h.to_string());
    }
    // A digits-and-dots name that is not a valid IPv4 literal is not a
    // hostname either — nginx would try to resolve it and fail loudly at
    // config-load time, which is a worse failure than refusing it here.
    if h.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return Err(format!("invalid IPv4 upstream '{h}'"));
    }
    let valid = !h.is_empty()
        && h.len() <= 253
        && h.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
        && !h.starts_with('.')
        && !h.starts_with('-')
        && !h.ends_with('.')
        && !h.ends_with('-')
        && !h.contains("..");
    if valid {
        Ok(h.to_string())
    } else {
        Err(format!("invalid upstream host '{host}'"))
    }
}

/// A `host:port` upstream after validation — what `proxy_pass` receives.
pub fn normalize_upstream(host: &str, port: u16) -> Result<String, String> {
    let host = normalize_upstream_host(host)?;
    if port == 0 {
        return Err("upstream port must be 1-65535".to_string());
    }
    Ok(format!("{host}:{port}"))
}

/// The one file a proxy lives in. Validated names make this safe to build by
/// string interpolation alone.
pub fn stream_config_path(name: &str) -> String {
    format!("{STREAM_DIR}/{name}.conf")
}

/// Render one stream `server {}` block. Everything interpolated here has
/// already passed the validators; the render itself asserts nothing.
pub fn render_stream_server(
    listen_port: u16,
    upstream: &str,
    tls: Option<&TlsPaths>,
) -> String {
    let mut out = String::from(
        "# Managed by DockPanel — do not edit; rewritten by the agent.\nserver {\n",
    );
    match tls {
        Some(t) => {
            out.push_str(&format!("    listen {listen_port} ssl;\n"));
            out.push_str(&format!("    ssl_certificate {};\n", t.cert));
            out.push_str(&format!("    ssl_certificate_key {};\n", t.key));
            out.push_str("    ssl_protocols TLSv1.2 TLSv1.3;\n");
        }
        None => out.push_str(&format!("    listen {listen_port};\n")),
    }
    out.push_str(&format!("    proxy_pass {upstream};\n"));
    // Database connections idle far past nginx's 10m default; killing them
    // mid-session is the classic "remote access drops after coffee break"
    // bug, so the timeout is generous while connect stays tight.
    out.push_str("    proxy_connect_timeout 10s;\n    proxy_timeout 1h;\n}\n");
    out
}

/// Whether the requested public listen port can actually be bound on this
/// host right now — the backend's allocation is authoritative for
/// uniqueness, but the agent still checks because a stale row or a manually
/// bound port must never produce a config nginx cannot start.
pub fn listen_port_free(port: u16) -> bool {
    std::net::TcpListener::bind(("0.0.0.0", port)).is_ok()
}

/// Write a managed stream proxy: validate, write temp+rename, `nginx -t`,
/// reload, roll back on failure. Returns the rendered path on success.
pub async fn write_stream_proxy(
    name: &str,
    listen_port: u16,
    upstream_host: &str,
    upstream_port: u16,
    tls: Option<&TlsPaths>,
) -> Result<String, String> {
    validate_proxy_name(name)?;
    validate_listen_port(listen_port)?;
    let upstream = normalize_upstream(upstream_host, upstream_port)?;

    if !stream_available() {
        return Err(
            "nginx stream module/include is not wired on this box — run update.sh or enable \
             the stream module, then retry"
                .to_string(),
        );
    }
    if !listen_port_free(listen_port) {
        return Err(format!("port {listen_port} is already bound on this host"));
    }

    // `nginx -t` is a whole-server test — writing into a box whose config is
    // already broken would pin someone else's defect on this proxy.
    if let Ok(out) = test_config().await {
        if !out.success {
            return Err(format!(
                "nginx config is already failing `nginx -t` — refusing to write a stream \
                 proxy on top of a broken configuration: {}",
                out.stderr.trim()
            ));
        }
    }

    let path = stream_config_path(name);
    let previous = std::fs::read_to_string(&path).ok();
    let body = render_stream_server(listen_port, &upstream, tls);

    std::fs::create_dir_all(STREAM_DIR)
        .map_err(|e| format!("cannot create {STREAM_DIR}: {e}"))?;
    let tmp = format!("{path}.tmp");
    std::fs::write(&tmp, &body)
        .and_then(|_| std::fs::rename(&tmp, &path))
        .map_err(|e| {
            std::fs::remove_file(&tmp).ok();
            format!("failed to write {path}: {e}")
        })?;

    match test_config().await {
        Ok(out) if out.success => {
            crate::services::nginx::reload().await?;
            Ok(path)
        }
        Ok(out) => {
            let restored = restore_or_remove(&path, previous.as_deref());
            Err(format!(
                "nginx -t rejected the stream config: {}{}",
                out.stderr.trim(),
                restore_note(restored)
            ))
        }
        Err(e) => {
            restore_or_remove(&path, previous.as_deref());
            Err(format!("nginx -t could not run: {e}"))
        }
    }
}

/// Remove a managed stream proxy. Idempotent — a missing file is success,
/// because the caller's intent (no such listener) is already true.
pub async fn remove_stream_proxy(name: &str) -> Result<(), String> {
    validate_proxy_name(name)?;
    let path = stream_config_path(name);
    if !std::path::Path::new(&path).exists() {
        return Ok(());
    }
    let previous = std::fs::read_to_string(&path).ok();
    std::fs::remove_file(&path).map_err(|e| format!("failed to remove {path}: {e}"))?;

    match test_config().await {
        Ok(out) if out.success => crate::services::nginx::reload().await,
        Ok(out) => {
            let restored = restore_or_remove(&path, previous.as_deref());
            Err(format!(
                "nginx -t failed after removing {name}: {}{}",
                out.stderr.trim(),
                restore_note(restored)
            ))
        }
        Err(e) => {
            restore_or_remove(&path, previous.as_deref());
            Err(format!("nginx -t could not run: {e}"))
        }
    }
}

/// The stream files nginx currently reads, as (name, listen, upstream) — the
/// read side of the contract `write_stream_proxy` produces.
pub fn list_stream_proxies() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(STREAM_DIR) else {
        return out;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let Some(stem) = name.strip_suffix(".conf") else {
            continue;
        };
        if let Ok(body) = std::fs::read_to_string(entry.path()) {
            let upstream = body
                .lines()
                .find_map(|l| l.trim().strip_prefix("proxy_pass ").map(|s| s.trim_end_matches(';')))
                .unwrap_or("")
                .to_string();
            let listen = body
                .lines()
                .find_map(|l| {
                    let t = l.trim().strip_prefix("listen ")?.trim_end_matches(';');
                    Some(t.split_whitespace().next()?.to_string())
                })
                .unwrap_or_default();
            out.push((stem.to_string(), format!("{listen} -> {upstream}")));
        }
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_render_has_listen_proxy_pass_and_timeouts() {
        let body = render_stream_server(40001, "127.0.0.1:5450", None);
        assert!(body.contains("listen 40001;"));
        assert!(body.contains("proxy_pass 127.0.0.1:5450;"));
        assert!(body.contains("proxy_connect_timeout"));
        assert!(body.contains("proxy_timeout"));
        assert!(!body.contains("ssl"), "plain proxy must not claim TLS");
    }

    #[test]
    fn tls_render_adds_ssl_listen_and_registry_paths() {
        let tls = TlsPaths {
            cert: "/etc/dockpanel/ssl/registry/x/fullchain.pem".to_string(),
            key: "/etc/dockpanel/ssl/registry/x/privkey.pem".to_string(),
        };
        let body = render_stream_server(40002, "127.0.0.1:3306", Some(&tls));
        assert!(body.contains("listen 40002 ssl;"));
        assert!(body.contains("ssl_certificate /etc/dockpanel/ssl/registry/x/fullchain.pem;"));
        assert!(body.contains(
            "ssl_certificate_key /etc/dockpanel/ssl/registry/x/privkey.pem;"
        ));
    }

    #[test]
    fn proxy_names_that_escape_the_directory_are_rejected() {
        assert!(validate_proxy_name("db-main").is_ok());
        assert!(validate_proxy_name("a").is_ok());
        for bad in ["../evil", "a b", "Name", "x;y", "-lead", "trail-", "", "a/b"] {
            assert!(validate_proxy_name(bad).is_err(), "accepted '{bad}'");
        }
        let long = "a".repeat(49);
        assert!(validate_proxy_name(&long).is_err());
    }

    #[test]
    fn listen_ports_stay_inside_the_managed_range() {
        assert!(validate_listen_port(LISTEN_PORT_MIN).is_ok());
        assert!(validate_listen_port(LISTEN_PORT_MAX).is_ok());
        for p in [0u16, 80, 443, 3080, LISTEN_PORT_MIN - 1, LISTEN_PORT_MAX + 1] {
            assert!(validate_listen_port(p).is_err(), "accepted port {p}");
        }
    }

    #[test]
    fn upstream_hosts_are_strictly_validated() {
        assert_eq!(normalize_upstream_host("127.0.0.1").unwrap(), "127.0.0.1");
        assert_eq!(normalize_upstream_host("[::1]").unwrap(), "[::1]");
        assert_eq!(normalize_upstream_host("db.internal").unwrap(), "db.internal");
        for bad in ["", " ", "a; rm -rf", "a b", "-x", ".x", "x.", "a..b", "[::1", "999.1.1.1"] {
            assert!(normalize_upstream_host(bad).is_err(), "accepted '{bad}'");
        }
    }

    #[test]
    fn upstream_render_keeps_ipv6_brackets() {
        assert_eq!(normalize_upstream("[::1]", 5432).unwrap(), "[::1]:5432");
        assert!(normalize_upstream("127.0.0.1", 0).is_err());
    }

    #[test]
    fn stream_available_reads_the_nginx_conf_sentinel() {
        let dir = std::env::temp_dir().join("dockpanel-stream-avail");
        std::fs::create_dir_all(&dir).unwrap();
        let with = dir.join("with.conf");
        let without = dir.join("without.conf");
        std::fs::write(&with, "stream { include /etc/nginx/dockpanel-streams/*.conf; }\nhttp {}\n").unwrap();
        std::fs::write(&without, "events {} http {}\n").unwrap();
        assert!(stream_available_at(&with));
        assert!(!stream_available_at(&without));
        assert!(!stream_available_at(&dir.join("absent.conf")));
        std::fs::remove_dir_all(&dir).ok();
    }
}
