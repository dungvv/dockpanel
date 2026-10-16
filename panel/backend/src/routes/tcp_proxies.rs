//! Generic TCP proxies terminated by the host nginx `stream` module.
//!
//! Each row is one public listen port on one server forwarding to one
//! `host:port` upstream; the agent writes the actual `server {}` file under
//! /etc/nginx/dockpanel-streams and owns the firewall rule. Database remote
//! access (`kind='database'`) lives in `databases.rs` — this file owns only
//! the operator-defined generic kind and the shared port allocator.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use uuid::Uuid;

use crate::auth::{AuthUser, ServerScope};
use crate::error::{agent_error, err, internal_error, paginate, require_admin, ApiError};
use crate::AppState;

/// Public listen ports come only from this range — kept clear of the HTTP
/// listeners, the panel's own ports, the per-engine database pools, and the
/// Docker ephemeral range. The agent re-checks the range independently.
pub(crate) const LISTEN_PORT_MIN: i32 = 40000;
pub(crate) const LISTEN_PORT_MAX: i32 = 44999;

#[derive(serde::Serialize, sqlx::FromRow)]
pub struct TcpProxy {
    pub id: Uuid,
    pub server_id: Uuid,
    pub database_id: Option<Uuid>,
    pub certificate_id: Option<Uuid>,
    pub name: String,
    pub kind: String,
    pub listen_port: i32,
    pub upstream_host: String,
    pub upstream_port: i32,
    pub tls: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(serde::Deserialize)]
pub struct ListQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(serde::Deserialize)]
pub struct CreateProxyRequest {
    pub name: String,
    pub upstream_host: String,
    pub upstream_port: i32,
    #[serde(default)]
    pub tls: bool,
    pub certificate_id: Option<Uuid>,
}

/// The agent's rule, mirrored: the panel must refuse in its own words rather
/// than relaying the agent's refusal for a form it just validated.
fn valid_proxy_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 48
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !name.starts_with('-')
        && !name.ends_with('-')
}

/// Mirror of the agent's `normalize_upstream_host`: an IP literal (IPv6 in
/// brackets) or a hostname of letters/digits/dots/hyphens. Anything that
/// would make `proxy_pass` more than one token never reaches the agent.
fn valid_upstream_host(host: &str) -> bool {
    let h = host.trim();
    if h.is_empty() || h.len() > 253 {
        return false;
    }
    if let Some(inner) = h.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        return inner.parse::<std::net::Ipv6Addr>().is_ok();
    }
    if h.parse::<std::net::Ipv4Addr>().is_ok() {
        return true;
    }
    if h.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return false; // digits-and-dots that is not IPv4 is not a hostname
    }
    h.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
        && !h.starts_with('.')
        && !h.starts_with('-')
        && !h.ends_with('.')
        && !h.ends_with('-')
        && !h.contains("..")
}

/// First free public listen port on this server. `generate_series` finds the
/// lowest gap; the table's UNIQUE(server_id, listen_port) makes the insert
/// itself the last word under concurrency.
async fn allocate_listen_port(state: &AppState, server_id: Uuid) -> Result<i32, ApiError> {
    let row: Option<(i32,)> = sqlx::query_as(
        "SELECT s.port FROM generate_series($1::int, $2::int) AS s(port) \
         WHERE s.port NOT IN (SELECT listen_port FROM tcp_proxies WHERE server_id = $3) \
         LIMIT 1",
    )
    .bind(LISTEN_PORT_MIN)
    .bind(LISTEN_PORT_MAX)
    .bind(server_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| internal_error("allocate TCP listen port", e))?;

    row.map(|(p,)| p).ok_or_else(|| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "No TCP proxy ports left in the managed range",
        )
    })
}

/// Resolve a caller-supplied certificate on THIS server into the registry
/// paths the agent writes into the stream config. Scoped to the caller (or an
/// admin): a tenant enabling remote access on their database must not be able
/// to hang another user's certificate on the listener.
async fn certificate_paths(
    state: &AppState,
    server_id: Uuid,
    certificate_id: Uuid,
    user_id: Uuid,
    is_admin: bool,
) -> Result<(String, String), ApiError> {
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT cert_path, key_path FROM tls_certificates \
         WHERE id = $1 AND server_id = $2 AND (user_id = $3 OR $4)",
    )
    .bind(certificate_id)
    .bind(server_id)
    .bind(user_id)
    .bind(is_admin)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| internal_error("resolve certificate", e))?;

    row.ok_or_else(|| {
        err(
            StatusCode::BAD_REQUEST,
            "Certificate not found on this server",
        )
    })
}

/// The shared create path: agent first, row second — a persisted row is
/// truth about what exists, so the file must exist before the row does.
/// Task 4 (database remote access) calls this with kind="database".
pub(crate) async fn create_proxy(
    state: &AppState,
    agent: &crate::services::agent::AgentHandle,
    server_id: Uuid,
    user_id: Uuid,
    name: &str,
    kind: &str,
    upstream_host: &str,
    upstream_port: i32,
    tls: bool,
    certificate_id: Option<Uuid>,
    database_id: Option<Uuid>,
    container_id: Option<&str>,
    caller_is_admin: bool,
) -> Result<TcpProxy, ApiError> {
    // Refuse a taken name/database BEFORE the agent call: the insert's unique
    // violation used to arrive after the agent had already written, and the
    // rollback below then deleted the live proxy's file. (The agent also
    // refuses to overwrite, which covers two requests racing past this.)
    let taken: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM tcp_proxies \
         WHERE (server_id = $1 AND name = $2) OR ($3::uuid IS NOT NULL AND database_id = $3)",
    )
    .bind(server_id)
    .bind(name)
    .bind(database_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| internal_error("check tcp proxy name", e))?;
    if taken.is_some() {
        return Err(err(
            StatusCode::CONFLICT,
            match database_id {
                Some(_) => "Remote access is already enabled, or another database maps to the same proxy name",
                None => "A TCP proxy with this name already exists on this server",
            },
        ));
    }

    let listen_port = allocate_listen_port(state, server_id).await?;

    let mut agent_body = serde_json::json!({
        "name": name,
        "listen_port": listen_port,
        "tls": tls,
    });
    match container_id {
        // Database kind: the agent reads the upstream off the container's own
        // loopback binding; what the panel believes about `databases.port` is
        // never put on the wire as authoritative.
        Some(cid) => {
            agent_body["container_id"] = serde_json::json!(cid);
        }
        None => {
            agent_body["upstream_host"] = serde_json::json!(upstream_host);
            agent_body["upstream_port"] = serde_json::json!(upstream_port);
        }
    }
    if tls {
        let cert_id = certificate_id
            .ok_or_else(|| err(StatusCode::BAD_REQUEST, "tls requires certificate_id"))?;
        let (cert_path, key_path) =
            certificate_paths(state, server_id, cert_id, user_id, caller_is_admin).await?;
        agent_body["cert_path"] = serde_json::json!(cert_path);
        agent_body["key_path"] = serde_json::json!(key_path);
    }

    let agent_result = agent
        .post("/nginx/streams", Some(agent_body))
        .await
        .map_err(|e| agent_error("TCP proxy creation", e))?;

    // Record the upstream the agent actually wrote — for container-backed
    // proxies that is the binding it inspected, not the hint we sent.
    let (row_host, row_port) = agent_result
        .get("upstream")
        .and_then(|u| u.as_str())
        .and_then(|u| u.rsplit_once(':'))
        .map(|(h, p)| (h.to_string(), p.parse::<i32>().unwrap_or(upstream_port)))
        .unwrap_or_else(|| (upstream_host.to_string(), upstream_port));

    let row: TcpProxy = match sqlx::query_as(
        "INSERT INTO tcp_proxies \
         (server_id, user_id, database_id, certificate_id, name, kind, listen_port, \
          upstream_host, upstream_port, tls) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
         RETURNING id, server_id, database_id, certificate_id, name, kind, \
                   listen_port, upstream_host, upstream_port, tls, created_at",
    )
    .bind(server_id)
    .bind(user_id)
    .bind(database_id)
    .bind(certificate_id)
    .bind(name)
    .bind(kind)
    .bind(listen_port)
    .bind(&row_host)
    .bind(row_port)
    .bind(tls)
    .fetch_one(&state.db)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            // The agent already wrote the listener — remove it before the
            // row error escapes, or the box keeps a port the panel forgot.
            let path = format!("/nginx/streams/{name}?listen_port={listen_port}");
            if let Err(e2) = agent.delete(&path).await {
                tracing::error!(
                    "TCP proxy '{name}' row insert failed AND agent cleanup failed: {e2}"
                );
            }
            if e.to_string().contains("unique") || e.to_string().contains("duplicate") {
                return Err(err(
                    StatusCode::CONFLICT,
                    "Proxy name or port already in use on this server",
                ));
            }
            return Err(internal_error("create tcp proxy", e));
        }
    };

    Ok(row)
}

/// GET /api/tcp-proxies — list this server's proxies visible to the caller.
pub async fn list(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    ServerScope(server_id, _agent): ServerScope,
    axum::extract::Query(params): axum::extract::Query<ListQuery>,
) -> Result<Json<Vec<TcpProxy>>, ApiError> {
    let (limit, offset) = paginate(params.limit, params.offset);

    // Same admin-widening shape as databases::list — an admin of the server
    // sees its proxies even when a tenant owns the row.
    let proxies: Vec<TcpProxy> = sqlx::query_as(
        "SELECT p.id, p.server_id, p.database_id, p.certificate_id, p.name, p.kind, \
         p.listen_port, p.upstream_host, p.upstream_port, p.tls, p.created_at \
         FROM tcp_proxies p \
         WHERE p.server_id = $1 \
         AND (p.user_id = $2 OR EXISTS (SELECT 1 FROM users u, servers sv \
              WHERE u.id = $2 AND u.role = 'admin' AND sv.id = p.server_id \
              AND (sv.is_local OR sv.user_id = u.id))) \
         ORDER BY p.created_at DESC LIMIT $3 OFFSET $4",
    )
    .bind(server_id)
    .bind(claims.sub)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await
    .map_err(|e| internal_error("list tcp proxies", e))?;

    Ok(Json(proxies))
}

/// POST /api/tcp-proxies — create a generic TCP forward. Admin-only: a public
/// listen port on the host is infrastructure, not a per-site resource.
pub async fn create(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    ServerScope(server_id, agent): ServerScope,
    Json(body): Json<CreateProxyRequest>,
) -> Result<(StatusCode, Json<TcpProxy>), ApiError> {
    require_admin(&claims.role)?;

    if !valid_proxy_name(&body.name) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "Proxy name must be 1-48 chars: lowercase letters, digits and '-'",
        ));
    }
    if !valid_upstream_host(&body.upstream_host) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid upstream host"));
    }
    if body.upstream_port < 1 || body.upstream_port > 65535 {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid upstream port"));
    }

    let row = create_proxy(
        &state,
        &agent,
        server_id,
        claims.sub,
        body.name.trim(),
        "generic",
        body.upstream_host.trim(),
        body.upstream_port,
        body.tls,
        body.certificate_id,
        None,
        None,
        true,
    )
    .await?;

    tracing::info!(
        "TCP proxy created: {} :{} -> {}:{}",
        row.name,
        row.listen_port,
        row.upstream_host,
        row.upstream_port
    );
    crate::services::activity::log_activity_on_server(
        &state.db, claims.sub, &claims.email, "tcp_proxy.create",
        Some("tcp_proxy"), Some(&row.name),
        Some(&format!(":{} -> {}:{}", row.listen_port, row.upstream_host, row.upstream_port)),
        None, Some(server_id), claims.key_id,
    ).await;

    Ok((StatusCode::CREATED, Json(row)))
}

/// DELETE /api/tcp-proxies/{id} — remove the stream file, the firewall rule,
/// and the row, in that order.
pub async fn remove(
    State(state): State<AppState>,
    AuthUser(claims): AuthUser,
    ServerScope(server_id, agent): ServerScope,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_admin(&claims.role)?;

    let row: Option<(Uuid, String, i32, Option<Uuid>)> = sqlx::query_as(
        "SELECT id, name, listen_port, database_id FROM tcp_proxies \
         WHERE id = $1 AND server_id = $2",
    )
    .bind(id)
    .bind(server_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| internal_error("find tcp proxy", e))?;

    let (pid, name, listen_port, database_id) =
        row.ok_or_else(|| err(StatusCode::NOT_FOUND, "TCP proxy not found"))?;

    if database_id.is_some() {
        return Err(err(
            StatusCode::CONFLICT,
            "This proxy belongs to a database — disable its remote access instead",
        ));
    }

    // The file and the firewall rule go first: the row is the record of what
    // exists, so it leaves last — a deleted row pointing at a live listener
    // would be the panel lying about an open port.
    let path = format!("/nginx/streams/{name}?listen_port={listen_port}");
    agent
        .delete(&path)
        .await
        .map_err(|e| agent_error("TCP proxy removal", e))?;

    sqlx::query("DELETE FROM tcp_proxies WHERE id = $1")
        .bind(pid)
        .execute(&state.db)
        .await
        .map_err(|e| internal_error("delete tcp proxy", e))?;

    tracing::info!("TCP proxy deleted: {name} (port {listen_port})");
    crate::services::activity::log_activity_on_server(
        &state.db, claims.sub, &claims.email, "tcp_proxy.delete",
        Some("tcp_proxy"), Some(&name), Some(&format!("port {listen_port}")),
        None, Some(server_id), claims.key_id,
    ).await;

    Ok(Json(serde_json::json!({ "ok": true, "name": name })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_names_match_the_agent_rule() {
        assert!(valid_proxy_name("db-main"));
        assert!(valid_proxy_name("redis-1"));
        for bad in ["", "Name", "a b", "../x", "-x", "x-", "x;y"] {
            assert!(!valid_proxy_name(bad), "accepted '{bad}'");
        }
    }

    #[test]
    fn upstream_hosts_match_the_agent_rule() {
        assert!(valid_upstream_host("127.0.0.1"));
        assert!(valid_upstream_host("[::1]"));
        assert!(valid_upstream_host("db.internal"));
        for bad in ["", "a b", "999.1.1.1", "-x", "x.", "a..b", "h;rm -rf"] {
            assert!(!valid_upstream_host(bad), "accepted '{bad}'");
        }
    }
}
