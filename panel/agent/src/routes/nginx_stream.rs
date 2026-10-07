use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{delete, get},
    Json, Router,
};
use serde::Deserialize;

use crate::routes::AppState;
use crate::services::{firewall, nginx_stream};

#[derive(Deserialize)]
pub struct StreamProxyRequest {
    pub name: String,
    pub listen_port: u16,
    /// Generic proxies name the upstream explicitly. Database proxies send
    /// `container_id` instead — the upstream is read off the container's own
    /// loopback binding, never trusted from the wire.
    #[serde(default)]
    pub upstream_host: Option<String>,
    #[serde(default)]
    pub upstream_port: Option<u16>,
    /// When set, the upstream is derived from this managed container's
    /// existing 127.0.0.1 port binding.
    #[serde(default)]
    pub container_id: Option<String>,
    #[serde(default)]
    pub tls: bool,
    #[serde(default)]
    pub cert_path: Option<String>,
    #[serde(default)]
    pub key_path: Option<String>,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/nginx/streams", get(list_streams).post(create_stream))
        .route("/nginx/streams/{name}", delete(delete_stream))
}

/// Certificate/key paths arriving over the API must already live where
/// DockPanel keeps certificates — a stream config that points outside the
/// managed roots would let a caller make nginx read (and log) arbitrary
/// files at reload.
fn validate_cert_path(path: &str, field: &str) -> Result<(), (StatusCode, String)> {
    let ok = (path.starts_with("/etc/dockpanel/") || path.starts_with("/etc/letsencrypt/"))
        && !path.contains("..")
        && std::path::Path::new(path).is_file();
    if ok {
        Ok(())
    } else {
        Err((
            StatusCode::BAD_REQUEST,
            format!("{field} '{path}' is not a file under the managed certificate roots"),
        ))
    }
}

async fn create_stream(
    State(state): State<AppState>,
    Json(body): Json<StreamProxyRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Two shapes: an explicit host:port for generic forwards, or a container
    // id whose loopback binding the agent reads for itself. Never both —
    // letting a caller supply an upstream AND a container would quietly
    // choose which one is real.
    let (upstream_host, upstream_port) = match &body.container_id {
        Some(cid) => {
            let port = nginx_stream::container_loopback_port(&state.docker, cid)
                .await
                .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
            ("127.0.0.1".to_string(), port)
        }
        None => (
            body.upstream_host
                .clone()
                .ok_or_else(|| (StatusCode::BAD_REQUEST, "missing upstream_host".to_string()))?,
            body.upstream_port
                .ok_or_else(|| (StatusCode::BAD_REQUEST, "missing upstream_port".to_string()))?,
        ),
    };

    let tls = if body.tls {
        let cert = body.cert_path.clone().ok_or((
            StatusCode::BAD_REQUEST,
            "tls requires cert_path".to_string(),
        ))?;
        let key = body
            .key_path
            .clone()
            .ok_or((StatusCode::BAD_REQUEST, "tls requires key_path".to_string()))?;
        validate_cert_path(&cert, "cert_path")?;
        validate_cert_path(&key, "key_path")?;
        Some(nginx_stream::TlsPaths { cert, key })
    } else {
        None
    };

    let path = nginx_stream::write_stream_proxy(
        &body.name,
        body.listen_port,
        &upstream_host,
        upstream_port,
        tls.as_ref(),
    )
    .await
    .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    // The listener exists in nginx now — open the firewall so it is actually
    // reachable. A box without a firewall manager returns false; that is not
    // an error, the port is already open.
    if !firewall::add_port(&body.listen_port.to_string(), "tcp").await {
        tracing::warn!(
            "firewall rule for tcp/{} not added — no firewall manager or rule failed",
            body.listen_port
        );
    }

    Ok(Json(serde_json::json!({
        "ok": true,
        "name": body.name,
        "path": path,
        "listen_port": body.listen_port,
        "upstream": format!("{upstream_host}:{upstream_port}"),
    })))
}

async fn list_streams(State(_state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "available": nginx_stream::stream_available(),
        "proxies": nginx_stream::list_stream_proxies()
            .iter()
            .map(|(name, desc)| serde_json::json!({ "name": name, "listen_upstream": desc }))
            .collect::<Vec<_>>(),
    }))
}

#[derive(Deserialize)]
pub struct DeleteStreamQuery {
    pub listen_port: Option<u16>,
}

async fn delete_stream(
    State(_state): State<AppState>,
    Path(name): Path<String>,
    Query(q): Query<DeleteStreamQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    nginx_stream::remove_stream_proxy(&name)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    if let Some(port) = q.listen_port {
        firewall::remove_port(&port.to_string(), "tcp").await;
    }

    Ok(Json(serde_json::json!({ "ok": true, "name": name })))
}
