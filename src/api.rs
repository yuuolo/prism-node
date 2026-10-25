//! Local control API (loopback only by default):
//!   GET  /stats   per-user traffic counters (see [`crate::stats::Report`])
//!   POST /reload  re-read the config file, like SIGHUP
//!   GET  /version

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use tokio_util::sync::CancellationToken;

use crate::server::Node;

pub async fn serve(node: Arc<Node>, addr: SocketAddr, shutdown: CancellationToken) -> anyhow::Result<SocketAddr> {
    let app = Router::new()
        .route("/stats", get(|State(n): State<Arc<Node>>| async move { Json(n.stats.report()) }))
        .route(
            "/reload",
            post(|State(n): State<Arc<Node>>| async move {
                // Reading certificates and kicking sessions is quick but blocking.
                match tokio::task::spawn_blocking(move || n.reload()).await {
                    Ok(Ok(r)) => Ok(Json(r)),
                    Ok(Err(e)) => Err((StatusCode::UNPROCESSABLE_ENTITY, format!("{e:#}"))),
                    Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
                }
            }),
        )
        .route("/version", get(|| async { env!("CARGO_PKG_VERSION") }))
        .with_state(node);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).with_graceful_shutdown(shutdown.cancelled_owned()).await;
    });
    Ok(bound)
}

/// Minimal HTTP/1.1 client for the CLI (`prism-node stats` / `reload`).
pub fn call(addr: SocketAddr, method: &str, path: &str) -> anyhow::Result<String> {
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(3))
        .map_err(|e| anyhow::anyhow!("cannot reach the prism-node API at {addr} ({e}); is it running?"))?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    write!(s, "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")?;
    let mut resp = Vec::new();
    s.read_to_end(&mut resp)?;
    let resp = String::from_utf8_lossy(&resp);
    let (head, body) = resp.split_once("\r\n\r\n").unwrap_or((&resp, ""));
    let status = head.lines().next().unwrap_or("");
    if !status.contains(" 200 ") {
        anyhow::bail!("{status}: {body}");
    }
    Ok(body.to_string())
}
