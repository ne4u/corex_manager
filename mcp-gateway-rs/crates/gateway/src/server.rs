//! Axum server setup — routes, security headers, CORS, startup/shutdown.

use axum::middleware::Next;
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;

use crate::metrics::Metrics;
use crate::protocol::{handle_get, handle_options, handle_post, GatewayState};

/// Build the Axum router with all MCP gateway routes.
pub fn build_router(state: GatewayState) -> Router {
    let metrics = state.metrics.clone();
    Router::new()
        .route("/mcp", post(handle_post).get(handle_get).options(handle_options))
        .route("/healthz", get(handle_healthz))
        .route("/metrics", get(handle_metrics))
        .route("/status", get(handle_status))
        .route(
            "/.well-known/oauth-protected-resource",
            get(handle_oauth_protected_resource),
        )
        .layer(axum::middleware::from_fn(security_headers))
        .with_state(state)
        .route("/metrics_text", get(move || handle_metrics_text(metrics)))
}

/// Security headers middleware.
async fn security_headers(request: axum::extract::Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert("x-content-type-options", "nosniff".parse().unwrap());
    headers.insert("x-frame-options", "DENY".parse().unwrap());
    headers.insert("cache-control", "no-store".parse().unwrap());
    headers.insert("x-xss-protection", "1; mode=block".parse().unwrap());
    headers.insert("referrer-policy", "no-referrer".parse().unwrap());
    response
}

async fn handle_healthz(State(state): State<GatewayState>) -> impl IntoResponse {
    let configured = state.config.read().is_some();
    axum::Json(serde_json::json!({"status": "ok", "configured": configured}))
}

async fn handle_metrics(State(state): State<GatewayState>) -> impl IntoResponse {
    let body = state.metrics.render();
    (
        [("content-type", "text/plain; version=0.0.4")],
        body,
    )
}

async fn handle_metrics_text(metrics: Metrics) -> impl IntoResponse {
    let body = metrics.render();
    ([("content-type", "text/plain; version=0.0.4")], body)
}

async fn handle_oauth_protected_resource(headers: axum::http::HeaderMap) -> impl IntoResponse {
    let host = headers.get("host").and_then(|v| v.to_str().ok()).unwrap_or("");
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("https");
    let base_url = format!("{scheme}://{host}");
    axum::Json(serde_json::json!({
        "resource": format!("{base_url}/mcp"),
        "authorization_servers": [],
        "bearer_methods_supported": ["header"],
        "scopes_supported": [],
    }))
}

/// JSON status endpoint — returns metrics snapshot, active sessions, circuit
/// breaker state, catalog freshness, and alert state for UI consumption.
async fn handle_status(State(state): State<GatewayState>) -> impl IntoResponse {
    let metrics = state.metrics.snapshot();
    let active_sessions = state.sessions.active_count().await;
    let open_circuits = state.upstream.breaker().open_circuits();
    let catalog_freshness = state.catalog_store.freshness();
    let alerts = state.alerter.snapshot();
    let configured = state.config.read().is_some();

    let circuits: Vec<serde_json::Value> = open_circuits
        .into_iter()
        .map(|(id, failures, open_until)| {
            serde_json::json!({
                "server_id": id,
                "failures": failures,
                "open_until": open_until,
            })
        })
        .collect();

    let catalogs: Vec<serde_json::Value> = catalog_freshness
        .into_iter()
        .map(|(id, fetched_at, tools, resources, prompts)| {
            serde_json::json!({
                "server_id": id,
                "fetched_at": fetched_at,
                "tools": tools,
                "resources": resources,
                "prompts": prompts,
            })
        })
        .collect();

    let alerts_json: Vec<serde_json::Value> = alerts
        .into_iter()
        .map(|a| serde_json::to_value(a).unwrap_or_default())
        .collect();

    axum::Json(serde_json::json!({
        "status": "ok",
        "configured": configured,
        "metrics": metrics,
        "active_sessions": active_sessions,
        "open_circuits": circuits,
        "catalog_freshness": catalogs,
        "alerts": alerts_json,
    }))
}

use axum::extract::State;
use axum::response::IntoResponse;
