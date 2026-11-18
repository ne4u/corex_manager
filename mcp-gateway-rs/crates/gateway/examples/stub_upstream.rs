//! Stub MCP upstream server for benchmarking and manual testing.
//!
//! Serves canned JSON-RPC responses for initialize / tools/list /
//! resources/list / prompts/list / tools/call on `POST /mcp`, plus
//! `GET /healthz`. `initialize` returns a stable `mcp-session-id` header so
//! the gateway's lazy upstream-session path can be exercised end to end.
//!
//! Usage:
//!   STUB_PORT=8090 stub_upstream            # serve
//!   stub_upstream --hash <token>            # print a bcrypt hash (cost 12)
//!                                           # for seeding bench PATs

use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(|s| s.as_str()) == Some("--hash") {
        let token = args.get(2).expect("usage: stub_upstream --hash <token>");
        println!("{}", bcrypt::hash(token, 12).unwrap());
        return;
    }

    let app = Router::new()
        .route("/mcp", post(handle_mcp))
        .route("/healthz", get(|| async { "ok" }));

    let port = std::env::var("STUB_PORT").unwrap_or_else(|_| "8090".into());
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .expect("bind stub upstream");
    eprintln!("stub_upstream listening on :{port}");
    axum::serve(listener, app)
        .tcp_nodelay(true)
        .await
        .unwrap();
}

async fn handle_mcp(Json(body): Json<Value>) -> Response {
    let method = body.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let id = body.get("id").cloned().unwrap_or(Value::Null);

    // Notifications get a bare 202.
    if method.starts_with("notifications/") || body.get("id").is_none() {
        return axum::http::StatusCode::ACCEPTED.into_response();
    }

    let (result, session) = match method {
        "initialize" => (
            json!({
                "protocolVersion": "2025-03-26",
                "capabilities": {
                    "tools": {"listChanged": false},
                    "resources": {"listChanged": false},
                    "prompts": {"listChanged": false}
                },
                "serverInfo": {"name": "stub-upstream", "version": "0.1.0"}
            }),
            Some("stub-session-0000-0000".to_string()),
        ),
        "tools/list" => (
            json!({"tools": [{
                "name": "echo",
                "description": "Returns a fixed ok result",
                "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}}
            }]}),
            None,
        ),
        "resources/list" => (json!({"resources": []}), None),
        "resources/templates/list" => (json!({"resourceTemplates": []}), None),
        "prompts/list" => (json!({"prompts": []}), None),
        "tools/call" => (
            json!({"content": [{"type": "text", "text": "ok"}], "isError": false}),
            None,
        ),
        "ping" => (json!({}), None),
        _ => (json!({}), None),
    };

    let mut resp = Json(json!({"jsonrpc": "2.0", "id": id, "result": result})).into_response();
    if let Some(sid) = session {
        resp.headers_mut()
            .insert("mcp-session-id", axum::http::HeaderValue::from_str(&sid).unwrap());
    }
    resp
}
