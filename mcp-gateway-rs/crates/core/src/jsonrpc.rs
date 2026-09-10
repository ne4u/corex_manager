//! JSON-RPC 2.0 message types.
//!
//! A message is a request (has `id` + `method`), a response (has `id` +
//! `result` or `error`), or a notification (has `method`, no `id`).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::JsonRpcError;

pub const JSONRPC_VERSION: &str = "2.0";

/// A parsed JSON-RPC message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Message {
    Request(Request),
    Notification(Notification),
    Response(Response),
}

/// A JSON-RPC request (expects a response).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub jsonrpc: String,
    pub id: Value,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

/// A JSON-RPC notification (no response expected).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    pub jsonrpc: String,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

/// A JSON-RPC response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub jsonrpc: String,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl Response {
    pub fn success(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: Value, err: JsonRpcError) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            result: None,
            error: Some(err),
        }
    }
}

impl Message {
    /// Parse a single JSON-RPC message from a JSON value.
    pub fn from_value(value: &Value) -> Result<Self, serde_json::Error> {
        serde_json::from_value(value.clone())
    }

    /// Returns the method if this is a request or notification.
    pub fn method(&self) -> Option<&str> {
        match self {
            Message::Request(r) => Some(&r.method),
            Message::Notification(n) => Some(&n.method),
            Message::Response(_) => None,
        }
    }

    /// Returns the id if this is a request.
    pub fn request_id(&self) -> Option<&Value> {
        match self {
            Message::Request(r) => Some(&r.id),
            _ => None,
        }
    }
}

/// A batch of messages (JSON-RPC allows an array of requests/notifications).
pub fn parse_batch(value: &Value) -> Vec<Message> {
    match value {
        Value::Array(arr) => arr
            .iter()
            .filter_map(|v| Message::from_value(v).ok())
            .collect(),
        Value::Object(_) => Message::from_value(value).ok().into_iter().collect(),
        _ => Vec::new(),
    }
}
