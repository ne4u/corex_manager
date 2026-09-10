//! JSON-RPC 2.0 error codes and error response builder.
//!
//! Codes mirror the Python gateway (`mcp-gateway/protocol.py`).

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Standard JSON-RPC 2.0 error codes.
pub const PARSE_ERROR: i32 = -32700;
pub const INVALID_REQUEST: i32 = -32600;
pub const METHOD_NOT_FOUND: i32 = -32601;
pub const INVALID_PARAMS: i32 = -32602;
pub const INTERNAL_ERROR: i32 = -32603;

/// MCP-gateway-specific error codes.
pub const MCP_SERVER_ERROR: i32 = -32000;
pub const MCP_NOT_INITIALIZED: i32 = -32001;
pub const MCP_POLICY_DENIED: i32 = -32010;
pub const MCP_RATE_LIMITED: i32 = -32029;
pub const MCP_DLP_BLOCKED: i32 = -32050;
pub const MCP_GUARDRAIL_BLOCKED: i32 = -32051;

/// A JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl JsonRpcError {
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    pub fn with_data(mut self, data: serde_json::Value) -> Self {
        self.data = Some(data);
        self
    }
}

/// A typed error that carries a JSON-RPC code, used internally to short-circuit
/// request handling and produce a well-formed error response.
#[derive(Debug, Error)]
pub struct GatewayError {
    pub code: i32,
    pub message: String,
    pub data: Option<serde_json::Value>,
}

impl GatewayError {
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    pub fn with_data(mut self, data: serde_json::Value) -> Self {
        self.data = Some(data);
        self
    }

    pub fn policy_denied(msg: impl Into<String>) -> Self {
        Self::new(MCP_POLICY_DENIED, msg)
    }

    pub fn rate_limited(msg: impl Into<String>) -> Self {
        Self::new(MCP_RATE_LIMITED, msg)
    }

    pub fn dlp_blocked(msg: impl Into<String>) -> Self {
        Self::new(MCP_DLP_BLOCKED, msg)
    }

    pub fn guardrail_blocked(msg: impl Into<String>) -> Self {
        Self::new(MCP_GUARDRAIL_BLOCKED, msg)
    }

    pub fn not_initialized() -> Self {
        Self::new(MCP_NOT_INITIALIZED, "Session not initialized")
    }

    pub fn server_error(msg: impl Into<String>) -> Self {
        Self::new(MCP_SERVER_ERROR, msg)
    }

    pub fn to_jsonrpc(&self) -> JsonRpcError {
        JsonRpcError {
            code: self.code,
            message: self.message.clone(),
            data: self.data.clone(),
        }
    }
}

impl std::fmt::Display for GatewayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl From<serde_json::Error> for GatewayError {
    fn from(e: serde_json::Error) -> Self {
        Self::new(PARSE_ERROR, format!("JSON error: {e}"))
    }
}
