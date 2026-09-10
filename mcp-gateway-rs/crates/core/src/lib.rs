//! corex-core: JSON-RPC 2.0 + MCP types, config bundle, crypto, SSRF, errors.
//!
//! One-way dependency direction: this crate depends on nothing internal.
//! `scan`, `policy`, `proxy`, `gateway` depend on it.

pub mod config;
pub mod crypto;
pub mod error;
pub mod jsonrpc;
pub mod mcp_types;
pub mod ssrf;
