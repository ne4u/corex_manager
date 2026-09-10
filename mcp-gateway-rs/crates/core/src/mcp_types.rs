//! MCP protocol types: Tool, Resource, ResourceTemplate, Prompt, Capabilities.
//!
//! These are deliberately loose (most fields are `serde_json::Value` or
//! optional) because upstream catalogs vary and the gateway mostly forwards
//! them with namespace prefixing.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// MCP protocol version advertised by the gateway.
pub const PROTOCOL_VERSION: &str = "2025-11-25";

/// A tool definition (from `tools/list`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Tool {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "inputSchema", skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<Value>,
}

/// A resource definition (from `resources/list`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Resource {
    pub uri: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "mimeType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// A resource template (from `resources/templates/list`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResourceTemplate {
    #[serde(rename = "uriTemplate")]
    pub uri_template: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "mimeType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// A prompt definition (from `prompts/list`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Prompt {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Vec<PromptArgument>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PromptArgument {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub required: bool,
}

/// Server capabilities announced in `initialize`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Capabilities {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<ToolCapabilities>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceCapabilities>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompts: Option<PromptCapabilities>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logging: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCapabilities {
    #[serde(rename = "listChanged")]
    pub list_changed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceCapabilities {
    #[serde(rename = "listChanged")]
    pub list_changed: bool,
    pub subscribe: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptCapabilities {
    #[serde(rename = "listChanged")]
    pub list_changed: bool,
}

/// Server info announced in `initialize`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
}

/// Wrap an upstream resource URI as `mcp://{namespace}/{encoded-original}`.
pub fn wrap_resource_uri(namespace: &str, original_uri: &str) -> String {
    use urlencoding::encode;
    format!("mcp://{}/{}", namespace, encode(original_uri))
}

/// Invert a wrapped URI `mcp://{namespace}/{encoded}` back into `(namespace, original)`.
/// Returns `None` if the URI is not a wrapped gateway URI.
pub fn unwrap_resource_uri(uri: &str) -> Option<(String, String)> {
    let rest = uri.strip_prefix("mcp://")?;
    let (namespace, encoded) = rest.split_once('/')?;
    let original = urlencoding::decode(encoded).ok()?.into_owned();
    Some((namespace.to_string(), original))
}

/// Split a namespaced name `{namespace}__{name}` into `(namespace, name)`.
/// Returns `None` if there is no `__` separator.
pub fn split_namespace(name: &str) -> Option<(&str, &str)> {
    name.split_once("__")
}

/// Prefix a name as `{namespace}__{name}`.
pub fn prefix_name(namespace: &str, name: &str) -> String {
    format!("{namespace}__{name}")
}

// A tiny inline URL-encoder to avoid pulling another crate dependency.
mod urlencoding {
    pub fn encode(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for &b in s.as_bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(b as char);
                }
                _ => {
                    out.push('%');
                    out.push_str(&format!("{b:02X}"));
                }
            }
        }
        out
    }

    pub fn decode(s: &str) -> Result<std::borrow::Cow<'_, str>, ()> {
        percent_decode(s)
    }

    fn percent_decode(s: &str) -> Result<std::borrow::Cow<'_, str>, ()> {
        let bytes = s.as_bytes();
        if !bytes.contains(&b'%') {
            return Ok(std::borrow::Cow::Borrowed(s));
        }
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                let hi = hex_val(bytes[i + 1]).ok_or(())?;
                let lo = hex_val(bytes[i + 2]).ok_or(())?;
                out.push((hi << 4) | lo);
                i += 3;
            } else {
                out.push(bytes[i]);
                i += 1;
            }
        }
        String::from_utf8(out).map(std::borrow::Cow::Owned).map_err(|_| ())
    }

    fn hex_val(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'A'..=b'F' => Some(b - b'A' + 10),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_prefix_and_split() {
        assert_eq!(prefix_name("jira", "create_issue"), "jira__create_issue");
        assert_eq!(
            split_namespace("jira__create_issue"),
            Some(("jira", "create_issue"))
        );
        assert_eq!(split_namespace("noseparator"), None);
    }

    #[test]
    fn resource_uri_wrap_and_unwrap() {
        let wrapped = wrap_resource_uri("jira", "https://up.example.com/r/123?x=1 2");
        assert!(wrapped.starts_with("mcp://jira/"));
        let (ns, original) = unwrap_resource_uri(&wrapped).unwrap();
        assert_eq!(ns, "jira");
        assert_eq!(original, "https://up.example.com/r/123?x=1 2");
    }

    #[test]
    fn unwrap_rejects_non_gateway_uri() {
        assert!(unwrap_resource_uri("https://example.com").is_none());
        assert!(unwrap_resource_uri("mcp://onlynamespace").is_none());
    }
}
