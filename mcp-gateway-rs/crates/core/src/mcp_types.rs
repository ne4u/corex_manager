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

/// Gateway release advertised in MCP `serverInfo` and upstream `clientInfo`.
pub const GATEWAY_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Public namespace separator: `{namespace}--{name}`.
///
/// `__` is reserved by clients that qualify tools as `server__tool` and reject
/// a second `__` (Grok). Namespaces may contain single hyphens (`corex-manager`)
/// and tool names may contain underscores, so `--` still splits unambiguously.
pub const NAMESPACE_SEP: &str = "--";

/// Canonical separator stored in policy expressions (`mcp.tool`, `mcp.prompt`).
/// Incoming `--` names are rewritten to this form before evaluation, and
/// `tools/call` / `prompts/get` still accept names written with `__`.
pub const POLICY_NAMESPACE_SEP: &str = "__";

/// Split `{namespace}--{name}` or legacy `{namespace}__{name}`.
///
/// When both separators appear, the one that occurs first wins, so a `--`
/// inside a legacy tool name (or a `__` inside a public tool name) stays
/// with the tool. Returns `None` when neither separator is present.
pub fn split_namespace(name: &str) -> Option<(&str, &str)> {
    let dash = name.find(NAMESPACE_SEP);
    let under = name.find(POLICY_NAMESPACE_SEP);
    match (dash, under) {
        (Some(d), Some(u)) if d < u => name.split_once(NAMESPACE_SEP),
        (Some(_), Some(_)) => name.split_once(POLICY_NAMESPACE_SEP),
        (Some(_), None) => name.split_once(NAMESPACE_SEP),
        (None, Some(_)) => name.split_once(POLICY_NAMESPACE_SEP),
        (None, None) => None,
    }
}

/// Prefix a name as `{namespace}--{name}` for tools/list and prompts/list.
pub fn prefix_name(namespace: &str, name: &str) -> String {
    format!("{namespace}{NAMESPACE_SEP}{name}")
}

/// Rewrite a wire name to the policy form `{namespace}__{name}`.
///
/// `corex-manager--get_api` and `corex-manager__get_api` both become
/// `corex-manager__get_api`. Names with no separator are returned unchanged.
pub fn canonical_namespaced(name: &str) -> String {
    match split_namespace(name) {
        Some((ns, rest)) => format!("{ns}{POLICY_NAMESPACE_SEP}{rest}"),
        None => name.to_string(),
    }
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
        assert_eq!(prefix_name("jira", "create_issue"), "jira--create_issue");
        assert_eq!(
            prefix_name("corex-manager", "get_api_armor_settings"),
            "corex-manager--get_api_armor_settings"
        );
        assert_eq!(
            split_namespace("jira--create_issue"),
            Some(("jira", "create_issue"))
        );
        assert_eq!(
            split_namespace("jira__create_issue"),
            Some(("jira", "create_issue"))
        );
        assert_eq!(
            split_namespace("corex-manager--get_api_armor_settings"),
            Some(("corex-manager", "get_api_armor_settings"))
        );
        assert_eq!(
            split_namespace("corex-manager__get_api_armor_settings"),
            Some(("corex-manager", "get_api_armor_settings"))
        );
        // First separator wins when a tool name contains the other separator.
        assert_eq!(
            split_namespace("corex-manager--foo__bar"),
            Some(("corex-manager", "foo__bar"))
        );
        assert_eq!(
            split_namespace("corex-manager__foo--bar"),
            Some(("corex-manager", "foo--bar"))
        );
        assert_eq!(split_namespace("noseparator"), None);
        assert_eq!(
            canonical_namespaced("corex-manager--get_api"),
            "corex-manager__get_api"
        );
        assert_eq!(
            canonical_namespaced("corex-manager__get_api"),
            "corex-manager__get_api"
        );
        assert_eq!(canonical_namespaced("plain"), "plain");
        assert!(!prefix_name("corex-manager", "health").contains("__"));
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
