//! Discovery modes and meta-tools.
//!
//! Per-team discovery modes:
//! - `passthrough`: forward list methods directly to upstreams (no virtual registry).
//! - `meta-tools`: expose gateway-level meta-tools alongside upstream tools.
//! - `hybrid`: use `expose` flag per server — exposed servers appear in the
//!   virtual registry, non-exposed are accessible only via meta-tools.
//!
//! Meta-tools (namespaced as `gateway__*`):
//! - `list_servers`: list all available servers for the team.
//! - `list_tools`: list all tools across servers (with namespace prefix).
//! - `search_tools`: search tools by name/description.
//! - `describe_tool`: get full tool schema.
//! - `refresh_tools`: trigger a catalog refresh.

use serde_json::Value;

use corex_core::config::ServerConfig;
use corex_proxy::Catalog;

/// Discovery mode for a team.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryMode {
    Passthrough,
    MetaTools,
    Hybrid,
}

impl DiscoveryMode {
    pub fn parse(s: &str) -> Self {
        match s {
            "meta-tools" => DiscoveryMode::MetaTools,
            "hybrid" => DiscoveryMode::Hybrid,
            _ => DiscoveryMode::Passthrough,
        }
    }
}

/// Meta-tool names (prefixed with `gateway__`).
pub const META_LIST_SERVERS: &str = "gateway__list_servers";
pub const META_LIST_TOOLS: &str = "gateway__list_tools";
pub const META_SEARCH_TOOLS: &str = "gateway__search_tools";
pub const META_DESCRIBE_TOOL: &str = "gateway__describe_tool";
pub const META_REFRESH_TOOLS: &str = "gateway__refresh_tools";

/// Check if a tool name is a meta-tool.
pub fn is_meta_tool(name: &str) -> bool {
    matches!(
        name,
        META_LIST_SERVERS | META_LIST_TOOLS | META_SEARCH_TOOLS | META_DESCRIBE_TOOL | META_REFRESH_TOOLS
    )
}

/// Build the meta-tool definitions for `tools/list` injection.
pub fn meta_tool_definitions() -> Vec<Value> {
    vec![
        serde_json::json!({
            "name": META_LIST_SERVERS,
            "description": "List all available MCP servers for this team.",
            "inputSchema": {"type": "object", "properties": {}, "required": []},
            "_meta": {"mcp_server": "gateway", "mcp_meta_tool": true}
        }),
        serde_json::json!({
            "name": META_LIST_TOOLS,
            "description": "List all tools across all servers (with namespace prefix).",
            "inputSchema": {"type": "object", "properties": {}, "required": []},
            "_meta": {"mcp_server": "gateway", "mcp_meta_tool": true}
        }),
        serde_json::json!({
            "name": META_SEARCH_TOOLS,
            "description": "Search tools by name or description substring.",
            "inputSchema": {
                "type": "object",
                "properties": {"query": {"type": "string", "description": "Search query"}},
                "required": ["query"]
            },
            "_meta": {"mcp_server": "gateway", "mcp_meta_tool": true}
        }),
        serde_json::json!({
            "name": META_DESCRIBE_TOOL,
            "description": "Get the full schema for a specific tool.",
            "inputSchema": {
                "type": "object",
                "properties": {"name": {"type": "string", "description": "Full tool name (namespace__tool)"}},
                "required": ["name"]
            },
            "_meta": {"mcp_server": "gateway", "mcp_meta_tool": true}
        }),
        serde_json::json!({
            "name": META_REFRESH_TOOLS,
            "description": "Trigger a catalog refresh for all servers.",
            "inputSchema": {"type": "object", "properties": {}, "required": []},
            "_meta": {"mcp_server": "gateway", "mcp_meta_tool": true}
        }),
    ]
}

/// Execute a meta-tool call. Returns the JSON-RPC result value.
pub fn execute_meta_tool(
    tool_name: &str,
    args: &Value,
    servers: &[ServerConfig],
    catalogs: &[(i64, Catalog)],
) -> Value {
    match tool_name {
        META_LIST_SERVERS => {
            let server_list: Vec<Value> = servers
                .iter()
                .filter(|s| s.enabled)
                .map(|s| {
                    serde_json::json!({
                        "namespace": s.namespace,
                        "name": s.name,
                        "display_name": s.display_name,
                        "description": s.description,
                        "transport_type": s.transport_type,
                    })
                })
                .collect();
            serde_json::json!({"servers": server_list})
        }
        META_LIST_TOOLS => {
            let mut all_tools = Vec::new();
            for (sid, catalog) in catalogs {
                if let Some(server) = servers.iter().find(|s| s.id == *sid) {
                    let ns = &server.namespace;
                    for tool in &catalog.tools {
                        let mut prefixed = tool.clone();
                        if let Some(name) = prefixed.get("name").and_then(|v| v.as_str()).map(|s| s.to_string()) {
                            prefixed["name"] = Value::String(format!("{ns}__{name}"));
                        }
                        all_tools.push(prefixed);
                    }
                }
            }
            serde_json::json!({"tools": all_tools})
        }
        META_SEARCH_TOOLS => {
            let query = args.get("query").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
            let mut matches = Vec::new();
            for (sid, catalog) in catalogs {
                if let Some(server) = servers.iter().find(|s| s.id == *sid) {
                    let ns = &server.namespace;
                    for tool in &catalog.tools {
                        let name = tool.get("name").and_then(|v| v.as_str()).unwrap_or("");
                        let desc = tool.get("description").and_then(|v| v.as_str()).unwrap_or("");
                        if name.to_lowercase().contains(&query) || desc.to_lowercase().contains(&query) {
                            let mut prefixed = tool.clone();
                            prefixed["name"] = Value::String(format!("{ns}__{name}"));
                            matches.push(prefixed);
                        }
                    }
                }
            }
            serde_json::json!({"tools": matches})
        }
        META_DESCRIBE_TOOL => {
            let target = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
            // Split namespace__tool.
            if let Some((ns, original)) = target.split_once("__") {
                for (sid, catalog) in catalogs {
                    if servers.iter().any(|s| s.namespace == ns && s.id == *sid) {
                        for tool in &catalog.tools {
                            if tool.get("name").and_then(|v| v.as_str()) == Some(original) {
                                let mut detailed = tool.clone();
                                detailed["name"] = Value::String(target.to_string());
                                return serde_json::json!({"tool": detailed});
                            }
                        }
                    }
                }
            }
            serde_json::json!({"error": "Tool not found"})
        }
        META_REFRESH_TOOLS => {
            // Signal that a refresh is needed (the caller handles the actual refresh).
            serde_json::json!({"status": "refresh_triggered"})
        }
        _ => serde_json::json!({"error": "Unknown meta-tool"}),
    }
}

/// Filter servers based on discovery mode and `expose` flag.
/// In hybrid mode, only `expose=true` servers appear in the virtual registry.
pub fn visible_servers(servers: &[ServerConfig], mode: DiscoveryMode) -> Vec<&ServerConfig> {
    servers
        .iter()
        .filter(|s| s.enabled)
        .filter(|s| match mode {
            DiscoveryMode::Hybrid => s.expose.unwrap_or(true),
            _ => true,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use corex_core::config::ServerConfig;

    fn server(id: i64, ns: &str, expose: Option<bool>) -> ServerConfig {
        ServerConfig {
            id, team_id: 1, name: ns.into(), namespace: ns.into(),
            display_name: None, description: None,
            url: Some(format!("http://{ns}.example.com/mcp")), original_url: None,
            enabled: true, verify_tls: true,
            auth_type: None, auth_header: None, auth_secret: None,
            timeout_ms: 30000, max_body_bytes: 1048576,
            has_replicas: false, replica_count: 1,
            transport_type: "streamable_http".into(),
            command: None, args: vec![], env_vars: Value::Null,
            package_manager: None, source_package_name: None, installed_version: None,
            expose, oauth_enabled: false,
            oauth_client_id: None, oauth_client_secret: None, oauth_scopes: None,
            oauth_access_token: None, oauth_refresh_token: None,
        }
    }

    #[test]
    fn meta_tool_detection() {
        assert!(is_meta_tool("gateway__list_servers"));
        assert!(is_meta_tool("gateway__search_tools"));
        assert!(!is_meta_tool("jira__create"));
    }

    #[test]
    fn meta_tool_definitions_count() {
        let defs = meta_tool_definitions();
        assert_eq!(defs.len(), 5);
    }

    #[test]
    fn hybrid_filters_by_expose() {
        let servers = vec![
            server(1, "exposed", Some(true)),
            server(2, "hidden", Some(false)),
            server(3, "default", None),
        ];
        let visible = visible_servers(&servers, DiscoveryMode::Hybrid);
        assert_eq!(visible.len(), 2);
        assert!(visible.iter().all(|s| s.namespace != "hidden"));
    }

    #[test]
    fn passthrough_shows_all() {
        let servers = vec![
            server(1, "a", Some(false)),
            server(2, "b", Some(true)),
        ];
        let visible = visible_servers(&servers, DiscoveryMode::Passthrough);
        assert_eq!(visible.len(), 2);
    }

    #[test]
    fn list_servers_meta_tool() {
        let servers = vec![server(1, "jira", None), server(2, "github", None)];
        let result = execute_meta_tool(META_LIST_SERVERS, &Value::Null, &servers, &[]);
        assert_eq!(result["servers"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn search_tools_meta_tool() {
        let servers = vec![server(1, "jira", None)];
        let catalog = Catalog {
            tools: vec![
                serde_json::json!({"name": "create", "description": "Create an issue"}),
                serde_json::json!({"name": "read", "description": "Read an issue"}),
            ],
            resources: vec![], prompts: vec![], fetched_at: 0.0,
        };
        let result = execute_meta_tool(META_SEARCH_TOOLS, &serde_json::json!({"query": "create"}), &servers, &[(1, catalog)]);
        assert_eq!(result["tools"].as_array().unwrap().len(), 1);
        assert_eq!(result["tools"][0]["name"], "jira__create");
    }
}
