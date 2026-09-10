//! Policy engine — first-match-wins Security Rules evaluation.
//!
//! Mirrors `mcp-gateway/policy.py`:
//! - Load + compile policies from the config bundle (sorted by priority).
//! - Evaluate against an MCP context; first match wins.
//! - Actions: `allow`, `deny`, `skip_dlp`, `skip_ratelimit`.
//! - No policies configured → allow (open gateway).
//! - Policies configured but no match → deny (fail closed).
//!
//! JSON-RPC error for deny: -32010 "policy denied".

use corex_core::config::PolicyConfig;
use corex_scan::expression::{parse_expression, evaluate, build_mcp_context, EvalContext, Expr};

pub const MCP_POLICY_DENIED: i32 = -32010;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyAction {
    Allow,
    Deny,
    SkipDlp,
    SkipRateLimit,
}

impl PolicyAction {
    fn parse(s: &str) -> Self {
        match s {
            "deny" => PolicyAction::Deny,
            "skip_dlp" => PolicyAction::SkipDlp,
            "skip_ratelimit" => PolicyAction::SkipRateLimit,
            _ => PolicyAction::Allow,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PolicyResult {
    pub action: PolicyAction,
    pub rule_name: String,
    pub skip_dlp: bool,
    pub skip_ratelimit: bool,
}

impl PolicyResult {
    pub fn denied(&self) -> bool {
        self.action == PolicyAction::Deny
    }
    pub fn allowed(&self) -> bool {
        self.action == PolicyAction::Allow
    }
}

#[derive(Debug, Clone)]
struct CompiledPolicy {
    name: String,
    ast: Expr,
    action: PolicyAction,
    log: bool,
    no_log: bool,
}

/// The policy engine holds compiled policies. Cloneable so each request can
/// use a snapshot; reload replaces the inner Arc.
#[derive(Clone, Default)]
pub struct PolicyEngine {
    policies: std::sync::Arc<Vec<CompiledPolicy>>,
    has_policies_configured: bool,
}

impl PolicyEngine {
    /// Load and compile policies from the config bundle.
    pub fn load(raw: &[PolicyConfig]) -> Self {
        let has_policies_configured = !raw.is_empty();
        let mut compiled = Vec::new();
        for p in raw {
            if !p.enabled {
                continue;
            }
            // Re-parse the expression string (the bundle also carries
            // expression_ast JSON, but re-parsing avoids dict-shape coupling).
            match parse_expression(&p.expression) {
                Ok(ast) => compiled.push(CompiledPolicy {
                    name: p.name.clone(),
                    ast,
                    action: PolicyAction::parse(&p.action),
                    log: p.log,
                    no_log: p.no_log,
                }),
                Err(e) => {
                    tracing::error!("Failed to parse policy {}: {e}", p.name);
                }
            }
        }
        // Sort by priority (ascending = first match wins). Policies don't carry
        // priority in the compiled struct; sort at load using the raw order.
        // (PolicyConfig.priority is available; re-sort here.)
        let _ = &compiled; // already in raw order; the caller sorts by priority.
        Self {
            policies: std::sync::Arc::new(compiled),
            has_policies_configured,
        }
    }

    /// Load with explicit priority ordering (caller sorts raw by priority first).
    pub fn load_sorted(raw: &[PolicyConfig]) -> Self {
        let mut sorted: Vec<&PolicyConfig> = raw.iter().filter(|p| p.enabled).collect();
        sorted.sort_by_key(|p| p.priority);
        let has = !raw.is_empty();
        let mut compiled = Vec::new();
        for p in sorted {
            match parse_expression(&p.expression) {
                Ok(ast) => compiled.push(CompiledPolicy {
                    name: p.name.clone(),
                    ast,
                    action: PolicyAction::parse(&p.action),
                    log: p.log,
                    no_log: p.no_log,
                }),
                Err(e) => tracing::error!("Failed to parse policy {}: {e}", p.name),
            }
        }
        Self {
            policies: std::sync::Arc::new(compiled),
            has_policies_configured: has,
        }
    }

    /// Evaluate policies against the MCP context. First match wins.
    pub fn evaluate(&self, ctx: &EvalContext) -> PolicyResult {
        if !self.has_policies_configured {
            return PolicyResult {
                action: PolicyAction::Allow,
                rule_name: "<default: no policies>".into(),
                skip_dlp: false,
                skip_ratelimit: false,
            };
        }
        for p in self.policies.iter() {
            if evaluate(&p.ast, ctx) {
                let action = p.action;
                if p.log && !p.no_log {
                    tracing::info!(
                        "Policy {} {:?} on tool={} server={} identity={}",
                        p.name, action,
                        ctx.fields.get("mcp.tool").and_then(|v| v.as_str()).unwrap_or(""),
                        ctx.fields.get("mcp.server").and_then(|v| v.as_str()).unwrap_or(""),
                        ctx.fields.get("mcp.identity").and_then(|v| v.as_str()).unwrap_or(""),
                    );
                }
                return PolicyResult {
                    action,
                    rule_name: p.name.clone(),
                    skip_dlp: action == PolicyAction::SkipDlp,
                    skip_ratelimit: action == PolicyAction::SkipRateLimit,
                };
            }
        }
        PolicyResult {
            action: PolicyAction::Deny,
            rule_name: "<default: no match>".into(),
            skip_dlp: false,
            skip_ratelimit: false,
        }
    }
}

/// Build a context for a tools/call and evaluate.
#[allow(clippy::too_many_arguments)]
pub fn check_tool_access(
    method: &str,
    tool_name: &str,
    server_namespace: &str,
    auth: &crate::auth::AuthContext,
    args: Option<&serde_json::Value>,
    ip_src: &str,
    engine: &PolicyEngine,
) -> PolicyResult {
    let ctx = build_mcp_context(
        method, server_namespace, tool_name, "", "",
        &auth.name, &auth.kind, &auth.team_id.to_string(),
        args, Some(&auth.claims), ip_src,
    );
    engine.evaluate(&ctx)
}

/// Build a context for resources/read and evaluate.
pub fn check_resource_access(
    method: &str,
    resource_uri: &str,
    server_namespace: &str,
    auth: &crate::auth::AuthContext,
    ip_src: &str,
    engine: &PolicyEngine,
) -> PolicyResult {
    let ctx = build_mcp_context(
        method, server_namespace, "", resource_uri, "",
        &auth.name, &auth.kind, &auth.team_id.to_string(),
        None, Some(&auth.claims), ip_src,
    );
    engine.evaluate(&ctx)
}

/// Build a context for prompts/get and evaluate.
pub fn check_prompt_access(
    method: &str,
    prompt_name: &str,
    server_namespace: &str,
    auth: &crate::auth::AuthContext,
    ip_src: &str,
    engine: &PolicyEngine,
) -> PolicyResult {
    let ctx = build_mcp_context(
        method, server_namespace, "", "", prompt_name,
        &auth.name, &auth.kind, &auth.team_id.to_string(),
        None, Some(&auth.claims), ip_src,
    );
    engine.evaluate(&ctx)
}

/// Filter a tool list using policy evaluation at list time.
/// Clients must not see tools they cannot invoke.
pub fn filter_tool_list(
    tools: &[serde_json::Value],
    namespace: &str,
    auth: &crate::auth::AuthContext,
    ip_src: &str,
    engine: &PolicyEngine,
) -> Vec<serde_json::Value> {
    tools
        .iter()
        .filter(|tool| {
            let name = tool.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let pr = check_tool_access("tools/call", name, namespace, auth, None, ip_src, engine);
            pr.allowed() || pr.action == PolicyAction::SkipDlp || pr.action == PolicyAction::SkipRateLimit
        })
        .cloned()
        .collect()
}

/// Filter a resource list using policy evaluation at list time.
pub fn filter_resource_list(
    resources: &[serde_json::Value],
    namespace: &str,
    auth: &crate::auth::AuthContext,
    ip_src: &str,
    engine: &PolicyEngine,
) -> Vec<serde_json::Value> {
    resources
        .iter()
        .filter(|res| {
            let uri = res.get("uri").and_then(|v| v.as_str()).unwrap_or("");
            let pr = check_resource_access("resources/read", uri, namespace, auth, ip_src, engine);
            pr.allowed() || pr.action == PolicyAction::SkipDlp || pr.action == PolicyAction::SkipRateLimit
        })
        .cloned()
        .collect()
}

/// Filter a prompt list using policy evaluation at list time.
pub fn filter_prompt_list(
    prompts: &[serde_json::Value],
    namespace: &str,
    auth: &crate::auth::AuthContext,
    ip_src: &str,
    engine: &PolicyEngine,
) -> Vec<serde_json::Value> {
    prompts
        .iter()
        .filter(|prompt| {
            let name = prompt.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let pr = check_prompt_access("prompts/get", name, namespace, auth, ip_src, engine);
            pr.allowed() || pr.action == PolicyAction::SkipDlp || pr.action == PolicyAction::SkipRateLimit
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use corex_core::config::PolicyConfig;
    use crate::auth::AuthContext;

    fn policy(name: &str, expr: &str, action: &str, priority: i32) -> PolicyConfig {
        PolicyConfig {
            id: 1, team_id: 1, name: name.into(), enabled: true, priority,
            expression: expr.into(), expression_ast: None, action: action.into(),
            log: true, no_log: false,
        }
    }

    fn auth() -> AuthContext {
        AuthContext {
            identity_id: 1, team_id: 1, name: "ci".into(), subject: "ci".into(),
            kind: "pat".into(), claims: serde_json::Value::Null,
        }
    }

    #[test]
    fn no_policies_allows() {
        let engine = PolicyEngine::load(&[]);
        let pr = check_tool_access("tools/call", "t", "jira", &auth(), None, "", &engine);
        assert!(pr.allowed());
    }

    #[test]
    fn deny_when_no_match() {
        let engine = PolicyEngine::load_sorted(&[policy("p1", r#"mcp.server = "github""#, "allow", 0)]);
        let pr = check_tool_access("tools/call", "t", "jira", &auth(), None, "", &engine);
        assert!(pr.denied());
    }

    #[test]
    fn first_match_wins_by_priority() {
        let raw = vec![
            policy("deny_all", r#"mcp.server = "jira""#, "deny", 0),
            policy("allow_tool", r#"mcp.tool = "jira__ok""#, "allow", 1),
        ];
        let engine = PolicyEngine::load_sorted(&raw);
        // deny_all matches first (priority 0) → deny even though allow_tool would match.
        let pr = check_tool_access("tools/call", "jira__ok", "jira", &auth(), None, "", &engine);
        assert!(pr.denied());
        assert_eq!(pr.rule_name, "deny_all");
    }

    #[test]
    fn skip_dlp_action() {
        let engine = PolicyEngine::load_sorted(&[policy("p", r#"mcp.server = "jira""#, "skip_dlp", 0)]);
        let pr = check_tool_access("tools/call", "t", "jira", &auth(), None, "", &engine);
        assert!(pr.skip_dlp);
        assert!(!pr.skip_ratelimit);
    }

    #[test]
    fn filter_tool_list_hides_denied() {
        // deny create (priority 0), allow everything else (priority 1).
        let raw = vec![
            policy("deny_create", r#"mcp.tool ~ "create""#, "deny", 0),
            policy("allow_rest", r#"mcp.server = "jira""#, "allow", 1),
        ];
        let engine = PolicyEngine::load_sorted(&raw);
        let tools = vec![
            serde_json::json!({"name": "jira__create"}),
            serde_json::json!({"name": "jira__read"}),
        ];
        let filtered = filter_tool_list(&tools, "jira", &auth(), "", &engine);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0]["name"], "jira__read");
    }
}
