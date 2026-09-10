//! Skills engine — serves published SKILL.md as virtual prompts.
//!
//! Mirrors `mcp-gateway/skills.py`:
//! - Loads skills from the config bundle, compiles `enable_when` expressions.
//! - Injects enabled skills as virtual prompts in `prompts/list`.
//! - Skills are namespaced as `skill__{name}`.
//! - `prompts/get skill__{name}` renders the published body as a markdown
//!   user message, plus attached files as embedded resources.

use std::sync::Arc;

use parking_lot::RwLock;
use serde_json::Value;

use corex_core::config::SkillConfig;
use corex_policy::auth::AuthContext;
use corex_scan::expression::{parse_expression, evaluate, build_mcp_context, Expr};

pub const SKILL_NAMESPACE: &str = "skill";

#[derive(Clone)]
#[allow(dead_code)]
pub struct CompiledSkill {
    pub id: i64,
    pub team_id: i64,
    pub name: String,
    pub description: Option<String>,
    pub enabled: bool,
    pub enable_when: Option<String>,
    pub enable_when_ast: Option<Expr>,
    pub tags: Option<Value>,
    pub published_version_id: Option<i64>,
    pub published_body: Option<String>,
    pub published_frontmatter: Option<Value>,
    pub published_files: Option<Value>,
}

/// Skills registry — shared, reloadable.
#[derive(Clone, Default)]
pub struct SkillsRegistry {
    skills: Arc<RwLock<Vec<CompiledSkill>>>,
    has_configured: Arc<RwLock<bool>>,
}

impl SkillsRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load and compile skills from the config bundle.
    pub fn load(&self, raw: &[SkillConfig]) {
        let has = !raw.is_empty();
        let mut compiled = Vec::new();
        for s in raw {
            if !s.enabled {
                continue;
            }
            let enable_when_ast = if let Some(expr) = &s.enable_when {
                match parse_expression(expr) {
                    Ok(ast) => Some(ast),
                    Err(e) => {
                        tracing::error!("Skill {}: failed to parse enable_when: {e}", s.name);
                        None
                    }
                }
            } else {
                None
            };
            compiled.push(CompiledSkill {
                id: s.id,
                team_id: s.team_id,
                name: s.name.clone(),
                description: s.description.clone(),
                enabled: s.enabled,
                enable_when: s.enable_when.clone(),
                enable_when_ast,
                tags: s.tags.clone(),
                published_version_id: s.published_version_id,
                published_body: s.published_body.clone(),
                published_frontmatter: s.published_frontmatter.clone(),
                published_files: s.published_files.clone(),
            });
        }
        *self.skills.write() = compiled;
        *self.has_configured.write() = has;
        tracing::info!("Loaded {} skills (has_config: {has})", self.skills.read().len());
    }

    /// Return true if any skills are configured.
    pub fn has_skills(&self) -> bool {
        *self.has_configured.read() && !self.skills.read().is_empty()
    }

    /// Return skills that are enabled, published, and whose enable_when passes.
    pub fn get_enabled_skills(&self, auth: &AuthContext) -> Vec<CompiledSkill> {
        let skills = self.skills.read();
        let mut result = Vec::new();
        for skill in skills.iter() {
            if !skill.enabled || skill.published_version_id.is_none() {
                continue;
            }
            if let Some(ast) = &skill.enable_when_ast {
                let ctx = build_mcp_context(
                    "prompts/list",
                    SKILL_NAMESPACE,
                    "", "", "",
                    &auth.name, &auth.kind, &auth.team_id.to_string(),
                    None, Some(&auth.claims), "",
                );
                if !evaluate(ast, &ctx) {
                    continue;
                }
            }
            result.push(skill.clone());
        }
        result
    }

    /// Find a skill by its name.
    pub fn get_skill_by_name(&self, name: &str) -> Option<CompiledSkill> {
        self.skills.read().iter().find(|s| s.name == name).cloned()
    }

    /// Return the namespaced prompt name for a skill.
    pub fn skill_prompt_name(skill_name: &str) -> String {
        format!("{SKILL_NAMESPACE}__{skill_name}")
    }

    /// Build a prompts/list entry for a skill.
    pub fn build_prompt_entry(skill: &CompiledSkill) -> Value {
        serde_json::json!({
            "name": Self::skill_prompt_name(&skill.name),
            "description": skill.description.as_deref().unwrap_or(&format!("Skill: {}", skill.name)),
            "arguments": [],
            "_meta": {
                "mcp_server": SKILL_NAMESPACE,
                "mcp_original_name": skill.name,
                "mcp_skill": true,
                "tags": skill.tags.clone(),
            }
        })
    }

    /// Render a skill as a prompts/get response.
    pub fn render_skill_prompt(skill: &CompiledSkill) -> Value {
        let mut messages = Vec::new();
        let body = skill.published_body.as_deref().unwrap_or("");
        let mut message = serde_json::json!({
            "role": "user",
            "content": {"type": "text", "text": body},
        });
        if let Some(fm) = &skill.published_frontmatter {
            if !fm.is_null() {
                message["_meta"] = serde_json::json!({"frontmatter": fm});
            }
        }
        messages.push(message);
        // Add attached files as embedded resources.
        if let Some(files) = &skill.published_files {
            if let Some(arr) = files.as_array() {
                for f in arr {
                    let path = f.get("path").and_then(|v| v.as_str()).unwrap_or("file");
                    let media_type = f.get("media_type").and_then(|v| v.as_str()).unwrap_or("application/octet-stream");
                    let content_b64 = f.get("content_b64").and_then(|v| v.as_str()).unwrap_or("");
                    if !content_b64.is_empty() {
                        messages.push(serde_json::json!({
                            "role": "user",
                            "content": {
                                "type": "resource",
                                "resource": {
                                    "uri": format!("skill://{}/{path}", skill.name),
                                    "mimeType": media_type,
                                    "blob": content_b64,
                                }
                            }
                        }));
                    }
                }
            }
        }
        serde_json::json!({
            "jsonrpc": "2.0",
            "result": {"messages": messages}
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corex_core::config::SkillConfig;

    fn skill(name: &str, enabled: bool, published: bool) -> SkillConfig {
        SkillConfig {
            id: 1, team_id: 1, name: name.into(), description: Some("test".into()),
            enabled, enable_when: None, tags: Some(serde_json::json!(["a"])),
            enable_when_ast: None,
            published_version_id: if published { Some(1) } else { None },
            published_body: Some("# Hello".into()),
            published_frontmatter: None, published_files: None,
        }
    }

    #[test]
    fn load_and_query() {
        let reg = SkillsRegistry::new();
        reg.load(&[skill("s1", true, true), skill("s2", false, true), skill("s3", true, false)]);
        assert!(reg.has_skills());
        let auth = AuthContext {
            identity_id: 1, team_id: 1, name: "ci".into(), subject: "ci".into(),
            kind: "pat".into(), claims: Value::Null,
        };
        let enabled = reg.get_enabled_skills(&auth);
        assert_eq!(enabled.len(), 1);
        assert_eq!(enabled[0].name, "s1");
    }

    #[test]
    fn prompt_name_and_entry() {
        assert_eq!(SkillsRegistry::skill_prompt_name("my_skill"), "skill__my_skill");
        let _s = skill("test", true, true);
        let compiled = CompiledSkill {
            id: 1, team_id: 1, name: "test".into(), description: Some("d".into()),
            enabled: true, enable_when: None, enable_when_ast: None,
            tags: None, published_version_id: Some(1),
            published_body: Some("body".into()), published_frontmatter: None, published_files: None,
        };
        let entry = SkillsRegistry::build_prompt_entry(&compiled);
        assert_eq!(entry["name"], "skill__test");
        assert_eq!(entry["_meta"]["mcp_skill"], true);
    }

    #[test]
    fn render_prompt() {
        let compiled = CompiledSkill {
            id: 1, team_id: 1, name: "test".into(), description: None,
            enabled: true, enable_when: None, enable_when_ast: None,
            tags: None, published_version_id: Some(1),
            published_body: Some("# Hello World".into()),
            published_frontmatter: Some(serde_json::json!({"version": "1.0"})),
            published_files: None,
        };
        let rendered = SkillsRegistry::render_skill_prompt(&compiled);
        assert_eq!(rendered["result"]["messages"][0]["content"]["text"], "# Hello World");
        assert_eq!(rendered["result"]["messages"][0]["_meta"]["frontmatter"]["version"], "1.0");
    }
}
