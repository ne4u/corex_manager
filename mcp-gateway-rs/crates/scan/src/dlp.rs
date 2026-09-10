//! DLP (Data Loss Prevention) engine — native Rust port of `shared/dlp_core.py`.
//!
//! Built-in detector *patterns* live in `defaults.rs` (compiled once). Rules
//! come from the config bundle and are **optional** — with no rules, no
//! scanning occurs (same as the Python gateway).
//!
//! Actions: `block`, `redact`, `tokenize`. Tokenization uses a callback
//! (Valkey-backed in the gateway).

use regex::{Regex, RegexBuilder};

use corex_core::config::DlpRuleConfig;

use crate::defaults;

/// Maximum text length for regex scanning (prevents ReDoS on huge inputs).
pub fn max_scan_length() -> usize {
    std::env::var("DLP_MAX_SCAN_LENGTH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100_000)
}

/// Known ReDoS-vulnerable pattern fragments (checked at compile time).
const REDOS_PATTERNS: &[&str] = &[
    r"\(.*[+*].*\)[+*]",   // nested quantifiers like (a+)+
    r"\(.*\|.*\)[+*]?",    // alternation with quantifier
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DlpAction {
    Block,
    Redact,
    Tokenize,
}

impl DlpAction {
    fn parse(s: &str) -> Self {
        match s {
            "redact" => DlpAction::Redact,
            "tokenize" => DlpAction::Tokenize,
            _ => DlpAction::Block,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyTo {
    JsonStrings,
    AllText,
}

impl ApplyTo {
    fn parse(s: Option<&str>) -> Self {
        match s {
            Some("all_text") => ApplyTo::AllText,
            _ => ApplyTo::JsonStrings,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Request,
    Response,
    Both,
}

impl Direction {
    fn parse(s: &str) -> Self {
        match s {
            "request" => Direction::Request,
            "response" => Direction::Response,
            _ => Direction::Both,
        }
    }
    fn matches(self, scan: Direction) -> bool {
        match self {
            Direction::Both => true,
            _ => self == scan,
        }
    }
}

/// A compiled DLP rule.
#[derive(Debug, Clone)]
pub struct CompiledDlpRule {
    pub name: String,
    pub priority: i32,
    pub direction: Direction,
    pub detector: String,
    pub regex: Regex,
    pub action: DlpAction,
    pub token_prefix: String,
    pub token_ttl: u32,
    pub apply_to: ApplyTo,
}

/// A tokenize callback: `(matched_text, prefix, ttl) -> token`.
#[allow(clippy::type_complexity)]
pub type TokenizeFn = Box<dyn Fn(&str, &str, u32) -> String + Send + Sync>;

/// Compile raw DLP rule configs into compiled rules (sorted by priority).
/// Skips disabled rules, unknown detectors, invalid regex, and ReDoS patterns.
pub fn compile_rules(raw: &[DlpRuleConfig]) -> Vec<CompiledDlpRule> {
    let mut compiled = Vec::new();
    for r in raw {
        if !r.enabled {
            continue;
        }
        let detector = r.detector.as_deref().unwrap_or("custom");
        let pattern = if detector == "custom" {
            r.find_regex.as_deref()
        } else {
            defaults::detector_pattern(detector)
        };

        let pattern = match pattern {
            Some(p) if !p.is_empty() => p,
            _ => {
                tracing::warn!("DLP rule {}: unknown/empty detector {}", r.name, detector);
                continue;
            }
        };

        // ReDoS check.
        if is_redos(pattern) {
            tracing::warn!("DLP rule {}: potentially ReDoS-vulnerable regex, skipping", r.name);
            continue;
        }

        // Compile case-insensitive (Python uses re.IGNORECASE).
        let regex = match RegexBuilder::new(pattern).case_insensitive(true).build() {
            Ok(re) => re,
            Err(e) => {
                tracing::warn!("DLP rule {}: invalid regex: {e}", r.name);
                continue;
            }
        };

        compiled.push(CompiledDlpRule {
            name: r.name.clone(),
            priority: r.priority,
            direction: Direction::parse(&r.direction),
            detector: detector.to_string(),
            regex,
            action: DlpAction::parse(&r.action),
            token_prefix: r.token_prefix.clone().unwrap_or_else(|| "tok_".into()),
            token_ttl: r.token_ttl.unwrap_or(3600),
            apply_to: ApplyTo::parse(r.apply_to.as_deref()),
        });
    }
    compiled.sort_by_key(|r| r.priority);
    compiled
}

/// Check a pattern string for ReDoS-vulnerable fragments.
pub fn is_redos(pattern: &str) -> bool {
    REDOS_PATTERNS.iter().any(|rp| {
        Regex::new(rp)
            .map(|re| re.is_match(pattern))
            .unwrap_or(false)
    })
}

/// A single DLP detection hit.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DlpHit {
    pub rule: String,
    pub detector: String,
    pub action: String,
    pub count: usize,
}

/// Result of a DLP scan.
#[derive(Debug, Clone, Default)]
pub struct DlpScanResult {
    pub blocked: bool,
    pub modified: bool,
    pub hits: Vec<DlpHit>,
    pub modified_data: serde_json::Value,
}

fn scan_text(
    text: &str,
    rules: &[&CompiledDlpRule],
    scan_direction: Direction,
    tokenize: Option<&TokenizeFn>,
) -> (String, Vec<DlpHit>) {
    let mut hits = Vec::new();
    let mut modified = text.to_string();
    let mut any_block = false;
    let max = max_scan_length();
    let scan_text = if text.len() > max { &text[..max] } else { text };

    for rule in rules {
        if !rule.direction.matches(scan_direction) {
            continue;
        }
        let count = rule.regex.find_iter(scan_text).count();
        if count == 0 {
            continue;
        }
        match rule.action {
            DlpAction::Block => {
                any_block = true;
                hits.push(DlpHit {
                    rule: rule.name.clone(),
                    detector: rule.detector.clone(),
                    action: "block".into(),
                    count,
                });
                break;
            }
            DlpAction::Redact => {
                modified = rule.regex.replace_all(&modified, "[REDACTED]").to_string();
                hits.push(DlpHit {
                    rule: rule.name.clone(),
                    detector: rule.detector.clone(),
                    action: "redact".into(),
                    count,
                });
            }
            DlpAction::Tokenize => {
                if let Some(fn_) = tokenize {
                    let prefix = rule.token_prefix.clone();
                    let ttl = rule.token_ttl;
                    let re = rule.regex.clone();
                    modified = re
                        .replace_all(&modified, |caps: &regex::Captures| {
                            fn_(&caps[0], &prefix, ttl)
                        })
                        .to_string();
                } else {
                    modified = rule.regex.replace_all(&modified, "[REDACTED]").to_string();
                }
                hits.push(DlpHit {
                    rule: rule.name.clone(),
                    detector: rule.detector.clone(),
                    action: "tokenize".into(),
                    count,
                });
            }
        }
    }

    if any_block {
        (text.to_string(), hits)
    } else {
        (modified, hits)
    }
}

fn scan_json_strings(
    value: &serde_json::Value,
    rules: &[&CompiledDlpRule],
    scan_direction: Direction,
    tokenize: Option<&TokenizeFn>,
) -> (serde_json::Value, Vec<DlpHit>) {
    let mut all_hits = Vec::new();
    let any_block = std::sync::atomic::AtomicBool::new(false);
    let ab = &any_block;

    fn walk(
        value: &serde_json::Value,
        rules: &[&CompiledDlpRule],
        scan_direction: Direction,
        tokenize: Option<&TokenizeFn>,
        hits: &mut Vec<DlpHit>,
        any_block: &std::sync::atomic::AtomicBool,
    ) -> serde_json::Value {
        if any_block.load(std::sync::atomic::Ordering::Relaxed) {
            return value.clone();
        }
        match value {
            serde_json::Value::String(s) => {
                let (modified, h) = scan_text(s, rules, scan_direction, tokenize);
                for hit in h {
                    if hit.action == "block" {
                        any_block.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                    hits.push(hit);
                }
                serde_json::Value::String(modified)
            }
            serde_json::Value::Object(map) => {
                let mut out = serde_json::Map::new();
                for (k, v) in map {
                    out.insert(k.clone(), walk(v, rules, scan_direction, tokenize, hits, any_block));
                }
                serde_json::Value::Object(out)
            }
            serde_json::Value::Array(arr) => {
                serde_json::Value::Array(
                    arr.iter()
                        .map(|v| walk(v, rules, scan_direction, tokenize, hits, any_block))
                        .collect(),
                )
            }
            other => other.clone(),
        }
    }

    let modified = walk(value, rules, scan_direction, tokenize, &mut all_hits, ab);
    if any_block.load(std::sync::atomic::Ordering::Relaxed) {
        (value.clone(), all_hits)
    } else {
        (modified, all_hits)
    }
}

fn scan_all_text(
    data: &serde_json::Value,
    rules: &[&CompiledDlpRule],
    scan_direction: Direction,
    tokenize: Option<&TokenizeFn>,
) -> (serde_json::Value, Vec<DlpHit>) {
    let text = data.to_string();
    let (modified, hits) = scan_text(&text, rules, scan_direction, tokenize);
    if hits.iter().any(|h| h.action == "block") {
        return (data.clone(), hits);
    }
    if modified == text {
        return (data.clone(), hits);
    }
    match serde_json::from_str(&modified) {
        Ok(v) => (v, hits),
        Err(_) => (data.clone(), hits),
    }
}

/// Scan request params for sensitive data.
pub fn scan_request(
    params: &serde_json::Value,
    rules: &[CompiledDlpRule],
    tokenize: Option<&TokenizeFn>,
) -> DlpScanResult {
    scan(params, rules, Direction::Request, tokenize)
}

/// Scan response body for sensitive data.
pub fn scan_response(
    body: &serde_json::Value,
    rules: &[CompiledDlpRule],
    tokenize: Option<&TokenizeFn>,
) -> DlpScanResult {
    scan(body, rules, Direction::Response, tokenize)
}

fn scan(
    data: &serde_json::Value,
    rules: &[CompiledDlpRule],
    scan_direction: Direction,
    tokenize: Option<&TokenizeFn>,
) -> DlpScanResult {
    let mut result = DlpScanResult::default();
    if rules.is_empty() {
        result.modified_data = data.clone();
        return result;
    }

    let applicable: Vec<&CompiledDlpRule> = rules
        .iter()
        .filter(|r| r.direction.matches(scan_direction))
        .collect();
    if applicable.is_empty() {
        result.modified_data = data.clone();
        return result;
    }

    let apply_to = if applicable.iter().any(|r| r.apply_to == ApplyTo::AllText) {
        ApplyTo::AllText
    } else {
        applicable[0].apply_to
    };

    let (modified, hits) = match apply_to {
        ApplyTo::AllText => scan_all_text(data, &applicable, scan_direction, tokenize),
        ApplyTo::JsonStrings => scan_json_strings(data, &applicable, scan_direction, tokenize),
    };

    result.modified = modified != *data;
    result.blocked = hits.iter().any(|h| h.action == "block");
    result.hits = hits;
    result.modified_data = modified;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use corex_core::config::DlpRuleConfig;

    fn cc_rule(action: &str) -> DlpRuleConfig {
        DlpRuleConfig {
            id: 1,
            team_id: 1,
            name: "cc".into(),
            enabled: true,
            priority: 0,
            direction: "both".into(),
            detector: Some("credit_card".into()),
            find_regex: None,
            action: action.into(),
            token_prefix: Some("tok_".into()),
            token_ttl: Some(3600),
            apply_to: Some("json_strings".into()),
        }
    }

    #[test]
    fn no_rules_no_scan() {
        let result = scan_request(&serde_json::json!({"x": "4111 1111 1111 1111"}), &[], None);
        assert!(!result.blocked);
        assert!(!result.modified);
        assert_eq!(result.modified_data, serde_json::json!({"x": "4111 1111 1111 1111"}));
    }

    #[test]
    fn block_on_credit_card() {
        let rules = compile_rules(&[cc_rule("block")]);
        let result = scan_request(&serde_json::json!({"x": "4111 1111 1111 1111"}), &rules, None);
        assert!(result.blocked);
        assert_eq!(result.hits.len(), 1);
        assert_eq!(result.hits[0].action, "block");
    }

    #[test]
    fn redact_credit_card() {
        let rules = compile_rules(&[cc_rule("redact")]);
        let result = scan_request(&serde_json::json!({"x": "4111 1111 1111 1111"}), &rules, None);
        assert!(!result.blocked);
        assert!(result.modified);
        assert_eq!(result.modified_data, serde_json::json!({"x": "[REDACTED]"}));
    }

    #[test]
    fn tokenize_uses_callback() {
        let rules = compile_rules(&[cc_rule("tokenize")]);
        let tokenize: TokenizeFn = Box::new(|m, _p, _t| format!("tok_{}", &m[..4]));
        let result = scan_request(&serde_json::json!({"x": "4111 1111 1111 1111"}), &rules, Some(&tokenize));
        assert!(!result.blocked);
        assert!(result.modified);
        assert!(result.modified_data["x"].as_str().unwrap().starts_with("tok_"));
    }

    #[test]
    fn redos_pattern_skipped() {
        let raw = DlpRuleConfig {
            id: 2,
            team_id: 1,
            name: "redos".into(),
            enabled: true,
            priority: 0,
            direction: "both".into(),
            detector: Some("custom".into()),
            find_regex: Some(r"(a+)+b".into()),
            action: "block".into(),
            token_prefix: None,
            token_ttl: None,
            apply_to: None,
        };
        let rules = compile_rules(&[raw]);
        assert!(rules.is_empty(), "ReDoS pattern must be skipped");
    }

    #[test]
    fn direction_filter() {
        let mut rule = cc_rule("block");
        rule.direction = "response".into();
        let rules = compile_rules(&[rule]);
        // Request scan should not block on a response-only rule.
        let result = scan_request(&serde_json::json!({"x": "4111 1111 1111 1111"}), &rules, None);
        assert!(!result.blocked);
        // Response scan should block.
        let result = scan_response(&serde_json::json!({"x": "4111 1111 1111 1111"}), &rules, None);
        assert!(result.blocked);
    }
}
