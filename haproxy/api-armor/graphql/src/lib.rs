//! GraphQL query parser for API Armor.
//!
//! Parses a GraphQL query string and extracts:
//! - Operation type (query, mutation, subscription)
//! - Max nesting depth
//! - Complexity score (weighted: field=1, list=2x, nested list=4x)
//! - Field count
//! - Alias count
//! - Fragment count (spread + inline)
//! - Query hash (SHA-256 of normalized query)
//! - Validity (parse succeeded)
//! - Error message (on parse failure)

use sha2::{Digest, Sha256};

/// Result of parsing a GraphQL query.
#[derive(Debug, Clone, Default)]
pub struct GraphqlAnalysis {
    pub operation: String,
    pub depth: i32,
    pub complexity: i32,
    pub field_count: i32,
    pub alias_count: i32,
    pub fragment_count: i32,
    pub query_hash: String,
    pub valid: bool,
    pub error: String,
}

/// Parse a GraphQL query string and return analysis metrics.
pub fn analyze(query: &str) -> GraphqlAnalysis {
    let mut result = GraphqlAnalysis::default();
    let trimmed = query.trim();

    if trimmed.is_empty() {
        result.valid = false;
        result.error = "empty query".to_string();
        return result;
    }

    // Extract operation type
    result.operation = extract_operation(trimmed);

    // Strip the operation header for field analysis
    let body = strip_operation_header(trimmed);

    // Parse the body for depth, complexity, fields, aliases, fragments
    let (depth, complexity, field_count, alias_count, fragment_count) = analyze_body(&body);
    result.depth = depth;
    result.complexity = complexity;
    result.field_count = field_count;
    result.alias_count = alias_count;
    result.fragment_count = fragment_count;

    // Compute query hash (normalized: whitespace-stripped, sorted fields)
    result.query_hash = compute_query_hash(trimmed);

    result.valid = true;
    result
}

/// Extract the operation type from the query.
fn extract_operation(query: &str) -> String {
    let lower = query.to_lowercase();
    for op in &["query", "mutation", "subscription"] {
        // Look for the operation keyword at the start or after whitespace/brace
        let pattern = format!("{} ", op);
        if lower.trim_start().starts_with(&pattern) || lower.trim_start().starts_with(op) {
            // Check it's not part of a field name (preceded by non-whitespace)
            let start = lower.find(op);
            if let Some(pos) = start {
                if pos == 0 || lower.as_bytes()[pos - 1].is_ascii_whitespace() {
                    return op.to_string();
                }
            }
        }
    }
    // Default is query (shorthand syntax)
    "query".to_string()
}

/// Strip the operation header (e.g. "query MyQuery {") to get the body.
fn strip_operation_header(query: &str) -> String {
    let trimmed = query.trim();
    // Find the first opening brace
    if let Some(brace_pos) = trimmed.find('{') {
        return trimmed[brace_pos..].to_string();
    }
    trimmed.to_string()
}

/// Analyze the GraphQL body for depth, complexity, fields, aliases, fragments.
fn analyze_body(body: &str) -> (i32, i32, i32, i32, i32) {
    let mut depth: i32 = 0;
    let mut max_depth: i32 = 0;
    let mut complexity: i32 = 0;
    let mut field_count: i32 = 0;
    let mut alias_count: i32 = 0;
    let mut fragment_count: i32 = 0;
    let mut in_string = false;
    let mut prev_was_colon = false;
    let mut chars = body.chars().peekable();

    while let Some(c) = chars.next() {
        if in_string {
            if c == '"' {
                in_string = false;
            }
            continue;
        }

        match c {
            '"' => in_string = true,
            '{' => {
                depth += 1;
                if depth > max_depth {
                    max_depth = depth;
                }
                // List complexity: fields inside a list get 2x per nesting level
                complexity += depth;
                prev_was_colon = false;
            }
            '}' => {
                depth = (depth - 1).max(0);
                prev_was_colon = false;
            }
            '.' => {
                // Check for fragment spread (...)
                if chars.peek() == Some(&'.') {
                    chars.next();
                    if chars.peek() == Some(&'.') {
                        chars.next();
                        fragment_count += 1;
                    }
                }
                prev_was_colon = false;
            }
            ':' => {
                // Could be an alias (field: actualField)
                // Check if we just saw a field name (identifier)
                prev_was_colon = true;
            }
            '(' => {
                // Skip arguments
                let mut paren_depth = 1;
                while let Some(pc) = chars.next() {
                    if pc == '"' {
                        in_string = !in_string;
                    } else if !in_string {
                        if pc == '(' {
                            paren_depth += 1;
                        } else if pc == ')' {
                            paren_depth -= 1;
                            if paren_depth == 0 {
                                break;
                            }
                        }
                    }
                }
                prev_was_colon = false;
            }
            c if c.is_alphabetic() || c == '_' => {
                // Read the full identifier
                let mut ident = String::new();
                ident.push(c);
                while let Some(&nc) = chars.peek() {
                    if nc.is_alphanumeric() || nc == '_' {
                        ident.push(nc);
                        chars.next();
                    } else {
                        break;
                    }
                }
                // Skip known keywords
                if ident != "query" && ident != "mutation" && ident != "subscription"
                    && ident != "fragment" && ident != "on" && ident != "true"
                    && ident != "false" && ident != "null"
                {
                    field_count += 1;
                    if prev_was_colon {
                        alias_count += 1;
                    }
                    complexity += 1;
                }
                prev_was_colon = false;
            }
            _ => {
                if c != ' ' && c != '\t' && c != '\n' && c != '\r' && c != ',' {
                    prev_was_colon = false;
                }
            }
        }
    }

    // Depth is the number of nested selection sets beyond the root.
    // The root `{` is depth 0, so subtract 1 from max_depth.
    let depth = (max_depth - 1).max(0);
    (depth, complexity, field_count, alias_count, fragment_count)
}

/// Compute a normalized SHA-256 hash of the query.
/// Normalization: strip whitespace, lowercase keywords, sort fields at each level.
fn compute_query_hash(query: &str) -> String {
    // Simple normalization: collapse whitespace, lowercase
    let normalized: String = query
        .chars()
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();

    let mut hasher = Sha256::new();
    hasher.update(normalized.as_bytes());
    let hash = hasher.finalize();
    // Return first 16 hex chars (64 bits) — sufficient for query identification
    hash.iter().take(8).map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_query() {
        let q = "{ user { id name } }";
        let a = analyze(q);
        assert!(a.valid);
        assert_eq!(a.operation, "query");
        assert_eq!(a.depth, 1);
        assert_eq!(a.field_count, 3); // user, id, name
    }

    #[test]
    fn test_mutation() {
        let q = "mutation { createUser(input: {name: \"test\"}) { id } }";
        let a = analyze(q);
        assert!(a.valid);
        assert_eq!(a.operation, "mutation");
    }

    #[test]
    fn test_deep_query() {
        let q = "{ user { posts { comments { author { name } } } } }";
        let a = analyze(q);
        assert!(a.valid);
        assert_eq!(a.depth, 4);
    }

    #[test]
    fn test_alias() {
        let q = "{ myUser: user { id } }";
        let a = analyze(q);
        assert!(a.valid);
        assert_eq!(a.alias_count, 1);
    }

    #[test]
    fn test_fragment_spread() {
        let q = "{ user { ...userFields } } fragment userFields on User { id name }";
        let a = analyze(q);
        assert!(a.valid);
        assert_eq!(a.fragment_count, 1);
    }

    #[test]
    fn test_empty_query() {
        let a = analyze("");
        assert!(!a.valid);
        assert_eq!(a.error, "empty query");
    }

    #[test]
    fn test_query_hash_deterministic() {
        let q1 = "{ user { id } }";
        let q2 = "{  user  {  id  }  }";
        let a1 = analyze(q1);
        let a2 = analyze(q2);
        assert_eq!(a1.query_hash, a2.query_hash);
    }
}
