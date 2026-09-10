//! Expression engine — native Rust port of `shared/expression_core.py`.
//!
//! Cloudflare-style expression language: tokenizer, recursive-descent parser,
//! typed AST, and evaluator with field resolution + list references.
//!
//! The gateway re-parses the `expression` string at config-load time (the
//! bundle also carries a pre-computed `expression_ast` JSON, but re-parsing
//! avoids coupling to the Python AST dict shape).

use regex::Regex;
use serde_json::{Map, Value};

/// A typed expression AST node.
#[derive(Debug, Clone)]
pub enum Expr {
    And(Vec<Expr>),
    Or(Vec<Expr>),
    Not(Box<Expr>),
    Compare {
        field: String,
        op: Op,
        value: Literal,
        /// Pre-compiled regex for `~` / `!~` ops.
        regex: Option<Regex>,
    },
    InList {
        field: String,
        list_type: String,
        list_name: String,
        negated: bool,
    },
    InLiterals {
        field: String,
        values: Vec<Literal>,
        negated: bool,
    },
    Exists {
        field: String,
        negated: bool,
    },
    BoolField {
        field: String,
        negated: bool,
    },
    Literal(bool),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Eq,
    Neq,
    RegexMatch,
    RegexNotMatch,
    Gt,
    Lt,
    Ge,
    Le,
    Contains,
    StartsWith,
    EndsWith,
}

#[derive(Debug, Clone)]
pub enum Literal {
    Str(String),
    Int(i64),
    Bool(bool),
}

impl Literal {
    fn as_str(&self) -> String {
        match self {
            Literal::Str(s) => s.clone(),
            Literal::Int(i) => i.to_string(),
            Literal::Bool(b) => b.to_string(),
        }
    }
}

/// Evaluation context: a flat field map plus an optional list resolver.
pub struct EvalContext {
    pub fields: Map<String, Value>,
    #[allow(clippy::type_complexity)]
    pub list_resolver: Option<Box<dyn Fn(&str, &str, &str) -> bool + Send + Sync>>,
}

impl EvalContext {
    pub fn new() -> Self {
        Self {
            fields: Map::new(),
            list_resolver: None,
        }
    }
}

impl Default for EvalContext {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum TokenKind {
    LParen,
    RParen,
    LBracket,
    RBracket,
    Comma,
    Op(String),
    Keyword(String),
    Ident(String),
    String(String),
    Number(i64),
    ListRef(String, String), // (type, name)
    Eof,
}

#[derive(Debug, Clone)]
struct Token {
    kind: TokenKind,
    pos: usize,
}

const KEYWORDS: &[&str] = &[
    "and",
    "or",
    "not",
    "in",
    "contains",
    "starts_with",
    "ends_with",
    "exists",
    "true",
    "false",
];

fn tokenize(text: &str) -> Result<Vec<Token>, String> {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let mut i = 0;
    let mut tokens = Vec::new();
    let two_char_ops = ["!=", "!~", ">=", "<="];
    let one_char_ops = ['=', '~', '>', '<'];

    while i < n {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        match c {
            '(' => {
                tokens.push(Token { kind: TokenKind::LParen, pos: i });
                i += 1;
                continue;
            }
            ')' => {
                tokens.push(Token { kind: TokenKind::RParen, pos: i });
                i += 1;
                continue;
            }
            '[' => {
                tokens.push(Token { kind: TokenKind::LBracket, pos: i });
                i += 1;
                continue;
            }
            ']' => {
                tokens.push(Token { kind: TokenKind::RBracket, pos: i });
                i += 1;
                continue;
            }
            ',' => {
                tokens.push(Token { kind: TokenKind::Comma, pos: i });
                i += 1;
                continue;
            }
            _ => {}
        }

        // Two-char ops
        if i + 1 < n {
            let two: String = chars[i..i + 2].iter().collect();
            if two_char_ops.contains(&two.as_str()) {
                tokens.push(Token { kind: TokenKind::Op(two), pos: i });
                i += 2;
                continue;
            }
        }
        if one_char_ops.contains(&c) {
            tokens.push(Token { kind: TokenKind::Op(c.to_string()), pos: i });
            i += 1;
            continue;
        }

        // Strings
        if c == '"' || c == '\'' {
            let quote = c;
            let mut buf = String::new();
            let start = i;
            i += 1;
            while i < n {
                if chars[i] == '\\' && i + 1 < n {
                    buf.push(chars[i + 1]);
                    i += 2;
                    continue;
                }
                if chars[i] == quote {
                    break;
                }
                buf.push(chars[i]);
                i += 1;
            }
            if i >= n {
                return Err(format!("Unterminated string at position {start}"));
            }
            i += 1; // skip closing quote
            tokens.push(Token { kind: TokenKind::String(buf), pos: start });
            continue;
        }

        // Numbers (including negative)
        if c.is_ascii_digit() || (c == '-' && i + 1 < n && chars[i + 1].is_ascii_digit()) {
            let start = i;
            if c == '-' {
                i += 1;
            }
            while i < n && chars[i].is_ascii_digit() {
                i += 1;
            }
            let s: String = chars[start..i].iter().collect();
            let num: i64 = s.parse().map_err(|_| format!("Invalid number at {start}"))?;
            tokens.push(Token { kind: TokenKind::Number(num), pos: start });
            continue;
        }

        // List reference $type:name
        if c == '$' {
            let start = i;
            i += 1;
            while i < n && (chars[i].is_alphanumeric() || ":._-".contains(chars[i])) {
                i += 1;
            }
            let ref_str: String = chars[start + 1..i].iter().collect();
            if ref_str.is_empty() {
                return Err(format!("Invalid list reference at position {start}"));
            }
            let (list_type, list_name) = ref_str
                .split_once(':')
                .ok_or_else(|| format!("List reference must be $type:name at position {start}"))?;
            tokens.push(Token {
                kind: TokenKind::ListRef(list_type.to_string(), list_name.to_string()),
                pos: start,
            });
            continue;
        }

        // AS numbers: AS12345 (case-insensitive first two chars)
        if (c == 'A' || c == 'a')
            && i + 1 < n
            && (chars[i + 1] == 'S' || chars[i + 1] == 's')
            && i + 2 < n
            && chars[i + 2].is_ascii_digit()
        {
            let start = i;
            i += 2;
            while i < n && chars[i].is_ascii_digit() {
                i += 1;
            }
            let s: String = chars[start + 2..i].iter().collect();
            tokens.push(Token {
                kind: TokenKind::String(format!("AS{s}")),
                pos: start,
            });
            continue;
        }

        // Identifiers / keywords
        if c.is_alphabetic() || c == '_' {
            let start = i;
            while i < n && (chars[i].is_alphanumeric() || chars[i] == '.' || chars[i] == '_') {
                i += 1;
            }
            let word: String = chars[start..i].iter().collect();
            let lower = word.to_lowercase();
            if KEYWORDS.contains(&lower.as_str()) {
                tokens.push(Token { kind: TokenKind::Keyword(lower), pos: start });
            } else {
                tokens.push(Token { kind: TokenKind::Ident(word), pos: start });
            }
            continue;
        }

        return Err(format!("Unexpected character {c:?} at position {i}"));
    }

    tokens.push(Token { kind: TokenKind::Eof, pos: n });
    Ok(tokens)
}

// ---------------------------------------------------------------------------
// Parser (recursive descent)
// ---------------------------------------------------------------------------

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    bool_fields: Vec<String>,
}

impl Parser {
    fn new(tokens: Vec<Token>, bool_fields: Vec<String>) -> Self {
        Self { tokens, pos: 0, bool_fields }
    }

    fn peek(&self) -> &Token {
        &self.tokens[self.pos]
    }

    fn advance(&mut self) -> Token {
        let t = self.tokens[self.pos].clone();
        self.pos += 1;
        t
    }

    fn expect_kind(&mut self, kind: &TokenKind) -> Result<Token, String> {
        if !token_eq(&self.peek().kind, kind) {
            return Err(format!(
                "Expected {:?} but got {:?} at position {}",
                kind,
                self.peek().kind,
                self.peek().pos
            ));
        }
        Ok(self.advance())
    }

    fn parse(&mut self) -> Result<Expr, String> {
        let node = self.parse_or()?;
        if !matches!(self.peek().kind, TokenKind::Eof) {
            return Err(format!(
                "Unexpected token {:?} at position {}",
                self.peek().kind,
                self.peek().pos
            ));
        }
        Ok(node)
    }

    fn parse_or(&mut self) -> Result<Expr, String> {
        let mut children = vec![self.parse_and()?];
        while let TokenKind::Keyword(k) = &self.peek().kind {
            if k == "or" {
                self.advance();
                children.push(self.parse_and()?);
            } else {
                break;
            }
        }
        if children.len() == 1 {
            Ok(children.pop().unwrap())
        } else {
            Ok(Expr::Or(children))
        }
    }

    fn parse_and(&mut self) -> Result<Expr, String> {
        let mut children = vec![self.parse_not()?];
        while let TokenKind::Keyword(k) = &self.peek().kind {
            if k == "and" {
                self.advance();
                children.push(self.parse_not()?);
            } else {
                break;
            }
        }
        if children.len() == 1 {
            Ok(children.pop().unwrap())
        } else {
            Ok(Expr::And(children))
        }
    }

    fn parse_not(&mut self) -> Result<Expr, String> {
        if let TokenKind::Keyword(k) = &self.peek().kind {
            if k == "not" {
                self.advance();
                let child = self.parse_not()?;
                return Ok(Expr::Not(Box::new(child)));
            }
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Expr, String> {
        match &self.peek().kind {
            TokenKind::LParen => {
                self.advance();
                let node = self.parse_or()?;
                self.expect_kind(&TokenKind::RParen)?;
                Ok(node)
            }
            TokenKind::Keyword(k) if k == "true" || k == "false" => {
                let val = k == "true";
                self.advance();
                Ok(Expr::Literal(val))
            }
            _ => self.parse_condition(),
        }
    }

    fn parse_condition(&mut self) -> Result<Expr, String> {
        let field_tok = self.peek().clone();
        let field = match &field_tok.kind {
            TokenKind::Ident(s) => s.clone(),
            _ => {
                return Err(format!(
                    "Expected field name but got {:?} at position {}",
                    field_tok.kind, field_tok.pos
                ));
            }
        };
        self.advance();

        // Bracket key: field["key"]
        let full_field = if matches!(self.peek().kind, TokenKind::LBracket) {
            self.advance();
            let key_tok = self.peek().clone();
            let key = match &key_tok.kind {
                TokenKind::String(s) => s.clone(),
                _ => {
                    return Err(format!(
                        "Expected string key in brackets at position {}",
                        key_tok.pos
                    ));
                }
            };
            self.advance();
            self.expect_kind(&TokenKind::RBracket)?;
            format!("{field}[\"{key}\"]")
        } else {
            field
        };

        let mut negated = false;
        if let TokenKind::Keyword(k) = &self.peek().kind {
            if k == "not" {
                self.advance();
                negated = true;
                match &self.peek().kind {
                    TokenKind::Keyword(n) if n == "in" || n == "exists" => {}
                    _ => {
                        return Err(format!(
                            "Expected 'in' or 'exists' after 'not' at position {}",
                            self.peek().pos
                        ));
                    }
                }
            }
        }

        let tok = self.peek().clone();
        match &tok.kind {
            TokenKind::Keyword(k) if k == "in" => {
                self.advance();
                self.parse_in(&full_field, negated)
            }
            TokenKind::Keyword(k) if k == "exists" => {
                self.advance();
                Ok(Expr::Exists { field: full_field, negated })
            }
            TokenKind::Keyword(k)
                if k == "contains" || k == "starts_with" || k == "ends_with" =>
            {
                let op = match k.as_str() {
                    "contains" => Op::Contains,
                    "starts_with" => Op::StartsWith,
                    "ends_with" => Op::EndsWith,
                    _ => unreachable!(),
                };
                self.advance();
                let value = self.parse_value()?;
                Ok(Expr::Compare { field: full_field, op, value, regex: None })
            }
            TokenKind::Eof | TokenKind::RParen => {
                if self.bool_fields.contains(&full_field) {
                    Ok(Expr::BoolField { field: full_field, negated })
                } else {
                    Err(format!(
                        "Field {full_field:?} requires an operator at position {}",
                        tok.pos
                    ))
                }
            }
            TokenKind::Keyword(k) if k == "and" || k == "or" => {
                if self.bool_fields.contains(&full_field) {
                    Ok(Expr::BoolField { field: full_field, negated })
                } else {
                    Err(format!(
                        "Field {full_field:?} requires an operator at position {}",
                        tok.pos
                    ))
                }
            }
            TokenKind::Op(op) => {
                self.advance();
                let value = self.parse_value()?;
                let (op_enum, regex) = parse_op(op, &value)?;
                Ok(Expr::Compare { field: full_field, op: op_enum, value, regex })
            }
            _ => Err(format!(
                "Expected operator after field {full_field:?} at position {}",
                tok.pos
            )),
        }
    }

    fn parse_value(&mut self) -> Result<Literal, String> {
        let tok = self.peek().clone();
        match &tok.kind {
            TokenKind::String(s) => {
                self.advance();
                Ok(Literal::Str(s.clone()))
            }
            TokenKind::Number(n) => {
                self.advance();
                Ok(Literal::Int(*n))
            }
            TokenKind::Keyword(k) if k == "true" || k == "false" => {
                let v = k == "true";
                self.advance();
                Ok(Literal::Bool(v))
            }
            _ => Err(format!(
                "Expected value but got {:?} at position {}",
                tok.kind, tok.pos
            )),
        }
    }

    fn parse_in(&mut self, field: &str, negated: bool) -> Result<Expr, String> {
        let tok = self.peek().clone();
        match &tok.kind {
            TokenKind::ListRef(t, name) => {
                self.advance();
                Ok(Expr::InList {
                    field: field.to_string(),
                    list_type: t.clone(),
                    list_name: name.clone(),
                    negated,
                })
            }
            TokenKind::LBracket => {
                self.advance();
                let mut values = Vec::new();
                if matches!(self.peek().kind, TokenKind::RBracket) {
                    self.advance();
                    return Ok(Expr::InLiterals {
                        field: field.to_string(),
                        values,
                        negated,
                    });
                }
                loop {
                    values.push(self.parse_value()?);
                    if matches!(self.peek().kind, TokenKind::Comma) {
                        self.advance();
                        continue;
                    }
                    break;
                }
                self.expect_kind(&TokenKind::RBracket)?;
                Ok(Expr::InLiterals {
                    field: field.to_string(),
                    values,
                    negated,
                })
            }
            _ => Err(format!(
                "Expected list reference or '[' after 'in' at position {}",
                tok.pos
            )),
        }
    }
}

fn parse_op(op: &str, value: &Literal) -> Result<(Op, Option<Regex>), String> {
    let op_enum = match op {
        "=" => Op::Eq,
        "!=" => Op::Neq,
        "~" => Op::RegexMatch,
        "!~" => Op::RegexNotMatch,
        ">" => Op::Gt,
        "<" => Op::Lt,
        ">=" => Op::Ge,
        "<=" => Op::Le,
        _ => return Err(format!("Unknown operator {op:?}")),
    };
    let regex = if matches!(op_enum, Op::RegexMatch | Op::RegexNotMatch) {
        let pat = value.as_str();
        Some(Regex::new(&pat).map_err(|e| format!("Invalid regex {pat:?}: {e}"))?)
    } else {
        None
    };
    Ok((op_enum, regex))
}

fn token_eq(a: &TokenKind, b: &TokenKind) -> bool {
    match (a, b) {
        (TokenKind::LParen, TokenKind::LParen) => true,
        (TokenKind::RParen, TokenKind::RParen) => true,
        (TokenKind::LBracket, TokenKind::LBracket) => true,
        (TokenKind::RBracket, TokenKind::RBracket) => true,
        (TokenKind::Comma, TokenKind::Comma) => true,
        (TokenKind::Eof, TokenKind::Eof) => true,
        _ => a == b,
    }
}

/// Parse an expression string into a typed AST.
pub fn parse_expression(text: &str) -> Result<Expr, String> {
    parse_expression_with_bool_fields(text, &[])
}

/// Parse with a set of bare-boolean field names.
pub fn parse_expression_with_bool_fields(
    text: &str,
    bool_fields: &[&str],
) -> Result<Expr, String> {
    if text.trim().is_empty() {
        return Err("Expression is required".into());
    }
    let tokens = tokenize(text)?;
    let bf: Vec<String> = bool_fields.iter().map(|s| s.to_string()).collect();
    let mut parser = Parser::new(tokens, bf);
    parser.parse()
}

// ---------------------------------------------------------------------------
// Evaluator
// ---------------------------------------------------------------------------

/// Resolve a field name to a JSON value from the context.
/// Supports bracket fields `base["key"]` and dot-paths `a.b.c`.
pub fn resolve_field_value(field: &str, ctx: &Map<String, Value>) -> Option<Value> {
    // Bracket form: base["key"]
    if let (Some(bracket_pos), Some(end)) = (field.rfind("[\""), field.rfind("\"]")) {
        if end > bracket_pos {
            let base_field = &field[..bracket_pos];
            let key = &field[bracket_pos + 2..end];
            if let Some(Value::Object(map)) = ctx.get(base_field) {
                if let Some(v) = map.get(key) {
                    return Some(v.clone());
                }
            }
            return None;
        }
    }

    if let Some(v) = ctx.get(field) {
        return Some(v.clone());
    }

    // Dot-path
    let parts: Vec<&str> = field.split('.').collect();
    let mut val = Value::Object(serde_json::Map::from_iter(
        ctx.iter().map(|(k, v)| (k.clone(), v.clone())),
    ));
    for part in parts {
        match &val {
            Value::Object(map) => {
                let v = map.get(part)?;
                val = v.clone();
            }
            _ => return None,
        }
    }
    Some(val)
}

/// Evaluate an AST against a context. Returns `Ok(bool)` or an error for
/// unknown node types (shouldn't happen with the typed AST).
pub fn evaluate(expr: &Expr, ctx: &EvalContext) -> bool {
    match expr {
        Expr::And(children) => children.iter().all(|c| evaluate(c, ctx)),
        Expr::Or(children) => children.iter().any(|c| evaluate(c, ctx)),
        Expr::Not(child) => !evaluate(child, ctx),
        Expr::Literal(b) => *b,
        Expr::BoolField { field, negated } => {
            let val = resolve_field_value(field, &ctx.fields);
            let result = val.map(|v| value_truthy(&v)).unwrap_or(false);
            if *negated { !result } else { result }
        }
        Expr::Exists { field, negated } => {
            let val = resolve_field_value(field, &ctx.fields);
            let result = val.map(|v| !is_empty(&v)).unwrap_or(false);
            if *negated { !result } else { result }
        }
        Expr::Compare { field, op, value, regex } => {
            let actual = resolve_field_value(field, &ctx.fields);
            evaluate_compare(actual.as_ref(), *op, value, regex.as_ref())
        }
        Expr::InLiterals { field, values, negated } => {
            let actual = resolve_field_value(field, &ctx.fields);
            if actual.is_none() {
                return *negated;
            }
            let actual = actual.unwrap();
            let result = values.iter().any(|v| literal_matches(v, &actual));
            if *negated { !result } else { result }
        }
        Expr::InList { field, list_type, list_name, negated } => {
            let actual = resolve_field_value(field, &ctx.fields);
            if actual.is_none() {
                return *negated;
            }
            let actual_str = value_to_string(&actual.unwrap());
            if let Some(resolver) = &ctx.list_resolver {
                let in_list = resolver(list_type, list_name, &actual_str);
                if *negated { !in_list } else { in_list }
            } else {
                *negated
            }
        }
    }
}

fn evaluate_compare(
    actual: Option<&Value>,
    op: Op,
    expected: &Literal,
    regex: Option<&Regex>,
) -> bool {
    let actual = match actual {
        Some(v) => v,
        None => return false,
    };

    match expected {
        Literal::Bool(b) => {
            if op == Op::Eq {
                return value_truthy(actual) == *b;
            }
            false
        }
        Literal::Int(n) => {
            let actual_int = value_to_i64(actual);
            match op {
                Op::Eq => actual_int == Some(*n),
                Op::Neq => actual_int != Some(*n),
                Op::Gt => actual_int.map(|a| a > *n).unwrap_or(false),
                Op::Lt => actual_int.map(|a| a < *n).unwrap_or(false),
                Op::Ge => actual_int.map(|a| a >= *n).unwrap_or(false),
                Op::Le => actual_int.map(|a| a <= *n).unwrap_or(false),
                _ => false,
            }
        }
        Literal::Str(s) => {
            let actual_str = value_to_string(actual);
            match op {
                Op::Eq => actual_str == *s,
                Op::Neq => actual_str != *s,
                Op::RegexMatch => regex.map(|r| r.is_match(&actual_str)).unwrap_or(false),
                Op::RegexNotMatch => regex.map(|r| !r.is_match(&actual_str)).unwrap_or(false),
                Op::Contains => actual_str.contains(s),
                Op::StartsWith => actual_str.starts_with(s),
                Op::EndsWith => actual_str.ends_with(s),
                _ => false,
            }
        }
    }
}

fn literal_matches(lit: &Literal, actual: &Value) -> bool {
    match lit {
        Literal::Str(s) => value_to_string(actual) == *s,
        Literal::Int(n) => value_to_i64(actual) == Some(*n),
        Literal::Bool(b) => value_truthy(actual) == *b,
    }
}

fn value_truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(false),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

fn is_empty(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::String(s) => s.is_empty(),
        _ => false,
    }
}

fn value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn value_to_i64(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)),
        Value::String(s) => s.parse().ok().or_else(|| s.parse::<f64>().ok().map(|f| f as i64)),
        Value::Bool(b) => Some(*b as i64),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// MCP context builder (mirrors mcp-gateway/expression.py build_mcp_context)
// ---------------------------------------------------------------------------

/// Build the MCP evaluation context from request parameters.
#[allow(clippy::too_many_arguments)]
pub fn build_mcp_context(
    method: &str,
    server: &str,
    tool: &str,
    resource: &str,
    prompt: &str,
    identity_name: &str,
    identity_kind: &str,
    team_slug: &str,
    args: Option<&Value>,
    claims: Option<&Value>,
    ip_src: &str,
) -> EvalContext {
    let mut fields = Map::new();
    fields.insert("mcp.method".into(), Value::String(method.into()));
    fields.insert("mcp.server".into(), Value::String(server.into()));
    fields.insert("mcp.tool".into(), Value::String(tool.into()));
    fields.insert("mcp.resource".into(), Value::String(resource.into()));
    fields.insert("mcp.prompt".into(), Value::String(prompt.into()));
    fields.insert("mcp.identity".into(), Value::String(identity_name.into()));
    fields.insert("mcp.identity.kind".into(), Value::String(identity_kind.into()));
    fields.insert("mcp.team".into(), Value::String(team_slug.into()));
    fields.insert("mcp.arg".into(), args.cloned().unwrap_or(Value::Object(Map::new())));
    fields.insert(
        "auth.claim".into(),
        claims.cloned().unwrap_or(Value::Object(Map::new())),
    );
    fields.insert("ip.src".into(), Value::String(ip_src.into()));

    // Flatten common claim fields for dot-path access.
    if let Some(Value::Object(claims_map)) = claims {
        if let Some(sub) = claims_map.get("sub") {
            fields.insert("auth.claim.sub".into(), Value::String(value_to_string(sub)));
        }
        if let Some(iss) = claims_map.get("iss") {
            fields.insert("auth.claim.iss".into(), Value::String(value_to_string(iss)));
        }
        if let Some(aud) = claims_map.get("aud") {
            fields.insert("auth.claim.aud".into(), Value::String(value_to_string(aud)));
        }
    }

    EvalContext { fields, list_resolver: None }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ctx() -> EvalContext {
        let mut fields = Map::new();
        fields.insert("mcp.method".into(), json!("tools/call"));
        fields.insert("mcp.server".into(), json!("jira"));
        fields.insert("mcp.tool".into(), json!("jira__create"));
        fields.insert("mcp.team".into(), json!("engineering"));
        fields.insert("mcp.identity.kind".into(), json!("pat"));
        fields.insert("ip.src".into(), json!("10.0.0.1"));
        fields.insert("mcp.arg".into(), json!({"summary": "fix bug", "priority": 3}));
        fields.insert("auth.claim".into(), json!({"sub": "user-1", "iss": "auth0", "role": "admin"}));
        fields.insert("auth.claim.sub".into(), json!("user-1"));
        EvalContext { fields, list_resolver: None }
    }

    #[test]
    fn parse_and_eval_eq() {
        let e = parse_expression(r#"mcp.server = "jira""#).unwrap();
        assert!(evaluate(&e, &ctx()));
        let e = parse_expression(r#"mcp.server = "github""#).unwrap();
        assert!(!evaluate(&e, &ctx()));
    }

    #[test]
    fn parse_and_eval_and_or() {
        let e = parse_expression(r#"mcp.server = "jira" and mcp.method = "tools/call""#).unwrap();
        assert!(evaluate(&e, &ctx()));
        let e = parse_expression(r#"mcp.server = "jira" or mcp.server = "github""#).unwrap();
        assert!(evaluate(&e, &ctx()));
        let e = parse_expression(r#"mcp.server = "jira" and mcp.server = "github""#).unwrap();
        assert!(!evaluate(&e, &ctx()));
    }

    #[test]
    fn parse_not() {
        let e = parse_expression(r#"not mcp.server = "github""#).unwrap();
        assert!(evaluate(&e, &ctx()));
    }

    #[test]
    fn parse_contains_starts_ends() {
        let e = parse_expression(r#"mcp.tool contains "create""#).unwrap();
        assert!(evaluate(&e, &ctx()));
        let e = parse_expression(r#"mcp.tool starts_with "jira""#).unwrap();
        assert!(evaluate(&e, &ctx()));
        let e = parse_expression(r#"mcp.tool ends_with "create""#).unwrap();
        assert!(evaluate(&e, &ctx()));
    }

    #[test]
    fn parse_regex_match() {
        let e = parse_expression(r#"mcp.server ~ "ji.a""#).unwrap();
        assert!(evaluate(&e, &ctx()));
        let e = parse_expression(r#"mcp.server !~ "git.*""#).unwrap();
        assert!(evaluate(&e, &ctx()));
    }

    #[test]
    fn parse_numeric_compare() {
        let e = parse_expression(r#"mcp.arg["priority"] = 3"#).unwrap();
        assert!(evaluate(&e, &ctx()));
        let e = parse_expression(r#"mcp.arg["priority"] > 2"#).unwrap();
        assert!(evaluate(&e, &ctx()));
        let e = parse_expression(r#"mcp.arg["priority"] < 3"#).unwrap();
        assert!(!evaluate(&e, &ctx()));
    }

    #[test]
    fn parse_exists() {
        let e = parse_expression(r#"mcp.arg["summary"] exists"#).unwrap();
        assert!(evaluate(&e, &ctx()));
        let e = parse_expression(r#"mcp.arg["nonexistent"] exists"#).unwrap();
        assert!(!evaluate(&e, &ctx()));
        let e = parse_expression(r#"not mcp.arg["nonexistent"] exists"#).unwrap();
        assert!(evaluate(&e, &ctx()));
    }

    #[test]
    fn parse_in_literals() {
        let e = parse_expression(r#"mcp.server in ["jira", "github"]"#).unwrap();
        assert!(evaluate(&e, &ctx()));
        let e = parse_expression(r#"mcp.server in ["github", "gitlab"]"#).unwrap();
        assert!(!evaluate(&e, &ctx()));
    }

    #[test]
    fn parse_dot_path_field() {
        // Flattened claim field (exact-key match in context).
        let e = parse_expression(r#"auth.claim.sub = "user-1""#).unwrap();
        assert!(evaluate(&e, &ctx()));
        // Bracket form resolves the nested object: auth.claim["role"].
        let e = parse_expression(r#"auth.claim["role"] = "admin""#).unwrap();
        assert!(evaluate(&e, &ctx()));
    }

    #[test]
    fn parse_bool_literal_and_parens() {
        let e = parse_expression(r#"(mcp.server = "jira") and true"#).unwrap();
        assert!(evaluate(&e, &ctx()));
        let e = parse_expression(r#"false or mcp.server = "jira""#).unwrap();
        assert!(evaluate(&e, &ctx()));
    }

    #[test]
    fn parse_in_list_with_resolver() {
        let e = parse_expression(r#"ip.src in $network:internal"#).unwrap();
        let mut c = ctx();
        c.list_resolver = Some(Box::new(|_t, _n, val| val == "10.0.0.1"));
        assert!(evaluate(&e, &c));
    }

    #[test]
    fn parse_error_messages() {
        assert!(parse_expression("").is_err());
        assert!(parse_expression("mcp.server").is_err()); // no operator, not bool field
        assert!(parse_expression(r#"mcp.server = "#).is_err()); // unterminated string
    }

    #[test]
    fn build_mcp_context_works() {
        let args = json!({"x": 1});
        let claims = json!({"sub": "s", "iss": "i", "aud": "a"});
        let c = build_mcp_context(
            "tools/call", "jira", "jira__t", "", "", "ci", "pat", "eng",
            Some(&args), Some(&claims), "1.2.3.4",
        );
        assert_eq!(c.fields.get("mcp.server").unwrap(), &json!("jira"));
        assert_eq!(c.fields.get("auth.claim.sub").unwrap(), &json!("s"));
        assert_eq!(c.fields.get("ip.src").unwrap(), &json!("1.2.3.4"));
    }
}
