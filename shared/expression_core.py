"""Shared expression engine — tokenizer, parser, AST, and DNF normalizer.

This module is the single source of truth for the Cloudflare-style expression
language used by both the backend (security_rules.py → HAProxy ACL emission)
and the MCP Gateway (expression.py → in-process evaluator).

Consumers import:
    from shared.expression_core import (
        Token, parse_expression, validate_expression,
        to_dnf, negate_to_dnf,
    )

Consumer-specific concerns (field maps, evaluators, HAProxy translators) stay
in their respective modules. The parser accepts an optional ``bool_fields``
set so the backend can register HAProxy-specific boolean fields.
"""
from typing import Any, Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------

class Token:
    __slots__ = ("kind", "value", "pos")

    def __init__(self, kind: str, value: Any, pos: int):
        self.kind = kind
        self.value = value
        self.pos = pos

    def __repr__(self):
        return f"Token({self.kind}, {self.value!r}, pos={self.pos})"


_KEYWORDS = {
    "and", "or", "not", "in", "contains", "starts_with", "ends_with",
    "exists", "true", "false",
}

_TWO_CHAR_OPS = {"!=", "!~", ">=", "<="}
_ONE_CHAR_OPS = {"=", "~", ">", "<"}


def _tokenize(text: str) -> List[Token]:
    """Convert expression text into a list of tokens."""
    tokens: List[Token] = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
            continue
        if c == "(":
            tokens.append(Token("LPAREN", "(", i))
            i += 1
            continue
        if c == ")":
            tokens.append(Token("RPAREN", ")", i))
            i += 1
            continue
        if c == "[":
            tokens.append(Token("LBRACKET", "[", i))
            i += 1
            continue
        if c == "]":
            tokens.append(Token("RBRACKET", "]", i))
            i += 1
            continue
        if c == ",":
            tokens.append(Token("COMMA", ",", i))
            i += 1
            continue
        two = text[i:i + 2]
        if two in _TWO_CHAR_OPS:
            tokens.append(Token("OP", two, i))
            i += 2
            continue
        if c in _ONE_CHAR_OPS:
            tokens.append(Token("OP", c, i))
            i += 1
            continue
        if c == '"' or c == "'":
            quote = c
            j = i + 1
            buf = []
            while j < n:
                if text[j] == "\\" and j + 1 < n:
                    buf.append(text[j + 1])
                    j += 2
                    continue
                if text[j] == quote:
                    break
                buf.append(text[j])
                j += 1
            if j >= n:
                raise ValueError(f"Unterminated string at position {i}")
            tokens.append(Token("STRING", "".join(buf), i))
            i = j + 1
            continue
        if c.isdigit() or (c == "-" and i + 1 < n and text[i + 1].isdigit()):
            j = i + 1 if c == "-" else i
            while j < n and text[j].isdigit():
                j += 1
            tokens.append(Token("NUMBER", int(text[i:j]), i))
            i = j
            continue
        if c == "$":
            j = i + 1
            while j < n and (text[j].isalnum() or text[j] in "_.:-"):
                j += 1
            ref = text[i + 1:j]
            if not ref:
                raise ValueError(f"Invalid list reference at position {i}")
            if ":" in ref:
                list_type, list_name = ref.split(":", 1)
            else:
                raise ValueError(f"List reference must be $type:name at position {i}")
            tokens.append(Token("LISTREF", (list_type, list_name), i))
            i = j
            continue
        if (c in "Aa" and i + 1 < n and text[i + 1] in "Ss"
                and i + 2 < n and text[i + 2].isdigit()):
            j = i + 2
            while j < n and text[j].isdigit():
                j += 1
            tokens.append(Token("STRING", f"AS{text[i + 2:j]}", i))
            i = j
            continue
        if c.isalpha() or c == "_":
            j = i
            while j < n and (text[j].isalnum() or text[j] in "._"):
                j += 1
            word = text[i:j]
            lower = word.lower()
            if lower in _KEYWORDS:
                tokens.append(Token("KEYWORD", lower, i))
            else:
                tokens.append(Token("IDENT", word, i))
            i = j
            continue
        raise ValueError(f"Unexpected character {c!r} at position {i}")
    tokens.append(Token("EOF", None, n))
    return tokens


# ---------------------------------------------------------------------------
# AST node format (dicts for easy JSON serialization)
# ---------------------------------------------------------------------------
#
#   {"type": "compare", "field": "...", "op": "...", "value": ...}
#   {"type": "in_list", "field": "...", "list_type": "...", "list_name": "...", "negated": bool}
#   {"type": "in_literals", "field": "...", "values": [...], "negated": bool}
#   {"type": "exists", "field": "...", "negated": bool}
#   {"type": "bool_field", "field": "...", "negated": bool}
#   {"type": "literal", "value": bool}
#   {"type": "and", "children": [...]}
#   {"type": "or", "children": [...]}
#   {"type": "not", "child": ...}


# ---------------------------------------------------------------------------
# Parser (recursive descent)
# ---------------------------------------------------------------------------

class _Parser:
    def __init__(self, tokens: List[Token], bool_fields: Optional[Set[str]] = None):
        self.tokens = tokens
        self.pos = 0
        self.bool_fields = bool_fields or set()

    def peek(self) -> Token:
        return self.tokens[self.pos]

    def advance(self) -> Token:
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def expect(self, kind: str, value: Any = None) -> Token:
        tok = self.peek()
        if tok.kind != kind or (value is not None and tok.value != value):
            raise ValueError(f"Expected {kind} {value!r} but got {tok.kind} {tok.value!r} at position {tok.pos}")
        return self.advance()

    def parse(self) -> Dict[str, Any]:
        node = self._parse_or()
        if self.peek().kind != "EOF":
            tok = self.peek()
            raise ValueError(f"Unexpected token {tok.kind} {tok.value!r} at position {tok.pos}")
        return node

    def _parse_or(self) -> Dict[str, Any]:
        children = [self._parse_and()]
        while self.peek().kind == "KEYWORD" and self.peek().value == "or":
            self.advance()
            children.append(self._parse_and())
        if len(children) == 1:
            return children[0]
        return {"type": "or", "children": children}

    def _parse_and(self) -> Dict[str, Any]:
        children = [self._parse_not()]
        while self.peek().kind == "KEYWORD" and self.peek().value == "and":
            self.advance()
            children.append(self._parse_not())
        if len(children) == 1:
            return children[0]
        return {"type": "and", "children": children}

    def _parse_not(self) -> Dict[str, Any]:
        if self.peek().kind == "KEYWORD" and self.peek().value == "not":
            self.advance()
            child = self._parse_not()
            return {"type": "not", "child": child}
        return self._parse_primary()

    def _parse_primary(self) -> Dict[str, Any]:
        tok = self.peek()
        if tok.kind == "LPAREN":
            self.advance()
            node = self._parse_or()
            self.expect("RPAREN")
            return node
        # Bare boolean literals: true / false
        if tok.kind == "KEYWORD" and tok.value in ("true", "false"):
            self.advance()
            return {"type": "literal", "value": tok.value == "true"}
        return self._parse_condition()

    def _parse_condition(self) -> Dict[str, Any]:
        tok = self.peek()
        if tok.kind != "IDENT":
            raise ValueError(f"Expected field name but got {tok.kind} {tok.value!r} at position {tok.pos}")
        field = self.advance().value

        bracket_key = None
        if self.peek().kind == "LBRACKET":
            self.advance()
            key_tok = self.peek()
            if key_tok.kind == "STRING":
                bracket_key = self.advance().value
            else:
                raise ValueError(f"Expected string key in brackets at position {key_tok.pos}")
            self.expect("RBRACKET")
            full_field = f'{field}["{bracket_key}"]'
        else:
            full_field = field

        negated = False
        if self.peek().kind == "KEYWORD" and self.peek().value == "not":
            self.advance()
            negated = True
            next_tok = self.peek()
            if next_tok.kind != "KEYWORD" or next_tok.value not in ("in", "exists"):
                raise ValueError(f"Expected 'in' or 'exists' after 'not' at position {next_tok.pos}")

        tok = self.peek()
        if tok.kind == "KEYWORD" and tok.value == "in":
            self.advance()
            return self._parse_in(full_field, negated)
        if tok.kind == "KEYWORD" and tok.value == "exists":
            self.advance()
            return {"type": "exists", "field": full_field, "negated": negated}
        if tok.kind == "KEYWORD" and tok.value in ("contains", "starts_with", "ends_with"):
            op = self.advance().value
            value_tok = self.peek()
            if value_tok.kind == "STRING":
                value = self.advance().value
            elif value_tok.kind == "NUMBER":
                value = self.advance().value
            else:
                raise ValueError(f"Expected value after operator {op!r} at position {value_tok.pos}")
            return {"type": "compare", "field": full_field, "op": op, "value": value}
        # No operator — check for boolean field
        if tok.kind in ("EOF", "RPAREN") or (tok.kind == "KEYWORD" and tok.value in ("and", "or")):
            if full_field in self.bool_fields:
                return {"type": "bool_field", "field": full_field, "negated": negated}
            raise ValueError(f"Field {full_field!r} requires an operator at position {tok.pos}")
        if tok.kind == "OP":
            op = self.advance().value
            value_tok = self.peek()
            if value_tok.kind == "STRING":
                value = self.advance().value
            elif value_tok.kind == "NUMBER":
                value = self.advance().value
            elif value_tok.kind == "KEYWORD" and value_tok.value in ("true", "false"):
                value = self.advance().value == "true"
            else:
                raise ValueError(f"Expected value after operator {op!r} at position {value_tok.pos}")
            return {"type": "compare", "field": full_field, "op": op, "value": value}
        raise ValueError(f"Expected operator after field {full_field!r} at position {tok.pos}")

    def _parse_in(self, field: str, negated: bool) -> Dict[str, Any]:
        tok = self.peek()
        if tok.kind == "LISTREF":
            list_type, list_name = self.advance().value
            return {"type": "in_list", "field": field, "list_type": list_type, "list_name": list_name, "negated": negated}
        if tok.kind == "LBRACKET":
            self.advance()
            values: List[Any] = []
            if self.peek().kind == "RBRACKET":
                self.advance()
                return {"type": "in_literals", "field": field, "values": values, "negated": negated}
            while True:
                vtok = self.peek()
                if vtok.kind == "STRING":
                    values.append(self.advance().value)
                elif vtok.kind == "NUMBER":
                    values.append(self.advance().value)
                else:
                    raise ValueError(f"Expected value in list at position {vtok.pos}")
                if self.peek().kind == "COMMA":
                    self.advance()
                    continue
                break
            self.expect("RBRACKET")
            return {"type": "in_literals", "field": field, "values": values, "negated": negated}
        raise ValueError(f"Expected list reference or '[' after 'in' at position {tok.pos}")


def parse_expression(text: str, bool_fields: Optional[Set[str]] = None) -> Dict[str, Any]:
    """Parse a Cloudflare-style expression string into an AST dict.

    Args:
        text: The expression string to parse.
        bool_fields: Optional set of field names that can appear without an
            operator (bare boolean fields). Used by the backend to register
            HAProxy-specific boolean fields like ``http.request.tls``.

    Raises ValueError with a position-aware message on parse errors.
    """
    if not text or not text.strip():
        raise ValueError("Expression is required")
    tokens = _tokenize(text)
    parser = _Parser(tokens, bool_fields=bool_fields)
    return parser.parse()


def validate_expression(text: str, bool_fields: Optional[Set[str]] = None) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    """Validate an expression string. Returns (ok, ast, error)."""
    if not text or not text.strip():
        return True, None, None
    try:
        ast = parse_expression(text, bool_fields=bool_fields)
        return True, ast, None
    except ValueError as e:
        return False, None, str(e)


# ---------------------------------------------------------------------------
# DNF normalization (used by backend for HAProxy ACL emission)
# ---------------------------------------------------------------------------

def to_dnf(node: Dict[str, Any]) -> List[List[Dict[str, Any]]]:
    """Normalize AST to DNF: list of OR-groups, each group is a list of AND-terms.

    Each term is a "leaf" condition (compare/in_list/in_literals/exists/bool_field/literal),
    possibly wrapped in a single-level negation.
    """
    t = node["type"]
    if t == "or":
        result: List[List[Dict[str, Any]]] = []
        for child in node["children"]:
            result.extend(to_dnf(child))
        return result
    if t == "and":
        groups = [to_dnf(child) for child in node["children"]]
        result = [list()]
        for child_groups in groups:
            new_result = []
            for existing in result:
                for cg in child_groups:
                    new_result.append(existing + cg)
            result = new_result
        return result
    if t == "not":
        return _negate_to_dnf(node["child"])
    # Leaf
    return [[node]]


def _negate_to_dnf(node: Dict[str, Any]) -> List[List[Dict[str, Any]]]:
    """Negate a node and return DNF."""
    t = node["type"]
    if t == "or":
        groups = [_negate_to_dnf(child) for child in node["children"]]
        result = [list()]
        for child_groups in groups:
            new_result = []
            for existing in result:
                for cg in child_groups:
                    new_result.append(existing + cg)
            result = new_result
        return result
    if t == "and":
        result: List[List[Dict[str, Any]]] = []
        for child in node["children"]:
            result.extend(_negate_to_dnf(child))
        return result
    if t == "not":
        return to_dnf(node["child"])
    # Leaf: wrap in negation
    negated = dict(node)
    negated["negated"] = not node.get("negated", False)
    return [[negated]]


# ---------------------------------------------------------------------------
# Shared evaluator — runs AST against a context dict
# ---------------------------------------------------------------------------

def resolve_field_value(field: str, ctx: Dict[str, Any]) -> Any:
    """Resolve a field name to its value from a context dict.

    Supports:
    - Simple fields: mcp.method, mcp.server, mcp.tool, ip.src, etc.
    - Bracket fields: mcp.arg["path"], auth.claim["key"]
    - Dot-path fields: auth.claim.sub, mcp.identity.kind
    """
    import re

    bracket_match = re.match(r'^([\w.]+)\["(.+)"\]$', field)
    if bracket_match:
        base_field, key = bracket_match.group(1), bracket_match.group(2)
        base = ctx.get(base_field, {})
        if isinstance(base, dict):
            return str(base.get(key, "")) if base.get(key) is not None else None
        return None

    if field in ctx:
        return ctx[field]

    parts = field.split(".")
    val = ctx
    for part in parts:
        if isinstance(val, dict) and part in val:
            val = val[part]
        else:
            return None
    return val


def evaluate_leaf(node: Dict[str, Any], ctx: Dict[str, Any]) -> bool:
    """Evaluate a single leaf condition against the context."""
    import re

    t = node["type"]
    negated = node.get("negated", False)

    if t == "literal":
        return node["value"]

    if t == "bool_field":
        val = resolve_field_value(node["field"], ctx)
        result = bool(val)
        return (not result) if negated else result

    if t == "exists":
        val = resolve_field_value(node["field"], ctx)
        result = val is not None and val != ""
        return (not result) if negated else result

    if t == "compare":
        field = node["field"]
        op = node["op"]
        expected = node["value"]
        actual = resolve_field_value(field, ctx)

        if actual is None:
            return negated

        if isinstance(expected, bool):
            if op == "=":
                result = bool(actual) == expected
            else:
                return negated
        elif isinstance(expected, int):
            try:
                actual_int = int(actual)
            except (ValueError, TypeError):
                return negated
            if op == "=":
                result = actual_int == expected
            elif op == "!=":
                result = actual_int != expected
            elif op == ">":
                result = actual_int > expected
            elif op == "<":
                result = actual_int < expected
            elif op == ">=":
                result = actual_int >= expected
            elif op == "<=":
                result = actual_int <= expected
            else:
                return negated
        else:
            actual_str = str(actual)
            if op == "=":
                result = actual_str == expected
            elif op == "!=":
                result = actual_str != expected
            elif op == "~":
                result = re.search(expected, actual_str) is not None
            elif op == "!~":
                result = re.search(expected, actual_str) is None
            elif op == "contains":
                result = expected in actual_str
            elif op == "starts_with":
                result = actual_str.startswith(expected)
            elif op == "ends_with":
                result = actual_str.endswith(expected)
            else:
                return negated

        return (not result) if negated else result

    if t == "in_literals":
        actual = resolve_field_value(node["field"], ctx)
        if actual is None:
            return negated
        values = node["values"]
        result = any(actual == v or str(actual) == str(v) for v in values)
        return (not result) if negated else result

    if t == "in_list":
        actual = resolve_field_value(node["field"], ctx)
        if actual is None:
            return negated
        list_resolver = ctx.get("_list_resolver")
        if list_resolver:
            in_list = list_resolver(node["list_type"], node["list_name"], actual)
            return (not in_list) if negated else in_list
        return negated

    raise ValueError(f"Unknown node type: {t}")


def evaluate(node: Dict[str, Any], ctx: Dict[str, Any]) -> bool:
    """Evaluate an AST node against a context dict. Returns True/False."""
    t = node["type"]

    if t == "and":
        return all(evaluate(child, ctx) for child in node["children"])

    if t == "or":
        return any(evaluate(child, ctx) for child in node["children"])

    if t == "not":
        return not evaluate(node["child"], ctx)

    return evaluate_leaf(node, ctx)
