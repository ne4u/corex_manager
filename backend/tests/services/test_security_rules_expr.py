"""Tests for the security rules expression engine (tokenizer, parser, translator)."""
import os
import pytest
from unittest.mock import MagicMock

from app.services.security_rules import (
    parse_expression,
    translate,
    validate_expression,
    _to_dnf,
    _tokenize,
)


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------

class TestTokenizer:
    def test_simple_field(self):
        tokens = _tokenize('http.request.uri.path = "/wp-login.php"')
        assert len(tokens) == 4  # IDENT, OP, STRING, EOF
        assert tokens[0].kind == "IDENT"
        assert tokens[0].value == "http.request.uri.path"
        assert tokens[1].kind == "OP"
        assert tokens[1].value == "="
        assert tokens[2].kind == "STRING"
        assert tokens[2].value == "/wp-login.php"

    def test_and_or(self):
        tokens = _tokenize('http.host = "a" and http.host = "b" or http.host = "c"')
        kinds = [t.kind for t in tokens if t.kind != "EOF"]
        assert "KEYWORD" in kinds

    def test_list_ref(self):
        tokens = _tokenize('ip.src in $network:badactors')
        assert any(t.kind == "LISTREF" and t.value == ("network", "badactors") for t in tokens)

    def test_number(self):
        tokens = _tokenize('http.response.status_code = 403')
        assert any(t.kind == "NUMBER" and t.value == 403 for t in tokens)

    def test_parens(self):
        tokens = _tokenize('(http.host = "a" or http.host = "b") and ip.src = "1.2.3.4"')
        assert tokens[0].kind == "LPAREN"
        assert any(t.kind == "RPAREN" for t in tokens)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class TestParser:
    def test_simple_compare(self):
        ast = parse_expression('http.request.uri.path = "/wp-login.php"')
        assert ast["type"] == "compare"
        assert ast["field"] == "http.request.uri.path"
        assert ast["op"] == "="
        assert ast["value"] == "/wp-login.php"

    def test_and(self):
        ast = parse_expression('http.host = "a" and http.host = "b"')
        assert ast["type"] == "and"
        assert len(ast["children"]) == 2

    def test_or(self):
        ast = parse_expression('http.host = "a" or http.host = "b"')
        assert ast["type"] == "or"
        assert len(ast["children"]) == 2

    def test_not(self):
        ast = parse_expression('not http.host = "a"')
        assert ast["type"] == "not"
        assert ast["child"]["type"] == "compare"

    def test_precedence(self):
        # not > and > or
        ast = parse_expression('http.host = "a" or http.host = "b" and http.host = "c"')
        assert ast["type"] == "or"
        assert ast["children"][1]["type"] == "and"

    def test_parens(self):
        ast = parse_expression('(http.host = "a" or http.host = "b") and ip.src = "1.2.3.4"')
        assert ast["type"] == "and"
        assert ast["children"][0]["type"] == "or"

    def test_in_literals(self):
        ast = parse_expression('http.request.method in ["GET", "POST"]')
        assert ast["type"] == "in_literals"
        assert ast["values"] == ["GET", "POST"]

    def test_asn_literal_bare(self):
        # AS8075 without quotes should be tokenized as a string value
        ast = parse_expression('ip.geoip.asnum = AS8075')
        assert ast["type"] == "compare"
        assert ast["field"] == "ip.geoip.asnum"
        assert ast["op"] == "="
        assert ast["value"] == "AS8075"

    def test_asn_literal_lowercase(self):
        ast = parse_expression('ip.geoip.asnum = as8075')
        assert ast["value"] == "AS8075"

    def test_asn_literal_in_list(self):
        ast = parse_expression('ip.geoip.asnum in [AS8075, AS18403]')
        assert ast["type"] == "in_literals"
        assert ast["values"] == ["AS8075", "AS18403"]

    def test_in_list_ref(self):
        ast = parse_expression('ip.src in $network:badactors')
        assert ast["type"] == "in_list"
        assert ast["list_type"] == "network"
        assert ast["list_name"] == "badactors"

    def test_not_in(self):
        ast = parse_expression('http.request.method not in ["GET", "POST"]')
        assert ast["type"] == "in_literals"
        assert ast["negated"] is True

    def test_exists(self):
        ast = parse_expression('http.request.headers["x-api-key"] exists')
        assert ast["type"] == "exists"
        assert ast["field"] == 'http.request.headers["x-api-key"]'

    def test_not_exists(self):
        ast = parse_expression('http.request.headers["x-api-key"] not exists')
        assert ast["type"] == "exists"
        assert ast["negated"] is True

    def test_bool_field(self):
        ast = parse_expression('http.request.tls')
        assert ast["type"] == "bool_field"

    def test_regex(self):
        ast = parse_expression('http.request.uri.path ~ "^.*/wp-login.php$"')
        assert ast["type"] == "compare"
        assert ast["op"] == "~"

    def test_empty_raises(self):
        with pytest.raises(ValueError, match="required"):
            parse_expression("")

    def test_invalid_char_raises(self):
        with pytest.raises(ValueError, match="Unexpected character"):
            parse_expression("http.host @ 'a'")


# ---------------------------------------------------------------------------
# DNF normalization
# ---------------------------------------------------------------------------

class TestDNF:
    def test_simple_leaf(self):
        ast = parse_expression('http.host = "a"')
        dnf = _to_dnf(ast)
        assert len(dnf) == 1
        assert len(dnf[0]) == 1

    def test_and(self):
        ast = parse_expression('http.host = "a" and http.host = "b"')
        dnf = _to_dnf(ast)
        assert len(dnf) == 1  # one AND group
        assert len(dnf[0]) == 2  # two terms

    def test_or(self):
        ast = parse_expression('http.host = "a" or http.host = "b"')
        dnf = _to_dnf(ast)
        assert len(dnf) == 2  # two OR groups
        assert len(dnf[0]) == 1
        assert len(dnf[1]) == 1

    def test_not_or(self):
        # not(a or b) = not(a) and not(b) → one group with two negated terms
        ast = parse_expression('not (http.host = "a" or http.host = "b")')
        dnf = _to_dnf(ast)
        assert len(dnf) == 1
        assert len(dnf[0]) == 2
        assert dnf[0][0]["negated"] is True
        assert dnf[0][1]["negated"] is True

    def test_not_and(self):
        # not(a and b) = not(a) or not(b) → two groups
        ast = parse_expression('not (http.host = "a" and http.host = "b")')
        dnf = _to_dnf(ast)
        assert len(dnf) == 2
        assert dnf[0][0]["negated"] is True
        assert dnf[1][0]["negated"] is True

    def test_double_negation(self):
        ast = parse_expression('not not http.host = "a"')
        dnf = _to_dnf(ast)
        assert len(dnf) == 1
        assert dnf[0][0].get("negated", False) is False


# ---------------------------------------------------------------------------
# Translator
# ---------------------------------------------------------------------------

class TestTranslator:
    def setup_method(self):
        self.db = MagicMock()

    def test_string_eq(self):
        ast = parse_expression('http.request.uri.path = "/wp-login.php"')
        cond, phase = translate(ast, self.db)
        assert '{ path -m str /wp-login.php }' in cond
        assert phase == "request"

    def test_string_neq(self):
        ast = parse_expression('http.request.uri.path != "/wp-login.php"')
        cond, phase = translate(ast, self.db)
        assert '!{' in cond
        assert phase == "request"

    def test_string_neq_no_nested_braces(self):
        """Regression: != must produce !{ ... } not { !{ ... } }.
        HAProxy rejects { !{ ... } } with "missing fetch method in ACL
        expression '!{'".
        """
        ast = parse_expression('http.request.uri.path != "/wp-login.php"')
        cond, phase = translate(ast, self.db)
        assert '{ !{' not in cond

    def test_string_nregex_no_nested_braces(self):
        """Regression: !~ must produce !{ ... } not { !{ ... } }."""
        ast = parse_expression('http.request.uri.path !~ "^.*/wp-login.php$"')
        cond, phase = translate(ast, self.db)
        assert '{ !{' not in cond
        assert '!{' in cond

    def test_int_neq_no_nested_braces(self):
        """Regression: integer != must produce !{ ... } not { !{ ... } }."""
        ast = parse_expression('http.request.fingerprint.header_count != 5')
        cond, phase = translate(ast, self.db)
        assert '{ !{' not in cond
        assert '!{' in cond

    def test_regex(self):
        ast = parse_expression('http.request.uri.path ~ "^.*/wp-login.php$"')
        cond, phase = translate(ast, self.db)
        assert '-m reg' in cond
        assert phase == "request"

    def test_contains(self):
        ast = parse_expression('http.request.uri.path contains "admin"')
        cond, phase = translate(ast, self.db)
        assert '-m sub' in cond
        assert phase == "request"

    def test_int_eq(self):
        ast = parse_expression('http.response.status_code = 403')
        cond, phase = translate(ast, self.db)
        assert '-m int 403' in cond
        assert phase == "response"

    def test_int_gt(self):
        ast = parse_expression('http.response.status_code > 400')
        cond, phase = translate(ast, self.db)
        assert '-m int gt 400' in cond
        assert phase == "response"

    def test_beacon_trusted_gt_zero(self):
        """ip.beacon_trusted translates to a table_http_req_cnt stick table lookup."""
        ast = parse_expression('ip.beacon_trusted > 0')
        cond, phase = translate(ast, self.db)
        assert 'table_http_req_cnt(beacon_trust_table)' in cond
        assert '-m int gt 0' in cond
        assert phase == "request"

    def test_in_literals_string(self):
        ast = parse_expression('http.request.method in ["GET", "POST"]')
        cond, phase = translate(ast, self.db)
        assert '-m str' in cond
        assert 'GET' in cond
        assert 'POST' in cond
        assert phase == "request"

    def test_in_literals_int(self):
        ast = parse_expression('http.response.status_code in [200, 301]')
        cond, phase = translate(ast, self.db)
        assert '-m int' in cond
        assert '200' in cond
        assert '301' in cond
        assert phase == "response"

    def test_exists(self):
        ast = parse_expression('http.request.headers["x-api-key"] exists')
        cond, phase = translate(ast, self.db)
        assert '-m found' in cond
        assert 'req.hdr(x-api-key)' in cond
        assert phase == "request"

    def test_bool_field_tls(self):
        ast = parse_expression('http.request.tls')
        cond, phase = translate(ast, self.db)
        assert 'ssl_fc' in cond
        assert phase == "request"

    def test_scheme_https(self):
        ast = parse_expression('http.request.scheme = "https"')
        cond, phase = translate(ast, self.db)
        assert 'ssl_fc' in cond
        assert phase == "request"

    def test_scheme_http(self):
        ast = parse_expression('http.request.scheme = "http"')
        cond, phase = translate(ast, self.db)
        assert '!ssl_fc' in cond or '!{ ssl_fc' in cond
        assert phase == "request"

    def test_and_or(self):
        ast = parse_expression('http.host = "a" or http.host = "b"')
        cond, phase = translate(ast, self.db)
        assert ' or ' in cond
        assert phase == "request"

    def test_not(self):
        ast = parse_expression('not http.host = "a"')
        cond, phase = translate(ast, self.db)
        assert '!' in cond
        assert phase == "request"

    def test_ja4_field(self):
        ast = parse_expression('http.request.ja4 = "t13d1516h2_8daaf6152771_b186095e22b6"')
        cond, phase = translate(ast, self.db)
        assert 'lua.ja4_fp' in cond
        assert phase == "request"

    def test_ip_src(self):
        ast = parse_expression('ip.src = "1.2.3.4"')
        cond, phase = translate(ast, self.db)
        assert 'src' in cond
        assert phase == "request"

    def test_header_bracket(self):
        ast = parse_expression('http.request.headers["x-custom"] = "value"')
        cond, phase = translate(ast, self.db)
        assert 'req.hdr(x-custom)' in cond
        assert phase == "request"

    def test_response_header(self):
        ast = parse_expression('http.response.headers["x-powered-by"] = "php"')
        cond, phase = translate(ast, self.db)
        assert 'res.hdr(x-powered-by)' in cond
        assert phase == "response"

    def test_query_param(self):
        ast = parse_expression('http.request.uri.query["page"] = "admin"')
        cond, phase = translate(ast, self.db)
        assert 'url_query' in cond
        assert '-m reg' in cond
        assert phase == "request"


# ---------------------------------------------------------------------------
# List reference resolution
# ---------------------------------------------------------------------------

class TestListResolution:
    def test_missing_list_raises(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        ast = parse_expression('ip.src in $network:nonexistent')
        with pytest.raises(ValueError, match="not found"):
            translate(ast, db)

    def test_existing_list(self):
        db = MagicMock()
        mock_list = MagicMock()
        mock_list.name = "badactors"
        db.query.return_value.filter.return_value.first.return_value = mock_list
        ast = parse_expression('ip.src in $network:badactors')
        cond, phase = translate(ast, db)
        assert '-f' in cond
        assert 'network' in cond
        assert phase == "request"

    def test_in_pattern_list_parse(self):
        ast = parse_expression('http.request.user_agent in $pattern:bad_bots')
        assert ast["type"] == "in_list"
        assert ast["list_type"] == "pattern"
        assert ast["list_name"] == "bad_bots"

    def test_translate_pattern_list(self):
        db = MagicMock()
        mock_list = MagicMock()
        mock_list.name = "bad_bots"
        db.query.return_value.filter.return_value.first.return_value = mock_list
        ast = parse_expression('http.request.user_agent in $pattern:bad_bots')
        cond, phase = translate(ast, db)
        assert '-m reg -f' in cond
        assert 'pattern' in cond
        assert phase == "request"

    def test_translate_pattern_list_non_string_field_raises(self):
        db = MagicMock()
        mock_list = MagicMock()
        mock_list.name = "bad_bots"
        db.query.return_value.filter.return_value.first.return_value = mock_list
        ast = parse_expression('ip.src in $pattern:bad_bots')
        with pytest.raises(ValueError, match="string-typed"):
            translate(ast, db)


# ---------------------------------------------------------------------------
# Validation helper
# ---------------------------------------------------------------------------

class TestValidateExpression:
    def test_valid(self):
        ok, ast, err = validate_expression('http.host = "a"')
        assert ok is True
        assert err is None
        assert ast is not None

    def test_invalid(self):
        ok, ast, err = validate_expression('http.host @')
        assert ok is False
        assert err is not None

    def test_empty(self):
        ok, ast, err = validate_expression('')
        assert ok is True  # empty is valid (no rule)
        assert err is None


# ---------------------------------------------------------------------------
# rules_referencing_ja4 helper
# ---------------------------------------------------------------------------

class TestRulesReferencingJa4:
    def test_finds_ja4_rules(self, db):
        from app.services.security_rules import rules_referencing_ja4, parse_expression
        from app.models.models import SecurityRule

        r1 = SecurityRule(name="ja4-eq", expression='http.request.ja4 = "t13d1516h2_8daaf6152771_b186095e22b6"',
                          action="block", priority=0, listener_ids=[],
                          expression_ast=parse_expression('http.request.ja4 = "t13d1516h2_8daaf6152771_b186095e22b6"'))
        r2 = SecurityRule(name="path", expression='http.request.uri.path = "/foo"',
                          action="block", priority=1, listener_ids=[],
                          expression_ast=parse_expression('http.request.uri.path = "/foo"'))
        r3 = SecurityRule(name="ja4-in-list", expression='http.request.ja4 in $ja4:badbots',
                          action="block", priority=2, listener_ids=[],
                          expression_ast=parse_expression('http.request.ja4 in $ja4:badbots'))
        db.add_all([r1, r2, r3])
        db.commit()

        matches = rules_referencing_ja4(db)
        names = {m.name for m in matches}
        assert names == {"ja4-eq", "ja4-in-list"}

    def test_falls_back_to_text_scan(self, db):
        """Rules without expression_ast should still be found via raw text scan."""
        from app.services.security_rules import rules_referencing_ja4
        from app.models.models import SecurityRule

        r = SecurityRule(name="no-ast", expression='http.request.ja4 = "t13d..."',
                         action="block", priority=0, listener_ids=[],
                         expression_ast=None)
        db.add(r)
        db.commit()

        matches = rules_referencing_ja4(db)
        assert any(m.name == "no-ast" for m in matches)

    def test_skips_disabled_rules(self, db):
        from app.services.security_rules import rules_referencing_ja4
        from app.models.models import SecurityRule

        r = SecurityRule(name="disabled-ja4", expression='http.request.ja4 = "t13d..."',
                         action="block", enabled=False, priority=0, listener_ids=[])
        db.add(r)
        db.commit()

        matches = rules_referencing_ja4(db)
        assert all(m.name != "disabled-ja4" for m in matches)
