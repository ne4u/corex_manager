"""Host and path regexes must be quoted HAProxy words.

A bare ``\\$`` is a literal dollar, so ``use_backend ... if be_rule_*`` never
matches and the shared frontend returns 503. Inside quotes, ``\\$`` is an
end anchor.
"""

from app.services.haproxy import _backend_condition_expression, _safe_regex


def test_host_regex_quotes_the_dollar_anchor():
    expr = _backend_condition_expression(
        "host", None, "reg", r"^(www\.)?firestop\.dev(:\d+)?$"
    )
    assert expr == r'req.hdr(host) -m reg "^(www\\.)?firestop\\.dev(:\\d+)?\$"'


def test_safe_regex_escapes_quote_without_doubling_its_backslash():
    assert _safe_regex('foo"bar$') == r'"foo\"bar\$"'
