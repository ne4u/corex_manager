"""Tests for API Armor security rule field translation.

Verifies that req_fp, GraphQL, schema, auth, and profiling fields translate
correctly to HAProxy fetch expressions.
"""
from app.services.security_rules import parse_expression, translate


def _tr(expr, db):
    """Helper: parse + translate an expression, return the HAProxy condition string."""
    cond, _ = translate(parse_expression(expr), db)
    return cond


# --- Request Fingerprint (req_fp v2) fields ---

def test_req_fp_full_fingerprint(db):
    """http.request.fingerprint → var(txn.req_fp.full) (response-phase)."""
    cond = _tr('http.request.fingerprint = "abc123"', db)
    assert 'var(txn.req_fp.full)' in cond
    assert '-m str abc123' in cond


def test_req_fp_content_type(db):
    """http.request.fingerprint.content_type → var(txn.req_fp.ctype)."""
    cond = _tr('http.request.fingerprint.content_type = "json"', db)
    assert 'var(txn.req_fp.ctype)' in cond
    assert '-m str json' in cond


def test_req_fp_param_keys(db):
    """http.request.fingerprint.param_keys → var(txn.req_fp.param_keys)."""
    cond = _tr('http.request.fingerprint.param_keys = "ui"', db)
    assert 'var(txn.req_fp.param_keys)' in cond


def test_req_fp_auth_type(db):
    """http.request.fingerprint.auth_type → var(txn.req_fp.auth_type)."""
    cond = _tr('http.request.fingerprint.auth_type = "n"', db)
    assert 'var(txn.req_fp.auth_type)' in cond
    assert '-m str n' in cond


def test_req_fp_path_depth_int(db):
    """http.request.fingerprint.path_depth → integer comparison."""
    cond = _tr('http.request.fingerprint.path_depth > 5', db)
    assert 'var(txn.req_fp.path_depth)' in cond
    assert 'gt 5' in cond


def test_req_fp_body_depth_int(db):
    """http.request.fingerprint.body_depth → integer comparison."""
    cond = _tr('http.request.fingerprint.body_depth > 2', db)
    assert 'var(txn.req_fp.body_depth)' in cond
    assert 'gt 2' in cond


def test_req_fp_response_status(db):
    """http.response.fingerprint.status → integer comparison (response-phase)."""
    cond = _tr('http.response.fingerprint.status = 200', db)
    assert 'var(txn.req_fp.status)' in cond


def test_req_fp_response_body_bytes(db):
    """http.response.fingerprint.body_bytes → integer comparison."""
    cond = _tr('http.response.fingerprint.body_bytes > 1000', db)
    assert 'var(txn.req_fp.body_bytes)' in cond


# --- GraphQL fields ---

def test_graphql_depth(db):
    """graphql.depth → integer comparison."""
    cond = _tr('graphql.depth > 10', db)
    assert 'var(txn.gql.depth)' in cond
    assert 'gt 10' in cond


def test_graphql_complexity(db):
    """graphql.complexity → integer comparison."""
    cond = _tr('graphql.complexity > 1000', db)
    assert 'var(txn.gql.complexity)' in cond
    assert 'gt 1000' in cond


def test_graphql_operation(db):
    """graphql.operation → string comparison."""
    cond = _tr('graphql.operation = "query"', db)
    assert 'var(txn.gql.operation)' in cond
    assert '-m str query' in cond


def test_graphql_query_hash(db):
    """graphql.query_hash → string comparison."""
    cond = _tr('graphql.query_hash = "abc123"', db)
    assert 'var(txn.gql.query_hash)' in cond


def test_graphql_valid_bool(db):
    """graphql.valid = true → bare condition (bool field)."""
    cond = _tr('graphql.valid = true', db)
    assert 'var(txn.gql.valid)' in cond


def test_graphql_valid_bare(db):
    """graphql.valid (bare, no operator) → bool_field condition."""
    cond = _tr('graphql.valid', db)
    assert 'var(txn.gql.valid)' in cond


def test_graphql_valid_negated(db):
    """not graphql.valid → negated bool_field."""
    cond = _tr('not graphql.valid', db)
    assert '!{' in cond
    assert 'var(txn.gql.valid)' in cond


def test_var_bool_field_requires_match_method(db):
    """Regression: var() fetches require a -m match method in HAProxy.
    Without -m, HAProxy rejects with 'matching method must be specified first'.
    Bool vars store '0'/'1' strings, so use -m str 1.
    """
    # Bare bool_field
    cond = _tr('http.request.keep_alive', db)
    assert '-m str 1' in cond
    assert 'var(txn.risk_fp.keep_alive)' in cond
    # Negated bool_field
    cond = _tr('not http.request.keep_alive', db)
    assert '-m str 1' in cond
    assert '!{' in cond
    # = true comparison
    cond = _tr('auth.valid = true', db)
    assert '-m str 1' in cond
    # = false comparison
    cond = _tr('api.schema_valid = false', db)
    assert '-m str 1' in cond
    # Native bool fetch (ssl_fc) should NOT have -m str 1
    cond = _tr('http.request.tls', db)
    assert 'ssl_fc' in cond
    assert '-m str 1' not in cond


def test_graphql_field_count(db):
    """graphql.field_count → integer comparison."""
    cond = _tr('graphql.field_count > 50', db)
    assert 'var(txn.gql.field_count)' in cond


def test_graphql_alias_count(db):
    """graphql.alias_count → integer comparison."""
    cond = _tr('graphql.alias_count > 5', db)
    assert 'var(txn.gql.alias_count)' in cond


# --- Schema Validation fields ---

def test_api_schema_valid_bool(db):
    """api.schema_valid = false → negated condition."""
    cond = _tr('api.schema_valid = false', db)
    assert 'var(txn.api.schema_valid)' in cond


def test_api_schema_valid_bare(db):
    """api.schema_valid (bare) → bool_field condition."""
    cond = _tr('api.schema_valid', db)
    assert 'var(txn.api.schema_valid)' in cond


def test_api_schema_errors(db):
    """api.schema_errors → string comparison."""
    cond = _tr('api.schema_errors contains "missing"', db)
    assert 'var(txn.api.schema_errors)' in cond
    assert '-m sub missing' in cond


# --- Auth fields ---

def test_auth_valid_bool(db):
    """auth.valid = true → bare condition."""
    cond = _tr('auth.valid = true', db)
    assert 'var(txn.auth.valid)' in cond


def test_auth_valid_bare(db):
    """auth.valid (bare) → bool_field condition."""
    cond = _tr('auth.valid', db)
    assert 'var(txn.auth.valid)' in cond


def test_auth_type(db):
    """auth.type → string comparison."""
    cond = _tr('auth.type = "jwt"', db)
    assert 'var(txn.auth.type)' in cond
    assert '-m str jwt' in cond


def test_auth_claim_sub(db):
    """auth.claim.sub → string comparison."""
    cond = _tr('auth.claim.sub = "user-123"', db)
    assert 'var(txn.auth.claim_sub)' in cond
    assert '-m str user-123' in cond


def test_auth_claim_bracket(db):
    """auth.claim["role"] → bracket field access."""
    cond = _tr('auth.claim["role"] = "admin"', db)
    assert 'var(txn.auth.claim_role)' in cond
    assert '-m str admin' in cond


# --- Profiling fields ---

def test_api_profile_anomaly_bool(db):
    """api.profile_anomaly = true → bare condition."""
    cond = _tr('api.profile_anomaly = true', db)
    assert 'var(txn.api.profile_anomaly)' in cond


def test_api_profile_anomaly_bare(db):
    """api.profile_anomaly (bare) → bool_field condition."""
    cond = _tr('api.profile_anomaly', db)
    assert 'var(txn.api.profile_anomaly)' in cond


# --- Combined expressions ---

def test_combined_graphql_and_auth(db):
    """Combined expression with GraphQL and auth fields."""
    cond = _tr('graphql.depth > 10 and auth.valid = false', db)
    assert 'var(txn.gql.depth)' in cond
    assert 'var(txn.auth.valid)' in cond


def test_req_fp_and_graphql(db):
    """Combined req_fp and GraphQL expression."""
    cond = _tr('http.request.fingerprint.auth_type = "n" and graphql.depth > 5', db)
    assert 'var(txn.req_fp.auth_type)' in cond
    assert 'var(txn.gql.depth)' in cond
