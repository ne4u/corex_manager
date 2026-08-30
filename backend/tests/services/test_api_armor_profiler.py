"""Tests for API Armor behavioral profiling sampler."""
import json
import os
import tempfile

from app.services.api_armor_profiler import (
    ApiArmorProfiler,
    normalize_path,
    extract_dimension,
    check_anomaly,
    finalize_profile,
)
from app.models.api_armor import ApiProfile, ApiAnomaly


def test_normalize_path_numeric():
    """normalize_path replaces numeric IDs with :id."""
    assert normalize_path("/api/v1/users/123") == "/api/v1/users/:id"
    assert normalize_path("/api/v1/users/123/posts/456") == "/api/v1/users/:id/posts/:id"


def test_normalize_path_uuid():
    """normalize_path replaces UUIDs with :id."""
    assert normalize_path("/api/v1/users/550e8400-e29b-41d4-a716-446655440000") == "/api/v1/users/:id"


def test_normalize_path_mongo_objectid():
    """normalize_path replaces MongoDB ObjectIds with :id."""
    assert normalize_path("/api/v1/users/507f1f77bcf86cd799439011") == "/api/v1/users/:id"


def test_normalize_path_no_ids():
    """normalize_path leaves paths without IDs unchanged."""
    assert normalize_path("/api/v1/users") == "/api/v1/users"
    assert normalize_path("/api/v1/users/search") == "/api/v1/users/search"


def test_extract_dimension_content_type():
    """extract_dimension extracts content_type."""
    entry = {"content_type": "application/json"}
    assert extract_dimension(entry, "content_type") == "application/json"


def test_extract_dimension_body_structure():
    """extract_dimension extracts body_structure top_keys."""
    entry = {"body_structure": {"top_keys": ["name", "email", "age"]}}
    result = extract_dimension(entry, "body_structure")
    assert result == ["age", "email", "name"]  # sorted


def test_extract_dimension_graphql():
    """extract_dimension extracts GraphQL metrics."""
    entry = {"graphql": {"operation": "query", "depth": 3, "query_hash": "abc123"}}
    result = extract_dimension(entry, "graphql")
    assert result["operation"] == "query"
    assert result["depth"] == 3


def test_extract_dimension_auth_type():
    """extract_dimension extracts auth_type."""
    entry = {"auth_type": "jwt"}
    assert extract_dimension(entry, "auth_type") == "jwt"


def test_extract_dimension_unknown():
    """extract_dimension returns None for unknown dimensions."""
    entry = {}
    assert extract_dimension(entry, "unknown") is None


def test_check_anomaly_no_anomaly(db):
    """check_anomaly returns None when values are in the baseline."""
    profile = ApiProfile(
        method="POST",
        path="/api/v1/users",
        dimensions={
            "content_type": {"values": ["application/json"], "count": 10},
            "auth_type": {"values": ["jwt"], "count": 10},
        },
        sample_count=10,
        learned=True,
    )
    db.add(profile)
    db.commit()

    entry = {"content_type": "application/json", "auth_type": "jwt"}
    result = check_anomaly(profile, entry)
    assert result is None


def test_check_anomaly_detected(db):
    """check_anomaly returns the anomalous dimension name."""
    profile = ApiProfile(
        method="POST",
        path="/api/v1/users",
        dimensions={
            "content_type": {"values": ["application/json"], "count": 10},
            "auth_type": {"values": ["jwt"], "count": 10},
        },
        sample_count=10,
        learned=True,
    )
    db.add(profile)
    db.commit()

    # Content type not in baseline
    entry = {"content_type": "text/xml", "auth_type": "jwt"}
    result = check_anomaly(profile, entry)
    assert result == "content_type"


def test_finalize_profile_insufficient_samples(db):
    """finalize_profile fails with insufficient samples."""
    profile = ApiProfile(
        method="POST",
        path="/api/v1/users",
        dimensions={},
        sample_count=5,
        learned=False,
    )
    db.add(profile)
    db.commit()

    result = finalize_profile(db, profile.id, min_samples=100)
    assert result is False
    db.refresh(profile)
    assert profile.learned is False


def test_finalize_profile_success(db):
    """finalize_profile succeeds with sufficient samples."""
    profile = ApiProfile(
        method="POST",
        path="/api/v1/users",
        dimensions={},
        sample_count=150,
        learned=False,
    )
    db.add(profile)
    db.commit()

    result = finalize_profile(db, profile.id, min_samples=100)
    assert result is True
    db.refresh(profile)
    assert profile.learned is True


def test_profiler_processes_log_file(db):
    """ApiArmorProfiler reads a log file and creates profiles."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        # Write some profiling log entries
        entries = [
            {"method": "POST", "path": "/api/v1/users", "content_type": "application/json"},
            {"method": "POST", "path": "/api/v1/users", "content_type": "application/json"},
            {"method": "GET", "path": "/api/v1/users/123", "content_type": "application/json"},
        ]
        for entry in entries:
            f.write(json.dumps(entry) + "\n")
        f.flush()
        log_path = f.name

    try:
        profiler = ApiArmorProfiler(log_path=log_path, sample_interval=0.1)
        # Process once
        count = profiler._process_new_lines()
        assert count == 3

        # Verify profiles were created
        profiles = db.query(ApiProfile).all()
        assert len(profiles) == 2  # POST /api/v1/users and GET /api/v1/users/:id

        post_profile = next(p for p in profiles if p.method == "POST")
        assert post_profile.sample_count == 2
        assert "content_type" in (post_profile.dimensions or {})

        get_profile = next(p for p in profiles if p.method == "GET")
        assert get_profile.path == "/api/v1/users/:id"  # normalized
    finally:
        os.unlink(log_path)


def test_profiler_handles_log_rotation(db):
    """ApiArmorProfiler handles log rotation (file shrinks)."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write(json.dumps({"method": "POST", "path": "/api/v1/users/with/long/path"}) + "\n")
        f.flush()
        log_path = f.name

    try:
        profiler = ApiArmorProfiler(log_path=log_path, sample_interval=0.1)
        # Process the first line
        profiler._process_new_lines()
        assert profiler._offset > 0

        # Simulate log rotation — truncate and write a shorter line
        with open(log_path, "w") as f:
            f.write(json.dumps({"method": "GET", "path": "/x"}) + "\n")

        # Process again — should detect rotation (file_size < offset) and reset
        count = profiler._process_new_lines()
        assert count == 1
    finally:
        os.unlink(log_path)
