"""Tests for the API Armor schema-learning sampler."""
import json
import os
import tempfile

from app.models.api_armor import ApiSchema
from app.services.api_armor_schema_learner import (
    ApiArmorSchemaLearner,
    ingest_schema_learning_entry_from_log,
    prune_learned_schemas,
)


def test_ingest_schema_learning_from_log(db):
    """ingest_schema_learning_entry_from_log creates a learned schema."""
    entry = {
        "method": "POST",
        "path": "/api/v1/users",
        "body_sample": {"name": "alice", "email": "alice@example.com"},
    }
    ingest_schema_learning_entry_from_log(entry)

    schema = db.query(ApiSchema).filter(ApiSchema.method == "POST").first()
    assert schema is not None
    assert schema.path == "/api/v1/users"
    assert schema.source == "learned"
    assert schema.schema["type"] == "object"
    assert "name" in schema.schema["properties"]


def test_ingest_schema_learning_merges(db):
    """Two observations for the same endpoint are merged."""
    ingest_schema_learning_entry_from_log({
        "method": "POST",
        "path": "/api/v1/users",
        "body_sample": {"name": "alice"},
    })
    ingest_schema_learning_entry_from_log({
        "method": "POST",
        "path": "/api/v1/users",
        "body_sample": {"name": "bob", "age": 30},
    })

    schema = db.query(ApiSchema).first()
    assert schema.sample_count == 2
    assert "name" in schema.schema["properties"]
    assert "age" in schema.schema["properties"]


def test_learner_processes_log_file(db):
    """ApiArmorSchemaLearner tails a log file with body samples."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        entries = [
            {"method": "POST", "path": "/api/v1/users", "body_sample": {"name": "x"}},
            {"method": "GET", "path": "/api/v1/users", "body_sample": {}},
        ]
        for e in entries:
            f.write(json.dumps(e) + "\n")
        f.flush()
        log_path = f.name

    try:
        learner = ApiArmorSchemaLearner(log_path=log_path, sample_interval=0.1)
        learner._process_new_lines()
        schemas = db.query(ApiSchema).order_by(ApiSchema.id).all()
        assert len(schemas) == 2
        assert schemas[0].method == "POST"
        assert schemas[1].method == "GET"
    finally:
        os.unlink(log_path)


def test_prune_learned_schemas(db):
    """prune_learned_schemas removes old learned schemas."""
    from datetime import datetime, timedelta, timezone

    old = ApiSchema(
        name="old",
        method="POST",
        path="/old",
        schema={},
        source="learned",
        enabled=True,
        created_at=datetime.now(timezone.utc) - timedelta(days=90),
    )
    new = ApiSchema(
        name="new",
        method="POST",
        path="/new",
        schema={},
        source="learned",
        enabled=True,
        created_at=datetime.now(timezone.utc),
    )
    db.add_all([old, new])
    db.commit()

    count = prune_learned_schemas(db, retention_days=30)
    db.commit()

    assert count == 1
    remaining = db.query(ApiSchema).all()
    assert len(remaining) == 1
    assert remaining[0].name == "new"
