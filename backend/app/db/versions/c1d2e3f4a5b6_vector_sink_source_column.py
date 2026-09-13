"""vector_sink: sources list -> source string (1-to-1 model)

Revision ID: c1d2e3f4a5b6
Revises: b0c1d2e3f4a5
Create Date: 2026-09-13

The Vector log pipeline now uses a 1-to-1 source-per-sink model: each sink
has exactly one source, and sources are auto-enabled when a sink references
them. This replaces the previous model where each sink had a list of sources
and sources were enabled via separate toggles.
"""
from alembic import op
import sqlalchemy as sa

revision = "c1d2e3f4a5b6"
down_revision = "b0c1d2e3f4a5"
branch_labels = None
depends_on = None


def upgrade():
    # Add the new source column (nullable first for migration).
    op.add_column("vector_sinks", sa.Column("source", sa.String(), nullable=True))

    # Migrate data: take the first element of the sources JSON list.
    conn = op.get_bind()
    rows = conn.execute(sa.text("SELECT id, sources FROM vector_sinks")).fetchall()
    for row in rows:
        sources = row[1] if row[1] else []
        if isinstance(sources, str):
            import json
            try:
                sources = json.loads(sources)
            except (json.JSONDecodeError, TypeError):
                sources = []
        first = sources[0] if sources else "corex"
        conn.execute(
            sa.text("UPDATE vector_sinks SET source = :src WHERE id = :id"),
            {"src": first, "id": row[0]},
        )

    # Make the column non-nullable now that all rows have a value.
    op.alter_column("vector_sinks", "source", nullable=False, server_default="corex")

    # Drop the old sources column.
    op.drop_column("vector_sinks", "sources")


def downgrade():
    # Re-add the sources column as a JSON list.
    op.add_column("vector_sinks", sa.Column("sources", sa.JSON(), nullable=True))

    # Migrate data back: wrap the single source in a list.
    conn = op.get_bind()
    rows = conn.execute(sa.text("SELECT id, source FROM vector_sinks")).fetchall()
    for row in rows:
        import json
        sources = json.dumps([row[1]] if row[1] else [])
        conn.execute(
            sa.text("UPDATE vector_sinks SET sources = :srcs WHERE id = :id"),
            {"srcs": sources, "id": row[0]},
        )

    op.alter_column("vector_sinks", "sources", nullable=False, server_default="[]")
    op.drop_column("vector_sinks", "source")
