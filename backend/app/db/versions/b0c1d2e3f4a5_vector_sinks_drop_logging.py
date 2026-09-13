"""Add vector_sinks table; drop log_destinations and logged_fields.

The Logging page's Log Destinations / Logged Fields management is replaced by
the Vector log pipeline (sources: coreX/WAF/MCP; sinks: S3, Azure, Datadog,
Elasticsearch, HTTP, New Relic, Splunk). HAProxy's stdout log target is now
always emitted, and a managed `log tcp+<vector>:601` line is generated when
the coreX source is enabled.

Revision ID: b0c1d2e3f4a5
Revises: b5c6d7e8f9a0
Create Date: 2026-09-18 00:00:00

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "b0c1d2e3f4a5"
down_revision = "b5c6d7e8f9a0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "vector_sinks",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("type", sa.String(), nullable=False),
        sa.Column("sources", sa.JSON(), nullable=False),
        sa.Column("options", sa.JSON(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_vector_sinks_id"), "vector_sinks", ["id"], unique=False)
    op.create_index(op.f("ix_vector_sinks_name"), "vector_sinks", ["name"], unique=True)

    op.drop_index(op.f("ix_logged_fields_id"), table_name="logged_fields")
    op.drop_table("logged_fields")
    op.drop_index(op.f("ix_log_destinations_name"), table_name="log_destinations")
    op.drop_index(op.f("ix_log_destinations_id"), table_name="log_destinations")
    op.drop_table("log_destinations")


def downgrade() -> None:
    op.create_table(
        "log_destinations",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("listener_id", sa.Integer(), nullable=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("target", sa.String(), nullable=False),
        sa.Column("facility", sa.String(), nullable=True),
        sa.Column("level", sa.String(), nullable=True),
        sa.Column("format", sa.String(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=True),
        sa.ForeignKeyConstraint(["listener_id"], ["listeners.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_log_destinations_id"), "log_destinations", ["id"], unique=False)
    op.create_index(op.f("ix_log_destinations_name"), "log_destinations", ["name"], unique=True)
    op.create_table(
        "logged_fields",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("listener_id", sa.Integer(), nullable=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("field", sa.String(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=True),
        sa.ForeignKeyConstraint(["listener_id"], ["listeners.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_logged_fields_id"), "logged_fields", ["id"], unique=False)

    op.drop_index(op.f("ix_vector_sinks_name"), table_name="vector_sinks")
    op.drop_index(op.f("ix_vector_sinks_id"), table_name="vector_sinks")
    op.drop_table("vector_sinks")
