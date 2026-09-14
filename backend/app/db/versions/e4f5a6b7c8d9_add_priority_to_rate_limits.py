"""add_priority_to_rate_limits

Revision ID: e4f5a6b7c8d9
Revises: c1d2e3f4a5b6
Create Date: 2026-09-19 00:00:00.000000

Adds a ``priority`` column to ``rate_limits`` so rules can be ordered via
drag-and-drop in the UI. Emission order in haproxy.cfg follows priority;
existing rows keep their current (id) order via the backfill.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e4f5a6b7c8d9"
down_revision: str | Sequence[str] | None = "c1d2e3f4a5b6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add priority column to rate_limits, preserving existing row order."""
    with op.batch_alter_table("rate_limits", schema=None) as batch_op:
        batch_op.add_column(sa.Column("priority", sa.Integer(), nullable=False, server_default="0"))
        batch_op.create_index("ix_rate_limits_priority", ["priority"])

    # Backfill: preserve the de-facto creation order rules had before ordering existed.
    op.execute("UPDATE rate_limits SET priority = id")


def downgrade() -> None:
    """Remove priority column from rate_limits."""
    with op.batch_alter_table("rate_limits", schema=None) as batch_op:
        batch_op.drop_index("ix_rate_limits_priority")
        batch_op.drop_column("priority")
