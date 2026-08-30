"""set_last_applied_at

Revision ID: w4x5y6z7a8b9
Revises: v3w4x5y6z7a8
Create Date: 2026-08-29 03:00:00.000000

Backfills the ``last_applied_at`` setting from the most recent
``ConfigSnapshot.created_at``. This setting is the source of truth for
the audit log's pending-vs-applied determination (replacing the old
``snapshot_id`` stamping approach).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'w4x5y6z7a8b9'
down_revision: Union[str, Sequence[str], None] = 'v3w4x5y6z7a8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Set last_applied_at from the most recent config snapshot."""
    conn = op.get_bind()

    # Check if the settings table exists (it should, but be defensive).
    inspector = sa.inspect(conn)
    tables = set(inspector.get_table_names())
    if "settings" not in tables or "config_snapshots" not in tables:
        return

    # Get the most recent snapshot's created_at
    row = conn.execute(sa.text(
        "SELECT created_at FROM config_snapshots ORDER BY created_at DESC LIMIT 1"
    )).fetchone()

    if not row or not row[0]:
        # No snapshots exist — nothing to backfill.
        return

    created_at = row[0]
    # Format as ISO string (the setting stores string values)
    if hasattr(created_at, 'isoformat'):
        val = created_at.isoformat()
    else:
        val = str(created_at)

    # Insert or update the setting. Use a portable upsert pattern.
    existing = conn.execute(
        sa.text("SELECT id FROM settings WHERE key = 'last_applied_at'")
    ).fetchone()
    if existing:
        conn.execute(
            sa.text("UPDATE settings SET value = :val WHERE key = 'last_applied_at'"),
            {"val": val},
        )
    else:
        conn.execute(
            sa.text("INSERT INTO settings (key, value) VALUES ('last_applied_at', :val)"),
            {"val": val},
        )
    print(f"[set_last_applied_at] Set last_applied_at to {val}")


def downgrade() -> None:
    """Remove the last_applied_at setting."""
    conn = op.get_bind()
    conn.execute(sa.text("DELETE FROM settings WHERE key = 'last_applied_at'"))
