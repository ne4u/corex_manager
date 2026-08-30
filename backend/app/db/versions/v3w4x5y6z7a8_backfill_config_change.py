"""backfill_config_change

Revision ID: v3w4x5y6z7a8
Revises: u2v3w4x5y6z7
Create Date: 2026-08-29 02:00:00.000000

Backfills the config_change column for existing audit_events rows that were
created before the column existed. The schema migration (u2v3w4x5y6z7) set
config_change=true for all existing rows, but some of those rows represent
non-config-affecting actions (validate_risk_rule, login, theme changes, etc.)
that should have config_change=false so they don't appear in the audit log
"Pending Changes" section.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'v3w4x5y6z7a8'
down_revision: Union[str, Sequence[str], None] = 'u2v3w4x5y6z7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Backfill config_change for existing audit events.

    Uses the is_config_change() helper from the audit service to determine
    the correct value for each event based on its method and path. Events
    that don't affect generated config (validation, auth, theme, user CRUD,
    captcha keys, etc.) are updated to config_change=false.
    """
    from app.services.audit import is_config_change

    conn = op.get_bind()
    # Fetch all events that still have the default config_change=true.
    # We only need id, method, and path to determine the correct value.
    rows = conn.execute(
        sa.text("SELECT id, method, path FROM audit_events WHERE config_change = true")
    ).fetchall()

    updated = 0
    for row in rows:
        if not is_config_change(row.method, row.path):
            conn.execute(
                sa.text("UPDATE audit_events SET config_change = false WHERE id = :id"),
                {"id": row.id},
            )
            updated += 1

    if updated:
        print(f"[backfill_config_change] Updated {updated} events to config_change=false")


def downgrade() -> None:
    """No downgrade — resetting all events to config_change=true would be
    incorrect since it would re-introduce the original false positives."""
    pass
