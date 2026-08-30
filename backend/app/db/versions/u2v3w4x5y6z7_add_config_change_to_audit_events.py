"""add_config_change_to_audit_events

Revision ID: u2v3w4x5y6z7
Revises: t1u2v3w4x5y6
Create Date: 2026-08-29 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'u2v3w4x5y6z7'
down_revision: Union[str, Sequence[str], None] = 't1u2v3w4x5y6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add config_change boolean column to audit_events.

    Defaults to True so existing rows are treated as config-affecting,
    preserving backward compatibility. New events get the correct value
    from the audit middleware based on the request path.

    Uses server_default=sa.text('true') (not integer 1) because PostgreSQL
    requires a boolean literal for BOOLEAN columns; SQLite also accepts
    'true' as a boolean default.
    """
    with op.batch_alter_table('audit_events', schema=None) as batch_op:
        batch_op.add_column(
            sa.Column('config_change', sa.Boolean(), nullable=False, server_default=sa.text('true'))
        )


def downgrade() -> None:
    """Remove the config_change column."""
    with op.batch_alter_table('audit_events', schema=None) as batch_op:
        batch_op.drop_column('config_change')
