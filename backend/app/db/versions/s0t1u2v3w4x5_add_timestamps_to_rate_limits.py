"""add_timestamps_to_rate_limits

Revision ID: s0t1u2v3w4x5
Revises: r9s0t1u2v3w4
Create Date: 2026-08-28 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 's0t1u2v3w4x5'
down_revision: Union[str, Sequence[str], None] = 'r9s0t1u2v3w4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add created_at and updated_at columns to rate_limits.

    Both default to the current timestamp so existing rows are backfilled.
    """
    with op.batch_alter_table('rate_limits', schema=None) as batch_op:
        batch_op.add_column(
            sa.Column('created_at', sa.DateTime(), nullable=True, server_default=sa.func.now())
        )
        batch_op.add_column(
            sa.Column('updated_at', sa.DateTime(), nullable=True, server_default=sa.func.now())
        )


def downgrade() -> None:
    """Remove created_at and updated_at columns from rate_limits."""
    with op.batch_alter_table('rate_limits', schema=None) as batch_op:
        batch_op.drop_column('updated_at')
        batch_op.drop_column('created_at')
