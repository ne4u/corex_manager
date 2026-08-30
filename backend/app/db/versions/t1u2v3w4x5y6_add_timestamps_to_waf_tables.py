"""add_timestamps_to_waf_tables

Revision ID: t1u2v3w4x5y6
Revises: s0t1u2v3w4x5
Create Date: 2026-08-28 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 't1u2v3w4x5y6'
down_revision: Union[str, Sequence[str], None] = 's0t1u2v3w4x5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add updated_at to waf_rules and created_at/updated_at to waf_exceptions.

    waf_rules already has created_at; we only add updated_at.
    waf_exceptions has neither; we add both. All default to now() so
    existing rows are backfilled.
    """
    with op.batch_alter_table('waf_rules', schema=None) as batch_op:
        batch_op.add_column(
            sa.Column('updated_at', sa.DateTime(), nullable=True, server_default=sa.func.now())
        )

    with op.batch_alter_table('waf_exceptions', schema=None) as batch_op:
        batch_op.add_column(
            sa.Column('created_at', sa.DateTime(), nullable=True, server_default=sa.func.now())
        )
        batch_op.add_column(
            sa.Column('updated_at', sa.DateTime(), nullable=True, server_default=sa.func.now())
        )


def downgrade() -> None:
    """Remove the timestamp columns added by this migration."""
    with op.batch_alter_table('waf_exceptions', schema=None) as batch_op:
        batch_op.drop_column('updated_at')
        batch_op.drop_column('created_at')

    with op.batch_alter_table('waf_rules', schema=None) as batch_op:
        batch_op.drop_column('updated_at')
