"""add_rate_key_to_rate_limits

Revision ID: d5e6f7a8b9c0
Revises: c4d5e6f7a8b9
Create Date: 2026-08-15 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd5e6f7a8b9c0'
down_revision: Union[str, Sequence[str], None] = 'c4d5e6f7a8b9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add rate_key and rate_header columns to rate_limits.

    rate_key controls the counter dimension (src, user_id, header, path, asn).
    rate_header specifies the header name when rate_key is user_id or header.
    Both default to src / NULL so existing rows behave exactly as before.
    """
    with op.batch_alter_table('rate_limits', schema=None) as batch_op:
        batch_op.add_column(
            sa.Column('rate_key', sa.String(), nullable=True, server_default='src')
        )
        batch_op.add_column(
            sa.Column('rate_header', sa.String(), nullable=True)
        )


def downgrade() -> None:
    """Remove rate_key and rate_header columns from rate_limits."""
    with op.batch_alter_table('rate_limits', schema=None) as batch_op:
        batch_op.drop_column('rate_header')
        batch_op.drop_column('rate_key')
