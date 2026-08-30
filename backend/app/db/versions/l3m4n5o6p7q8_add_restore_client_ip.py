"""add_restore_client_ip

Revision ID: l3m4n5o6p7q8
Revises: 1bd52a98a1cb
Create Date: 2026-08-20 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'l3m4n5o6p7q8'
down_revision: Union[str, Sequence[str], None] = '1bd52a98a1cb'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add restore_client_ip and client_ip_header columns to backends.

    restore_client_ip toggles per-pool client-IP restoration from a header
    (e.g. X-Forwarded-For) for CDN-backed pools. client_ip_header names the
    header to extract the real client IP from. Both default so existing pools
    behave exactly as before (toggle off, default header).
    """
    from sqlalchemy import inspect as sa_inspect

    bind = op.get_bind()
    inspector = sa_inspect(bind)
    existing_cols = [c['name'] for c in inspector.get_columns('backends')]

    with op.batch_alter_table('backends', schema=None) as batch_op:
        if 'restore_client_ip' not in existing_cols:
            batch_op.add_column(
                sa.Column('restore_client_ip', sa.Boolean(), nullable=True, server_default=sa.text('false'))
            )
        if 'client_ip_header' not in existing_cols:
            batch_op.add_column(
                sa.Column('client_ip_header', sa.String(), nullable=True, server_default='X-Forwarded-For')
            )


def downgrade() -> None:
    """Remove restore_client_ip and client_ip_header columns from backends."""
    with op.batch_alter_table('backends', schema=None) as batch_op:
        batch_op.drop_column('client_ip_header')
        batch_op.drop_column('restore_client_ip')
