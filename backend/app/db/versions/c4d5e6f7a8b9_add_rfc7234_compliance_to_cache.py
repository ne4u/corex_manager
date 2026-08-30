"""add_rfc7234_compliance_to_cache

Revision ID: c4d5e6f7a8b9
Revises: b3c4d5e6f7a8
Create Date: 2026-08-14 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c4d5e6f7a8b9'
down_revision: Union[str, Sequence[str], None] = 'b3c4d5e6f7a8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add haproxy_rfc7234_compliance column to cache_configs.

    Defaults to False (CDN-style behavior): request-side Cache-Control/Pragma
    headers are stripped before the memory cache lookup so a single client's
    "no-cache" reload does not bypass the shared cache for everyone. Existing
    rows inherit the server default of False.
    """
    with op.batch_alter_table('cache_configs', schema=None) as batch_op:
        batch_op.add_column(
            sa.Column('haproxy_rfc7234_compliance', sa.Boolean(), nullable=True, server_default=sa.text('false'))
        )


def downgrade() -> None:
    """Remove haproxy_rfc7234_compliance column from cache_configs."""
    with op.batch_alter_table('cache_configs', schema=None) as batch_op:
        batch_op.drop_column('haproxy_rfc7234_compliance')
