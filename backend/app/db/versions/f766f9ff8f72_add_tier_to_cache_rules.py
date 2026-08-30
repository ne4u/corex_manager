"""add_tier_to_cache_rules

Revision ID: f766f9ff8f72
Revises: a1b2c3d4e5f6
Create Date: 2026-08-11 13:32:55.647813

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f766f9ff8f72'
down_revision: Union[str, Sequence[str], None] = 'a1b2c3d4e5f6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add tier column to cache_rules table for tier-specific rule application.
    
    Existing rules are set to 'memory' tier since the previous behavior was to
    cache everything in memory by default. Users can update rules or create
    disk-tier rules as needed.
    """
    # Add tier column with temporary default for existing rules
    with op.batch_alter_table('cache_rules', schema=None) as batch_op:
        batch_op.add_column(sa.Column('tier', sa.String(), nullable=False, server_default='memory'))
    
    # Remove server default so new rules must explicitly specify tier
    with op.batch_alter_table('cache_rules', schema=None) as batch_op:
        batch_op.alter_column('tier', server_default=None)


def downgrade() -> None:
    """Remove tier column from cache_rules table."""
    with op.batch_alter_table('cache_rules', schema=None) as batch_op:
        batch_op.drop_column('tier')
