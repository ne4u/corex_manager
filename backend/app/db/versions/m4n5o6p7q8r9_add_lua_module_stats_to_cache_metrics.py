"""add_lua_module_stats_to_cache_metrics

Revision ID: m4n5o6p7q8r9
Revises: l3m4n5o6p7q8
Create Date: 2026-08-22 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'm4n5o6p7q8r9'
down_revision: Union[str, Sequence[str], None] = 'l3m4n5o6p7q8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add lua_module_stats JSON column to cache_metric_snapshots.

    Stores cumulative bytes-saved counters from the Rust Lua modules
    (brotli/zstd compression and WebP image conversion), queried via
    HAProxy socket CLI commands registered by the modules.
    """
    from sqlalchemy import inspect as sa_inspect

    bind = op.get_bind()
    inspector = sa_inspect(bind)
    existing_cols = [c['name'] for c in inspector.get_columns('cache_metric_snapshots')]

    if 'lua_module_stats' not in existing_cols:
        with op.batch_alter_table('cache_metric_snapshots', schema=None) as batch_op:
            batch_op.add_column(sa.Column('lua_module_stats', sa.JSON(), nullable=True))


def downgrade() -> None:
    """Remove lua_module_stats column from cache_metric_snapshots."""
    with op.batch_alter_table('cache_metric_snapshots', schema=None) as batch_op:
        batch_op.drop_column('lua_module_stats')
