"""add_hit_multiplier_to_rulesets

Revision ID: p7q8r9s0t1u2
Revises: o6p7q8r9s0t1
Create Date: 2026-08-27 00:00:00.000000

Adds hit_multiplier_enabled and density_weight columns to risk_rulesets
for density-based score amplification:
  final = raw_score + floor(hit_density * density_weight), capped at 99
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'p7q8r9s0t1u2'
down_revision: Union[str, Sequence[str], None] = 'o6p7q8r9s0t1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add hit_multiplier_enabled and density_weight to risk_rulesets."""
    from sqlalchemy import inspect as sa_inspect

    bind = op.get_bind()
    inspector = sa_inspect(bind)
    existing_cols = [c['name'] for c in inspector.get_columns('risk_rulesets')]

    with op.batch_alter_table('risk_rulesets', schema=None) as batch_op:
        if 'hit_multiplier_enabled' not in existing_cols:
            batch_op.add_column(
                sa.Column('hit_multiplier_enabled', sa.Boolean(),
                          nullable=True, server_default=sa.text('false'))
            )
        if 'density_weight' not in existing_cols:
            batch_op.add_column(
                sa.Column('density_weight', sa.Float(),
                          nullable=True, server_default=sa.text('0.0'))
            )


def downgrade() -> None:
    """Remove hit_multiplier columns from risk_rulesets."""
    with op.batch_alter_table('risk_rulesets', schema=None) as batch_op:
        batch_op.drop_column('density_weight')
        batch_op.drop_column('hit_multiplier_enabled')
