"""drop_density_columns

Revision ID: r9s0t1u2v3w4
Revises: q8r9s0t1u2v3
Create Date: 2026-08-28 02:00:00.000000

Drops hit_multiplier_enabled and density_weight from risk_rulesets.
The density-based amplification feature has been removed in favor of a
simpler model: rules have points (-99 to 99), and the total of matched
rules is clamped to [0, 99] at runtime by the Lua risk_compute action.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'r9s0t1u2v3w4'
down_revision: Union[str, Sequence[str], None] = 'q8r9s0t1u2v3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Drop hit_multiplier_enabled and density_weight from risk_rulesets."""
    from sqlalchemy import inspect as sa_inspect

    bind = op.get_bind()
    inspector = sa_inspect(bind)
    existing_cols = [c['name'] for c in inspector.get_columns('risk_rulesets')]

    with op.batch_alter_table('risk_rulesets', schema=None) as batch_op:
        if 'hit_multiplier_enabled' in existing_cols:
            batch_op.drop_column('hit_multiplier_enabled')
        if 'density_weight' in existing_cols:
            batch_op.drop_column('density_weight')


def downgrade() -> None:
    """Restore hit_multiplier_enabled and density_weight."""
    with op.batch_alter_table('risk_rulesets', schema=None) as batch_op:
        batch_op.add_column(
            sa.Column('hit_multiplier_enabled', sa.Boolean(),
                      nullable=True, server_default=sa.text('false'))
        )
        batch_op.add_column(
            sa.Column('density_weight', sa.Float(),
                      nullable=True, server_default=sa.text('0.0'))
        )
