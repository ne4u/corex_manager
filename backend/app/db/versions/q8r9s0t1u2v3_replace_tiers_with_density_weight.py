"""replace_tiers_with_density_weight

Revision ID: q8r9s0t1u2v3
Revises: p7q8r9s0t1u2
Create Date: 2026-08-27 02:00:00.000000

Replaces hit_multiplier_tiers (JSON) with density_weight (Float) on
risk_rulesets. The tier-based multiplier was replaced by a simpler
additive formula: final = raw + floor(density * density_weight).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'q8r9s0t1u2v3'
down_revision: Union[str, Sequence[str], None] = 'p7q8r9s0t1u2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add density_weight, drop hit_multiplier_tiers."""
    from sqlalchemy import inspect as sa_inspect

    bind = op.get_bind()
    inspector = sa_inspect(bind)
    existing_cols = [c['name'] for c in inspector.get_columns('risk_rulesets')]

    with op.batch_alter_table('risk_rulesets', schema=None) as batch_op:
        if 'density_weight' not in existing_cols:
            batch_op.add_column(
                sa.Column('density_weight', sa.Float(),
                          nullable=True, server_default=sa.text('0.0'))
            )
        if 'hit_multiplier_tiers' in existing_cols:
            batch_op.drop_column('hit_multiplier_tiers')


def downgrade() -> None:
    """Restore hit_multiplier_tiers, drop density_weight."""
    with op.batch_alter_table('risk_rulesets', schema=None) as batch_op:
        batch_op.add_column(
            sa.Column('hit_multiplier_tiers', sa.JSON(), nullable=True)
        )
        batch_op.drop_column('density_weight')
