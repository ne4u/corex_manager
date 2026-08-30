"""add_risk_rules

Revision ID: n5o6p7q8r9s0
Revises: m4n5o6p7q8r9
Create Date: 2026-08-26 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'n5o6p7q8r9s0'
down_revision: Union[str, Sequence[str], None] = 'm4n5o6p7q8r9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create risk_rules table."""
    from sqlalchemy import inspect as sa_inspect

    bind = op.get_bind()
    inspector = sa_inspect(bind)
    existing_tables = inspector.get_table_names()

    if 'risk_rules' not in existing_tables:
        op.create_table(
            'risk_rules',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('name', sa.String(), nullable=False),
            sa.Column('enabled', sa.Boolean(), nullable=True),
            sa.Column('priority', sa.Integer(), nullable=False),
            sa.Column('listener_ids', sa.JSON(), nullable=True),
            sa.Column('expression', sa.Text(), nullable=False),
            sa.Column('expression_ast', sa.JSON(), nullable=True),
            sa.Column('points', sa.Integer(), nullable=False),
            sa.Column('category', sa.String(), nullable=True),
            sa.Column('log', sa.Boolean(), nullable=True),
            sa.Column('created_at', sa.DateTime(), nullable=True),
            sa.Column('updated_at', sa.DateTime(), nullable=True),
            sa.PrimaryKeyConstraint('id'),
        )
        op.create_index('ix_risk_rules_id', 'risk_rules', ['id'])
        op.create_index('ix_risk_rules_name', 'risk_rules', ['name'])
        op.create_index('ix_risk_rules_priority', 'risk_rules', ['priority'])


def downgrade() -> None:
    """Drop risk_rules table."""
    op.drop_index('ix_risk_rules_priority', table_name='risk_rules')
    op.drop_index('ix_risk_rules_name', table_name='risk_rules')
    op.drop_index('ix_risk_rules_id', table_name='risk_rules')
    op.drop_table('risk_rules')
