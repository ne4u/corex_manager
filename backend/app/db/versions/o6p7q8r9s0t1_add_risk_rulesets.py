"""add_risk_rulesets

Revision ID: o6p7q8r9s0t1
Revises: n5o6p7q8r9s0
Create Date: 2026-08-27 00:00:00.000000

Creates the risk_rulesets table and adds a ruleset_id FK to risk_rules.
Existing risk rules are backfilled to a "default" ruleset (id=1).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'o6p7q8r9s0t1'
down_revision: Union[str, Sequence[str], None] = 'n5o6p7q8r9s0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create risk_rulesets table, seed 'default' ruleset, add ruleset_id FK."""
    from sqlalchemy import inspect as sa_inspect

    bind = op.get_bind()
    inspector = sa_inspect(bind)
    existing_tables = inspector.get_table_names()

    # Create risk_rulesets table if it doesn't exist (handles partial migration).
    if 'risk_rulesets' not in existing_tables:
        op.create_table(
            'risk_rulesets',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('name', sa.String(), nullable=False),
            sa.Column('slug', sa.String(), nullable=False),
            sa.Column('description', sa.String(), nullable=True),
            sa.Column('enabled', sa.Boolean(), nullable=True),
            sa.Column('priority', sa.Integer(), nullable=True),
            sa.Column('created_at', sa.DateTime(), nullable=True),
            sa.Column('updated_at', sa.DateTime(), nullable=True),
            sa.PrimaryKeyConstraint('id'),
            sa.UniqueConstraint('slug'),
        )
        op.create_index('ix_risk_rulesets_id', 'risk_rulesets', ['id'])
        op.create_index('ix_risk_rulesets_slug', 'risk_rulesets', ['slug'])

    # Seed the "default" ruleset (id=1) if it doesn't already exist.
    # Use true/false literals for PostgreSQL boolean compatibility.
    result = bind.execute(
        sa.text("SELECT 1 FROM risk_rulesets WHERE id = 1")
    ).fetchone()
    if result is None:
        op.execute(
            "INSERT INTO risk_rulesets (id, name, slug, description, enabled, priority, created_at, updated_at) "
            "VALUES (1, 'Default', 'default', 'Default risk scoring ruleset', true, 0, NOW(), NOW())"
        )

    # Check if ruleset_id column already exists on risk_rules (partial migration).
    if 'risk_rules' in existing_tables:
        risk_columns = [c['name'] for c in inspector.get_columns('risk_rules')]
    else:
        risk_columns = []

    if 'ruleset_id' not in risk_columns:
        # Add ruleset_id column to risk_rules (nullable initially for backfill).
        # Also drop the old index on name (we're moving to a composite
        # unique constraint on (name, ruleset_id) so the same rule name can
        # exist in different rulesets).
        with op.batch_alter_table('risk_rules', schema=None) as batch_op:
            # Drop index if it exists (may not exist on all DBs)
            existing_indexes = [i['name'] for i in inspector.get_indexes('risk_rules')]
            if 'ix_risk_rules_name' in existing_indexes:
                batch_op.drop_index('ix_risk_rules_name')
            batch_op.add_column(sa.Column('ruleset_id', sa.Integer(), nullable=True))

        # Backfill: assign all existing rules to the default ruleset.
        op.execute("UPDATE risk_rules SET ruleset_id = 1 WHERE ruleset_id IS NULL")

        # Make the column NOT NULL, add FK + index, and add composite unique constraint.
        with op.batch_alter_table('risk_rules', schema=None) as batch_op:
            batch_op.alter_column('ruleset_id', existing_type=sa.Integer(),
                                  nullable=False)
            batch_op.create_foreign_key(
                'fk_risk_rules_ruleset_id', 'risk_rulesets',
                ['ruleset_id'], ['id'], ondelete='CASCADE',
            )
            batch_op.create_index('ix_risk_rules_ruleset_id', ['ruleset_id'])
            batch_op.create_unique_constraint('uq_risk_rules_name_ruleset', ['name', 'ruleset_id'])


def downgrade() -> None:
    """Drop ruleset_id FK + column, drop risk_rulesets table."""
    with op.batch_alter_table('risk_rules', schema=None) as batch_op:
        batch_op.drop_index('ix_risk_rules_ruleset_id')
        batch_op.drop_constraint('uq_risk_rules_name_ruleset', type_='unique')
        batch_op.drop_constraint('fk_risk_rules_ruleset_id', type_='foreignkey')
        batch_op.drop_column('ruleset_id')
        # Restore the old unique index on name
        batch_op.create_index('ix_risk_rules_name', ['name'], unique=True)

    op.drop_index('ix_risk_rulesets_slug', table_name='risk_rulesets')
    op.drop_index('ix_risk_rulesets_id', table_name='risk_rulesets')
    op.drop_table('risk_rulesets')
