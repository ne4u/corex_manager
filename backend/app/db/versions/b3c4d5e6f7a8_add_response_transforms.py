"""add response_transforms

Revision ID: b3c4d5e6f7a8
Revises: 96c2928dd4bc
Create Date: 2026-08-13 19:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b3c4d5e6f7a8'
down_revision: Union[str, Sequence[str], None] = '96c2928dd4bc'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create response_transforms table for response body rewrite/inject/mask rules."""
    op.create_table('response_transforms',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('backend_id', sa.Integer(), nullable=True),
        sa.Column('backend_ids', sa.JSON(), nullable=True),
        sa.Column('priority', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=True),
        sa.Column('transform_type', sa.String(), nullable=False),
        sa.Column('content_types', sa.String(), nullable=True),
        sa.Column('max_body_size', sa.Integer(), nullable=True),
        sa.Column('find_regex', sa.Text(), nullable=True),
        sa.Column('replace_string', sa.Text(), nullable=True),
        sa.Column('inject_string', sa.Text(), nullable=True),
        sa.Column('inject_position', sa.String(), nullable=True),
        sa.Column('mask_mode', sa.String(), nullable=True),
        sa.Column('detector', sa.String(), nullable=True),
        sa.Column('token_mode', sa.String(), nullable=True),
        sa.Column('token_prefix', sa.String(), nullable=True),
        sa.Column('token_ttl', sa.Integer(), nullable=True),
        sa.Column('encrypt_key_env', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['backend_id'], ['backends.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_response_transforms_id'), 'response_transforms', ['id'], unique=False)
    op.create_index(op.f('ix_response_transforms_name'), 'response_transforms', ['name'], unique=True)
    op.create_index(op.f('ix_response_transforms_priority'), 'response_transforms', ['priority'], unique=False)


def downgrade() -> None:
    """Drop response_transforms table."""
    op.drop_index(op.f('ix_response_transforms_priority'), table_name='response_transforms')
    op.drop_index(op.f('ix_response_transforms_name'), table_name='response_transforms')
    op.drop_index(op.f('ix_response_transforms_id'), table_name='response_transforms')
    op.drop_table('response_transforms')
