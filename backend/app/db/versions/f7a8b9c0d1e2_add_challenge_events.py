"""add challenge_events table

Revision ID: f7a8b9c0d1e2
Revises: e6f7a8b9c0d1
Create Date: 2026-08-16 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f7a8b9c0d1e2'
down_revision: Union[str, Sequence[str], None] = 'e6f7a8b9c0d1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'challenge_events',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('rule_type', sa.String(), nullable=False),
        sa.Column('rule_id', sa.Integer(), nullable=True),
        sa.Column('rule_name', sa.String(), nullable=True),
        sa.Column('listener_id', sa.Integer(), nullable=True),
        sa.Column('client_ip', sa.String(), nullable=True),
        sa.Column('event_type', sa.String(), nullable=False),
    )
    op.create_index('ix_challenge_events_id', 'challenge_events', ['id'])
    op.create_index('ix_challenge_events_created_at', 'challenge_events', ['created_at'])


def downgrade() -> None:
    op.drop_index('ix_challenge_events_created_at', table_name='challenge_events')
    op.drop_index('ix_challenge_events_id', table_name='challenge_events')
    op.drop_table('challenge_events')
