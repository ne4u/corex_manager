"""add request_id to challenge_events

Revision ID: g8b9c0d1e2f3
Revises: f7a8b9c0d1e2
Create Date: 2026-08-16 01:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'g8b9c0d1e2f3'
down_revision: Union[str, None] = 'f7a8b9c0d1e2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('challenge_events', sa.Column('request_id', sa.String(), nullable=True))
    op.create_index('ix_challenge_events_request_id', 'challenge_events', ['request_id'])


def downgrade() -> None:
    op.drop_index('ix_challenge_events_request_id', table_name='challenge_events')
    op.drop_column('challenge_events', 'request_id')
