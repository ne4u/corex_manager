"""add_datetime_format_and_timezone_to_user_preferences

Revision ID: x5y6z7a8b9c0
Revises: w4x5y6z7a8b9
Create Date: 2026-08-29 04:00:00.000000

Adds ``datetime_format`` and ``timezone`` columns to ``user_preferences``
so each user can choose how dates/times are displayed in the UI. The
backend stores/sends UTC; the frontend converts per the user's preference.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'x5y6z7a8b9c0'
down_revision: Union[str, Sequence[str], None] = 'w4x5y6z7a8b9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add datetime_format and timezone columns to user_preferences."""
    with op.batch_alter_table('user_preferences') as batch_op:
        batch_op.add_column(sa.Column('datetime_format', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('timezone', sa.String(), nullable=True))


def downgrade() -> None:
    """Drop the datetime_format and timezone columns from user_preferences."""
    with op.batch_alter_table('user_preferences') as batch_op:
        batch_op.drop_column('timezone')
        batch_op.drop_column('datetime_format')
