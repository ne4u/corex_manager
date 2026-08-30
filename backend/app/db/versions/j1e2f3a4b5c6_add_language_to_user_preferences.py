"""add_language_to_user_preferences

Revision ID: j1e2f3a4b5c6
Revises: i0d1e2f3a4b5
Create Date: 2026-08-17 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'j1e2f3a4b5c6'
down_revision: Union[str, Sequence[str], None] = 'i0d1e2f3a4b5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add language column to user_preferences and backfill 'en' for existing rows."""
    with op.batch_alter_table('user_preferences') as batch_op:
        batch_op.add_column(sa.Column('language', sa.String(), nullable=True))
    # Backfill existing rows with the default language.
    op.execute("UPDATE user_preferences SET language = 'en' WHERE language IS NULL")


def downgrade() -> None:
    """Drop the language column from user_preferences."""
    with op.batch_alter_table('user_preferences') as batch_op:
        batch_op.drop_column('language')
