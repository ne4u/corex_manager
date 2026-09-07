"""add_ignored_to_page_protect_scripts

Revision ID: f1a2b3c4d5e6
Revises: e3f4a5b6c7d8
Create Date: 2026-09-07 00:00:00.000000

Adds an ``ignored`` boolean column to ``page_protect_scripts`` so users can
mark dynamic, authenticated, or otherwise legitimate assets that should not be
periodically hashed or included in CSP policy recommendations.

Existing rows are backfilled to ``false``.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f1a2b3c4d5e6'
down_revision: Union[str, Sequence[str], None] = 'e3f4a5b6c7d8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add ignored column to page_protect_scripts and backfill existing rows."""
    with op.batch_alter_table('page_protect_scripts') as batch_op:
        batch_op.add_column(sa.Column('ignored', sa.Boolean(), nullable=True))

    # Existing rows default to not ignored.
    op.execute("UPDATE page_protect_scripts SET ignored = false WHERE ignored IS NULL")


def downgrade() -> None:
    """Remove ignored column from page_protect_scripts."""
    with op.batch_alter_table('page_protect_scripts') as batch_op:
        batch_op.drop_column('ignored')
