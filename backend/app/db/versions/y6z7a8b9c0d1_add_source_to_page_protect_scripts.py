"""add_source_to_page_protect_scripts

Revision ID: y6z7a8b9c0d1
Revises: x5y6z7a8b9c0
Create Date: 2026-08-29 06:00:00.000000

Adds a ``source`` column to ``page_protect_scripts`` to track how each
entry entered the inventory: ``csp`` (from CSP violation reports),
``manual`` (user-added), or ``beacon`` (from JS beacon injection).
Existing rows are backfilled to ``csp``.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'y6z7a8b9c0d1'
down_revision: Union[str, Sequence[str], None] = 'x5y6z7a8b9c0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add source column to page_protect_scripts and backfill existing rows."""
    with op.batch_alter_table('page_protect_scripts') as batch_op:
        batch_op.add_column(sa.Column('source', sa.String(), nullable=True))

    # Backfill existing rows to 'csp' (they were all detected from CSP reports)
    op.execute("UPDATE page_protect_scripts SET source = 'csp' WHERE source IS NULL")


def downgrade() -> None:
    """Remove source column from page_protect_scripts."""
    with op.batch_alter_table('page_protect_scripts') as batch_op:
        batch_op.drop_column('source')
