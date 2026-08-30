"""add_last_hash_at_to_page_protect_scripts

Revision ID: z7a8b9c0d1e2
Revises: y6z7a8b9c0d1
Create Date: 2026-08-30 06:00:00.000000

Adds a ``last_hash_at`` column to ``page_protect_scripts`` to track when
the last successful hash was computed. This distinguishes a failed check
(``hash_checked_at`` updated but ``last_hash_at`` is older) from a
successful one (both timestamps match), so the UI can show "Error" status
after a connection failure even if a previous check succeeded.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'z7a8b9c0d1e2'
down_revision: Union[str, Sequence[str], None] = 'y6z7a8b9c0d1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add last_hash_at column to page_protect_scripts."""
    with op.batch_alter_table('page_protect_scripts') as batch_op:
        batch_op.add_column(sa.Column('last_hash_at', sa.DateTime(), nullable=True))

    # Backfill: existing rows with a last_hash already had a successful check,
    # so set last_hash_at = hash_checked_at for those rows.
    op.execute(
        "UPDATE page_protect_scripts SET last_hash_at = hash_checked_at "
        "WHERE last_hash IS NOT NULL AND hash_checked_at IS NOT NULL"
    )


def downgrade() -> None:
    """Remove last_hash_at column from page_protect_scripts."""
    with op.batch_alter_table('page_protect_scripts') as batch_op:
        batch_op.drop_column('last_hash_at')
