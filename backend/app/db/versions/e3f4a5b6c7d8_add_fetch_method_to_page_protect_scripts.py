"""add_fetch_method_to_page_protect_scripts

Revision ID: e3f4a5b6c7d8
Revises: d1e2f3a4b5c6
Create Date: 2026-09-05 06:00:00.000000

Adds ``fetch_method`` and ``last_fetch_method`` columns to
``page_protect_scripts`` so the hasher can fetch assets using the correct
HTTP method. Some third-party endpoints (e.g. Cloudflare's beacon) only
respond to POST.

``fetch_method`` is the user-configured method: ``auto`` (default, probe
GET then POST on 405/403 and persist the working method), ``GET``, or
``POST``. ``last_fetch_method`` records the method used by the last
successful check so the auto-probe cost is one-time.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e3f4a5b6c7d8'
down_revision: Union[str, Sequence[str], None] = 'd1e2f3a4b5c6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add fetch_method and last_fetch_method columns to page_protect_scripts."""
    with op.batch_alter_table('page_protect_scripts') as batch_op:
        batch_op.add_column(sa.Column('fetch_method', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('last_fetch_method', sa.String(), nullable=True))

    # Backfill: existing rows default to 'auto' (probe GET then POST).
    op.execute("UPDATE page_protect_scripts SET fetch_method = 'auto' WHERE fetch_method IS NULL")


def downgrade() -> None:
    """Remove fetch_method and last_fetch_method columns from page_protect_scripts."""
    with op.batch_alter_table('page_protect_scripts') as batch_op:
        batch_op.drop_column('last_fetch_method')
        batch_op.drop_column('fetch_method')
