"""add_content_to_page_protect_scripts

Revision ID: a2b3c4d5e6f7
Revises: f1a2b3c4d5e6
Create Date: 2026-09-07 00:00:00.000000

Adds a ``content`` text column to ``page_protect_scripts`` so the hasher can
persist the fetched body of an asset when its hash changes or no prior content
exists. The stored content can be retrieved by an AI agent via the MCP layer
or by a user for manual analysis.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a2b3c4d5e6f7'
down_revision: Union[str, Sequence[str], None] = 'f1a2b3c4d5e6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add content column to page_protect_scripts."""
    with op.batch_alter_table('page_protect_scripts') as batch_op:
        batch_op.add_column(sa.Column('content', sa.Text(), nullable=True))


def downgrade() -> None:
    """Remove content column from page_protect_scripts."""
    with op.batch_alter_table('page_protect_scripts') as batch_op:
        batch_op.drop_column('content')
