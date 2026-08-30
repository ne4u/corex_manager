"""remove backend persist

Revision ID: ed2234cbf245
Revises: f766f9ff8f72
Create Date: 2026-08-12 13:01:07.708511

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'ed2234cbf245'
down_revision: Union[str, Sequence[str], None] = 'f766f9ff8f72'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Drop the unused 'persist' column from the backends table."""
    with op.batch_alter_table('backends', schema=None) as batch_op:
        batch_op.drop_column('persist')


def downgrade() -> None:
    """Add the 'persist' column back to the backends table."""
    with op.batch_alter_table('backends', schema=None) as batch_op:
        batch_op.add_column(sa.Column('persist', sa.Boolean(), nullable=True))
