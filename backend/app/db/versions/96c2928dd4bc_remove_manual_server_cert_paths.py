"""remove manual server cert paths

Revision ID: 96c2928dd4bc
Revises: 81c898db0531
Create Date: 2026-08-12 19:21:52.850041

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '96c2928dd4bc'
down_revision: Union[str, Sequence[str], None] = '81c898db0531'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Drop the manual ca_file and client_cert columns from servers."""
    with op.batch_alter_table('servers', schema=None) as batch_op:
        batch_op.drop_column('ca_file')
        batch_op.drop_column('client_cert')


def downgrade() -> None:
    """Re-add the manual ca_file and client_cert columns to servers."""
    with op.batch_alter_table('servers', schema=None) as batch_op:
        batch_op.add_column(sa.Column('ca_file', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('client_cert', sa.String(), nullable=True))
