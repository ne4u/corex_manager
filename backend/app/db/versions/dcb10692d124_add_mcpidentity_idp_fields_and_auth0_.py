"""Add McpIdentity idp fields and auth0 settings

Revision ID: dcb10692d124
Revises: a2b3c4d5e6f7
Create Date: 2026-09-09 10:23:00.296071

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'dcb10692d124'
down_revision: Union[str, Sequence[str], None] = 'a2b3c4d5e6f7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('mcp_identities', schema=None) as batch_op:
        batch_op.add_column(sa.Column('idp_source', sa.String(), nullable=False, server_default='manual'))
        batch_op.add_column(sa.Column('idp_external_id', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('idp_user_info', sa.JSON(), nullable=True))

    # ### end Alembic commands ###


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('mcp_identities', schema=None) as batch_op:
        batch_op.drop_column('idp_user_info')
        batch_op.drop_column('idp_external_id')
        batch_op.drop_column('idp_source')

    # ### end Alembic commands ###
