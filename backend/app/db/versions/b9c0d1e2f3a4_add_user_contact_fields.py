"""add_user_contact_fields

Revision ID: b9c0d1e2f3a4
Revises: a8b9c0d1e2f3
Create Date: 2026-08-31 18:00:00.000000

Adds ``email``, ``first_name``, ``last_name``, and ``organization`` columns
to the ``users`` table. These are the contact fields required by the SSL Labs
v4 API registration endpoint.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b9c0d1e2f3a4'
down_revision: Union[str, Sequence[str], None] = 'a8b9c0d1e2f3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add contact fields to users table."""
    with op.batch_alter_table('users') as batch_op:
        batch_op.add_column(sa.Column('email', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('first_name', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('last_name', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('organization', sa.String(), nullable=True))


def downgrade() -> None:
    """Drop contact fields from users table."""
    with op.batch_alter_table('users') as batch_op:
        batch_op.drop_column('organization')
        batch_op.drop_column('last_name')
        batch_op.drop_column('first_name')
        batch_op.drop_column('email')
