"""add_detokenize_query_to_response_transforms

Revision ID: a8b9c0d1e2f3
Revises: z7a8b9c0d1e2
Create Date: 2026-08-30 12:00:00.000000

Adds a ``detokenize_query`` boolean column to ``response_transforms``.
When True on a mask-type rule, the Rust resp_transform module also
detokenizes/decrypts tokens in URL query strings on incoming requests
(in addition to the existing request-body detokenization).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a8b9c0d1e2f3'
down_revision: Union[str, Sequence[str], None] = 'z7a8b9c0d1e2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add detokenize_query column to response_transforms."""
    with op.batch_alter_table('response_transforms') as batch_op:
        batch_op.add_column(sa.Column('detokenize_query', sa.Boolean(),
                                      nullable=False, server_default='0'))


def downgrade() -> None:
    """Remove detokenize_query column from response_transforms."""
    with op.batch_alter_table('response_transforms') as batch_op:
        batch_op.drop_column('detokenize_query')
