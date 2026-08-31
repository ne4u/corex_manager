"""add_password_and_login_timestamps

Revision ID: d1e2f3a4b5c6
Revises: c0d1e2f3a4b5
Create Date: 2026-08-31 00:00:00.000000

Adds ``last_login_at`` and ``password_changed_at`` columns to the ``users``
table to support password rotation enforcement and a "last login" column in
the Users admin tab. Existing users are backfilled so that
``password_changed_at = created_at`` (they are not forced to change their
password immediately on upgrade; they expire only after the configured
rotation period elapses).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd1e2f3a4b5c6'
down_revision: Union[str, Sequence[str], None] = 'c0d1e2f3a4b5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add last_login_at and password_changed_at columns to users."""
    with op.batch_alter_table('users') as batch_op:
        batch_op.add_column(sa.Column('last_login_at', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('password_changed_at', sa.DateTime(), nullable=True))

    # Backfill: existing users are treated as if they set their password at
    # account creation time, so they are not immediately prompted to change it.
    op.execute(
        "UPDATE users SET password_changed_at = created_at "
        "WHERE password_changed_at IS NULL AND created_at IS NOT NULL"
    )


def downgrade() -> None:
    """Remove last_login_at and password_changed_at columns from users."""
    with op.batch_alter_table('users') as batch_op:
        batch_op.drop_column('password_changed_at')
        batch_op.drop_column('last_login_at')
