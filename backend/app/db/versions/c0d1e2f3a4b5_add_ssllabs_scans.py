"""add_ssllabs_scans

Revision ID: c0d1e2f3a4b5
Revises: b9c0d1e2f3a4
Create Date: 2026-08-31 18:01:00.000000

Creates the ``ssllabs_scans`` table for storing SSL Labs assessment
results. Multiple historical scans per (certificate_id, host) are kept;
the ``ssllabs_max_scans_per_host`` setting controls retention.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c0d1e2f3a4b5'
down_revision: Union[str, Sequence[str], None] = 'b9c0d1e2f3a4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create ssllabs_scans table."""
    op.create_table(
        'ssllabs_scans',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('certificate_id', sa.Integer(), nullable=False),
        sa.Column('host', sa.String(), nullable=False),
        sa.Column('status', sa.String(), nullable=False),
        sa.Column('status_message', sa.String(), nullable=True),
        sa.Column('grade', sa.String(), nullable=True),
        sa.Column('report', sa.JSON(), nullable=True),
        sa.Column('start_time', sa.BigInteger(), nullable=True),
        sa.Column('test_time', sa.BigInteger(), nullable=True),
        sa.Column('engine_version', sa.String(), nullable=True),
        sa.Column('criteria_version', sa.String(), nullable=True),
        sa.Column('error', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['certificate_id'], ['certificates.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_ssllabs_scans_id'), 'ssllabs_scans', ['id'], unique=False)
    op.create_index(op.f('ix_ssllabs_scans_certificate_id'), 'ssllabs_scans', ['certificate_id'], unique=False)
    op.create_index(op.f('ix_ssllabs_scans_host'), 'ssllabs_scans', ['host'], unique=False)
    op.create_index('ix_ssllabs_scans_cert_host_created', 'ssllabs_scans', ['certificate_id', 'host', 'created_at'], unique=False)


def downgrade() -> None:
    """Drop ssllabs_scans table."""
    op.drop_index('ix_ssllabs_scans_cert_host_created', table_name='ssllabs_scans')
    op.drop_index(op.f('ix_ssllabs_scans_host'), table_name='ssllabs_scans')
    op.drop_index(op.f('ix_ssllabs_scans_certificate_id'), table_name='ssllabs_scans')
    op.drop_index(op.f('ix_ssllabs_scans_id'), table_name='ssllabs_scans')
    op.drop_table('ssllabs_scans')
