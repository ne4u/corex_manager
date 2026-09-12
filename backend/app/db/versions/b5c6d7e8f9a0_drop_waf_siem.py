"""drop_waf_siem

Revision ID: b5c6d7e8f9a0
Revises: a9b8c7d6e5f4
Create Date: 2026-09-12 00:00:00.000000

Drops the waf_siem_integrations table and the waf_rules.siem_integration_id
column. The WAF SIEM forwarding feature (SiemForwarder background thread and
/waf/siem-integrations API) has been removed.

Idempotent and safe to run on any DB that has reached the baseline revision.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b5c6d7e8f9a0'
down_revision: Union[str, Sequence[str], None] = 'a9b8c7d6e5f4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Drop siem_integration_id from waf_rules and the waf_siem_integrations table."""
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing_tables = set(inspector.get_table_names())

    # Drop the FK column first so the table drop can't trip on the reference.
    if 'waf_rules' in existing_tables:
        cols = [c['name'] for c in inspector.get_columns('waf_rules')]
        if 'siem_integration_id' in cols:
            with op.batch_alter_table('waf_rules', schema=None) as batch_op:
                batch_op.drop_column('siem_integration_id')

    if 'waf_siem_integrations' in existing_tables:
        op.drop_table('waf_siem_integrations')


def downgrade() -> None:
    """Not reversible: the removed table/column are not part of the current model."""
    pass
