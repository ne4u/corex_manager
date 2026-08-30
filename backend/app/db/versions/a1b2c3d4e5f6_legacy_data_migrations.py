"""legacy data migrations

Drops legacy tables that were removed in favor of Security Lists and the
audit_events system, and applies the security_rules.log semantics change
(log now means "record action in request log", default True).

These operations were previously performed by the hand-rolled
_add_missing_columns() helper in core/database.py. They are idempotent and
safe to run on any DB that has reached the baseline revision.

Revision ID: a1b2c3d4e5f6
Revises: 8b9ba74c6828
Create Date: 2026-08-11 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, Sequence[str], None] = '8b9ba74c6828'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Legacy tables removed in favor of Security Lists (NetworkList/AsnList/GeoList)
# and the audit_events system. Safe to drop if they still exist from older
# schema versions.
_LEGACY_TABLES = [
    "audit_logs",        # replaced by audit_events
    "network_acls",      # replaced by NetworkList
    "geo_acls",          # replaced by GeoList
    "asn_acls",          # replaced by AsnList
    "waf_threat_feeds",  # removed (Security Lists successor)
    "waf_threat_ips",    # removed (Security Lists successor)
    "waf_geo_exceptions",  # removed (Security Lists successor)
]


def upgrade() -> None:
    """Drop legacy tables and apply the security_rules.log semantics change."""
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing_tables = set(inspector.get_table_names())

    # Drop legacy tables (idempotent — only drops if present)
    for table_name in _LEGACY_TABLES:
        if table_name in existing_tables:
            op.drop_table(table_name)

    # The semantics of security_rules.log changed: it used to mean "add
    # X-Security-Log header" (default False) and now means "record action in
    # request log" (default True). All existing rules should have logging
    # enabled under the new semantics.
    if "security_rules" in existing_tables:
        # Use TRUE for PostgreSQL boolean compatibility (SQLite also accepts TRUE)
        op.execute("UPDATE security_rules SET log = TRUE")


def downgrade() -> None:
    """Downgrade schema.

    Not reversible: the legacy tables cannot be recreated (their schemas are
    not part of the current model), and the log=1 update cannot be undone
    without knowing the original per-rule values.
    """
    pass
