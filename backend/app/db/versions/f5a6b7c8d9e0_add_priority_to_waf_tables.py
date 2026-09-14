"""add_priority_to_waf_tables

Revision ID: f5a6b7c8d9e0
Revises: e4f5a6b7c8d9
Create Date: 2026-09-19 00:00:00.000000

Adds ``priority`` columns to ``waf_rules`` and ``waf_exceptions`` so both
can be ordered via drag-and-drop in the UI. WAF rule order is semantic:
``_app_directives`` merges rules with tuning parameters taken from the
first rule, and the HAProxy emitter uses the first matching rule's rate
settings. Exception order controls emission order of the generated
SecRule/SecRuleRemove* lines. Existing rows keep their current (id)
order via the backfill.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f5a6b7c8d9e0"
down_revision: str | Sequence[str] | None = "e4f5a6b7c8d9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add priority columns to waf_rules and waf_exceptions."""
    with op.batch_alter_table("waf_rules", schema=None) as batch_op:
        batch_op.add_column(sa.Column("priority", sa.Integer(), nullable=False, server_default="0"))
        batch_op.create_index("ix_waf_rules_priority", ["priority"])

    with op.batch_alter_table("waf_exceptions", schema=None) as batch_op:
        batch_op.add_column(sa.Column("priority", sa.Integer(), nullable=False, server_default="0"))
        batch_op.create_index("ix_waf_exceptions_priority", ["priority"])

    # Backfill: preserve the de-facto creation order rows had before ordering existed.
    op.execute("UPDATE waf_rules SET priority = id")
    op.execute("UPDATE waf_exceptions SET priority = id")


def downgrade() -> None:
    """Remove priority columns from waf_rules and waf_exceptions."""
    with op.batch_alter_table("waf_exceptions", schema=None) as batch_op:
        batch_op.drop_index("ix_waf_exceptions_priority")
        batch_op.drop_column("priority")

    with op.batch_alter_table("waf_rules", schema=None) as batch_op:
        batch_op.drop_index("ix_waf_rules_priority")
        batch_op.drop_column("priority")
