"""converge_captcha_to_challenge

Revision ID: e6f7a8b9c0d1
Revises: d5e6f7a8b9c0
Create Date: 2026-08-15 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = 'e6f7a8b9c0d1'
down_revision: Union[str, Sequence[str], None] = 'd5e6f7a8b9c0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Converge the former "captcha" WAF action into "challenge".

    The "challenge" and "captcha" actions produced identical HAProxy config,
    so "captcha" is removed as a distinct action. Existing rows are rewritten
    in-place so generated config is unchanged after the rename. The same
    normalization is applied to rate_action, which also accepted "captcha".
    """
    op.execute(
        "UPDATE waf_rules SET action = 'challenge' WHERE action = 'captcha'"
    )
    op.execute(
        "UPDATE waf_rules SET rate_action = 'challenge' WHERE rate_action = 'captcha'"
    )


def downgrade() -> None:
    """No-op: we cannot know which "challenge" rows were originally "captcha"."""
    pass
