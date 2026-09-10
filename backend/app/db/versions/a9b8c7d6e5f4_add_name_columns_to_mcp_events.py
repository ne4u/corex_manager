"""Add identity_name, team_name, server_name to mcp_events.

Revision ID: a9b8c7d6e5f4
Revises: a69151848ae7
Create Date: 2026-09-10 22:00:00

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "a9b8c7d6e5f4"
down_revision = "a69151848ae7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("mcp_events", sa.Column("identity_name", sa.String(), nullable=True))
    op.add_column("mcp_events", sa.Column("team_name", sa.String(), nullable=True))
    op.add_column("mcp_events", sa.Column("server_name", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("mcp_events", "server_name")
    op.drop_column("mcp_events", "team_name")
    op.drop_column("mcp_events", "identity_name")
