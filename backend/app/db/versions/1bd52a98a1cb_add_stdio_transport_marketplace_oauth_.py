"""add stdio transport marketplace oauth fields to mcp_servers

Revision ID: 1bd52a98a1cb
Revises: k2f3a4b5c6d7
Create Date: 2026-08-19 14:46:57.853493

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '1bd52a98a1cb'
down_revision: Union[str, Sequence[str], None] = 'k2f3a4b5c6d7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Add new columns to mcp_servers
    with op.batch_alter_table('mcp_servers', schema=None) as batch_op:
        batch_op.add_column(sa.Column('transport_type', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('command', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('args_json', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('env_vars_json', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('package_manager', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('source_package_name', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('installed_version', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('installer_user_id', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('oauth_enabled', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('oauth_client_id', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('oauth_client_secret_enc', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('oauth_scopes', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('oauth_auth_status', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('oauth_token_enc', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('oauth_refresh_token_enc', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('oauth_token_expires_at', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('oauth_auth_server_metadata_url', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('oauth_protected_resource_metadata_url', sa.String(), nullable=True))
        batch_op.alter_column('url', existing_type=sa.String(), nullable=True)

    # Set defaults for existing rows
    op.execute(
        "UPDATE mcp_servers SET transport_type = 'streamable_http', "
        "oauth_enabled = FALSE, oauth_auth_status = 'not_configured' "
        "WHERE transport_type IS NULL"
    )

    # Create mcp_installations table
    op.create_table('mcp_installations',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('server_id', sa.Integer(), nullable=False),
        sa.Column('package_manager', sa.String(), nullable=False),
        sa.Column('package_name', sa.String(), nullable=False),
        sa.Column('version', sa.String(), nullable=True),
        sa.Column('status', sa.String(), nullable=True),
        sa.Column('output', sa.Text(), nullable=True),
        sa.Column('error', sa.Text(), nullable=True),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['server_id'], ['mcp_servers.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('mcp_installations', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_mcp_installations_id'), ['id'], unique=False)
        batch_op.create_index(batch_op.f('ix_mcp_installations_server_id'), ['server_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    # Drop mcp_installations table
    with op.batch_alter_table('mcp_installations', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_mcp_installations_server_id'))
        batch_op.drop_index(batch_op.f('ix_mcp_installations_id'))
    op.drop_table('mcp_installations')

    # Remove new columns from mcp_servers
    with op.batch_alter_table('mcp_servers', schema=None) as batch_op:
        batch_op.alter_column('url', existing_type=sa.String(), nullable=False)
        batch_op.drop_column('oauth_protected_resource_metadata_url')
        batch_op.drop_column('oauth_auth_server_metadata_url')
        batch_op.drop_column('oauth_token_expires_at')
        batch_op.drop_column('oauth_refresh_token_enc')
        batch_op.drop_column('oauth_token_enc')
        batch_op.drop_column('oauth_auth_status')
        batch_op.drop_column('oauth_scopes')
        batch_op.drop_column('oauth_client_secret_enc')
        batch_op.drop_column('oauth_client_id')
        batch_op.drop_column('oauth_enabled')
        batch_op.drop_column('installer_user_id')
        batch_op.drop_column('installed_version')
        batch_op.drop_column('source_package_name')
        batch_op.drop_column('package_manager')
        batch_op.drop_column('env_vars_json')
        batch_op.drop_column('args_json')
        batch_op.drop_column('command')
        batch_op.drop_column('transport_type')
