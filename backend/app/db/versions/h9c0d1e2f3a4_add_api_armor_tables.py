"""add api_armor tables

Revision ID: h9c0d1e2f3a4
Revises: g8b9c0d1e2f3
Create Date: 2026-08-16 12:00:00.000000

Creates the API Armor feature tables:
- openapi_specs: uploaded OpenAPI 3.x specifications for schema validation
- api_schemas: per-endpoint JSON Schemas (from OpenAPI or learned from traffic)
- auth_policies: JWT/API-key validation policies
- api_key_lists / api_key_list_entries: API key collections for proxy-side validation
- api_profiles: learned multi-dimensional behavioral baselines per endpoint
- api_anomalies: requests that deviated from learned profiles

Also adds path_pattern, method, and api_armor_scoped columns to rate_limits
for per-endpoint rate limiting.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'h9c0d1e2f3a4'
down_revision: Union[str, None] = 'g8b9c0d1e2f3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create API Armor tables and extend rate_limits."""

    # --- openapi_specs ---
    op.create_table('openapi_specs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('spec', sa.Text(), nullable=False),
        sa.Column('spec_json', sa.JSON(), nullable=True),
        sa.Column('version', sa.String(), nullable=True),
        sa.Column('listener_ids', sa.JSON(), nullable=True),
        sa.Column('backend_ids', sa.JSON(), nullable=True),
        sa.Column('enabled', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_openapi_specs_id'), 'openapi_specs', ['id'], unique=False)
    op.create_index(op.f('ix_openapi_specs_name'), 'openapi_specs', ['name'], unique=True)

    # --- api_schemas ---
    op.create_table('api_schemas',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('method', sa.String(), nullable=False),
        sa.Column('path', sa.String(), nullable=False),
        sa.Column('schema', sa.JSON(), nullable=False),
        sa.Column('spec_id', sa.Integer(), nullable=True),
        sa.Column('source', sa.String(), nullable=True),
        sa.Column('enabled', sa.Boolean(), nullable=True),
        sa.Column('sample_count', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['spec_id'], ['openapi_specs.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_api_schemas_id'), 'api_schemas', ['id'], unique=False)

    # --- api_key_lists ---
    op.create_table('api_key_lists',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('description', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_api_key_lists_id'), 'api_key_lists', ['id'], unique=False)
    op.create_index(op.f('ix_api_key_lists_name'), 'api_key_lists', ['name'], unique=True)

    # --- api_key_list_entries ---
    op.create_table('api_key_list_entries',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('list_id', sa.Integer(), nullable=False),
        sa.Column('value', sa.String(), nullable=False),
        sa.Column('note', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['list_id'], ['api_key_lists.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_api_key_list_entries_id'), 'api_key_list_entries', ['id'], unique=False)

    # --- auth_policies ---
    op.create_table('auth_policies',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('listener_ids', sa.JSON(), nullable=True),
        sa.Column('backend_ids', sa.JSON(), nullable=True),
        sa.Column('auth_type', sa.String(), nullable=True),
        sa.Column('jwt_algorithm', sa.String(), nullable=True),
        sa.Column('jwt_secret_env', sa.String(), nullable=True),
        sa.Column('jwt_jwks_url', sa.String(), nullable=True),
        sa.Column('jwt_issuer', sa.String(), nullable=True),
        sa.Column('jwt_audience', sa.String(), nullable=True),
        sa.Column('jwt_claim_headers', sa.JSON(), nullable=True),
        sa.Column('api_key_header', sa.String(), nullable=True),
        sa.Column('api_key_list_id', sa.Integer(), nullable=True),
        sa.Column('on_failure', sa.String(), nullable=True),
        sa.Column('enabled', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['api_key_list_id'], ['api_key_lists.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_auth_policies_id'), 'auth_policies', ['id'], unique=False)
    op.create_index(op.f('ix_auth_policies_name'), 'auth_policies', ['name'], unique=True)

    # --- api_profiles ---
    op.create_table('api_profiles',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('listener_id', sa.Integer(), nullable=True),
        sa.Column('method', sa.String(), nullable=False),
        sa.Column('path', sa.String(), nullable=False),
        sa.Column('dimensions', sa.JSON(), nullable=False),
        sa.Column('sample_count', sa.Integer(), nullable=True),
        sa.Column('first_seen', sa.DateTime(), nullable=True),
        sa.Column('last_seen', sa.DateTime(), nullable=True),
        sa.Column('status_codes', sa.JSON(), nullable=True),
        sa.Column('learned', sa.Boolean(), nullable=True),
        sa.ForeignKeyConstraint(['listener_id'], ['listeners.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_api_profiles_id'), 'api_profiles', ['id'], unique=False)

    # --- api_anomalies ---
    op.create_table('api_anomalies',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('listener_id', sa.Integer(), nullable=True),
        sa.Column('method', sa.String(), nullable=False),
        sa.Column('path', sa.String(), nullable=False),
        sa.Column('dimension', sa.String(), nullable=False),
        sa.Column('observed_value', sa.Text(), nullable=True),
        sa.Column('expected_values', sa.JSON(), nullable=True),
        sa.Column('request_id', sa.String(), nullable=True),
        sa.Column('client_ip', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['listener_id'], ['listeners.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_api_anomalies_id'), 'api_anomalies', ['id'], unique=False)
    op.create_index(op.f('ix_api_anomalies_created_at'), 'api_anomalies', ['created_at'], unique=False)

    # --- Extend rate_limits with per-endpoint scoping ---
    op.add_column('rate_limits', sa.Column('path_pattern', sa.String(), nullable=True))
    op.add_column('rate_limits', sa.Column('method', sa.String(), nullable=True))
    op.add_column('rate_limits', sa.Column('api_armor_scoped', sa.Boolean(), nullable=True, server_default=sa.text('false')))
    # Backfill: set existing rows to False (column was added as nullable)
    op.execute("UPDATE rate_limits SET api_armor_scoped = false WHERE api_armor_scoped IS null")


def downgrade() -> None:
    """Drop API Armor tables and revert rate_limits extensions."""
    op.drop_column('rate_limits', 'api_armor_scoped')
    op.drop_column('rate_limits', 'method')
    op.drop_column('rate_limits', 'path_pattern')

    op.drop_index(op.f('ix_api_anomalies_created_at'), table_name='api_anomalies')
    op.drop_index(op.f('ix_api_anomalies_id'), table_name='api_anomalies')
    op.drop_table('api_anomalies')

    op.drop_index(op.f('ix_api_profiles_id'), table_name='api_profiles')
    op.drop_table('api_profiles')

    op.drop_index(op.f('ix_auth_policies_name'), table_name='auth_policies')
    op.drop_index(op.f('ix_auth_policies_id'), table_name='auth_policies')
    op.drop_table('auth_policies')

    op.drop_index(op.f('ix_api_key_list_entries_id'), table_name='api_key_list_entries')
    op.drop_table('api_key_list_entries')

    op.drop_index(op.f('ix_api_key_lists_name'), table_name='api_key_lists')
    op.drop_index(op.f('ix_api_key_lists_id'), table_name='api_key_lists')
    op.drop_table('api_key_lists')

    op.drop_index(op.f('ix_api_schemas_id'), table_name='api_schemas')
    op.drop_table('api_schemas')

    op.drop_index(op.f('ix_openapi_specs_name'), table_name='openapi_specs')
    op.drop_index(op.f('ix_openapi_specs_id'), table_name='openapi_specs')
    op.drop_table('openapi_specs')
