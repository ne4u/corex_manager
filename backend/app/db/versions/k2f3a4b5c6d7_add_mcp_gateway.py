"""add mcp gateway tables

Revision ID: k2f3a4b5c6d7
Revises: j1e2f3a4b5c6
Create Date: 2026-08-19 18:00:00.000000

Creates the MCP Gateway feature tables:
- teams / user_teams: soft multi-team tenancy
- mcp_servers: registered remote MCP servers (Streamable HTTP upstreams)
- mcp_server_replicas: additional replica URLs for multi-replica upstreams
- mcp_identities: PAT/JWT identities for gateway auth
- mcp_policies: Security Rules-language tool policies (gateway-evaluated)
- mcp_dlp_rules: DLP detector rules for request/response scanning
- mcp_skills / mcp_skill_versions: versioned SKILL.md catalog
- mcp_guardrails: injection/jailbreak detection rules
- mcp_events: observational telemetry (excluded from config snapshots)
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'k2f3a4b5c6d7'
down_revision: Union[str, Sequence[str], None] = 'j1e2f3a4b5c6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- teams ---
    op.create_table('teams',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('slug', sa.String(), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name'),
        sa.UniqueConstraint('slug'),
    )
    op.create_index(op.f('ix_teams_id'), 'teams', ['id'], unique=False)
    op.create_index(op.f('ix_teams_name'), 'teams', ['name'], unique=True)
    op.create_index(op.f('ix_teams_slug'), 'teams', ['slug'], unique=True)

    # --- user_teams ---
    op.create_table('user_teams',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('team_id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['team_id'], ['teams.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', 'team_id', name='uq_user_team'),
    )
    op.create_index(op.f('ix_user_teams_id'), 'user_teams', ['id'], unique=False)
    op.create_index(op.f('ix_user_teams_user_id'), 'user_teams', ['user_id'], unique=False)
    op.create_index(op.f('ix_user_teams_team_id'), 'user_teams', ['team_id'], unique=False)

    # --- mcp_servers ---
    op.create_table('mcp_servers',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('team_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('display_name', sa.String(), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('url', sa.String(), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=True),
        sa.Column('verify_tls', sa.Boolean(), nullable=True),
        sa.Column('auth_type', sa.String(), nullable=True),
        sa.Column('auth_header', sa.String(), nullable=True),
        sa.Column('auth_secret_enc', sa.Text(), nullable=True),
        sa.Column('timeout_ms', sa.Integer(), nullable=True),
        sa.Column('max_body_bytes', sa.Integer(), nullable=True),
        sa.Column('namespace', sa.String(), nullable=False),
        sa.Column('health_status', sa.String(), nullable=True),
        sa.Column('last_seen_at', sa.DateTime(), nullable=True),
        sa.Column('last_error', sa.Text(), nullable=True),
        sa.Column('last_catalog_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['team_id'], ['teams.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name'),
    )
    op.create_index(op.f('ix_mcp_servers_id'), 'mcp_servers', ['id'], unique=False)
    op.create_index(op.f('ix_mcp_servers_name'), 'mcp_servers', ['name'], unique=True)
    op.create_index(op.f('ix_mcp_servers_team_id'), 'mcp_servers', ['team_id'], unique=False)

    # --- mcp_server_replicas ---
    op.create_table('mcp_server_replicas',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('server_id', sa.Integer(), nullable=False),
        sa.Column('url', sa.String(), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=True),
        sa.Column('verify_tls', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['server_id'], ['mcp_servers.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('server_id', 'url', name='uq_server_replica_url'),
    )
    op.create_index(op.f('ix_mcp_server_replicas_id'), 'mcp_server_replicas', ['id'], unique=False)
    op.create_index(op.f('ix_mcp_server_replicas_server_id'), 'mcp_server_replicas', ['server_id'], unique=False)

    # --- mcp_identities ---
    op.create_table('mcp_identities',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('team_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('subject', sa.String(), nullable=True),
        sa.Column('kind', sa.String(), nullable=True),
        sa.Column('pat_hash', sa.String(), nullable=True),
        sa.Column('pat_prefix', sa.String(), nullable=True),
        sa.Column('jwt_issuer', sa.String(), nullable=True),
        sa.Column('jwt_audience', sa.String(), nullable=True),
        sa.Column('jwt_jwks_url', sa.String(), nullable=True),
        sa.Column('enabled', sa.Boolean(), nullable=True),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('last_used_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['team_id'], ['teams.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_mcp_identities_id'), 'mcp_identities', ['id'], unique=False)
    op.create_index(op.f('ix_mcp_identities_team_id'), 'mcp_identities', ['team_id'], unique=False)

    # --- mcp_policies ---
    op.create_table('mcp_policies',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('team_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=True),
        sa.Column('priority', sa.Integer(), nullable=True),
        sa.Column('expression', sa.Text(), nullable=False),
        sa.Column('expression_ast', sa.JSON(), nullable=True),
        sa.Column('action', sa.String(), nullable=True),
        sa.Column('log', sa.Boolean(), nullable=True),
        sa.Column('no_log', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['team_id'], ['teams.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name'),
    )
    op.create_index(op.f('ix_mcp_policies_id'), 'mcp_policies', ['id'], unique=False)
    op.create_index(op.f('ix_mcp_policies_team_id'), 'mcp_policies', ['team_id'], unique=False)

    # --- mcp_dlp_rules ---
    op.create_table('mcp_dlp_rules',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('team_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=True),
        sa.Column('priority', sa.Integer(), nullable=True),
        sa.Column('direction', sa.String(), nullable=True),
        sa.Column('detector', sa.String(), nullable=False),
        sa.Column('find_regex', sa.Text(), nullable=True),
        sa.Column('action', sa.String(), nullable=True),
        sa.Column('token_prefix', sa.String(), nullable=True),
        sa.Column('token_ttl', sa.Integer(), nullable=True),
        sa.Column('apply_to', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['team_id'], ['teams.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_mcp_dlp_rules_id'), 'mcp_dlp_rules', ['id'], unique=False)
    op.create_index(op.f('ix_mcp_dlp_rules_team_id'), 'mcp_dlp_rules', ['team_id'], unique=False)

    # --- mcp_skill_versions (created before mcp_skills due to FK from skills.published_version_id) ---
    op.create_table('mcp_skill_versions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('skill_id', sa.Integer(), nullable=False),
        sa.Column('version', sa.Integer(), nullable=False),
        sa.Column('frontmatter', sa.JSON(), nullable=True),
        sa.Column('body', sa.Text(), nullable=False),
        sa.Column('files', sa.JSON(), nullable=True),
        sa.Column('created_by', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['skill_id'], ['mcp_skills.id'], ondelete='CASCADE', use_alter=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('skill_id', 'version', name='uq_skill_version'),
    )
    op.create_index(op.f('ix_mcp_skill_versions_id'), 'mcp_skill_versions', ['id'], unique=False)
    op.create_index(op.f('ix_mcp_skill_versions_skill_id'), 'mcp_skill_versions', ['skill_id'], unique=False)

    # --- mcp_skills ---
    op.create_table('mcp_skills',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('team_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('enabled', sa.Boolean(), nullable=True),
        sa.Column('enable_when', sa.Text(), nullable=True),
        sa.Column('enable_when_ast', sa.JSON(), nullable=True),
        sa.Column('tags', sa.JSON(), nullable=True),
        sa.Column('published_version_id', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['team_id'], ['teams.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['published_version_id'], ['mcp_skill_versions.id'], use_alter=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name'),
    )
    op.create_index(op.f('ix_mcp_skills_id'), 'mcp_skills', ['id'], unique=False)
    op.create_index(op.f('ix_mcp_skills_team_id'), 'mcp_skills', ['team_id'], unique=False)

    # --- mcp_guardrails ---
    op.create_table('mcp_guardrails',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('team_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=True),
        sa.Column('priority', sa.Integer(), nullable=True),
        sa.Column('direction', sa.String(), nullable=True),
        sa.Column('pack', sa.String(), nullable=True),
        sa.Column('find_regex', sa.Text(), nullable=True),
        sa.Column('action', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['team_id'], ['teams.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_mcp_guardrails_id'), 'mcp_guardrails', ['id'], unique=False)
    op.create_index(op.f('ix_mcp_guardrails_team_id'), 'mcp_guardrails', ['team_id'], unique=False)

    # --- mcp_events ---
    op.create_table('mcp_events',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('captured_at', sa.DateTime(), nullable=True),
        sa.Column('request_id', sa.String(), nullable=True),
        sa.Column('session_id', sa.String(), nullable=True),
        sa.Column('identity_id', sa.Integer(), nullable=True),
        sa.Column('team_id', sa.Integer(), nullable=True),
        sa.Column('server_id', sa.Integer(), nullable=True),
        sa.Column('jsonrpc_method', sa.String(), nullable=True),
        sa.Column('tool', sa.String(), nullable=True),
        sa.Column('resource_uri', sa.String(), nullable=True),
        sa.Column('prompt', sa.String(), nullable=True),
        sa.Column('action', sa.String(), nullable=True),
        sa.Column('status', sa.String(), nullable=True),
        sa.Column('latency_ms', sa.Integer(), nullable=True),
        sa.Column('error', sa.Text(), nullable=True),
        sa.Column('bytes_in', sa.Integer(), nullable=True),
        sa.Column('bytes_out', sa.Integer(), nullable=True),
        sa.Column('dlp_hits', sa.JSON(), nullable=True),
        sa.Column('guardrail_hits', sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_mcp_events_id'), 'mcp_events', ['id'], unique=False)
    op.create_index(op.f('ix_mcp_events_captured_at'), 'mcp_events', ['captured_at'], unique=False)
    op.create_index(op.f('ix_mcp_events_identity_id'), 'mcp_events', ['identity_id'], unique=False)
    op.create_index(op.f('ix_mcp_events_team_id'), 'mcp_events', ['team_id'], unique=False)


def downgrade() -> None:
    op.drop_table('mcp_events')
    op.drop_table('mcp_guardrails')
    op.drop_table('mcp_skills')
    op.drop_table('mcp_skill_versions')
    op.drop_table('mcp_dlp_rules')
    op.drop_table('mcp_policies')
    op.drop_table('mcp_identities')
    op.drop_table('mcp_server_replicas')
    op.drop_table('mcp_servers')
    op.drop_table('user_teams')
    op.drop_table('teams')
