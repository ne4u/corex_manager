"""MCP Gateway CRUD router — Phase 0.

Endpoints for teams, servers (+replicas), identities, policies, DLP rules,
guardrails, and skills. All write operations require operator role + team
membership (admin bypasses). Secrets are write-only (never returned).
"""
import os
import re
import secrets
import yaml
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..deps import get_current_user, get_db, require_write, rate_limit, get_user_team_ids
from ...models.mcp import (
    Team, UserTeam, McpServer, McpServerReplica, McpIdentity,
    McpPolicy, McpDlpRule, McpSkill, McpSkillVersion, McpGuardrail,
    McpInstallation, McpEvent,
)
from ...models.models import User
from ...schemas.mcp import (
    TeamCreate, TeamUpdate, TeamResponse,
    UserTeamCreate, UserTeamResponse,
    McpServerCreate, McpServerUpdate, McpServerResponse,
    McpServerReplicaCreate, McpServerReplicaUpdate, McpServerReplicaResponse,
    McpIdentityCreate, McpIdentityUpdate, McpIdentityResponse,
    PatCreateResponse,
    McpPolicyCreate, McpPolicyUpdate, McpPolicyResponse,
    McpDlpRuleCreate, McpDlpRuleUpdate, McpDlpRuleResponse,
    McpSkillCreate, McpSkillUpdate, McpSkillResponse,
    McpSkillVersionCreate, McpSkillVersionResponse,
    McpSkillImportRequest,
    McpGuardrailCreate, McpGuardrailUpdate, McpGuardrailResponse,
    McpInstallationResponse,
    MarketplaceSearchResult, MarketplacePackageDetails,
    MarketplaceInstallRequest, MarketplaceUninstallRequest,
    DiscoverEnvVarsRequest, DiscoverEnvVarsResponse,
    OAuthDiscoverRequest, OAuthDiscoverResponse,
    OAuthConfigureRequest, OAuthStatusResponse, OAuthAuthorizeResponse,
    McpEventResponse, McpEventListResponse,
    SessionInfo, SessionListResponse,
    ConfigStatusResponse,
    AlertConfigResponse, AlertConfigUpdate, AlertHistoryItem,
    ServerCatalogResponse,
)
from ...services.mcp_secrets import encrypt_secret, has_secrets_key
from ...core.valkey_client import _get_client as get_valkey_client

router = APIRouter(prefix="/mcp", tags=["mcp"])

_NamespaceRe = re.compile(r"^[a-z0-9_-]+$")


def _slugify(name: str) -> str:
    return re.sub(r"[^a-z0-9-]", "-", name.lower()).strip("-")


import json as _json

def _server_to_response(obj: McpServer) -> McpServerResponse:
    args = []
    if obj.args_json:
        try:
            args = _json.loads(obj.args_json)
        except Exception:
            pass
    return McpServerResponse(
        id=obj.id,
        team_id=obj.team_id,
        name=obj.name,
        display_name=obj.display_name,
        description=obj.description,
        url=obj.url,
        enabled=obj.enabled,
        verify_tls=obj.verify_tls,
        auth_type=obj.auth_type,
        auth_header=obj.auth_header,
        has_secret=bool(obj.auth_secret_enc),
        timeout_ms=obj.timeout_ms,
        max_body_bytes=obj.max_body_bytes,
        namespace=obj.namespace,
        health_status=obj.health_status,
        last_seen_at=obj.last_seen_at,
        last_error=obj.last_error,
        last_catalog_at=obj.last_catalog_at,
        transport_type=obj.transport_type or "streamable_http",
        command=obj.command,
        args=args,
        has_env_vars=bool(obj.env_vars_json),
        env_var_names=list(_json.loads(obj.env_vars_json).keys()) if obj.env_vars_json else None,
        package_manager=obj.package_manager,
        source_package_name=obj.source_package_name,
        installed_version=obj.installed_version,
        oauth_enabled=obj.oauth_enabled or False,
        oauth_auth_status=obj.oauth_auth_status or "not_configured",
        oauth_client_id=obj.oauth_client_id,
        oauth_scopes=obj.oauth_scopes,
        oauth_auth_server_metadata_url=obj.oauth_auth_server_metadata_url,
        oauth_protected_resource_metadata_url=obj.oauth_protected_resource_metadata_url,
        created_at=obj.created_at,
        updated_at=obj.updated_at,
    )


def _identity_to_response(obj: McpIdentity) -> McpIdentityResponse:
    return McpIdentityResponse(
        id=obj.id,
        team_id=obj.team_id,
        name=obj.name,
        description=obj.description,
        subject=obj.subject,
        kind=obj.kind,
        pat_prefix=obj.pat_prefix,
        jwt_issuer=obj.jwt_issuer,
        jwt_audience=obj.jwt_audience,
        jwt_jwks_url=obj.jwt_jwks_url,
        enabled=obj.enabled,
        expires_at=obj.expires_at,
        created_at=obj.created_at,
        last_used_at=obj.last_used_at,
    )


def _validate_replica_path(primary_url: str, replica_url: str) -> None:
    """Reject if the URL path differs from the primary server's path."""
    primary_path = urlparse(primary_url).path or "/"
    replica_path = urlparse(replica_url).path or "/"
    if primary_path != replica_path:
        raise HTTPException(
            status_code=400,
            detail=f"Replica URL path '{replica_path}' must match primary path '{primary_path}'",
        )


# ==================== Teams ====================

@router.get("/teams", response_model=List[TeamResponse])
def list_teams(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    _=Depends(rate_limit),
):
    team_ids = get_user_team_ids(db, user)
    if not team_ids:
        return []
    return db.query(Team).filter(Team.id.in_(team_ids)).order_by(Team.name).all()


@router.post("/teams", response_model=TeamResponse)
def create_team(
    t: TeamCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_write),
    _=Depends(rate_limit),
):
    if not user.is_admin and user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admins can create teams")
    obj = Team(**t.model_dump())
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


@router.put("/teams/{tid}", response_model=TeamResponse)
def update_team(
    tid: int,
    t_in: TeamUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_write),
    _=Depends(rate_limit),
):
    obj = db.get(Team, tid)
    if not obj:
        raise HTTPException(status_code=404, detail="Team not found")
    if not user.is_admin and user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admins can edit teams")
    for k, v in t_in.model_dump(exclude_unset=True).items():
        setattr(obj, k, v)
    db.commit()
    db.refresh(obj)
    return obj


@router.delete("/teams/{tid}")
def delete_team(
    tid: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_write),
    _=Depends(rate_limit),
):
    obj = db.get(Team, tid)
    if not obj:
        raise HTTPException(status_code=404, detail="Team not found")
    if not user.is_admin and user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admins can delete teams")
    db.delete(obj)
    db.commit()
    return {"ok": True}


@router.post("/teams/{tid}/members", response_model=UserTeamResponse)
def add_team_member(
    tid: int,
    m: UserTeamCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_write),
    _=Depends(rate_limit),
):
    if not user.is_admin and user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admins can add team members")
    team = db.get(Team, tid)
    if not team:
        raise HTTPException(status_code=404, detail="Team not found")
    target_user = db.query(User).filter(User.id == m.user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    existing = db.query(UserTeam).filter(
        UserTeam.user_id == m.user_id, UserTeam.team_id == tid
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail="User already in team")
    obj = UserTeam(user_id=m.user_id, team_id=tid)
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


@router.delete("/teams/{tid}/members/{uid}")
def remove_team_member(
    tid: int,
    uid: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_write),
    _=Depends(rate_limit),
):
    if not user.is_admin and user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admins can remove team members")
    obj = db.query(UserTeam).filter(
        UserTeam.user_id == uid, UserTeam.team_id == tid
    ).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Membership not found")
    db.delete(obj)
    db.commit()
    return {"ok": True}


@router.get("/teams/{tid}/members", response_model=List[UserTeamResponse])
def list_team_members(
    tid: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    _=Depends(rate_limit),
):
    """List members of a team."""
    team = db.get(Team, tid)
    if not team:
        raise HTTPException(status_code=404, detail="Team not found")
    team_ids = get_user_team_ids(db, user)
    if tid not in team_ids and not (user.is_admin or user.role == "admin"):
        raise HTTPException(status_code=403, detail="Not a member of this team")
    return db.query(UserTeam).filter(UserTeam.team_id == tid).all()


# ==================== Servers ====================

@router.get("/servers", response_model=List[McpServerResponse])
def list_servers(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    _=Depends(rate_limit),
):
    team_ids = get_user_team_ids(db, user)
    if not team_ids:
        return []
    servers = db.query(McpServer).filter(McpServer.team_id.in_(team_ids)).order_by(McpServer.name).all()
    return [_server_to_response(s) for s in servers]


@router.post("/servers", response_model=McpServerResponse)
def create_server(
    s: McpServerCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_write),
    _=Depends(rate_limit),
):
    team_ids = get_user_team_ids(db, user)
    if s.team_id not in team_ids:
        raise HTTPException(status_code=403, detail="Not a member of this team")
    namespace = s.namespace or _slugify(s.name)
    if not _NamespaceRe.match(namespace):
        raise HTTPException(status_code=400, detail="Namespace must match [a-z0-9_-]+")
    if "__" in namespace:
        raise HTTPException(status_code=400, detail="Namespace cannot contain double underscore")
    existing = db.query(McpServer).filter(McpServer.namespace == namespace).first()
    if existing:
        raise HTTPException(status_code=409, detail="Namespace already in use")

    auth_secret_enc = None
    if s.auth_secret and s.auth_type != "none":
        if not has_secrets_key():
            raise HTTPException(status_code=500, detail="MCP_SECRETS_KEY not configured")
        auth_secret_enc = encrypt_secret(s.auth_secret)

    # stdio transport fields
    args_json = None
    if s.args:
        args_json = _json.dumps(s.args)

    env_vars_json = None
    if s.env_vars:
        encrypted_env = {}
        for k, v in s.env_vars.items():
            if v:
                if not has_secrets_key():
                    raise HTTPException(status_code=500, detail="MCP_SECRETS_KEY not configured")
                encrypted_env[k] = encrypt_secret(v)
        env_vars_json = _json.dumps(encrypted_env)

    # OAuth client secret encryption
    oauth_client_secret_enc = None
    if s.oauth_client_secret:
        if not has_secrets_key():
            raise HTTPException(status_code=500, detail="MCP_SECRETS_KEY not configured")
        oauth_client_secret_enc = encrypt_secret(s.oauth_client_secret)

    # Validate: stdio servers need command; HTTP servers need url
    if s.transport_type == "stdio" and not s.command:
        raise HTTPException(status_code=400, detail="command is required for stdio transport")
    if s.transport_type != "stdio" and not s.url:
        raise HTTPException(status_code=400, detail="url is required for non-stdio transport")

    obj = McpServer(
        team_id=s.team_id,
        name=s.name,
        display_name=s.display_name,
        description=s.description,
        url=s.url,
        enabled=s.enabled,
        verify_tls=s.verify_tls,
        auth_type=s.auth_type,
        auth_header=s.auth_header or ("Authorization" if s.auth_type == "bearer" else None),
        auth_secret_enc=auth_secret_enc,
        timeout_ms=s.timeout_ms,
        max_body_bytes=s.max_body_bytes,
        namespace=namespace,
        transport_type=s.transport_type,
        command=s.command,
        args_json=args_json,
        env_vars_json=env_vars_json,
        package_manager=s.package_manager,
        source_package_name=s.source_package_name,
        oauth_enabled=s.oauth_enabled,
        oauth_client_id=s.oauth_client_id,
        oauth_client_secret_enc=oauth_client_secret_enc,
        oauth_scopes=s.oauth_scopes,
        oauth_auth_status="not_configured" if s.oauth_enabled else None,
        oauth_auth_server_metadata_url=s.oauth_auth_server_metadata_url,
        oauth_protected_resource_metadata_url=s.oauth_protected_resource_metadata_url,
    )
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return _server_to_response(obj)


@router.put("/servers/{sid}", response_model=McpServerResponse)
def update_server(
    sid: int,
    s_in: McpServerUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_write),
    _=Depends(rate_limit),
):
    obj = db.get(McpServer, sid)
    if not obj:
        raise HTTPException(status_code=404, detail="Server not found")
    team_ids = get_user_team_ids(db, user)
    if obj.team_id not in team_ids:
        raise HTTPException(status_code=403, detail="Not a member of this team")

    data = s_in.model_dump(exclude_unset=True)
    # Handle secret update
    auth_secret = data.pop("auth_secret", None)
    if auth_secret is not None:
        if not has_secrets_key():
            raise HTTPException(status_code=500, detail="MCP_SECRETS_KEY not configured")
        obj.auth_secret_enc = encrypt_secret(auth_secret)

    # Handle OAuth client secret update
    oauth_client_secret = data.pop("oauth_client_secret", None)
    if oauth_client_secret is not None:
        if not has_secrets_key():
            raise HTTPException(status_code=500, detail="MCP_SECRETS_KEY not configured")
        obj.oauth_client_secret_enc = encrypt_secret(oauth_client_secret)

    # Handle args -> args_json
    args = data.pop("args", None)
    if args is not None:
        obj.args_json = _json.dumps(args) if args else None

    # Handle env_vars -> env_vars_json (encrypt values)
    env_vars = data.pop("env_vars", None)
    if env_vars is not None:
        if env_vars:
            encrypted_env = {}
            for k, v in env_vars.items():
                if v:
                    if not has_secrets_key():
                        raise HTTPException(status_code=500, detail="MCP_SECRETS_KEY not configured")
                    encrypted_env[k] = encrypt_secret(v)
            obj.env_vars_json = _json.dumps(encrypted_env)
        else:
            obj.env_vars_json = None

    # Namespace change validation
    if "namespace" in data and data["namespace"] is not None:
        ns = data["namespace"]
        if not _NamespaceRe.match(ns):
            raise HTTPException(status_code=400, detail="Namespace must match [a-z0-9_-]+")
        if "__" in ns:
            raise HTTPException(status_code=400, detail="Namespace cannot contain double underscore")
        existing = db.query(McpServer).filter(
            McpServer.namespace == ns, McpServer.id != sid
        ).first()
        if existing:
            raise HTTPException(status_code=409, detail="Namespace already in use")
    for k, v in data.items():
        setattr(obj, k, v)
    db.commit()
    db.refresh(obj)
    return _server_to_response(obj)


@router.delete("/servers/{sid}")
def delete_server(
    sid: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_write),
    _=Depends(rate_limit),
):
    obj = db.get(McpServer, sid)
    if not obj:
        raise HTTPException(status_code=404, detail="Server not found")
    team_ids = get_user_team_ids(db, user)
    if obj.team_id not in team_ids:
        raise HTTPException(status_code=403, detail="Not a member of this team")
    db.delete(obj)
    db.commit()
    return {"ok": True}


# ==================== Server Replicas ====================

@router.get("/servers/{sid}/replicas", response_model=List[McpServerReplicaResponse])
def list_replicas(
    sid: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    _=Depends(rate_limit),
):
    server = db.get(McpServer, sid)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    team_ids = get_user_team_ids(db, user)
    if server.team_id not in team_ids:
        raise HTTPException(status_code=403, detail="Not a member of this team")
    return db.query(McpServerReplica).filter(McpServerReplica.server_id == sid).order_by(McpServerReplica.id).all()


@router.post("/servers/{sid}/replicas", response_model=McpServerReplicaResponse)
def create_replica(
    sid: int,
    r: McpServerReplicaCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_write),
    _=Depends(rate_limit),
):
    server = db.get(McpServer, sid)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    team_ids = get_user_team_ids(db, user)
    if server.team_id not in team_ids:
        raise HTTPException(status_code=403, detail="Not a member of this team")
    _validate_replica_path(server.url, r.url)
    obj = McpServerReplica(
        server_id=sid,
        url=r.url,
        enabled=r.enabled,
        verify_tls=r.verify_tls,
    )
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


@router.put("/servers/{sid}/replicas/{rid}", response_model=McpServerReplicaResponse)
def update_replica(
    sid: int,
    rid: int,
    r_in: McpServerReplicaUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_write),
    _=Depends(rate_limit),
):
    server = db.get(McpServer, sid)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    team_ids = get_user_team_ids(db, user)
    if server.team_id not in team_ids:
        raise HTTPException(status_code=403, detail="Not a member of this team")
    obj = db.get(McpServerReplica, rid)
    if not obj or obj.server_id != sid:
        raise HTTPException(status_code=404, detail="Replica not found")
    data = r_in.model_dump(exclude_unset=True)
    if "url" in data and data["url"] is not None:
        _validate_replica_path(server.url, data["url"])
    for k, v in data.items():
        setattr(obj, k, v)
    db.commit()
    db.refresh(obj)
    return obj


@router.delete("/servers/{sid}/replicas/{rid}")
def delete_replica(
    sid: int,
    rid: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_write),
    _=Depends(rate_limit),
):
    server = db.get(McpServer, sid)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    team_ids = get_user_team_ids(db, user)
    if server.team_id not in team_ids:
        raise HTTPException(status_code=403, detail="Not a member of this team")
    obj = db.get(McpServerReplica, rid)
    if not obj or obj.server_id != sid:
        raise HTTPException(status_code=404, detail="Replica not found")
    db.delete(obj)
    db.commit()
    return {"ok": True}


# ==================== Identities ====================

@router.get("/identities", response_model=List[McpIdentityResponse])
def list_identities(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    _=Depends(rate_limit),
):
    team_ids = get_user_team_ids(db, user)
    if not team_ids:
        return []
    identities = db.query(McpIdentity).filter(McpIdentity.team_id.in_(team_ids)).order_by(McpIdentity.name).all()
    return [_identity_to_response(i) for i in identities]


@router.post("/identities", response_model=McpIdentityResponse)
def create_identity(
    i: McpIdentityCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_write),
    _=Depends(rate_limit),
):
    team_ids = get_user_team_ids(db, user)
    if i.team_id not in team_ids:
        raise HTTPException(status_code=403, detail="Not a member of this team")
    obj = McpIdentity(
        team_id=i.team_id,
        name=i.name,
        description=i.description,
        subject=i.subject or i.name,
        kind=i.kind,
        jwt_issuer=i.jwt_issuer,
        jwt_audience=i.jwt_audience,
        jwt_jwks_url=i.jwt_jwks_url,
        enabled=i.enabled,
        expires_at=i.expires_at,
    )
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return _identity_to_response(obj)


@router.put("/identities/{iid}", response_model=McpIdentityResponse)
def update_identity(
    iid: int,
    i_in: McpIdentityUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_write),
    _=Depends(rate_limit),
):
    obj = db.get(McpIdentity, iid)
    if not obj:
        raise HTTPException(status_code=404, detail="Identity not found")
    team_ids = get_user_team_ids(db, user)
    if obj.team_id not in team_ids:
        raise HTTPException(status_code=403, detail="Not a member of this team")
    was_enabled = obj.enabled
    for k, v in i_in.model_dump(exclude_unset=True).items():
        setattr(obj, k, v)
    db.commit()
    db.refresh(obj)
    # If identity was disabled, revoke all tokens in Valkey
    if was_enabled and not obj.enabled:
        try:
            valkey_cache.set(f"mcp:rev:identity:{iid}", str(__import__("time").time()))
        except Exception:
            pass
    return _identity_to_response(obj)


@router.delete("/identities/{iid}")
def delete_identity(
    iid: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_write),
    _=Depends(rate_limit),
):
    obj = db.get(McpIdentity, iid)
    if not obj:
        raise HTTPException(status_code=404, detail="Identity not found")
    team_ids = get_user_team_ids(db, user)
    if obj.team_id not in team_ids:
        raise HTTPException(status_code=403, detail="Not a member of this team")
    db.delete(obj)
    db.commit()
    # Revoke all tokens for deleted identity
    try:
        valkey_cache.set(f"mcp:rev:identity:{iid}", str(__import__("time").time()))
    except Exception:
        pass
    return {"ok": True}


@router.post("/identities/{iid}/tokens", response_model=PatCreateResponse)
def issue_pat(
    iid: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_write),
    _=Depends(rate_limit),
):
    """Issue a PAT for a PAT-kind identity. Plaintext is shown once."""
    from ..deps import get_current_user as _gcu  # noqa
    obj = db.get(McpIdentity, iid)
    if not obj:
        raise HTTPException(status_code=404, detail="Identity not found")
    team_ids = get_user_team_ids(db, user)
    if obj.team_id not in team_ids:
        raise HTTPException(status_code=403, detail="Not a member of this team")
    if obj.kind != "pat":
        raise HTTPException(status_code=400, detail="PAT can only be issued for pat-kind identities")
    # Generate token: mcp_<prefix>.<secret>
    prefix = secrets.token_hex(4)  # 8 chars
    secret = secrets.token_urlsafe(32)
    pat = f"mcp_{prefix}.{secret}"
    # Hash the full PAT for storage
    from ...core.security import get_password_hash
    obj.pat_hash = get_password_hash(pat)
    obj.pat_prefix = f"mcp_{prefix}"
    db.commit()
    return PatCreateResponse(identity_id=iid, pat=pat, prefix=obj.pat_prefix)


# ==================== Policies ====================

@router.get("/policies", response_model=List[McpPolicyResponse])
def list_policies(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    _=Depends(rate_limit),
):
    team_ids = get_user_team_ids(db, user)
    if not team_ids:
        return []
    return db.query(McpPolicy).filter(McpPolicy.team_id.in_(team_ids)).order_by(McpPolicy.priority).all()


@router.post("/policies", response_model=McpPolicyResponse)
def create_policy(
    p: McpPolicyCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_write),
    _=Depends(rate_limit),
):
    team_ids = get_user_team_ids(db, user)
    if p.team_id not in team_ids:
        raise HTTPException(status_code=403, detail="Not a member of this team")
    max_priority = db.query(McpPolicy).order_by(McpPolicy.priority.desc()).first()
    priority = (max_priority.priority + 1) if max_priority else 0
    obj = McpPolicy(
        team_id=p.team_id,
        name=p.name,
        enabled=p.enabled,
        priority=priority,
        expression=p.expression,
        action=p.action,
        log=p.log,
        no_log=p.no_log,
    )
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


@router.put("/policies/{pid}", response_model=McpPolicyResponse)
def update_policy(
    pid: int,
    p_in: McpPolicyUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_write),
    _=Depends(rate_limit),
):
    obj = db.get(McpPolicy, pid)
    if not obj:
        raise HTTPException(status_code=404, detail="Policy not found")
    team_ids = get_user_team_ids(db, user)
    if obj.team_id not in team_ids:
        raise HTTPException(status_code=403, detail="Not a member of this team")
    for k, v in p_in.model_dump(exclude_unset=True).items():
        setattr(obj, k, v)
    db.commit()
    db.refresh(obj)
    return obj


@router.delete("/policies/{pid}")
def delete_policy(
    pid: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_write),
    _=Depends(rate_limit),
):
    obj = db.get(McpPolicy, pid)
    if not obj:
        raise HTTPException(status_code=404, detail="Policy not found")
    team_ids = get_user_team_ids(db, user)
    if obj.team_id not in team_ids:
        raise HTTPException(status_code=403, detail="Not a member of this team")
    db.delete(obj)
    db.commit()
    return {"ok": True}


# ==================== DLP Rules ====================

@router.get("/dlp-rules", response_model=List[McpDlpRuleResponse])
def list_dlp_rules(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    _=Depends(rate_limit),
):
    team_ids = get_user_team_ids(db, user)
    if not team_ids:
        return []
    return db.query(McpDlpRule).filter(McpDlpRule.team_id.in_(team_ids)).order_by(McpDlpRule.priority).all()


@router.post("/dlp-rules", response_model=McpDlpRuleResponse)
def create_dlp_rule(
    r: McpDlpRuleCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_write),
    _=Depends(rate_limit),
):
    team_ids = get_user_team_ids(db, user)
    if r.team_id not in team_ids:
        raise HTTPException(status_code=403, detail="Not a member of this team")
    if r.detector == "custom" and not r.find_regex:
        raise HTTPException(status_code=400, detail="find_regex required when detector=custom")
    max_priority = db.query(McpDlpRule).order_by(McpDlpRule.priority.desc()).first()
    priority = (max_priority.priority + 1) if max_priority else 0
    obj = McpDlpRule(
        team_id=r.team_id,
        name=r.name,
        enabled=r.enabled,
        priority=priority,
        direction=r.direction,
        detector=r.detector,
        find_regex=r.find_regex,
        action=r.action,
        token_prefix=r.token_prefix,
        token_ttl=r.token_ttl,
        apply_to=r.apply_to,
    )
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


@router.put("/dlp-rules/{rid}", response_model=McpDlpRuleResponse)
def update_dlp_rule(
    rid: int,
    r_in: McpDlpRuleUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_write),
    _=Depends(rate_limit),
):
    obj = db.get(McpDlpRule, rid)
    if not obj:
        raise HTTPException(status_code=404, detail="DLP rule not found")
    team_ids = get_user_team_ids(db, user)
    if obj.team_id not in team_ids:
        raise HTTPException(status_code=403, detail="Not a member of this team")
    for k, v in r_in.model_dump(exclude_unset=True).items():
        setattr(obj, k, v)
    db.commit()
    db.refresh(obj)
    return obj


@router.delete("/dlp-rules/{rid}")
def delete_dlp_rule(
    rid: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_write),
    _=Depends(rate_limit),
):
    obj = db.get(McpDlpRule, rid)
    if not obj:
        raise HTTPException(status_code=404, detail="DLP rule not found")
    team_ids = get_user_team_ids(db, user)
    if obj.team_id not in team_ids:
        raise HTTPException(status_code=403, detail="Not a member of this team")
    db.delete(obj)
    db.commit()
    return {"ok": True}


# ==================== Guardrails ====================

@router.get("/guardrails", response_model=List[McpGuardrailResponse])
def list_guardrails(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    _=Depends(rate_limit),
):
    team_ids = get_user_team_ids(db, user)
    if not team_ids:
        return []
    return db.query(McpGuardrail).filter(McpGuardrail.team_id.in_(team_ids)).order_by(McpGuardrail.priority).all()


@router.post("/guardrails", response_model=McpGuardrailResponse)
def create_guardrail(
    g: McpGuardrailCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_write),
    _=Depends(rate_limit),
):
    team_ids = get_user_team_ids(db, user)
    if g.team_id not in team_ids:
        raise HTTPException(status_code=403, detail="Not a member of this team")
    if g.pack == "custom" and not g.find_regex:
        raise HTTPException(status_code=400, detail="find_regex required when pack=custom")
    max_priority = db.query(McpGuardrail).order_by(McpGuardrail.priority.desc()).first()
    priority = (max_priority.priority + 1) if max_priority else 0
    obj = McpGuardrail(
        team_id=g.team_id,
        name=g.name,
        enabled=g.enabled,
        priority=priority,
        direction=g.direction,
        pack=g.pack,
        find_regex=g.find_regex,
        action=g.action,
    )
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


@router.put("/guardrails/{gid}", response_model=McpGuardrailResponse)
def update_guardrail(
    gid: int,
    g_in: McpGuardrailUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_write),
    _=Depends(rate_limit),
):
    obj = db.get(McpGuardrail, gid)
    if not obj:
        raise HTTPException(status_code=404, detail="Guardrail not found")
    team_ids = get_user_team_ids(db, user)
    if obj.team_id not in team_ids:
        raise HTTPException(status_code=403, detail="Not a member of this team")
    for k, v in g_in.model_dump(exclude_unset=True).items():
        setattr(obj, k, v)
    db.commit()
    db.refresh(obj)
    return obj


@router.delete("/guardrails/{gid}")
def delete_guardrail(
    gid: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_write),
    _=Depends(rate_limit),
):
    obj = db.get(McpGuardrail, gid)
    if not obj:
        raise HTTPException(status_code=404, detail="Guardrail not found")
    team_ids = get_user_team_ids(db, user)
    if obj.team_id not in team_ids:
        raise HTTPException(status_code=403, detail="Not a member of this team")
    db.delete(obj)
    db.commit()
    return {"ok": True}


# ==================== Skills ====================

@router.get("/skills", response_model=List[McpSkillResponse])
def list_skills(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    _=Depends(rate_limit),
):
    team_ids = get_user_team_ids(db, user)
    if not team_ids:
        return []
    return db.query(McpSkill).filter(McpSkill.team_id.in_(team_ids)).order_by(McpSkill.name).all()


@router.post("/skills", response_model=McpSkillResponse)
def create_skill(
    s: McpSkillCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_write),
    _=Depends(rate_limit),
):
    team_ids = get_user_team_ids(db, user)
    if s.team_id not in team_ids:
        raise HTTPException(status_code=403, detail="Not a member of this team")
    obj = McpSkill(
        team_id=s.team_id,
        name=s.name,
        description=s.description,
        enabled=s.enabled,
        enable_when=s.enable_when,
        tags=s.tags,
    )
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


@router.put("/skills/{sid}", response_model=McpSkillResponse)
def update_skill(
    sid: int,
    s_in: McpSkillUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_write),
    _=Depends(rate_limit),
):
    obj = db.get(McpSkill, sid)
    if not obj:
        raise HTTPException(status_code=404, detail="Skill not found")
    team_ids = get_user_team_ids(db, user)
    if obj.team_id not in team_ids:
        raise HTTPException(status_code=403, detail="Not a member of this team")
    for k, v in s_in.model_dump(exclude_unset=True).items():
        setattr(obj, k, v)
    db.commit()
    db.refresh(obj)
    return obj


@router.delete("/skills/{sid}")
def delete_skill(
    sid: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_write),
    _=Depends(rate_limit),
):
    obj = db.get(McpSkill, sid)
    if not obj:
        raise HTTPException(status_code=404, detail="Skill not found")
    team_ids = get_user_team_ids(db, user)
    if obj.team_id not in team_ids:
        raise HTTPException(status_code=403, detail="Not a member of this team")
    db.delete(obj)
    db.commit()
    return {"ok": True}


@router.get("/skills/{sid}/versions", response_model=List[McpSkillVersionResponse])
def list_skill_versions(
    sid: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    _=Depends(rate_limit),
):
    skill = db.get(McpSkill, sid)
    if not skill:
        raise HTTPException(status_code=404, detail="Skill not found")
    team_ids = get_user_team_ids(db, user)
    if skill.team_id not in team_ids:
        raise HTTPException(status_code=403, detail="Not a member of this team")
    return db.query(McpSkillVersion).filter(McpSkillVersion.skill_id == sid).order_by(McpSkillVersion.version.desc()).all()


@router.post("/skills/{sid}/versions", response_model=McpSkillVersionResponse)
def create_skill_version(
    sid: int,
    v: McpSkillVersionCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_write),
    _=Depends(rate_limit),
):
    skill = db.get(McpSkill, sid)
    if not skill:
        raise HTTPException(status_code=404, detail="Skill not found")
    team_ids = get_user_team_ids(db, user)
    if skill.team_id not in team_ids:
        raise HTTPException(status_code=403, detail="Not a member of this team")
    last = db.query(McpSkillVersion).filter(McpSkillVersion.skill_id == sid).order_by(McpSkillVersion.version.desc()).first()
    version = (last.version + 1) if last else 1
    obj = McpSkillVersion(
        skill_id=sid,
        version=version,
        frontmatter=v.frontmatter,
        body=v.body,
        files=v.files,
        created_by=user.username,
    )
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


@router.post("/skills/{sid}/publish", response_model=McpSkillResponse)
def publish_skill(
    sid: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_write),
    _=Depends(rate_limit),
):
    skill = db.get(McpSkill, sid)
    if not skill:
        raise HTTPException(status_code=404, detail="Skill not found")
    team_ids = get_user_team_ids(db, user)
    if skill.team_id not in team_ids:
        raise HTTPException(status_code=403, detail="Not a member of this team")
    latest = db.query(McpSkillVersion).filter(McpSkillVersion.skill_id == sid).order_by(McpSkillVersion.version.desc()).first()
    if not latest:
        raise HTTPException(status_code=400, detail="No versions to publish")
    skill.published_version_id = latest.id
    db.commit()
    db.refresh(skill)
    return skill


@router.post("/skills/{sid}/rollback", response_model=McpSkillResponse)
def rollback_skill(
    sid: int,
    version: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_write),
    _=Depends(rate_limit),
):
    skill = db.get(McpSkill, sid)
    if not skill:
        raise HTTPException(status_code=404, detail="Skill not found")
    team_ids = get_user_team_ids(db, user)
    if skill.team_id not in team_ids:
        raise HTTPException(status_code=403, detail="Not a member of this team")
    target = db.query(McpSkillVersion).filter(
        McpSkillVersion.skill_id == sid, McpSkillVersion.version == version
    ).first()
    if not target:
        raise HTTPException(status_code=404, detail="Version not found")
    skill.published_version_id = target.id
    db.commit()
    db.refresh(skill)
    return skill


# ==================== Metrics ====================

@router.get("/metrics")
def get_mcp_metrics(
    from_: Optional[datetime] = Query(None, alias="from"),
    to: Optional[datetime] = Query(None),
    step: Optional[int] = Query(None),
    breakdown: str = Query("action"),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    _=Depends(rate_limit),
):
    """Get time-series MCP gateway event metrics with breakdown."""
    from ...services.mcp_metrics import get_mcp_metrics as _get_metrics
    end = to or datetime.now(timezone.utc)
    start = from_ or (end - timedelta(minutes=5))
    return _get_metrics(db, start, end, step, breakdown)


# ==================== Marketplace ====================

@router.get("/marketplace/search", response_model=List[MarketplaceSearchResult])
async def marketplace_search(
    q: str = Query(..., min_length=1),
    manager: str = Query("npm", pattern="^(npm|pypi|all)$"),
    limit: int = Query(20, ge=1, le=50),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    _=Depends(rate_limit),
):
    """Search npm/PyPI for MCP server packages."""
    from ...services.mcp_marketplace import search_marketplace
    results = await search_marketplace(q, manager, limit)
    return results


@router.get("/marketplace/packages", response_model=MarketplacePackageDetails)
async def marketplace_package_details(
    manager: str = Query(..., pattern="^(npm|pypi|all)$"),
    name: str = Query(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    _=Depends(rate_limit),
):
    """Get detailed package information including README and discovered env vars."""
    from ...services.mcp_marketplace import get_package_details
    details = await get_package_details(manager, name)
    if not details:
        raise HTTPException(status_code=404, detail="Package not found")
    return details


@router.post("/marketplace/install", response_model=McpServerResponse)
async def marketplace_install(
    req: MarketplaceInstallRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_write),
    _=Depends(rate_limit),
):
    """Install a package as a new stdio MCP server."""
    from ...services.mcp_marketplace import install_package
    team_ids = get_user_team_ids(db, user)
    if req.team_id not in team_ids:
        raise HTTPException(status_code=403, detail="Not a member of this team")
    try:
        server = await install_package(
            db=db,
            manager=req.package_manager,
            package_name=req.package_name,
            team_id=req.team_id,
            name=req.name,
            namespace=req.namespace,
            display_name=req.display_name,
            env_vars=req.env_vars,
            custom_args=req.custom_args,
            version=req.version,
            user_id=user.id,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Install failed: {e}")
    return _server_to_response(server)


@router.post("/marketplace/uninstall")
async def marketplace_uninstall(
    req: MarketplaceUninstallRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_write),
    _=Depends(rate_limit),
):
    """Uninstall an MCP server package."""
    from ...services.mcp_marketplace import uninstall_package
    server = db.get(McpServer, req.server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    team_ids = get_user_team_ids(db, user)
    if server.team_id not in team_ids:
        raise HTTPException(status_code=403, detail="Not a member of this team")
    ok = uninstall_package(db, req.server_id)
    if not ok:
        raise HTTPException(status_code=400, detail="Cannot uninstall: server is not a marketplace package")
    return {"ok": True}


@router.post("/marketplace/discover-env-vars", response_model=DiscoverEnvVarsResponse)
async def marketplace_discover_env_vars(
    req: DiscoverEnvVarsRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    _=Depends(rate_limit),
):
    """Discover required environment variables for a package."""
    from ...services.mcp_marketplace import discover_env_vars
    env_vars = await discover_env_vars(req.package_manager, req.package_name)
    return DiscoverEnvVarsResponse(env_vars=env_vars)


@router.get("/installations/{sid}", response_model=List[McpInstallationResponse])
def list_installations(
    sid: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    _=Depends(rate_limit),
):
    """Get installation history for a server."""
    server = db.get(McpServer, sid)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    team_ids = get_user_team_ids(db, user)
    if server.team_id not in team_ids:
        raise HTTPException(status_code=403, detail="Not a member of this team")
    from ...services.mcp_marketplace import get_server_installations
    return get_server_installations(db, sid)


# ==================== Upstream OAuth ====================

@router.post("/servers/{sid}/oauth/discover", response_model=OAuthDiscoverResponse)
async def oauth_discover(
    sid: int,
    req: OAuthDiscoverRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_write),
    _=Depends(rate_limit),
):
    """Discover OAuth endpoints for an upstream MCP server."""
    import httpx
    server = db.get(McpServer, sid)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    team_ids = get_user_team_ids(db, user)
    if server.team_id not in team_ids:
        raise HTTPException(status_code=403, detail="Not a member of this team")

    # Try Protected Resource Metadata (RFC 9728)
    base_url = req.url.rstrip("/")
    result: dict = {}
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            # Try .well-known/oauth-protected-resource
            resp = await client.get(f"{base_url}/.well-known/oauth-protected-resource")
            if resp.status_code == 200:
                data = resp.json()
                result["authorization_servers"] = data.get("authorization_servers", [])

                # If authorization_servers found, fetch AS metadata from first one
                auth_servers = data.get("authorization_servers", [])
                if auth_servers:
                    for as_url in auth_servers:
                        as_base = as_url.rstrip("/")
                        as_resp = await client.get(f"{as_base}/.well-known/oauth-authorization-server")
                        if as_resp.status_code == 200:
                            as_data = as_resp.json()
                            result["authorization_endpoint"] = as_data.get("authorization_endpoint")
                            result["token_endpoint"] = as_data.get("token_endpoint")
                            result["registration_endpoint"] = as_data.get("registration_endpoint")
                            result["scopes_supported"] = as_data.get("scopes_supported")
                            result["grant_types_supported"] = as_data.get("grant_types_supported")
                            break

            # Fallback: try .well-known/oauth-authorization-server directly
            if not result.get("authorization_endpoint"):
                resp = await client.get(f"{base_url}/.well-known/oauth-authorization-server")
                if resp.status_code == 200:
                    data = resp.json()
                    result["authorization_endpoint"] = data.get("authorization_endpoint")
                    result["token_endpoint"] = data.get("token_endpoint")
                    result["registration_endpoint"] = data.get("registration_endpoint")
                    result["scopes_supported"] = data.get("scopes_supported")
                    result["grant_types_supported"] = data.get("grant_types_supported")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"OAuth discovery failed: {e}")

    return OAuthDiscoverResponse(**result)


@router.post("/servers/{sid}/oauth/configure", response_model=OAuthStatusResponse)
def oauth_configure(
    sid: int,
    req: OAuthConfigureRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_write),
    _=Depends(rate_limit),
):
    """Configure OAuth credentials for an upstream MCP server."""
    server = db.get(McpServer, sid)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    team_ids = get_user_team_ids(db, user)
    if server.team_id not in team_ids:
        raise HTTPException(status_code=403, detail="Not a member of this team")

    server.oauth_enabled = True
    server.oauth_client_id = req.client_id
    if req.client_secret:
        if not has_secrets_key():
            raise HTTPException(status_code=500, detail="MCP_SECRETS_KEY not configured")
        server.oauth_client_secret_enc = encrypt_secret(req.client_secret)
    server.oauth_scopes = req.scopes
    server.oauth_auth_status = "pending"
    if req.auth_server_metadata_url:
        server.oauth_auth_server_metadata_url = req.auth_server_metadata_url
    if req.protected_resource_metadata_url:
        server.oauth_protected_resource_metadata_url = req.protected_resource_metadata_url
    db.commit()
    db.refresh(server)

    # Regenerate config bundle
    from ...services.mcp_config import write_config_bundle
    try:
        write_config_bundle(db)
    except Exception:
        pass

    return OAuthStatusResponse(
        enabled=True,
        auth_status="pending",
        client_id=server.oauth_client_id,
        scopes=server.oauth_scopes,
    )


@router.get("/servers/{sid}/oauth/status", response_model=OAuthStatusResponse)
def oauth_status(
    sid: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    _=Depends(rate_limit),
):
    """Get OAuth status for an upstream MCP server."""
    server = db.get(McpServer, sid)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    team_ids = get_user_team_ids(db, user)
    if server.team_id not in team_ids:
        raise HTTPException(status_code=403, detail="Not a member of this team")

    # Build authorization URL if pending
    auth_url = None
    if server.oauth_auth_status == "pending" and server.oauth_auth_server_metadata_url:
        import httpx as _httpx
        try:
            resp = _httpx.get(server.oauth_auth_server_metadata_url, timeout=10.0, follow_redirects=True)
            if resp.status_code == 200:
                data = resp.json()
                auth_ep = data.get("authorization_endpoint", "")
                if auth_ep:
                    from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
                    params = {
                        "response_type": "code",
                        "client_id": server.oauth_client_id or "",
                        "redirect_uri": f"/api/v1/mcp/servers/{sid}/oauth/callback",
                    }
                    if server.oauth_scopes:
                        params["scope"] = server.oauth_scopes
                    parsed = urlparse(auth_ep)
                    existing_params = parse_qs(parsed.query)
                    for k, v in existing_params.items():
                        if k not in params:
                            params[k] = v[0]
                    auth_url = urlunparse(parsed._replace(query=urlencode(params)))
        except Exception:
            pass

    return OAuthStatusResponse(
        enabled=server.oauth_enabled or False,
        auth_status=server.oauth_auth_status,
        client_id=server.oauth_client_id,
        scopes=server.oauth_scopes,
        token_expires_at=server.oauth_token_expires_at,
        authorization_url=auth_url,
    )


@router.post("/servers/{sid}/oauth/authorize", response_model=OAuthAuthorizeResponse)
def oauth_authorize(
    sid: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_write),
    _=Depends(rate_limit),
):
    """Get the authorization URL to redirect the user to."""
    server = db.get(McpServer, sid)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    team_ids = get_user_team_ids(db, user)
    if server.team_id not in team_ids:
        raise HTTPException(status_code=403, detail="Not a member of this team")
    if not server.oauth_enabled or not server.oauth_client_id:
        raise HTTPException(status_code=400, detail="OAuth not configured")

    # Get status which builds the auth URL
    status = oauth_status(sid, db, user)
    if not status.authorization_url:
        raise HTTPException(status_code=400, detail="Could not build authorization URL. Ensure auth_server_metadata_url is set.")
    return OAuthAuthorizeResponse(authorization_url=status.authorization_url)


@router.get("/servers/{sid}/oauth/callback")
async def oauth_callback(
    sid: int,
    code: str = Query(...),
    state: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    _=Depends(rate_limit),
):
    """OAuth callback — exchanges authorization code for access token."""
    import httpx
    server = db.get(McpServer, sid)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    if not server.oauth_auth_server_metadata_url:
        raise HTTPException(status_code=400, detail="OAuth not configured")

    # Fetch token endpoint from AS metadata
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            resp = await client.get(server.oauth_auth_server_metadata_url)
            if resp.status_code != 200:
                raise HTTPException(status_code=502, detail="Failed to fetch AS metadata")
            as_data = resp.json()
            token_endpoint = as_data.get("token_endpoint")
            if not token_endpoint:
                raise HTTPException(status_code=400, detail="No token_endpoint in AS metadata")

            # Decrypt client secret
            from ...services.mcp_secrets import decrypt_secret
            client_secret = None
            if server.oauth_client_secret_enc:
                client_secret = decrypt_secret(server.oauth_client_secret_enc)

            # Exchange code for token
            token_resp = await client.post(token_endpoint, data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": server.oauth_client_id or "",
                "client_secret": client_secret or "",
                "redirect_uri": f"/api/v1/mcp/servers/{sid}/oauth/callback",
            })
            if token_resp.status_code != 200:
                server.oauth_auth_status = "error"
                db.commit()
                raise HTTPException(status_code=502, detail=f"Token exchange failed: {token_resp.text}")

            token_data = token_resp.json()
            access_token = token_data.get("access_token")
            refresh_token = token_data.get("refresh_token")
            expires_in = token_data.get("expires_in")

            # Encrypt and store tokens
            if access_token:
                server.oauth_token_enc = encrypt_secret(access_token)
            if refresh_token:
                server.oauth_refresh_token_enc = encrypt_secret(refresh_token)
            if expires_in:
                from datetime import timedelta
                server.oauth_token_expires_at = datetime.now(timezone.utc) + timedelta(seconds=int(expires_in))
            server.oauth_auth_status = "authorized"
            db.commit()

            # Regenerate config bundle
            from ...services.mcp_config import write_config_bundle
            try:
                write_config_bundle(db)
            except Exception:
                pass

            return {"ok": True, "status": "authorized"}
    except HTTPException:
        raise
    except Exception as e:
        server.oauth_auth_status = "error"
        db.commit()
        raise HTTPException(status_code=500, detail=f"OAuth callback failed: {e}")


@router.post("/servers/{sid}/oauth/disable")
def oauth_disable(
    sid: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_write),
    _=Depends(rate_limit),
):
    """Disable OAuth for an upstream MCP server."""
    server = db.get(McpServer, sid)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    team_ids = get_user_team_ids(db, user)
    if server.team_id not in team_ids:
        raise HTTPException(status_code=403, detail="Not a member of this team")

    server.oauth_enabled = False
    server.oauth_auth_status = "not_configured"
    server.oauth_token_enc = None
    server.oauth_refresh_token_enc = None
    server.oauth_token_expires_at = None
    db.commit()

    from ...services.mcp_config import write_config_bundle
    try:
        write_config_bundle(db)
    except Exception:
        pass

    return {"ok": True}


# ==================== Skill Import ====================

@router.post("/skills/import", response_model=McpSkillResponse)
def import_skill_from_url(
    req: McpSkillImportRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_write),
    _=Depends(rate_limit),
):
    """Import a skill from a URL.

    Fetches a SKILL.md file (or a ZIP archive containing one) from a URL,
    parses the YAML frontmatter and markdown body, creates a new skill
    with an initial version, and optionally auto-publishes it.

    Supported URL formats:
    - Raw SKILL.md URL (e.g. https://raw.githubusercontent.com/owner/repo/main/skills/foo/SKILL.md)
    - GitHub shorthand: owner/repo, owner/repo/skills/my-skill, or full github.com URL
    - URL to a .zip archive containing SKILL.md
    """
    import io
    import zipfile
    import httpx

    team_ids = get_user_team_ids(db, user)
    if req.team_id not in team_ids:
        raise HTTPException(status_code=403, detail="Not a member of this team")

    url = req.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    # Resolve GitHub shorthand to a raw SKILL.md URL
    raw_url = _resolve_skill_url(url)
    if not raw_url:
        raise HTTPException(
            status_code=400,
            detail="Could not resolve URL. Provide a direct SKILL.md URL, "
                   "GitHub owner/repo shorthand, or a ZIP archive URL.",
        )

    # Fetch the content
    try:
        resp = httpx.get(raw_url, follow_redirects=True, timeout=30.0)
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Failed to fetch URL: {exc}")

    content_bytes = resp.content
    content_type = resp.headers.get("content-type", "")

    # Determine if we got a ZIP or a raw markdown file
    frontmatter: Dict[str, Any] = {}
    body: str = ""
    files: Optional[Dict[str, str]] = None

    if content_bytes[:4] == b"PK\x03\x04" or "zip" in content_type:
        # ZIP archive — find SKILL.md inside
        try:
            zf = zipfile.ZipFile(io.BytesIO(content_bytes))
        except zipfile.BadZipFile:
            raise HTTPException(status_code=400, detail="Downloaded file is not a valid ZIP archive")

        skill_md_name = None
        for name in zf.namelist():
            if name.endswith("SKILL.md") and not name.startswith("__MACOSX"):
                skill_md_name = name
                break
        if not skill_md_name:
            raise HTTPException(status_code=400, detail="No SKILL.md found in the ZIP archive")

        skill_content = zf.read(skill_md_name).decode("utf-8", errors="replace")
        frontmatter, body = _parse_skill_md(skill_content)

        # Collect other files (skip manifest.json and SKILL.md itself)
        attached: Dict[str, str] = {}
        for name in zf.namelist():
            if name == skill_md_name or name.endswith("/") or name.startswith("__MACOSX"):
                continue
            if name.endswith("manifest.json"):
                continue
            try:
                attached[name] = zf.read(name).decode("utf-8", errors="replace")
            except Exception:
                pass
        if attached:
            files = attached
    else:
        # Raw markdown file
        skill_content = content_bytes.decode("utf-8", errors="replace")
        frontmatter, body = _parse_skill_md(skill_content)

    if not body.strip():
        raise HTTPException(status_code=400, detail="SKILL.md has no body content")

    # Determine skill name
    skill_name = req.name or frontmatter.get("name") or _derive_name_from_url(raw_url)
    # Sanitize: lowercase, replace non-alphanumeric with hyphens
    skill_name = re.sub(r"[^a-z0-9-]", "-", skill_name.lower()).strip("-")
    skill_name = re.sub(r"-+", "-", skill_name)
    if not skill_name or not re.match(r"^[a-z0-9-]+$", skill_name):
        raise HTTPException(status_code=400, detail=f"Invalid skill name derived: '{skill_name}'. Provide a name explicitly.")

    # Check for duplicate name
    existing = db.query(McpSkill).filter(McpSkill.name == skill_name).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"A skill named '{skill_name}' already exists")

    # Use frontmatter description if no explicit description
    description = req.description or frontmatter.get("description")

    # Create the skill
    skill = McpSkill(
        team_id=req.team_id,
        name=skill_name,
        description=description,
        enabled=True,
        tags=req.tags or (frontmatter.get("tags") if isinstance(frontmatter.get("tags"), list) else None),
    )
    db.add(skill)
    db.commit()
    db.refresh(skill)

    # Create version 1
    version = McpSkillVersion(
        skill_id=skill.id,
        version=1,
        frontmatter=frontmatter if frontmatter else None,
        body=body,
        files=files,
        created_by=user.username,
    )
    db.add(version)
    db.commit()
    db.refresh(version)

    # Auto-publish if requested
    if req.auto_publish:
        skill.published_version_id = version.id
        db.commit()
        db.refresh(skill)

    return skill


def _resolve_skill_url(url: str) -> Optional[str]:
    """Resolve various URL formats to a fetchable URL.

    Returns a URL that can be fetched with httpx.get(), or None if the URL
    cannot be resolved.
    """
    # Already a direct URL to a raw file or ZIP
    if url.startswith("http://") or url.startswith("https://"):
        # Raw GitHub URL — convert blob to raw
        if "github.com" in url and "/blob/" in url:
            return url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
        return url

    # GitHub shorthand: owner/repo or owner/repo/path
    if re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", url):
        parts = url.split("/")
        owner = parts[0]
        repo = parts[1]
        # If it's owner/repo with no path, try common skill locations
        if len(parts) == 2:
            # Try skills/<repo-name>/SKILL.md, then SKILL.md at root, then skills/SKILL.md
            candidates = [
                f"https://raw.githubusercontent.com/{owner}/{repo}/main/SKILL.md",
                f"https://raw.githubusercontent.com/{owner}/{repo}/main/skills/SKILL.md",
                f"https://raw.githubusercontent.com/{owner}/{repo}/master/SKILL.md",
                f"https://raw.githubusercontent.com/{owner}/{repo}/main/skills/{repo}/SKILL.md",
            ]
            import httpx
            for candidate in candidates:
                try:
                    r = httpx.head(candidate, follow_redirects=True, timeout=10.0)
                    if r.status_code == 200:
                        return candidate
                except httpx.HTTPError:
                    continue
            return None
        # owner/repo/path/to/skill → raw URL
        path = "/".join(parts[2:])
        # Try main branch first, then master
        for branch in ("main", "master"):
            candidate = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}/SKILL.md"
            if not path.endswith("SKILL.md"):
                candidate = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
            import httpx
            try:
                r = httpx.head(candidate, follow_redirects=True, timeout=10.0)
                if r.status_code == 200:
                    return candidate
            except httpx.HTTPError:
                continue
        return None

    return None


def _parse_skill_md(content: str) -> tuple:
    """Parse a SKILL.md file into (frontmatter_dict, body_string).

    SKILL.md files use YAML frontmatter delimited by --- lines:
    ---
    name: my-skill
    description: Does stuff
    ---
    # Markdown body...
    """
    frontmatter: Dict[str, Any] = {}
    body = content

    if content.startswith("---"):
        parts = content[3:].split("---", 1)
        if len(parts) == 2:
            yaml_text = parts[0].strip()
            body = parts[1].lstrip("\n")
            try:
                parsed = yaml.safe_load(yaml_text)
                if isinstance(parsed, dict):
                    frontmatter = parsed
            except yaml.YAMLError:
                pass

    return frontmatter, body


def _derive_name_from_url(url: str) -> str:
    """Derive a skill name from a URL path."""
    from urllib.parse import urlparse, unquote
    parsed = urlparse(url)
    path = unquote(parsed.path)
    # Get the last meaningful path segment
    segments = [s for s in path.split("/") if s]
    if not segments:
        return "imported-skill"
    # If last segment is SKILL.md, use the parent directory
    if segments[-1] == "SKILL.md":
        segments = segments[:-1]
    if segments:
        return segments[-1]
    return "imported-skill"


# ==================== Skill Export ====================

@router.post("/skills/{sid}/export")
def export_skill(
    sid: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    _=Depends(rate_limit),
):
    """Export a skill as a downloadable ZIP package (Anthropic Skill format)."""
    import io
    import zipfile

    skill = db.get(McpSkill, sid)
    if not skill:
        raise HTTPException(status_code=404, detail="Skill not found")
    team_ids = get_user_team_ids(db, user)
    if skill.team_id not in team_ids:
        raise HTTPException(status_code=403, detail="Not a member of this team")

    # Get published version
    pv = None
    if skill.published_version_id:
        pv = db.get(McpSkillVersion, skill.published_version_id)
    if not pv:
        raise HTTPException(status_code=400, detail="No published version to export")

    # Build SKILL.md content
    frontmatter = pv.frontmatter or {}
    if not frontmatter.get("name"):
        frontmatter["name"] = skill.name
    if not frontmatter.get("description") and skill.description:
        frontmatter["description"] = skill.description

    skill_md = f"---\n{yaml.dump(frontmatter, default_flow_style=False)}---\n\n{pv.body}\n"

    # Build ZIP
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("SKILL.md", skill_md)
        # Include attached files
        if pv.files:
            for filename, content in pv.files.items():
                if isinstance(content, str):
                    zf.writestr(filename, content)
                else:
                    zf.writestr(filename, _json.dumps(content, indent=2))
        # Include a manifest
        zf.writestr("manifest.json", _json.dumps({
            "skill_name": skill.name,
            "version": pv.version,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "exported_by": user.username,
        }, indent=2))

    buf.seek(0)
    filename = f"{skill.name}-v{pv.version}.zip"
    from fastapi import Response
    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ==================== Events ====================

@router.get("/events", response_model=McpEventListResponse)
def list_events(
    from_ts: Optional[str] = Query(None, alias="from"),
    to_ts: Optional[str] = Query(None, alias="to"),
    action: Optional[str] = Query(None),
    method: Optional[str] = Query(None, alias="method"),
    identity_id: Optional[int] = Query(None),
    server_id: Optional[int] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    _=Depends(rate_limit),
):
    """List MCP gateway events with optional filters."""
    team_ids = get_user_team_ids(db, user)
    q = db.query(McpEvent)
    if team_ids:
        q = q.filter(McpEvent.team_id.in_(team_ids))
    if from_ts:
        try:
            q = q.filter(McpEvent.captured_at >= datetime.fromisoformat(from_ts.replace("Z", "+00:00")))
        except Exception:
            pass
    if to_ts:
        try:
            q = q.filter(McpEvent.captured_at <= datetime.fromisoformat(to_ts.replace("Z", "+00:00")))
        except Exception:
            pass
    if action:
        q = q.filter(McpEvent.action == action)
    if method:
        q = q.filter(McpEvent.jsonrpc_method == method)
    if identity_id:
        q = q.filter(McpEvent.identity_id == identity_id)
    if server_id:
        q = q.filter(McpEvent.server_id == server_id)
    total = q.count()
    events = q.order_by(McpEvent.captured_at.desc()).offset(offset).limit(limit).all()
    return McpEventListResponse(events=events, total=total)


# ==================== Sessions ====================

@router.get("/sessions", response_model=SessionListResponse)
def list_sessions(
    identity_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    _=Depends(rate_limit),
):
    """List active MCP gateway sessions from Valkey."""
    import json
    client = get_valkey_client()
    if not client:
        return SessionListResponse(sessions=[], total=0)
    sessions = []
    try:
        for key in client.scan_iter("mcp:sess:*"):
            raw = client.get(key)
            if raw:
                data = json.loads(raw)
                if identity_id and data.get("identity_id") != identity_id:
                    continue
                session_id = key.split("mcp:sess:", 1)[1]
                sessions.append(SessionInfo(
                    session_id=session_id,
                    identity_id=data.get("identity_id", 0),
                    team_id=data.get("team_id"),
                    created_at=data.get("created_at", ""),
                    last_activity=data.get("last_activity"),
                    server_sessions=data.get("server_sessions"),
                ))
    except Exception:
        pass
    return SessionListResponse(sessions=sessions, total=len(sessions))


@router.delete("/sessions/{session_id}")
def revoke_session(
    session_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_write),
    _=Depends(rate_limit),
):
    """Revoke a specific MCP gateway session."""
    client = get_valkey_client()
    if not client:
        raise HTTPException(status_code=503, detail="Session store unavailable")
    key = f"mcp:sess:{session_id}"
    if not client.exists(key):
        raise HTTPException(status_code=404, detail="Session not found")
    client.delete(key)
    return {"ok": True}


@router.post("/identities/{iid}/revoke")
def revoke_identity_tokens(
    iid: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_write),
    _=Depends(rate_limit),
):
    """Revoke all tokens and sessions for an identity."""
    identity = db.get(McpIdentity, iid)
    if not identity:
        raise HTTPException(status_code=404, detail="Identity not found")
    team_ids = get_user_team_ids(db, user)
    if identity.team_id not in team_ids:
        raise HTTPException(status_code=403, detail="Not a member of this team")

    # Revoke via Valkey if available
    client = get_valkey_client()
    if client:
        import json
        import time
        try:
            # Set identity-level revocation
            client.set(f"mcp:rev:identity:{iid}", str(time.time()))
            # Delete all sessions for this identity
            for key in client.scan_iter("mcp:sess:*"):
                raw = client.get(key)
                if raw:
                    data = json.loads(raw)
                    if data.get("identity_id") == iid:
                        client.delete(key)
        except Exception:
            pass

    return {"ok": True}


# ==================== Config Status ====================

@router.get("/config/status", response_model=ConfigStatusResponse)
def config_status(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    _=Depends(rate_limit),
):
    """Get MCP config bundle status."""
    config_path = os.environ.get("MCP_CONFIG_PATH", "/app/data/mcp/config.json")
    last_generated = None
    bundle_size = None
    try:
        if os.path.exists(config_path):
            stat = os.stat(config_path)
            last_generated = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()
            bundle_size = stat.st_size
    except Exception:
        pass
    return ConfigStatusResponse(
        last_generated=last_generated,
        bundle_size=bundle_size,
        config_path=config_path,
    )


@router.post("/config/regenerate")
def regenerate_config(
    db: Session = Depends(get_db),
    user: User = Depends(require_write),
    _=Depends(rate_limit),
):
    """Manually regenerate the MCP config bundle."""
    from ...services.mcp_config import write_config_bundle
    try:
        write_config_bundle(db)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Config regeneration failed: {e}")
    return {"ok": True}


# ==================== Alerts ====================

@router.get("/alerts/config", response_model=AlertConfigResponse)
def get_alert_config(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    _=Depends(rate_limit),
):
    """Get alerting configuration."""
    webhook_url = os.environ.get("MCP_ALERT_WEBHOOK_URL", "")
    # Read thresholds from settings table if available
    thresholds: dict[str, int] = {}
    try:
        from ...models.models import Setting
        row = db.query(Setting).filter(Setting.key == "mcp_alert_thresholds").first()
        if row and row.value:
            thresholds = _json.loads(row.value)
    except Exception:
        pass
    return AlertConfigResponse(webhook_url=webhook_url or None, thresholds=thresholds)


@router.put("/alerts/config", response_model=AlertConfigResponse)
def update_alert_config(
    cfg: AlertConfigUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_write),
    _=Depends(rate_limit),
):
    """Update alerting configuration."""
    from ...models.models import Setting
    # Store thresholds in settings table
    try:
        row = db.query(Setting).filter(Setting.key == "mcp_alert_thresholds").first()
        if row:
            row.value = _json.dumps(cfg.thresholds)
        else:
            row = Setting(key="mcp_alert_thresholds", value=_json.dumps(cfg.thresholds))
            db.add(row)
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to save alert config: {e}")
    # Webhook URL is env-based; return what was requested
    return AlertConfigResponse(webhook_url=cfg.webhook_url, thresholds=cfg.thresholds)


@router.get("/alerts/history", response_model=List[AlertHistoryItem])
def alert_history(
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    _=Depends(rate_limit),
):
    """Get recent alert history."""
    # Alerts are logged as McpEvent entries with specific actions
    team_ids = get_user_team_ids(db, user)
    alert_actions = ["guardrail_blocked", "dlp_blocked", "policy_denied", "auth_failed", "rate_limited"]
    q = db.query(McpEvent).filter(McpEvent.action.in_(alert_actions))
    if team_ids:
        q = q.filter(McpEvent.team_id.in_(team_ids))
    events = q.order_by(McpEvent.captured_at.desc()).limit(limit).all()
    return [
        AlertHistoryItem(
            id=e.id,
            event_type=e.action or "unknown",
            message=e.error or f"{e.action} on {e.jsonrpc_method or 'unknown'}",
            created_at=e.captured_at,
            webhook_sent=False,
            webhook_status=None,
        )
        for e in events
    ]


# ==================== Server Catalog ====================

@router.get("/servers/{sid}/catalog", response_model=ServerCatalogResponse)
def get_server_catalog(
    sid: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    _=Depends(rate_limit),
):
    """Get cached catalog (tools/resources/prompts) for a server."""
    import json
    server = db.get(McpServer, sid)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    team_ids = get_user_team_ids(db, user)
    if server.team_id not in team_ids:
        raise HTTPException(status_code=403, detail="Not a member of this team")

    tools: list = []
    resources: list = []
    prompts: list = []
    last_refresh = None

    # Try Valkey first
    client = get_valkey_client()
    if client:
        try:
            raw = client.get(f"mcp:catalog:{sid}")
            if raw:
                catalog = json.loads(raw)
                tools = catalog.get("tools", [])
                resources = catalog.get("resources", [])
                prompts = catalog.get("prompts", [])
        except Exception:
            pass

    # Fallback: use last_catalog_at from server
    if server.last_catalog_at:
        last_refresh = server.last_catalog_at.isoformat() if hasattr(server.last_catalog_at, 'isoformat') else str(server.last_catalog_at)

    return ServerCatalogResponse(
        server_id=sid,
        tools=tools,
        resources=resources,
        prompts=prompts,
        last_refresh=last_refresh,
    )
