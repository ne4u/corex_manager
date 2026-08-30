"""MCP Marketplace service.

Search npm and PyPI for MCP server packages, install them as stdio MCP servers,
and track installation status. Supports env var discovery from package READMEs.
"""
import asyncio
import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from typing import Optional

import httpx
from sqlalchemy.orm import Session

from ..models.mcp import McpServer, McpInstallation
from .mcp_secrets import encrypt_secret
from .mcp_config import write_config_bundle

logger = logging.getLogger(__name__)

NPM_REGISTRY = "https://registry.npmjs.org"
NPM_SEARCH = "https://registry.npmjs.org/-/v1/search"
PYPI_SIMPLE = "https://pypi.org/simple"
PYPI_JSON = "https://pypi.org/pypi"
PYPI_SEARCH = "https://pypi.org/search"

# Timeout for registry HTTP calls
_REGISTRY_TIMEOUT = 15.0


async def search_npm(query: str, limit: int = 20) -> list[dict]:
    """Search npm registry for MCP-related packages."""
    results: list[dict] = []
    try:
        async with httpx.AsyncClient(timeout=_REGISTRY_TIMEOUT) as client:
            # Use npm search API
            search_query = f"mcp {query}" if "mcp" not in query.lower() else query
            resp = await client.get(NPM_SEARCH, params={"text": search_query, "size": min(limit * 2, 50)})
            if resp.status_code != 200:
                logger.warning("npm search returned %d", resp.status_code)
                return results

            data = resp.json()
            for obj in data.get("objects", []):
                pkg = obj.get("package", {})
                name = pkg.get("name", "")
                # Filter for MCP-related packages
                if not _is_mcp_package_npm(name, pkg.get("keywords", [])):
                    continue
                results.append({
                    "name": name,
                    "description": pkg.get("description"),
                    "version": pkg.get("version"),
                    "homepage": pkg.get("links", {}).get("homepage"),
                    "repository_url": pkg.get("links", {}).get("repository"),
                    "author": pkg.get("publisher", {}).get("username") if isinstance(pkg.get("publisher"), dict) else str(pkg.get("author", "")),
                    "license": pkg.get("license"),
                    "keywords": pkg.get("keywords", []),
                    "downloads": None,
                    "score": obj.get("searchScore", 0),
                })
                if len(results) >= limit:
                    break
    except Exception as e:
        logger.error("npm search error: %s", e)
    return results


async def search_pypi(query: str, limit: int = 20) -> list[dict]:
    """Search PyPI for MCP-related packages."""
    results: list[dict] = []
    try:
        async with httpx.AsyncClient(timeout=_REGISTRY_TIMEOUT, follow_redirects=True) as client:
            # PyPI doesn't have a great search API; use the XMLRPC-like search via pypi.org/search
            resp = await client.get(
                PYPI_SEARCH,
                params={"q": f"mcp {query}" if "mcp" not in query.lower() else query},
            )
            if resp.status_code != 200:
                logger.warning("pypi search returned %d", resp.status_code)
                return results

            # Parse the HTML search results (PyPI search returns HTML)
            text = resp.text
            # Extract package names from the search results page
            package_links = re.findall(r'/package/([a-zA-Z0-9_.-]+)/?', text)
            seen = set()
            for name in package_links:
                if name in seen:
                    continue
                seen.add(name)
                if not _is_mcp_package_pypi(name):
                    continue
                # Fetch package metadata
                try:
                    meta_resp = await client.get(f"{PYPI_JSON}/{name}/json")
                    if meta_resp.status_code == 200:
                        meta = meta_resp.json()
                        info = meta.get("info", {})
                        results.append({
                            "name": name,
                            "description": info.get("summary"),
                            "version": info.get("version"),
                            "homepage": info.get("home_page"),
                            "repository_url": info.get("project_urls", {}).get("Source", info.get("project_urls", {}).get("Repository")),
                            "author": info.get("author"),
                            "license": info.get("license"),
                            "keywords": (info.get("keywords") or "").split(",") if info.get("keywords") else [],
                            "downloads": None,
                            "score": None,
                        })
                except Exception:
                    pass
                if len(results) >= limit:
                    break
    except Exception as e:
        logger.error("pypi search error: %s", e)
    return results


def _is_mcp_package_npm(name: str, keywords: list[str]) -> bool:
    """Check if an npm package is MCP-related."""
    name_lower = name.lower()
    if "mcp" in name_lower or "model-context-protocol" in name_lower:
        return True
    if keywords and any("mcp" in k.lower() or "model-context-protocol" in k.lower() for k in keywords):
        return True
    return False


def _is_mcp_package_pypi(name: str) -> bool:
    """Check if a PyPI package is MCP-related."""
    name_lower = name.lower()
    return "mcp" in name_lower or "model-context-protocol" in name_lower


def _extract_author(author) -> str:
    """Extract author name from npm registry response (dict, string, or None)."""
    if not author:
        return ""
    if isinstance(author, dict):
        return author.get("name", "") or author.get("email", "")
    return str(author)


async def search_marketplace(query: str, manager: str = "npm", limit: int = 20) -> list[dict]:
    """Search the marketplace for MCP packages."""
    if manager == "npm":
        return await search_npm(query, limit)
    elif manager == "pypi":
        return await search_pypi(query, limit)
    else:
        # Search both
        npm_results = await search_npm(query, limit)
        pypi_results = await search_pypi(query, limit)
        return npm_results + pypi_results


async def get_package_details(manager: str, name: str) -> Optional[dict]:
    """Get detailed package information including README and discovered env vars."""
    if manager == "all":
        # Try npm first, then pypi
        result = await get_package_details("npm", name)
        if result:
            return result
        return await get_package_details("pypi", name)
    try:
        async with httpx.AsyncClient(timeout=_REGISTRY_TIMEOUT, follow_redirects=True) as client:
            if manager == "npm":
                resp = await client.get(f"{NPM_REGISTRY}/{name}")
                if resp.status_code != 200:
                    return None
                data = resp.json()
                latest = data.get("dist-tags", {}).get("latest")
                version_data = data.get("versions", {}).get(latest, {})
                readme = data.get("readme", "")
                if not readme or readme == "No README data.":
                    readme = version_data.get("readme", "")

                env_vars = _discover_env_vars_from_readme(readme)

                return {
                    "name": name,
                    "version": latest,
                    "description": data.get("description"),
                    "homepage": data.get("homepage"),
                    "repository_url": data.get("repository", {}).get("url") if isinstance(data.get("repository"), dict) else str(data.get("repository", "")),
                    "author": _extract_author(data.get("author")),
                    "license": data.get("license"),
                    "keywords": data.get("keywords", []),
                    "dependencies": version_data.get("dependencies", {}),
                    "readme": readme[:10000] if readme else None,
                    "required_env_vars": env_vars,
                }
            elif manager == "pypi":
                resp = await client.get(f"{PYPI_JSON}/{name}/json")
                if resp.status_code != 200:
                    return None
                data = resp.json()
                info = data.get("info", {})

                # Fetch README from long_description
                readme = info.get("description", "")
                env_vars = _discover_env_vars_from_readme(readme)

                return {
                    "name": name,
                    "version": info.get("version"),
                    "description": info.get("summary"),
                    "homepage": info.get("home_page"),
                    "repository_url": info.get("project_urls", {}).get("Source", info.get("project_urls", {}).get("Repository")),
                    "author": info.get("author"),
                    "license": info.get("license"),
                    "keywords": (info.get("keywords") or "").split(",") if info.get("keywords") else [],
                    "dependencies": info.get("requires_dist", {}),
                    "readme": readme[:10000] if readme else None,
                    "required_env_vars": env_vars,
                }
    except Exception as e:
        logger.error("get_package_details error: %s", e)
    return None


def _discover_env_vars_from_readme(readme: str) -> list[str]:
    """Discover required environment variables from a package README.

    Looks for patterns like:
    - JSON "env" blocks: `"ENV_VAR_NAME": "value"`
    - `ENV_VAR_NAME=...`
    - `export ENV_VAR_NAME=...`
    - `--env ENV_VAR_NAME`
    - `ENV_VAR_NAME: your_value`
    """
    if not readme:
        return []

    env_vars: list[str] = []
    seen = set()

    # Pattern: JSON env block values — "SOME_VAR": "..." (most common in MCP READMEs)
    # and standalone UPPERCASE_WITH_UNDERSCORES assignments
    patterns = [
        r'"([A-Z][A-Z0-9_]{2,})"\s*:\s*["\']',  # JSON: "VAR_NAME": "value"
        r'(?:export\s+)?([A-Z][A-Z0-9_]{2,})\s*=',  # export VAR= or VAR=
        r'--env\s+([A-Z][A-Z0-9_]{2,})',           # --env VAR
        r'`([A-Z][A-Z0-9_]{2,})`\s*[:=]',          # `VAR`: or `VAR`=
    ]

    for pattern in patterns:
        for match in re.finditer(pattern, readme):
            var_name = match.group(1).upper()
            # Filter out common false positives
            if var_name in ("README", "MIT", "APACHE", "GPL", "BSD", "JSON", "HTTP", "HTTPS", "URL", "API", "ID", "UUID", "TRUE", "FALSE", "NULL", "NONE", "ENV", "YAML", "XML"):
                continue
            if var_name not in seen:
                seen.add(var_name)
                env_vars.append(var_name)

    return env_vars[:20]  # Limit to 20


async def discover_env_vars(manager: str, package_name: str) -> list[str]:
    """Discover required env vars for a package."""
    details = await get_package_details(manager, package_name)
    if details and details.get("required_env_vars"):
        return details["required_env_vars"]
    return []


def _build_command_for_package(manager: str, package_name: str, version: Optional[str] = None, custom_args: Optional[list[str]] = None) -> tuple[str, list[str]]:
    """Build the command and args for running an MCP server package."""
    if manager == "npm":
        command = "npx"
        args = ["-y"]
        if version:
            args.append(f"{package_name}@{version}")
        else:
            args.append(package_name)
    elif manager == "pypi":
        command = "uvx"
        if version:
            args.append(f"{package_name}=={version}")
        else:
            args.append(package_name)
    else:
        command = "npx"
        args = ["-y", package_name]

    if custom_args:
        args.extend(custom_args)

    return command, args


async def install_package(
    db: Session,
    manager: str,
    package_name: str,
    team_id: int,
    name: Optional[str] = None,
    namespace: Optional[str] = None,
    display_name: Optional[str] = None,
    env_vars: Optional[dict[str, str]] = None,
    custom_args: Optional[list[str]] = None,
    version: Optional[str] = None,
    user_id: Optional[int] = None,
) -> McpServer:
    """Install a package as a new stdio MCP server.

    Creates the McpServer record, creates an McpInstallation tracking record,
    and triggers config bundle regeneration.
    """
    # Generate server name from package name if not provided
    if not name:
        name = package_name.replace("@", "").replace("/", "-").replace("_", "-").lower()
        # Remove common prefixes
        for prefix in ("mcp-server-", "mcp-", "model-context-protocol-"):
            if name.startswith(prefix):
                name = name[len(prefix):]
                break
        name = f"mcp-{name}"

    if not namespace:
        namespace = name

    # Build command and args
    command, args = _build_command_for_package(manager, package_name, version, custom_args)

    # Encrypt env var values
    env_vars_json = None
    if env_vars:
        encrypted_env = {}
        for k, v in env_vars.items():
            if v:
                try:
                    encrypted_env[k] = encrypt_secret(v)
                except Exception:
                    encrypted_env[k] = v
        env_vars_json = json.dumps(encrypted_env)

    # Get package version if not specified
    if not version:
        try:
            details = await get_package_details(manager, package_name)
            if details:
                version = details.get("version")
        except Exception:
            pass

    # Create the McpServer record
    server = McpServer(
        team_id=team_id,
        name=name,
        display_name=display_name or package_name,
        description=f"Installed from {manager}: {package_name}",
        url=None,
        enabled=True,
        transport_type="stdio",
        command=command,
        args_json=json.dumps(args),
        env_vars_json=env_vars_json,
        package_manager=manager,
        source_package_name=package_name,
        installed_version=version,
        installer_user_id=user_id,
        health_status="unknown",
        namespace=namespace,
    )
    db.add(server)
    db.flush()  # Get the server ID

    # Create installation tracking record
    installation = McpInstallation(
        server_id=server.id,
        package_manager=manager,
        package_name=package_name,
        version=version,
        status="completed",  # Package is installed via npx/uvx at runtime
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        output=f"Server created with command: {command} {' '.join(args)}",
    )
    db.add(installation)
    db.commit()

    # Regenerate config bundle
    try:
        write_config_bundle(db)
    except Exception as e:
        logger.error("Failed to write config bundle after install: %s", e)

    return server


def uninstall_package(db: Session, server_id: int) -> bool:
    """Uninstall an MCP server package.

    Deletes the server record and its installations. The config bundle is
    regenerated to remove the server from the gateway.
    """
    server = db.query(McpServer).filter(McpServer.id == server_id).first()
    if not server:
        return False

    # Only allow uninstall of marketplace-installed servers
    if not server.package_manager or server.package_manager == "none":
        return False

    # Delete the server (cascade will handle installations)
    db.delete(server)
    db.commit()

    # Regenerate config bundle
    try:
        write_config_bundle(db)
    except Exception as e:
        logger.error("Failed to write config bundle after uninstall: %s", e)

    return True


def get_installation_status(db: Session, installation_id: int) -> Optional[McpInstallation]:
    """Get the status of an installation task."""
    return db.query(McpInstallation).filter(McpInstallation.id == installation_id).first()


def get_server_installations(db: Session, server_id: int) -> list[McpInstallation]:
    """Get all installation records for a server."""
    return db.query(McpInstallation).filter(McpInstallation.server_id == server_id).order_by(McpInstallation.created_at.desc()).all()
