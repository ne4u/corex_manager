#!/usr/bin/env python3
"""Deploy coreX Manager to a remote Linux Docker host.

Prompts for host, SSH user, SSH password, and (optionally) sudo password, then
rsyncs the project and runs selective `docker compose build` / `docker compose
up -d` on the remote host — only rebuilding/restarting services whose files
changed since the last deploy.

Usage:
    python3 deploy.py
    python3 deploy.py --host 1.2.3.4 --user admin --remote-path /opt/corex_manager
    python3 deploy.py --dry-run
    python3 deploy.py --force-rebuild corex
    python3 deploy.py --force-rebuild all

Requirements (local):
    python3, ssh, rsync, sshpass

Remote requirements:
    docker with compose plugin, user able to run `docker` either directly or
    via passwordless/sudo access.
"""
import argparse
import getpass
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_REMOTE_PATH = "/opt/corex_manager"
MANIFEST_FILENAME = ".deploy-manifest.json"
SSH_OPTS = [
    # accept-new: automatically accept and record new host keys on first
    # connection, but refuse to connect if a known key has changed (MITM
    # protection). Safer than StrictHostKeyChecking=no.
    "-o", "StrictHostKeyChecking=accept-new",
    "-o", "LogLevel=ERROR",
]


RSYNC_EXCLUDES = [
    ".git",
    ".gitignore",
    ".env",
    ".DS_Store",
    "__pycache__",
    "*.pyc",
    ".venv",
    ".venv-*",
    "venv",
    "node_modules",
    # Rust build artifacts. Each haproxy/*/ crate has its own `target/` dir
    # (~2.3 GB combined) which is gitignored per-crate but would otherwise be
    # rsynced and land in the haproxy Docker build context. They are also
    # host-arch (macOS) artifacts, useless to the alpine Rust builder stages.
    # Excluding them additionally keeps change detection honest: a local
    # `cargo build` would otherwise flag the corex service for rebuild on
    # every deploy. `_is_excluded` matches any path component, so this bare
    # entry covers all crates.
    "target",
    "frontend/dist",
    "__tests__",
    "*.test.*",
    "*.spec.*",
    "backend/tests",
    "frontend/vitest.config.ts",
    "frontend/src/test-setup.ts",
    "frontend/src/vitest-globals.d.ts",
    # Runtime directories — never synced.
    # `data/` is a named Docker volume (haproxy-data); the host dir is local-dev only.
    # `certs/` is a bind mount but its contents are runtime-managed (acme.sh, backend);
    # the deploy script only ensures the directory exists (see mkdir in main()).
    "data/",
    "certs/",
    # Git backup directories (from history rewrites)
    ".git.backup.*",
    # Dev-only files — not needed in production
    "AGENTS.md",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    "deploy.py",
    "deploy.md",
    "TODO.md",
    "requirements-dev.txt",
    ".devin",
    "docs",
    # Deploy manifest — managed by this script, not synced via rsync
    MANIFEST_FILENAME,
]


# ---------------------------------------------------------------------------
# Service → path mapping
# ---------------------------------------------------------------------------
# Maps each Docker Compose service to the file paths that trigger a rebuild
# (Dockerfile COPY paths baked into the image) vs a restart-only (bind-mounted
# paths that are updated by rsync at runtime).
#
# Path matching is prefix-based: a changed file `haproxy/req_fp/src/lib.rs`
# matches the `haproxy/` prefix, so the `corex` service needs a rebuild.
#
# Derived from:
# - backend/Dockerfile: COPY requirements.txt, backend/app, backend/entrypoint.sh
# - frontend/Dockerfile: COPY . . (entire frontend/ context)
# - haproxy/Dockerfile: COPY haproxy/* (all subdirs + lua + entrypoint.sh)
# - docker-compose.yml volumes: ./backend/app:/app/app (bind mount)

SERVICE_PATHS: dict[str, dict[str, list[str]]] = {
    "api": {
        # Files baked into the image via Dockerfile COPY — changes require rebuild
        "rebuild": ["backend/Dockerfile", "requirements.txt", "backend/entrypoint.sh"],
        # Bind-mounted paths — changes only need a container restart
        "restart": ["backend/app/"],
    },
    "corex": {
        # Entire haproxy/ dir is COPYed into the image (Dockerfile + Rust modules + lua)
        "rebuild": ["haproxy/"],
        "restart": [],
    },
    "frontend": {
        # Entire frontend/ dir is the build context (COPY . .)
        "rebuild": ["frontend/"],
        "restart": [],
    },
    "coraza-spoa-init": {
        # No build (uses busybox image); init.sh and coraza-spoa.yaml are bind-mounted
        "rebuild": [],
        "restart": ["coraza-spoa/"],
    },
    "coraza-spoa": {
        # No build; restarted as a dependency of coraza-spoa-init
        "rebuild": [],
        "restart": [],
    },
}

# Services that have a Dockerfile (can be rebuilt)
BUILDABLE_SERVICES = {"api", "corex", "frontend"}

# Files that trigger a full redeploy (all services) when changed.
# `.env` is deliberately absent: it is in RSYNC_EXCLUDES (so it is never hashed
# and could never appear in the change set) and the remote copy is seeded once
# from .env.example and then owned by the host. Edit the remote .env by hand and
# use --force-rebuild to pick it up.
FULL_REDEPLOY_PATHS = {"docker-compose.yml", ".env.example"}


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _require(name: str):
    if not shutil.which(name):
        print(f"Error: '{name}' is not installed or not on PATH.", file=sys.stderr)
        sys.exit(1)


def _run(cmd: list[str], env: dict | None = None, input_text: str | None = None) -> tuple[int, str]:
    """Run a local command and return (exit_code, stdout+stderr)."""
    p = subprocess.run(
        cmd,
        env=env,
        input=input_text,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return p.returncode, (p.stdout or "")


def _ssh_cmd(host: str, user: str, command: str, ssh_pass: str, input_text: str | None = None) -> int:
    """Run a remote command using sshpass with SSH password from env."""
    env = os.environ.copy()
    env["SSHPASS"] = ssh_pass
    args = ["sshpass", "-e", "ssh"] + SSH_OPTS + [f"{user}@{host}", command]
    p = subprocess.Popen(
        args,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    out, _ = p.communicate(input=input_text)
    if out:
        print(out, end="")
    return p.returncode


def _ssh_capture(host: str, user: str, command: str, ssh_pass: str, input_text: str | None = None) -> tuple[int, str]:
    """Run a remote command and capture stdout (no printing). Returns (exit_code, stdout)."""
    env = os.environ.copy()
    env["SSHPASS"] = ssh_pass
    args = ["sshpass", "-e", "ssh"] + SSH_OPTS + [f"{user}@{host}", command]
    p = subprocess.Popen(
        args,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    out, _ = p.communicate(input=input_text)
    return p.returncode, (out or "")


def _rsync(host: str, user: str, remote_path: str, ssh_pass: str) -> int:
    """Rsync project to remote host."""
    env = os.environ.copy()
    env["SSHPASS"] = ssh_pass

    # Build the ssh command string for rsync
    ssh_cmd = "ssh " + " ".join(shlex.quote(o) for o in SSH_OPTS)
    cmd = ["sshpass", "-e", "rsync", "-avz", "--delete", "-e", ssh_cmd]
    for ex in RSYNC_EXCLUDES:
        cmd.extend(["--exclude", ex])
    cmd.append(f"{PROJECT_ROOT}/")
    cmd.append(f"{user}@{host}:{remote_path}")

    print(f"Rsyncing project to {user}@{host}:{remote_path} ...")
    rc, out = _run(cmd, env=env)
    if out:
        print(out, end="")
    return rc


def _detect_sudo(host: str, user: str, ssh_pass: str, sudo_pass: str) -> str | None:
    """Return shell prefix needed to run docker on the remote host."""
    # Plain docker access
    if _ssh_cmd(host, user, "docker ps -q", ssh_pass) == 0:
        return ""

    # Passwordless sudo
    if _ssh_cmd(host, user, "sudo -n docker ps -q", ssh_pass) == 0:
        return "sudo -n "

    # Sudo with password
    if sudo_pass:
        test = f"SUDO_PW={shlex.quote(sudo_pass)}; cd / && echo \"$SUDO_PW\" | sudo -S docker ps -q"
        if _ssh_cmd(host, user, test, ssh_pass) == 0:
            return f"SUDO_PW={shlex.quote(sudo_pass)}; export SUDO_PW; echo \"$SUDO_PW\" | sudo -S "

    print("Error: remote user cannot run docker with the provided credentials.", file=sys.stderr)
    return None


def _remote_docker(host: str, user: str, ssh_pass: str, sudo_prefix: str, remote_path: str, *commands: str) -> int:
    """Run docker commands on the remote host inside the deploy directory."""
    joined = "; ".join(commands)
    if sudo_prefix:
        command = f"{sudo_prefix}bash -c {shlex.quote(f'cd {shlex.quote(remote_path)} && {joined}')}"
    else:
        command = f"cd {shlex.quote(remote_path)} && {joined}"
    return _ssh_cmd(host, user, command, ssh_pass)


def _prompt(args: argparse.Namespace) -> tuple[str, str, str, str, str]:
    host = args.host or input("Remote host (IP or hostname): ").strip()
    user = args.user or input("Remote user with sudo access: ").strip()
    ssh_password = args.password or getpass.getpass("SSH password: ")
    if not ssh_password:
        print("Error: SSH password is required.", file=sys.stderr)
        sys.exit(1)
    sudo_password = args.sudo_password or getpass.getpass(
        "Sudo password (leave empty to use SSH password): "
    )
    if not sudo_password:
        sudo_password = ssh_password
    remote_path = args.remote_path or DEFAULT_REMOTE_PATH
    return host, user, ssh_password, sudo_password, remote_path


# ---------------------------------------------------------------------------
# Change detection
# ---------------------------------------------------------------------------

def _is_excluded(rel_path: str, excludes: list[str]) -> bool:
    """Check if a relative path matches any rsync exclude pattern."""
    parts = Path(rel_path).parts
    for ex in excludes:
        # Match against the full path and each component
        if fnmatch(rel_path, ex) or fnmatch(rel_path, ex + "/*"):
            return True
        for part in parts:
            if fnmatch(part, ex):
                return True
        # Also match directory excludes (e.g., "data/" matches "data/anything")
        ex_clean = ex.rstrip("/")
        for i in range(len(parts)):
            if fnmatch("/".join(parts[: i + 1]), ex_clean):
                return True
    return False


def _compute_file_hashes(root: Path, excludes: list[str]) -> dict[str, str]:
    """Walk the project tree and compute SHA-256 of each file.

    Returns a dict mapping relative path (forward-slash) to "sha256:hexdigest".
    Skips files matching the rsync exclude patterns.
    """
    hashes: dict[str, str] = {}
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if _is_excluded(rel, excludes):
            continue
        try:
            h = hashlib.sha256(path.read_bytes()).hexdigest()
            hashes[rel] = f"sha256:{h}"
        except (OSError, PermissionError):
            # Skip files we can't read (socket, broken symlink, etc.)
            continue
    return hashes


def _detect_changed_files(
    local_hashes: dict[str, str], remote_manifest: dict | None
) -> tuple[set[str], set[str], set[str]]:
    """Compare local file hashes against the remote manifest.

    Returns (changed, added, deleted) sets of file paths.
    """
    if remote_manifest is None or "files" not in remote_manifest:
        return set(), set(), set()

    remote_files = remote_manifest["files"]
    local_keys = set(local_hashes.keys())
    remote_keys = set(remote_files.keys())

    added = local_keys - remote_keys
    deleted = remote_keys - local_keys
    changed = {
        f for f in (local_keys & remote_keys) if local_hashes[f] != remote_files[f]
    }

    return changed, added, deleted


def _map_files_to_services(
    changed_files: set[str],
) -> tuple[set[str], set[str]]:
    """Map changed file paths to services.

    Returns (services_to_rebuild, services_to_restart).
    A service is added to rebuild if any changed file matches a rebuild path.
    A service is added to restart if any changed file matches a restart path
    AND the service is not already in the rebuild set.
    """
    services_to_rebuild: set[str] = set()
    services_to_restart: set[str] = set()

    for filepath in changed_files:
        for service, paths in SERVICE_PATHS.items():
            # Check rebuild paths (prefix match)
            for rp in paths["rebuild"]:
                if filepath == rp or filepath.startswith(rp.rstrip("/") + "/") or filepath.startswith(rp):
                    services_to_rebuild.add(service)
                    break

            # Check restart paths (prefix match) — only if not already rebuilding
            if service not in services_to_rebuild:
                for rp in paths["restart"]:
                    if filepath == rp or filepath.startswith(rp.rstrip("/") + "/") or filepath.startswith(rp):
                        services_to_restart.add(service)
                        break

    # Remove services from restart if they're in rebuild (rebuild supersedes restart)
    services_to_restart -= services_to_rebuild

    return services_to_rebuild, services_to_restart


# ---------------------------------------------------------------------------
# Manifest management
# ---------------------------------------------------------------------------

def _download_manifest(
    host: str, user: str, ssh_pass: str, sudo_prefix: str, remote_path: str
) -> dict | None:
    """Download the deploy manifest from the remote host.

    Returns the parsed JSON dict, or None if the manifest doesn't exist.
    """
    manifest_remote = f"{remote_path}/{MANIFEST_FILENAME}"
    if sudo_prefix:
        cmd = f"{sudo_prefix}cat {shlex.quote(manifest_remote)}"
    else:
        cmd = f"cat {shlex.quote(manifest_remote)}"
    rc, out = _ssh_capture(host, user, cmd, ssh_pass)
    if rc != 0 or not out.strip():
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        print("Warning: remote manifest is corrupted — doing full deploy.", file=sys.stderr)
        return None


def _upload_manifest(
    host: str,
    user: str,
    ssh_pass: str,
    sudo_prefix: str,
    remote_path: str,
    manifest: dict,
) -> int:
    """Upload the deploy manifest to the remote host."""
    manifest_json = json.dumps(manifest, indent=2, sort_keys=True)
    manifest_remote = f"{remote_path}/{MANIFEST_FILENAME}"
    if sudo_prefix:
        # Wrap in bash -c so sudo applies to the redirect
        inner = f"cat > {shlex.quote(manifest_remote)}"
        cmd = f"{sudo_prefix}bash -c {shlex.quote(inner)}"
    else:
        cmd = f"cat > {shlex.quote(manifest_remote)}"
    return _ssh_cmd(host, user, cmd, ssh_pass, input_text=manifest_json)


# ---------------------------------------------------------------------------
# Deploy plan printer
# ---------------------------------------------------------------------------

def _print_deploy_plan(
    services_to_rebuild: set[str],
    services_to_restart: set[str],
    full_redeploy: bool,
    changed_files: set[str],
    force_rebuild: list[str],
) -> None:
    """Print a summary of what will be deployed."""
    print("\n" + "=" * 60)
    print("Deploy Plan")
    print("=" * 60)

    if changed_files:
        print(f"\n  Changed files ({len(changed_files)}):")
        for f in sorted(changed_files)[:30]:
            print(f"    {f}")
        if len(changed_files) > 30:
            print(f"    ... and {len(changed_files) - 30} more")
    else:
        print("\n  No files changed since last deploy.")

    if force_rebuild:
        print(f"\n  Force rebuild: {', '.join(force_rebuild)}")

    if full_redeploy:
        print("\n  Full redeploy: yes (compose/env changed or no manifest)")
    else:
        print(f"\n  Full redeploy: no")

    if services_to_rebuild:
        print(f"  Services to rebuild: {', '.join(sorted(services_to_rebuild))}")
    else:
        print("  Services to rebuild: (none)")

    if services_to_restart:
        print(f"  Services to restart: {', '.join(sorted(services_to_restart))}")
    else:
        print("  Services to restart: (none)")

    print("\n  Commands:")
    if full_redeploy:
        print("    docker compose build")
        print("    docker compose up -d")
    elif not services_to_rebuild and not services_to_restart:
        print("    docker compose up -d")
    else:
        if services_to_rebuild:
            build_targets = " ".join(sorted(services_to_rebuild))
            print(f"    docker compose build {build_targets}")
            print(f"    docker compose up -d --no-deps {build_targets}")
        if services_to_restart:
            restart_targets = " ".join(sorted(services_to_restart))
            print(f"    docker compose restart {restart_targets}")
        if "coraza-spoa-init" in services_to_restart:
            print("    docker compose up -d --force-recreate coraza-spoa-init")
            print("    docker compose restart coraza-spoa")
    print("=" * 60)


# ---------------------------------------------------------------------------
# Main deploy flow
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="Deploy HAProxy Manager to a remote Docker host.")
    parser.add_argument("--host", help="Remote host IP or hostname")
    parser.add_argument("--user", help="Remote SSH user")
    parser.add_argument("--password", help="SSH password (will be prompted if omitted)")
    parser.add_argument("--sudo-password", help="Sudo password (will default to SSH password)")
    parser.add_argument("--remote-path", default=DEFAULT_REMOTE_PATH, help="Remote deploy path")
    parser.add_argument("--yes", "-y", action="store_true", help="Skip confirmation prompts")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be rebuilt/restarted without making changes",
    )
    parser.add_argument(
        "--force-rebuild",
        action="append",
        default=[],
        metavar="SERVICE",
        help="Force rebuild of a service (e.g., --force-rebuild corex). "
        "Use 'all' for all buildable services. Can be specified multiple times.",
    )
    args = parser.parse_args()

    _require("sshpass")
    _require("rsync")
    _require("ssh")

    host, user, ssh_password, sudo_password, remote_path = _prompt(args)

    if not args.yes:
        print(f"\nWill deploy {PROJECT_ROOT} -> {user}@{host}:{remote_path}")
        if args.dry_run:
            print("(dry-run mode — no changes will be made)")
        answer = input("Continue? [y/N]: ").strip().lower()
        if answer not in ("y", "yes"):
            print("Aborted.")
            return 0

    print("\nChecking remote host...")
    rc = _ssh_cmd(host, user, f"mkdir -p {shlex.quote(remote_path)}", ssh_password)
    if rc != 0:
        print("Error: could not connect or create remote path.", file=sys.stderr)
        return 1

    print("Checking docker access on remote host...")
    sudo_prefix = _detect_sudo(host, user, ssh_password, sudo_password)
    if sudo_prefix is None:
        return 1
    if sudo_prefix:
        if "SUDO_PW" in sudo_prefix:
            print("Docker requires sudo; password will be sent to remote sudo.")
        else:
            print("Docker uses sudo (passwordless).")

    # ------------------------------------------------------------------
    # Change detection
    # ------------------------------------------------------------------
    print("\nComputing local file hashes...")
    local_hashes = _compute_file_hashes(PROJECT_ROOT, RSYNC_EXCLUDES)
    print(f"  {len(local_hashes)} files hashed.")

    print("Downloading remote manifest...")
    remote_manifest = _download_manifest(host, user, ssh_password, sudo_prefix, remote_path)

    if remote_manifest is None:
        print("  No manifest found — will do full deploy.")
        services_to_rebuild = set(BUILDABLE_SERVICES)
        services_to_restart: set[str] = set()
        full_redeploy = True
        all_changes: set[str] = set()
    else:
        deployed_at = remote_manifest.get("deployed_at", "unknown")
        print(f"  Last deploy: {deployed_at}")

        changed, added, deleted = _detect_changed_files(local_hashes, remote_manifest)
        all_changes = changed | added | deleted

        if added:
            print(f"  Added: {len(added)} files")
        if changed:
            print(f"  Changed: {len(changed)} files")
        if deleted:
            print(f"  Deleted: {len(deleted)} files")

        # Check for full-redeploy triggers
        full_redeploy = any(p in all_changes for p in FULL_REDEPLOY_PATHS)

        if full_redeploy:
            print("  compose/env file changed — full redeploy.")
            services_to_rebuild = set(BUILDABLE_SERVICES)
            services_to_restart = set()
        elif not all_changes:
            print("  No changes detected.")
            services_to_rebuild = set()
            services_to_restart = set()
        else:
            services_to_rebuild, services_to_restart = _map_files_to_services(all_changes)

    # Apply --force-rebuild overrides
    if args.force_rebuild:
        if "all" in args.force_rebuild:
            services_to_rebuild = set(BUILDABLE_SERVICES)
            print("\n  --force-rebuild all: forcing rebuild of all buildable services.")
        else:
            for svc in args.force_rebuild:
                if svc in BUILDABLE_SERVICES:
                    services_to_rebuild.add(svc)
                    print(f"\n  --force-rebuild {svc}: forcing rebuild.")
                else:
                    print(f"\n  Warning: '{svc}' is not a buildable service (ignored).", file=sys.stderr)
            # Force-rebuild supersedes restart for the same service
            services_to_restart -= services_to_rebuild

    # Print deploy plan
    _print_deploy_plan(
        services_to_rebuild, services_to_restart, full_redeploy, all_changes, args.force_rebuild
    )

    if args.dry_run:
        print("\n--dry-run: no changes made.")
        return 0

    if not args.yes:
        answer = input("\nProceed with deploy? [y/N]: ").strip().lower()
        if answer not in ("y", "yes"):
            print("Aborted.")
            return 0

    # ------------------------------------------------------------------
    # Rsync (always — sync files to remote)
    # ------------------------------------------------------------------
    if _rsync(host, user, remote_path, ssh_password) != 0:
        print("Error: rsync failed.", file=sys.stderr)
        return 1

    # `certs/` is a bind mount (./certs:/app/certs) but its contents are
    # runtime-managed (acme.sh, backend cert issuance), so it is excluded from
    # rsync. Ensure the directory exists on the remote so the bind mount works.
    # `data/` is a named Docker volume (haproxy-data), so no host dir is needed.
    print("\nEnsuring certs/ exists on remote...")
    _ssh_cmd(host, user, f"mkdir -p {shlex.quote(remote_path)}/certs", ssh_password)

    print("\nEnsuring .env exists on remote...")
    _remote_docker(
        host, user, ssh_password, sudo_prefix, remote_path,
        "test -f .env || cp .env.example .env",
    )

    # ------------------------------------------------------------------
    # Execute deploy plan
    # ------------------------------------------------------------------
    if full_redeploy:
        # Full redeploy — build all services, then start
        print("\nFull redeploy — building and starting all services...")
        rc = _remote_docker(
            host, user, ssh_password, sudo_prefix, remote_path,
            "docker compose build",
            "docker compose up -d",
        )
    elif not services_to_rebuild and not services_to_restart:
        # No changes — ensure all containers are running (no build)
        print("\nNo changes — ensuring all services are running...")
        rc = _remote_docker(
            host, user, ssh_password, sudo_prefix, remote_path,
            "docker compose up -d",
        )
    elif services_to_rebuild:
        # Rebuild changed services (with layer cache, no --no-cache)
        build_targets = " ".join(sorted(services_to_rebuild))
        print(f"\nBuilding services: {build_targets}...")
        rc = _remote_docker(
            host, user, ssh_password, sudo_prefix, remote_path,
            f"docker compose build {build_targets}",
            f"docker compose up -d --no-deps {build_targets}",
        )
        # Restart services that only need a restart (e.g., backend/app/ changes)
        if rc == 0 and services_to_restart:
            restart_targets = " ".join(sorted(services_to_restart))
            print(f"\nRestarting services: {restart_targets}...")
            rc = _remote_docker(
                host, user, ssh_password, sudo_prefix, remote_path,
                f"docker compose restart {restart_targets}",
            )
    else:
        # Only restarts needed (e.g., backend/app/ changes or coraza-spoa config)
        restart_targets = " ".join(sorted(services_to_restart))
        print(f"\nRestarting services: {restart_targets}...")
        rc = _remote_docker(
            host, user, ssh_password, sudo_prefix, remote_path,
            f"docker compose restart {restart_targets}",
        )

    # Handle coraza-spoa special case: force-recreate init, then restart spoa
    if rc == 0 and "coraza-spoa-init" in services_to_restart:
        print("\nRecreating coraza-spoa-init and restarting coraza-spoa...")
        rc = _remote_docker(
            host, user, ssh_password, sudo_prefix, remote_path,
            "docker compose up -d --force-recreate coraza-spoa-init",
            "docker compose restart coraza-spoa",
        )

    if rc != 0:
        print("Error: docker compose build/up failed.", file=sys.stderr)
        return 1

    # ------------------------------------------------------------------
    # Upload manifest on success
    # ------------------------------------------------------------------
    print("\nUploading deploy manifest...")
    manifest = {
        "deployed_at": datetime.now(timezone.utc).isoformat(),
        "files": local_hashes,
    }
    _upload_manifest(host, user, ssh_password, sudo_prefix, remote_path, manifest)

    print("\nDeployment complete.")
    print(f"  Frontend (HTTP):  http://{host}:3000")
    print(f"  Frontend (HTTPS): https://{host}:3443  (self-signed cert — browser will warn)")
    print(f"  API:              https://{host}:8000  (self-signed cert)")
    print(f"  HAProxy:          http://{host}:80 / https://{host}:443")
    print(f"  Stats:            http://{host}:8404")
    print(f"  Captcha:          http://{host}:3001")
    print(f"\n  Note: The backend API now serves over HTTPS with a self-signed")
    print(f"  certificate. Direct API access requires -k (insecure) with curl.")
    print(f"  The frontend nginx proxies API requests over HTTPS internally.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
