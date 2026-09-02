#!/usr/bin/env python3
"""Deploy coreX Manager to a remote Docker host or Kubernetes cluster.

Supports three deployment targets:

  docker      (default): rsync + docker compose build/up on a remote host
  k8s-remote: rsync + build images on remote + load into k8s + helm upgrade
  k8s-cluster: build images locally + load into local cluster + helm upgrade

All targets share the same selective-rebuild change detection: a manifest of
file hashes is compared against the last deploy, and only services whose files
changed are rebuilt/restarted.

Usage:
    python3 deploy.py
    python3 deploy.py --host 1.2.3.4 --user admin --remote-path /opt/corex_manager
    python3 deploy.py --target k8s-remote --host 1.2.3.4 --user admin
    python3 deploy.py --target k8s-cluster --release-name corex --namespace corex
    python3 deploy.py --dry-run
    python3 deploy.py --force-rebuild corex
    python3 deploy.py --force-rebuild all

Requirements (local):
    python3, ssh, rsync, sshpass (for remote targets), helm (for k8s targets)

Remote requirements (docker target):
    docker with compose plugin, user able to run `docker` either directly or
    via passwordless/sudo access.

Remote requirements (k8s-remote target):
    docker (for building images), helm, kubectl, and a running k8s cluster
    (kind/minikube/k3s/etc.) with its container runtime accessible for image
    loading.

Local requirements (k8s-cluster target):
    docker (for building images), helm, kubectl, and a local k8s cluster
    (kind/minikube/docker desktop) with its container runtime accessible.
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
# Kubernetes deployment constants
# ---------------------------------------------------------------------------

HELM_CHART_PATH = PROJECT_ROOT / "k8s" / "charts" / "corex-manager"

# Maps Docker Compose service names to the Helm chart image keys. Used by the
# k8s deploy targets to set image tags via --set when a service is rebuilt.
K8S_SERVICE_TO_IMAGE_KEY = {
    "api": "image.api.tag",
    "corex": "image.corex.tag",
    "frontend": "image.frontend.tag",
}

# Image names matching the Helm chart defaults (used for docker build / load)
K8S_IMAGE_NAMES = {
    "api": "corex-api",
    "corex": "corex-corex",
    "frontend": "corex-frontend",
}


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
# Kubernetes deploy helpers
# ---------------------------------------------------------------------------

def _detect_k8s_loader() -> str:
    """Detect the available image loading mechanism for the local k8s cluster.

    Returns one of: "kind", "minikube", "ctr", "docker-desktop".
    """
    if shutil.which("kind"):
        return "kind"
    if shutil.which("minikube"):
        return "minikube"
    # k3s / k8s with containerd
    if shutil.which("ctr"):
        return "ctr"
    # Docker Desktop with built-in k8s — images built locally are visible
    return "docker-desktop"


def _load_image_local(loader: str, image_name: str, image_tag: str) -> int:
    """Load a locally-built image into the local k8s cluster."""
    full_name = f"{image_name}:{image_tag}"
    if loader == "kind":
        rc, out = _run(["kind", "load", "docker-image", full_name])
        if out:
            print(out, end="")
        return rc
    elif loader == "minikube":
        rc, out = _run(["minikube", "image", "load", full_name])
        if out:
            print(out, end="")
        return rc
    elif loader == "ctr":
        # ctr -n k8s.io images import <tar> — requires exporting first
        rc, out = _run(["docker", "save", full_name, "-o", f"/tmp/{image_name}.tar"])
        if rc != 0:
            print(out, end="")
            return rc
        rc, out = _run(["sudo", "ctr", "-n", "k8s.io", "images", "import", f"/tmp/{image_name}.tar"])
        if out:
            print(out, end="")
        return rc
    else:
        # Docker Desktop — image is already visible to the k8s cluster
        print(f"  (docker-desktop: {full_name} already available)")
        return 0


def _build_image_local(service: str, image_tag: str = "latest") -> int:
    """Build a Docker image locally for the given service."""
    image_name = K8S_IMAGE_NAMES.get(service, f"corex-{service}")
    full_name = f"{image_name}:{image_tag}"

    # Determine the build context and Dockerfile
    if service == "api":
        context = str(PROJECT_ROOT)
        dockerfile = "backend/Dockerfile"
    elif service == "corex":
        context = str(PROJECT_ROOT)
        dockerfile = "haproxy/Dockerfile"
    elif service == "frontend":
        context = str(PROJECT_ROOT / "frontend")
        dockerfile = "Dockerfile"
    else:
        print(f"  Warning: unknown service '{service}' for k8s image build", file=sys.stderr)
        return 1

    print(f"  Building {full_name} (context={context}, dockerfile={dockerfile})...")
    rc, out = _run(["docker", "build", "-t", full_name, "-f", dockerfile, context])
    if out:
        print(out, end="")
    return rc


def _helm_upgrade(release_name: str, namespace: str, values_file: str | None,
                  image_overrides: dict[str, str], dry_run: bool = False) -> int:
    """Run helm upgrade --install for the corex-manager chart."""
    cmd = [
        "helm", "upgrade", "--install", release_name,
        str(HELM_CHART_PATH),
        "--namespace", namespace,
        "--create-namespace",
    ]
    if values_file:
        cmd.extend(["-f", values_file])
    # Set image tags for rebuilt services
    for service, tag in image_overrides.items():
        image_key = K8S_SERVICE_TO_IMAGE_KEY.get(service)
        if image_key:
            cmd.extend(["--set", f"{image_key}={tag}"])
    if dry_run:
        cmd.append("--dry-run")
    print(f"  Running: {' '.join(cmd)}")
    rc, out = _run(cmd)
    if out:
        print(out, end="")
    return rc


def _print_k8s_deploy_plan(
    services_to_rebuild: set[str],
    full_redeploy: bool,
    changed_files: set[str],
    force_rebuild: list[str],
    target: str,
    release_name: str,
    namespace: str,
) -> None:
    """Print a summary of what will be deployed for k8s targets."""
    print("\n" + "=" * 60)
    print(f"K8s Deploy Plan (target={target}, release={release_name}, ns={namespace})")
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
        print(f"  Images to rebuild: {', '.join(sorted(services_to_rebuild))}")
    else:
        print("  Images to rebuild: (none)")

    print(f"\n  Helm: upgrade --install {release_name} (namespace={namespace})")
    print("=" * 60)


# ---------------------------------------------------------------------------
# Main deploy flow
# ---------------------------------------------------------------------------

def _deploy_docker(args: argparse.Namespace) -> int:
    """Original Docker Compose deploy flow — unchanged behavior."""
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


def _deploy_k8s(args: argparse.Namespace, target: str) -> int:
    """Kubernetes deploy flow — shared by k8s-remote and k8s-cluster.

    For k8s-remote: rsync to remote, build images on remote, load into the
    remote cluster's container runtime, then helm upgrade on remote.

    For k8s-cluster: build images locally, load into the local cluster,
    then helm upgrade locally.
    """
    release_name = args.release_name
    namespace = args.namespace
    values_file = args.values_file
    image_tag = args.image_tag

    is_remote = target == "k8s-remote"

    if is_remote:
        _require("sshpass")
        _require("rsync")
        _require("ssh")
        host, user, ssh_password, sudo_password, remote_path = _prompt(args)
    else:
        _require("docker")
        _require("helm")
        _require("kubectl")

    # ------------------------------------------------------------------
    # Change detection (shared logic)
    # ------------------------------------------------------------------
    print("\nComputing local file hashes...")
    local_hashes = _compute_file_hashes(PROJECT_ROOT, RSYNC_EXCLUDES)
    print(f"  {len(local_hashes)} files hashed.")

    # For k8s-remote, the manifest lives on the remote host
    # For k8s-cluster, the manifest lives locally
    if is_remote:
        print("Downloading remote manifest...")
        # Reuse sudo detection for remote manifest access
        sudo_prefix = ""  # helm/kubectl don't need sudo; manifest is in remote_path
        remote_manifest = _download_manifest(host, user, ssh_password, sudo_prefix, remote_path)
    else:
        print("Reading local manifest...")
        local_manifest_path = PROJECT_ROOT / MANIFEST_FILENAME
        if local_manifest_path.exists():
            try:
                remote_manifest = json.loads(local_manifest_path.read_text())
            except json.JSONDecodeError:
                print("  Warning: local manifest is corrupted — doing full deploy.")
                remote_manifest = None
        else:
            remote_manifest = None

    if remote_manifest is None:
        print("  No manifest found — will do full deploy.")
        services_to_rebuild = set(BUILDABLE_SERVICES)
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

        full_redeploy = any(p in all_changes for p in FULL_REDEPLOY_PATHS)

        if full_redeploy:
            print("  compose/env file changed — full redeploy.")
            services_to_rebuild = set(BUILDABLE_SERVICES)
        elif not all_changes:
            print("  No changes detected.")
            services_to_rebuild = set()
        else:
            services_to_rebuild, _ = _map_files_to_services(all_changes)
            # For k8s, restart-only changes still require a rebuild since
            # bind-mounted paths in Docker Compose become baked into the
            # image in k8s. So we treat all changed services as rebuild targets.
            # However, coraza-spoa-init and coraza-spoa don't have images in k8s
            # (they're sidecar containers in the corex pod), so filter them out.
            services_to_rebuild = {s for s in services_to_rebuild if s in K8S_SERVICE_TO_IMAGE_KEY}

    # Apply --force-rebuild overrides
    if args.force_rebuild:
        if "all" in args.force_rebuild:
            services_to_rebuild = set(K8S_SERVICE_TO_IMAGE_KEY.keys())
            print("\n  --force-rebuild all: forcing rebuild of all k8s images.")
        else:
            for svc in args.force_rebuild:
                if svc in K8S_SERVICE_TO_IMAGE_KEY:
                    services_to_rebuild.add(svc)
                    print(f"\n  --force-rebuild {svc}: forcing rebuild.")
                else:
                    print(f"\n  Warning: '{svc}' is not a k8s image service (ignored).", file=sys.stderr)

    # Print deploy plan
    _print_k8s_deploy_plan(
        services_to_rebuild, full_redeploy, all_changes, args.force_rebuild,
        target, release_name, namespace,
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
    # Build and load images
    # ------------------------------------------------------------------
    image_overrides: dict[str, str] = {}

    if is_remote:
        # k8s-remote: rsync, build on remote, load into remote cluster
        if _rsync(host, user, remote_path, ssh_password) != 0:
            print("Error: rsync failed.", file=sys.stderr)
            return 1

        # Detect the image loader on the remote host
        print("\nDetecting remote k8s image loader...")
        loader_rc, loader_out = _ssh_capture(host, user, "which kind minikube ctr 2>/dev/null", ssh_password)
        remote_loader = "docker-desktop"
        if "kind" in (loader_out or ""):
            remote_loader = "kind"
        elif "minikube" in (loader_out or ""):
            remote_loader = "minikube"
        elif "ctr" in (loader_out or ""):
            remote_loader = "ctr"
        print(f"  Remote loader: {remote_loader}")

        for service in sorted(services_to_rebuild):
            image_name = K8S_IMAGE_NAMES.get(service, f"corex-{service}")
            full_name = f"{image_name}:{image_tag}"
            print(f"\n  Building {full_name} on remote...")

            # Build on remote
            if service == "api":
                ctx = str(remote_path)
                df = "backend/Dockerfile"
            elif service == "corex":
                ctx = str(remote_path)
                df = "haproxy/Dockerfile"
            elif service == "frontend":
                ctx = f"{remote_path}/frontend"
                df = "Dockerfile"
            else:
                continue

            build_cmd = f"docker build -t {shlex.quote(full_name)} -f {shlex.quote(df)} {shlex.quote(ctx)}"
            rc = _ssh_cmd(host, user, build_cmd, ssh_password)
            if rc != 0:
                print(f"Error: remote build of {service} failed.", file=sys.stderr)
                return 1

            # Load into remote cluster
            if remote_loader == "kind":
                _ssh_cmd(host, user, f"kind load docker-image {shlex.quote(full_name)}", ssh_password)
            elif remote_loader == "minikube":
                _ssh_cmd(host, user, f"minikube image load {shlex.quote(full_name)}", ssh_password)
            elif remote_loader == "ctr":
                tar_path = f"/tmp/{image_name}.tar"
                _ssh_cmd(host, user, f"docker save {shlex.quote(full_name)} -o {shlex.quote(tar_path)}", ssh_password)
                _ssh_cmd(host, user, f"sudo ctr -n k8s.io images import {shlex.quote(tar_path)}", ssh_password)
            # docker-desktop: no load needed

            image_overrides[service] = image_tag

        # Helm upgrade on remote
        print(f"\n  Running helm upgrade on remote...")
        helm_set_args = []
        for service, tag in image_overrides.items():
            image_key = K8S_SERVICE_TO_IMAGE_KEY.get(service)
            if image_key:
                helm_set_args.extend(["--set", f"{image_key}={tag}"])

        helm_cmd_parts = [
            "helm", "upgrade", "--install", shlex.quote(release_name),
            shlex.quote(f"{remote_path}/k8s/charts/corex-manager"),
            "--namespace", shlex.quote(namespace),
            "--create-namespace",
        ]
        if values_file:
            # Copy values file to remote via scp
            scp_env = os.environ.copy()
            scp_env["SSHPASS"] = ssh_password
            scp_cmd = ["sshpass", "-e", "scp"] + SSH_OPTS + [values_file, f"{user}@{host}:{remote_path}/values.yaml"]
            scp_rc, scp_out = _run(scp_cmd, env=scp_env)
            if scp_out:
                print(scp_out, end="")
            helm_cmd_parts.extend(["-f", f"{remote_path}/values.yaml"])
        helm_cmd_parts.extend(helm_set_args)
        helm_cmd = " ".join(helm_cmd_parts)
        rc = _ssh_cmd(host, user, f"cd {shlex.quote(remote_path)} && {helm_cmd}", ssh_password)
        if rc != 0:
            print("Error: remote helm upgrade failed.", file=sys.stderr)
            return 1

        # Upload manifest
        print("\nUploading deploy manifest...")
        manifest = {
            "deployed_at": datetime.now(timezone.utc).isoformat(),
            "files": local_hashes,
        }
        _upload_manifest(host, user, ssh_password, "", remote_path, manifest)

    else:
        # k8s-cluster: build locally, load into local cluster, helm upgrade locally
        loader = _detect_k8s_loader()
        print(f"\nLocal k8s image loader: {loader}")

        for service in sorted(services_to_rebuild):
            rc = _build_image_local(service, image_tag)
            if rc != 0:
                print(f"Error: local build of {service} failed.", file=sys.stderr)
                return 1

            rc = _load_image_local(loader, K8S_IMAGE_NAMES.get(service, f"corex-{service}"), image_tag)
            if rc != 0:
                print(f"Error: failed to load {service} image into cluster.", file=sys.stderr)
                return 1

            image_overrides[service] = image_tag

        # Helm upgrade locally
        print(f"\n  Running helm upgrade...")
        rc = _helm_upgrade(release_name, namespace, values_file, image_overrides)
        if rc != 0:
            print("Error: helm upgrade failed.", file=sys.stderr)
            return 1

        # Save manifest locally
        print("\nSaving deploy manifest...")
        manifest = {
            "deployed_at": datetime.now(timezone.utc).isoformat(),
            "files": local_hashes,
        }
        (PROJECT_ROOT / MANIFEST_FILENAME).write_text(json.dumps(manifest, indent=2, sort_keys=True))

    print("\nK8s deployment complete.")
    print(f"  Release:  {release_name}")
    print(f"  Namespace: {namespace}")
    print(f"  Check status: kubectl get pods -n {namespace}")
    if not is_remote:
        print(f"  Port-forward:  kubectl port-forward svc/{release_name}-frontend -n {namespace} 3443:443")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Deploy coreX Manager to Docker or Kubernetes.")
    parser.add_argument("--target", choices=["docker", "k8s-remote", "k8s-cluster"],
                        default="docker", help="Deployment target (default: docker)")
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
    # Kubernetes-specific options
    parser.add_argument("--release-name", default="corex", help="Helm release name (k8s targets)")
    parser.add_argument("--namespace", default="corex", help="Kubernetes namespace (k8s targets)")
    parser.add_argument("--values-file", help="Path to Helm values.yaml override file (k8s targets)")
    parser.add_argument("--image-tag", default="latest", help="Docker image tag for rebuilt images (k8s targets)")
    args = parser.parse_args()

    if args.target == "docker":
        return _deploy_docker(args)
    else:
        return _deploy_k8s(args, args.target)


if __name__ == "__main__":
    sys.exit(main())
