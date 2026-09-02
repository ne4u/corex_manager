# coreX Manager Deploy

`deploy.py` deploys the project to a remote Linux Docker host or a Kubernetes cluster using `rsync`, `docker compose`, and `helm`. It uses **selective rebuilds** — only rebuilding and redeploying services whose files changed since the last deploy.

## Deployment Targets

| Target | Description |
|--------|-------------|
| `docker` (default) | rsync + `docker compose build/up` on a remote host |
| `k8s-remote` | rsync + build images on remote + load into k8s + `helm upgrade` on remote |
| `k8s-cluster` | build images locally + load into local cluster + `helm upgrade` locally |

All targets share the same selective-rebuild change detection via the deploy manifest.

## What it does

1. **Collects credentials** for the remote host.
2. **Creates the remote path** if it does not exist.
3. **Detects Docker access** on the remote host (direct, passwordless `sudo`, or `sudo` with a password).
4. **Computes local file hashes** (SHA-256) for all project files.
5. **Downloads the deploy manifest** (`.deploy-manifest.json`) from the remote host to compare against local hashes.
6. **Detects changed files** by comparing local hashes against the manifest.
7. **Maps changed files to services** using a hardcoded service→path mapping (see below).
8. **Rsyncs the project** to the remote path, excluding local artifacts (see below).
9. **Ensures `.env` exists** on the remote by copying from `.env.example` if missing.
10. **Builds and/or restarts only the affected services** (see behavior below).
11. **Uploads the updated manifest** to the remote for the next deploy's change detection.

## Selective rebuild behavior

The script only rebuilds/restarts services whose files changed. The mapping is:

| Service | Rebuild (image) when these change | Restart only when these change |
|---------|----------------------------------|-------------------------------|
| `api` | `backend/Dockerfile`, `requirements.txt`, `backend/entrypoint.sh` | `backend/app/` (bind-mounted at runtime) |
| `corex` | `haproxy/` (Dockerfile, Rust modules, lua scripts, entrypoint) | — |
| `frontend` | `frontend/` (Dockerfile, src, nginx.conf, entrypoint) | — |
| `coraza-spoa-init` | — (no build) | `coraza-spoa/` (bind-mounted init.sh + config) |
| `coraza-spoa` | — (prebuilt image) | Restarted when coraza-spoa-init is recreated |
| `valkey`, `cap`, `varnish` | — (prebuilt images, no project files) | — |

### Special cases

- **`docker-compose.yml` or `.env` changes** → full redeploy (all services, `docker compose up -d`).
- **`backend/app/` changes** → `docker compose restart api` only (~5s). No image rebuild needed because `backend/app/` is bind-mounted into the container.
- **`coraza-spoa/` changes** → `docker compose up -d --force-recreate coraza-spoa-init` then `docker compose restart coraza-spoa`.
- **No changes** → `docker compose up -d` (ensures all containers are running, no rebuilds).
- **No manifest** (first deploy or manifest deleted) → full deploy (rebuild all buildable services).

### Build cache

The script uses Docker's layer cache (no `--no-cache`). Unchanged layers (e.g., `pip install`, `npm ci`, `cargo build`) are reused, making incremental builds fast. Use `--force-rebuild` to force a rebuild when needed.

## Deploy manifest

A `.deploy-manifest.json` file is stored on the remote host after each successful deploy. It contains SHA-256 hashes of all synced files and the deploy timestamp. On the next deploy, local hashes are compared against the manifest to detect changes.

If the manifest is missing (first deploy, manual cleanup), the script falls back to a full deploy.

## Rsync excludes

The following are excluded from rsync:
- `.git`, `.env`, `.venv`, `node_modules`
- `frontend/dist`
- Test files (`__tests__`, `*.test.*`, `*.spec.*`, `backend/tests`, `frontend/vitest.config.ts`, etc.)
- `data/`, `certs/` (runtime-managed)
- `.deploy-manifest.json` (managed by the deploy script)
- Dev-only files (`AGENTS.md`, `deploy.py`, `deploy.md`, `TODO.md`, `docs/`, `.devin/`)

## Requirements

**Local:**
- `python3`
- `ssh`
- `rsync`
- `sshpass`

**Remote:**
- Docker with the Compose plugin
- User can run `docker` directly, with passwordless `sudo`, or with `sudo` that accepts a password

## Usage

```bash
# Interactive deploy (prompts for host, user, passwords)
python3 deploy.py

# Non-interactive with flags
python3 deploy.py --host 1.2.3.4 --user admin --remote-path /opt/corex_manager -y

# Preview what would be rebuilt/restarted (no changes made)
python3 deploy.py --dry-run

# Force rebuild of a specific service (ignoring change detection)
python3 deploy.py --force-rebuild corex

# Force rebuild of all buildable services
python3 deploy.py --force-rebuild all

# Force rebuild multiple services
python3 deploy.py --force-rebuild corex --force-rebuild frontend
```

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `--host` | Remote host IP or hostname | Prompt |
| `--user` | Remote SSH user | Prompt |
| `--password` | SSH password | Prompt |
| `--sudo-password` | Sudo password (defaults to SSH password) | Prompt (defaults to SSH password) |
| `--remote-path` | Directory on the remote host to deploy into | `/opt/corex_manager` |
| `--yes`, `-y` | Skip confirmation prompts | `False` |
| `--dry-run` | Show what would be rebuilt/restarted without making changes | `False` |
| `--force-rebuild` | Force rebuild of a service (e.g., `--force-rebuild corex`). Use `all` for all buildable services. Can be specified multiple times. | — |

## Kubernetes deployment

The `--target k8s-cluster` and `--target k8s-remote` modes deploy via the Helm chart in `k8s/charts/corex-manager/`. See `k8s/README.md` for full architecture details.

### k8s-cluster (local cluster — kind/minikube/docker-desktop)

```bash
# Build images, load into local cluster, helm upgrade
python3 deploy.py --target k8s-cluster \
  --release-name corex \
  --namespace corex \
  --values-file my-values.yaml
```

### k8s-remote (remote cluster via SSH)

```bash
# rsync to remote, build on remote, load into remote cluster, helm upgrade on remote
python3 deploy.py --target k8s-remote \
  --host 1.2.3.4 --user admin \
  --release-name corex \
  --namespace corex \
  --values-file my-values.yaml
```

### Kubernetes-specific options

| Option | Description | Default |
|--------|-------------|---------|
| `--target` | Deployment target: `docker`, `k8s-remote`, `k8s-cluster` | `docker` |
| `--release-name` | Helm release name | `corex` |
| `--namespace` | Kubernetes namespace | `corex` |
| `--values-file` | Path to Helm values.yaml override | — |
| `--image-tag` | Docker image tag for rebuilt images | `latest` |

## Access after deploy

After a successful deployment the services are available at:

- **Frontend:** `http://<host>:3000`
- **API:** `http://<host>:8000`
- **HAProxy:** `http://<host>:80` / `https://<host>:443`
- **HAProxy Stats:** `http://<host>:8404`
- **Captcha:** `http://<host>:3001`

## MCP Gateway + coreX Manager MCP Server

The stack includes an optional MCP gateway (policy/DLP/guardrails proxy) and the coreX Manager MCP server (exposes the control plane as MCP tools).

### Enabling

1. Set in `.env`:
   ```
   MCP_GATEWAY_ENABLED=true
   MCP_SECRETS_KEY=<python -c "import secrets; print(secrets.token_urlsafe(32))">
   MCP_SELF_REGISTER=true
   COREX_MCP_TOKEN=<python -c "import secrets; print(secrets.token_urlsafe(32))">
   MCP_SERVICE_TOKEN=<python -c "import secrets; print(secrets.token_urlsafe(32))">
   ```
2. Rebuild: `python scripts/deploy.py --force-rebuild mcp-gateway,mcp-server`
3. The backend auto-registers the mcp-server into the gateway on startup.

### Access after deploy

- **MCP Gateway:** `http://<host>:8081/mcp` (tools appear as `corex-manager__*`)
- **MCP Server (direct):** `http://<host>:8082/mcp` (bare tool names; requires `Authorization: Bearer <COREX_MCP_TOKEN>`)

### Connecting AI CLI agents

See `docs/mcp-skill.md` for install snippets for Devin CLI, Claude Code, Cursor, Windsurf, and Continue.

## Migration from HAProxy Manager

If you have an existing deployment from before the `coreX Manager` rename, perform these steps after pulling the renamed code:

1. **Update `.env`**: add or change `HAPROXY_CONTAINER_NAME=corex` (was `haproxy` or unset). Without this, log retrieval and config validation via Docker SDK will fail (it looks for a container named `haproxy` that no longer exists).
2. **Stop the stack**: `docker compose down` (volumes `haproxy-data` and `haproxy-run` are preserved by name — all data survives).
3. **Rebuild and start**: `docker compose up -d --build` (containers are recreated on the new `corex-net` network; the `corex` container gets a `haproxy` network alias so internal DNS references like `DATAPLANE_API_URL=https://haproxy:5555/v3` still resolve).
4. **Optional cleanup**: remove the orphaned old network and container:
   ```bash
   docker network rm <project>_haproxy-net   # e.g. haproxy_manager_haproxy-net
   docker rm haproxy                         # old container (if not auto-removed)
   ```
   Only do this after confirming the new stack works.
5. **Update external scripts**: any scripts referencing `docker logs haproxy`, `docker restart haproxy`, or `deploy.py --force-rebuild haproxy` should use `corex` instead.

> **Fresh deployments** need no migration — the defaults are already set to `corex`.
