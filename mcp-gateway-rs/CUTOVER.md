# MCP Gateway Rust — Operational Validation & Cutover Runbook

## Overview

This document describes how to validate and cut over from the Python MCP gateway
(`mcp-gateway`, port 8081) to the Rust MCP gateway (`mcp-gateway-rs`, port 8089).

The Rust gateway is designed as a drop-in replacement. Both gateways can run
simultaneously during validation, sharing the same Valkey instance and config
bundle.

## Architecture

```
                ┌─────────────────┐
                │   HAProxy       │
                │  (port 443/80)  │
                └──┬──────────┬───┘
                   │          │
          ┌────────▼──┐  ┌───▼──────────┐
          │ Python GW │  │ Rust GW      │
          │ :8081     │  │ :8089        │
          │ (current) │  │ (validation) │
          └────┬──────┘  └───┬──────────┘
               │             │
               └──────┬──────┘
                      │
              ┌───────▼───────┐
              │   Valkey      │
              │   :6379       │
              └───────────────┘
```

## Phase 1: Build & Local Validation

### Prerequisites

- Rust 1.82+ (edition 2021)
- Docker & Docker Compose
- Access to the Valkey instance

### Build

```bash
cd mcp-gateway-rs

# Compile all crates
cargo build --release

# Run tests
cargo test --workspace

# Run clippy
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Expected: 107+ tests passing, clippy clean.

### Local Run

```bash
# Set required env vars
export MCP_SECRETS_KEY="<your-key>"
export MCP_CONFIG_PATH="data/mcp/config.bundle.json"
export VALKEY_HOST=valkey
export MCP_GATEWAY_BIND=0.0.0.0:8089

# Run
cargo run --release -p corex-gateway
```

Verify:
```bash
curl http://localhost:8089/healthz
# Expected: {"status":"ok","configured":true}

curl http://localhost:8089/metrics
# Expected: Prometheus text format

curl http://localhost:8089/.well-known/oauth-protected-resource
# Expected: RFC 9728 metadata JSON
```

## Phase 2: Parallel Docker Deployment

The Rust gateway is integrated into the project's `deploy.py` script and Docker
Compose. Files are rsynced to the remote host on every deploy (the 3.5GB
`target/` directory is excluded via the existing `"target"` entry in
`RSYNC_EXCLUDES`).

The `mcp-gateway-rs` service uses the `mcp-rs` Compose profile, so it is opt-in
and does not start with a normal `deploy.py` run or `docker compose up`.

### Option A: Deploy via `deploy.py` (Docker Compose target)

**First deploy (sync files + build + start the Rust gateway):**

```bash
# 1. Deploy the project normally — this rsyncs all files including mcp-gateway-rs/
python3 deploy.py --host <host> --user <user> -y

# 2. On the remote host, build and start the Rust gateway with the profile:
ssh <user>@<host> 'cd /opt/corex_manager && \
  docker compose --profile mcp-rs build mcp-gateway-rs && \
  docker compose --profile mcp-rs up -d mcp-gateway-rs'
```

**Subsequent deploys (rsync + restart):**

```bash
python3 deploy.py --host <host> --user <user> -y
# Then on the remote:
ssh <user>@<host> 'cd /opt/corex_manager && \
  docker compose --profile mcp-rs up -d --no-deps mcp-gateway-rs'
```

> **Note:** `deploy.py` does not include `mcp-gateway-rs` in its change
> detection (`SERVICE_PATHS`/`BUILDABLE_SERVICES`) because it is an optional
> service behind a Compose profile. The rsync always syncs the source files;
> you trigger the build/restart manually as shown above.

**Dry-run (preview what will be synced):**

```bash
python3 deploy.py --dry-run --host <host> --user <user>
```

### Option B: Deploy via `deploy.py` (Docker Swarm target)

The Rust gateway is registered in `SWARM_OPTIONAL_IMAGE_NAMES` as
`corex-mcp-gateway-rs`. To build and deploy via Swarm:

```bash
python3 deploy.py --target swarm --host <host> --user <user> \
  --stack-name corex -y
# Then on the remote, build the image and redeploy the stack:
ssh <user>@<host> 'cd /opt/corex_manager && \
  docker build -t corex-mcp-gateway-rs:latest \
    -f mcp-gateway-rs/Dockerfile mcp-gateway-rs/ && \
  docker stack deploy -c docker-swarm.yml corex'
```

### Option C: Local Docker Compose (no deploy.py)

For local testing or single-host deploys without `deploy.py`:

```bash
# Build and start the Rust gateway (uses the mcp-rs profile)
docker compose --profile mcp-rs up -d mcp-gateway-rs
```

### Verify both gateways are running

```bash
# Python gateway
curl http://localhost:8081/healthz

# Rust gateway
curl http://localhost:8089/healthz
```

### Validation Checklist

Run each check against **both** gateways and compare results:

#### 1. Authentication
- [ ] Valid PAT token → 200 with session
- [ ] Invalid token → 401 with WWW-Authenticate
- [ ] Expired token → 401
- [ ] Brute-force lockout after threshold

#### 2. Session Lifecycle
- [ ] `initialize` → 200 with `Mcp-Session-Id` header
- [ ] Request without session → 400
- [ ] Request with invalid session → 400
- [ ] Session identity mismatch → 403

#### 3. Protocol Methods
- [ ] `ping` → 200 with empty result
- [ ] `tools/list` → merged tools with namespace prefix
- [ ] `tools/call` → routed to upstream, response returned
- [ ] `resources/list` → merged resources with URI wrapping
- [ ] `resources/read` → routed to upstream
- [ ] `resources/templates/list` → merged templates
- [ ] `prompts/list` → merged prompts + skills
- [ ] `prompts/get` → routed to upstream or skill rendered
- [ ] `logging/setLevel` → 200

#### 4. New MCP Features (Rust only)
- [ ] `resources/subscribe` → 200 acknowledgment
- [ ] `resources/unsubscribe` → 200 acknowledgment
- [ ] `completion/complete` → forwarded to upstream
- [ ] `listChanged: true` in capabilities → actual notifications emitted

#### 5. Discovery Modes
- [ ] Passthrough: tools/list shows all team servers
- [ ] Meta-tools: `gateway__list_servers`, `gateway__list_tools`,
      `gateway__search_tools`, `gateway__describe_tool`, `gateway__refresh_tools`
      appear in tools/list and are callable
- [ ] Hybrid: only `expose=true` servers in tools/list; meta-tools available

#### 6. Policy Enforcement
- [ ] Denied tool → error code -32010
- [ ] No policies configured → allow all
- [ ] Policies configured, no match → deny (fail-closed)
- [ ] `skip_dlp` action → DLP not applied
- [ ] `skip_ratelimit` action → rate limit not applied

#### 7. DLP & Guardrails
- [ ] DLP request block → error code -32020
- [ ] DLP response block → error code -32020
- [ ] Guardrail request block → error code -32021
- [ ] Guardrail response block → error code -32021
- [ ] Redaction modifies params/response

#### 8. Rate Limiting
- [ ] Per-identity/tool limit → error code -32029
- [ ] Per-IP limit → error code -32029
- [ ] Concurrent limit → error code -32029
- [ ] Team RPM override applied

#### 9. Events & Metrics
- [ ] NDJSON events written to `MCP_EVENTS_LOG_PATH`
- [ ] Event rotation: 2 files (active + `.1`)
- [ ] Prometheus `/metrics` endpoint returns counters
- [ ] Alert thresholds trigger webhooks

#### 10. Config Reload
- [ ] Config file change detected within 5s
- [ ] Hot reload without restart
- [ ] Policies/DLP/guardrails/skills reloaded

## Phase 2b: UI Configuration

The coreX Manager frontend has two relevant pages for MCP gateway management.
Both gateways share the same config bundle, so UI changes apply to both.

### 1. Feature Flags page (enable/disable the gateway)

Navigate to **Settings → Feature Flags** in the UI.

- **MCP Gateway** toggle: enables/disables the Python gateway
  (`mcp_gateway_enabled` setting). This controls whether the Python gateway
  processes requests.
- The Rust gateway (`mcp-gateway-rs`) is controlled separately via the
  `mcp-rs` Docker Compose profile — there is no UI toggle for it yet.

### 2. MCP Gateway Settings tab (configuration)

Navigate to **Settings → MCP Gateway** in the UI. This tab has three sections:

#### General Settings
- **Allowed Origins**: comma-separated list of allowed Origin headers
  (e.g., `https://claude.ai,https://cursor.sh`).
- **JWT Config**: issuer, audience, and JWKS URL for JWT authentication.
- **Rate Limiting**: default RPM, per-IP limit, concurrent limit, and
  per-team RPM overrides.
- **Log Payloads**: toggle whether request/response payloads are included
  in NDJSON event logs.

Click **Save Settings** to persist. These settings are written to the
backend settings store and included in the next config bundle regeneration.

#### Config Bundle
- Shows the last generation timestamp and bundle size.
- **Regenerate** button: triggers the backend to rebuild the encrypted
  config bundle (`config.bundle.json`) from the current settings, servers,
  policies, DLP rules, guardrails, and skills. Both gateways read this file.

#### Alerting
- **Webhook URL**: Slack/Teams webhook for security alerts.
- **Thresholds**: per-event-type thresholds (guardrail_blocked, dlp_blocked,
  policy_denied, auth_failed, rate_limited). Set to 0 to disable.
- **Recent Alerts**: shows the last 20 alerts with webhook delivery status.

### Config bundle flow

```
UI Settings → Backend API → Config Bundle (encrypted) → Both Gateways
                                ↓
                    config.bundle.json on disk
                                ↓
              Python GW (8081) reads it directly
              Rust GW   (8089) reads it + hot-reloads on change
```

After changing any setting in the UI, click **Regenerate** to produce a new
config bundle. Both gateways will pick up the changes:
- Python: on next request (reads file each time).
- Rust: within 5 seconds (file watcher polls mtime).

## Phase 3: Cutover

### Prerequisites

- All validation checklist items pass
- No behavioral discrepancies between Python and Rust gateways
- Event logs show comparable traffic patterns
- The Rust gateway container (`mcp-gateway-rs`) is running on port 8089
  (see Phase 2)

### Cutover Steps (via UI)

The cutover is a UI-driven operation. The backend reads the `mcp_gateway_backend`
setting and generates the HAProxy `backend mcp_gateway` section accordingly:
`"python"` → `mcp-gateway:8081`, `"rust"` → `mcp-gateway-rs:8089`.

1. **Snapshot current state**
   ```bash
   # Record Python gateway metrics
   curl http://localhost:8081/metrics > /tmp/python-metrics-before.txt
   curl http://localhost:8089/metrics > /tmp/rust-metrics-before.txt
   ```

2. **Switch the gateway backend in the UI**
   - Navigate to **Settings → MCP Gateway → General Settings**
   - Under **Gateway Backend**, select **Rust (mcp-gateway-rs)**
   - Click **Save Settings**
   - This writes `mcp_gateway_backend = "rust"` to the settings store.

3. **Regenerate the HAProxy config**
   - Navigate to **Settings → MCP Gateway → Config Bundle**
   - Click **Regenerate** (this rebuilds the config bundle AND triggers
     HAProxy config regeneration with the new backend target)
   - Alternatively, trigger an HAProxy reload via deploy.py:
     ```bash
     python3 deploy.py --host <host> --user <user> --force-rebuild corex -y
     ```

4. **Verify traffic flowing to Rust gateway**
   ```bash
   # Check Rust metrics increasing
   watch -n5 'curl -s http://localhost:8089/metrics | grep mcp_gateway_requests_total'
   ```

5. **Monitor for 15 minutes**
   - Check error rates
   - Check event logs
   - Check alert webhooks
   - Verify in the UI under **Settings → MCP Gateway** that the config
     bundle is current and alerts are not firing

6. **Stop Python gateway** (optional, after confidence period)
   ```bash
   # On the remote host:
   ssh <user>@<host> 'cd /opt/corex_manager && docker compose stop mcp-gateway'
   ```

### Rollback (via UI)

If issues are detected:

1. **Switch the gateway backend back to Python in the UI**
   - Navigate to **Settings → MCP Gateway → General Settings**
   - Under **Gateway Backend**, select **Python (mcp-gateway)**
   - Click **Save Settings**

2. **Regenerate the HAProxy config**
   - Navigate to **Settings → MCP Gateway → Config Bundle**
   - Click **Regenerate**
   - Alternatively, via deploy.py:
     ```bash
     python3 deploy.py --host <host> --user <user> --force-rebuild corex -y
     ```

3. **Investigate**
   - Check Rust gateway logs: `docker compose logs mcp-gateway-rs`
   - Check event logs: `data/mcp/events.ndjson`
   - Compare with Python gateway behavior
   - Review the UI under **Settings → MCP Gateway → Recent Alerts** for
     any security events triggered during the cutover window

## Key Differences from Python Gateway

| Feature | Python | Rust |
|---------|--------|------|
| Port | 8081 | 8089 |
| `listChanged` | Advertised but not emitted | Advertised and emitted |
| `resources/subscribe` | Not supported (error) | Supported (acknowledgment) |
| `completion/complete` | Not supported | Forwarded to upstream |
| `/metrics` | Not available | Prometheus text format |
| Event rotation | 10 files | 2 files |
| Discovery modes | Passthrough only | Passthrough, meta-tools, hybrid |
| Meta-tools | Not available | 5 meta-tools |
| Config reload | Watched file | Watched file (5s poll) |
| Valkey key prefix | `mcp:` | `mcp:gw:` (isolated) |
| HAProxy routing | `mcp_gateway_backend` setting = `"python"` | `mcp_gateway_backend` setting = `"rust"` |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_GATEWAY_BIND` | `0.0.0.0:8089` | Bind address |
| `MCP_CONFIG_PATH` | `data/mcp/config.bundle.json` | Config bundle path |
| `MCP_SECRETS_KEY` | (required) | Decryption key for config bundle |
| `MCP_EVENTS_LOG_PATH` | `data/mcp/events.ndjson` | NDJSON event log path |
| `MCP_EVENTS_MAX_BYTES` | `104857600` (100MB) | Max bytes per event file |
| `MCP_LOG_PAYLOADS` | `false` | Log request/response payloads |
| `VALKEY_HOST` | `valkey` | Valkey hostname |
| `VALKEY_PORT` | `6379` | Valkey port |
| `VALKEY_PASSWORD` | (empty) | Valkey password |
| `RUST_LOG` | `info` | Log level |
| `MCP_ALERT_WEBHOOK_URL` | (empty) | Alert webhook URL |
| `MCP_ALERT_WEBHOOK_TIMEOUT` | `5` | Webhook timeout (seconds) |
| `MCP_HEALTH_CHECK_INTERVAL` | `30` | Health check interval (seconds) |
