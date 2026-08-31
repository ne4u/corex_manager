# coreX Platform

![coreX Platform](corex.png)

**Website: [www.corex.app](https://www.corex.app)**

A full-featured control plane, data plane, and modern web GUI for HAProxy —
load balancing, TLS, WAF, caching, bot protection, and API security, managed
from one place.

The coreX Platform generates and hot-reloads HAProxy configuration from a friendly
UI/REST API, and orchestrates the surrounding data-plane services (Coraza WAF,
Varnish disk cache, Valkey, CAPTCHA) via Docker Compose.

## Features

### Load balancing & TLS
- **Listeners** with HTTP/2, QUIC, TLS, Proxy Protocol, and per-listener policies
- **Backends** with load-balancing algorithms (roundrobin, leastconn, source, uri, static-rr), sticky sessions, health checks, and server-side mTLS
- **Certificate management** — Let's Encrypt (HTTP-01 and DNS challenges for common providers), custom uploads, custom CA bundles, automatic renewal
- **Cipher suite baselines** (FIPS, FedRAMP, PCI, Modern, Custom) with HSTS options

### Security
- **WAF** — Coraza SPOA with OWASP Core Rule Set: rule management, exceptions, per-path/method/content-type rules, snapshots and restore
- **Security Lists** — named IP/CIDR, ASN, GeoIP country, and JA4 TLS-fingerprint lists with dynamic feed ingestion and auto-apply
- **Security Rules** — ordered, first-match-wins rules with a full expression language (allow/block/skip actions, custom error pages)
- **Pattern Lists** for regex matching
- **Rate limiting** — basic, advanced (stick-table), response-code based, and WAF-triggered with tarpit/block durations
- **CAPTCHA challenges** — built-in Cap (native), Google reCAPTCHA, or Cloudflare Turnstile, with client binding
- **API Armor** — GraphQL protection, JSON schema validation, auth enforcement, and endpoint profiling
- **Page Protect** — client-side security: CSP monitoring, script inventory, and code-change detection via a lightweight beacon
- **Fingerprinting** — JA4 TLS fingerprints and HTTP request fingerprints (native Rust/Lua modules)

### Performance
- **Two-tier caching** — HAProxy in-memory cache plus Varnish-backed disk cache, driven by ordered cacheability rules
- **Response compression** — Brotli, Zstandard, and Gzip via a native Rust module
- **Image-to-WebP conversion** on the fly, negotiated from the `Accept` header
- **Response transforms** — body rewriting, masking, and tokenization

### Operations
- **Dashboards** — HAProxy metrics, WAF events, cache performance, with time-range selection
- **Live log viewer** with GeoIP enrichment and expandable request details
- **Audit log** of configuration changes with pending/applied tracking
- **Config lifecycle** — diff viewer, validate, apply, revert, and rollback to snapshots
- **GeoIP** — automatic MaxMind GeoLite2 downloads (bring your own license key)
- **Users & auth** — JWT sessions, TOTP two-factor, per-user preferences
- **Theming & i18n** — built-in and custom themes; English, Arabic, German, Spanish, and French translations
- **MCP** — a built-in MCP server for managing coreX with AI agents, plus an optional multi-tenant MCP gateway with team-based access control, DLP/guardrails, and skill versioning

## Quick Start (Docker Compose)

Requirements: Docker with the Compose plugin.

```bash
cp .env.example .env
# Edit .env — at minimum set SECRET_KEY and ADMIN_PASSWORD (see SECURITY.md)
docker compose up --build -d
```

- Web UI: [https://localhost:3443](https://localhost:3443)
- API: [https://localhost:8000](https://localhost:8000)
- CAPTCHA: [http://localhost:3001](http://localhost:3001)
- Managed HAProxy: ports 80/443

Log in with username `admin` and the password you set in `ADMIN_PASSWORD`.
If `ADMIN_PASSWORD` is not set, a random password is generated on first boot
and printed once in the API logs (`docker compose logs api | grep password`).

## Development Setup

Requirements: Python 3.14+ and Node.js 20+.

```bash
# 1. Backend
python3.14 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cd backend
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# 2. Frontend (separate terminal)
cd frontend
npm install
npm run dev
```

Open [http://localhost:5173](http://localhost:5173).

Run tests:

```bash
pytest backend/tests/          # backend
cd frontend && npm test        # frontend
```

## Architecture

| Service | Role |
|---------|------|
| `api` | FastAPI control plane: config generation, cert manager, metrics samplers, task queue |
| `corex` | HAProxy data plane with native Rust/Lua modules (GeoIP, compression, fingerprinting, WebP) |
| `frontend` | React + Vite + TailwindCSS management GUI |
| `coraza-spoa` | Coraza WAF engine (HAProxy SPOE filter) |
| `varnish` | Disk cache tier |
| `valkey` | Cache, rate limiting, sessions, task queue |
| `postgres` | Primary database (SQLite also supported for development) |
| `cap` | Built-in CAPTCHA service (optional) |
| `mcp-server` / `mcp-gateway` | AI agent integration (optional) |

## Project Structure

```
.
├── backend/app/        # FastAPI control plane
│   ├── api/            # routers and schemas
│   ├── core/           # config, database, valkey client
│   ├── db/             # Alembic migrations
│   ├── models/         # SQLAlchemy models
│   └── services/       # HAProxy config generation, certs, metrics, WAF, tasks
├── frontend/           # React management GUI
├── haproxy/            # HAProxy image, Rust/Lua native modules
├── coraza-spoa/        # Coraza WAF configuration
├── mcp-server/         # MCP server for AI-driven management
├── mcp-gateway/        # multi-tenant MCP gateway
├── shared/             # code shared between backend and gateway
├── deploy.py           # selective-rebuild deploy script (see deploy.md)
└── docker-compose.yml
```

## Deployment

See [deploy.md](deploy.md) for deploying to a remote Docker host with
selective service rebuilds, and [SECURITY.md](SECURITY.md) for the production
hardening checklist.

## License

Licensed under the [Apache License 2.0 with the Commons Clause condition](LICENSE).
You may use, modify, and self-host coreX Manager freely, but you may not sell
it (including offering it as a paid hosted service) without a separate
license. Vendored third-party components retain their original licenses — see
[NOTICE](NOTICE).
