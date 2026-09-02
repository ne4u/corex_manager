# coreX Manager — Kubernetes Deployment

This directory contains the Helm chart and documentation for deploying coreX
Manager to Kubernetes. The Helm chart supports both self-contained
(in-cluster PostgreSQL/Valkey) and external database deployments.

## Architecture

### Sidecar Pod (StatefulSet)

The tightly-coupled services — `api` (backend), `corex` (HAProxy),
`coraza-spoa` (WAF), and optionally `varnish` (disk cache) — run as containers
in a **single Pod**. This is required because:

1. **Shared volume**: All containers share the `haproxy-data` volume
   (config files, certificates, Coraza logs, VCL).
2. **Unix socket**: The API communicates with HAProxy via `/var/run/haproxy.sock`,
   which requires co-location.
3. **localhost networking**: HAProxy proxies to Coraza SPOA and Varnish via
   `127.0.0.1`, avoiding network hops.

`shareProcessNamespace: true` is set so the API container can signal Coraza's
PID 1 for restarts (the Kubernetes API cannot restart a single container in a
pod without rolling the whole pod).

### Runtime Backend Selection

The backend uses a runtime abstraction (`backend/app/services/runtime/`) that
auto-detects the deployment environment:

- **Docker Compose** (default): Uses the Docker SDK (`docker.from_env()`) for
  container exec, log retrieval, and restarts.
- **Kubernetes**: Uses the Kubernetes API (in-cluster config) for exec, log
  retrieval, and restarts. Targets the pod's own containers via the downward
  API (`COREX_POD_NAME`, `COREX_POD_NAMESPACE`).
- **None**: Graceful degradation — falls back to local binaries where available.

Set `COREX_RUNTIME=kubernetes` explicitly, or leave it as `auto` and the
backend will detect the K8s service account token automatically.

### HAProxy DNS Resolver

The HAProxy config's `resolvers` section is parameterized via:

- `HAPROXY_RESOLVER_NAME` (default: `docker`)
- `HAPROXY_RESOLVER_NAMESERVER` (default: `127.0.0.11:53`)

For Kubernetes, the Helm chart sets these to `kube-dns` and the cluster's
CoreDNS IP (default: `169.254.25.10:53`). Override via `values.yaml`:

```yaml
env:
  HAPROXY_RESOLVER_NAME: "kube-dns"
  HAPROXY_RESOLVER_NAMESERVER: "10.96.0.10:53"  # your cluster's DNS IP
```

### Database and Cache

Both PostgreSQL and Valkey support **in-cluster** (StatefulSet) and
**external** deployment modes:

```yaml
# In-cluster (default)
postgres:
  enabled: true
  password: "strong-password"

# External
postgres:
  enabled: false
  external:
    host: "db.internal.example.com"
    port: 5432
    database: "haproxy_manager"
    user: "haproxy"
    password: "strong-password"
```

The same pattern applies to `valkey`.

## Quick Start

### Prerequisites

- A running Kubernetes cluster (kind, minikube, k3s, EKS, GKE, AKS, etc.)
- `helm` 3.x installed
- `kubectl` installed
- Docker images built and available to the cluster

### 1. Build Images

```bash
# Build all images
docker build -t corex-api:latest -f backend/Dockerfile .
docker build -t corex-corex:latest -f haproxy/Dockerfile .
docker build -t corex-frontend:latest -f frontend/Dockerfile .

# Load into kind
kind load docker-image corex-api:latest corex-corex:latest corex-frontend:latest

# Or load into minikube
minikube image load corex-api:latest corex-corex:latest corex-frontend:latest
```

### 2. Create a Values File

```bash
cp k8s/charts/corex-manager/values.yaml my-values.yaml
# Edit my-values.yaml — at minimum set:
#   secrets.secretKey (generate: python -c "import secrets; print(secrets.token_urlsafe(32))")
#   secrets.adminPassword
#   secrets.dataplaneApiPassword
#   postgres.password
```

### 3. Install the Chart

```bash
helm install corex k8s/charts/corex-manager \
  -n corex \
  --create-namespace \
  -f my-values.yaml
```

### 4. Access the UI

```bash
# Port-forward the frontend
kubectl port-forward svc/corex-frontend -n corex 3443:443
# Open https://localhost:3443
```

### 5. Expose HAProxy

```bash
# For LoadBalancer type (cloud clusters):
kubectl get svc corex-corex -n corex

# For local clusters, use port-forward:
kubectl port-forward svc/corex-corex -n corex 8080:80 8443:443
```

## Deploy Script

The `deploy.py` script supports three targets:

### Docker (default — unchanged)

```bash
python3 deploy.py --host 1.2.3.4 --user admin
```

### k8s-cluster (local cluster)

Builds images locally, loads them into the local cluster (kind/minikube),
and runs `helm upgrade`:

```bash
python3 deploy.py --target k8s-cluster \
  --release-name corex \
  --namespace corex \
  --values-file my-values.yaml
```

### k8s-remote (remote cluster via SSH)

Rsyncs the project to a remote host, builds images on the remote, loads them
into the remote cluster, and runs `helm upgrade` on the remote:

```bash
python3 deploy.py --target k8s-remote \
  --host 1.2.3.4 --user admin \
  --release-name corex \
  --namespace corex \
  --values-file my-values.yaml
```

All targets share the same selective-rebuild change detection: a manifest of
file hashes is compared against the last deploy, and only services whose files
changed are rebuilt.

## Configuration Reference

See `k8s/charts/corex-manager/values.yaml` for all configurable options. Key
sections:

| Section | Description |
|---------|-------------|
| `image.*` | Container image repos/tags/pull policies |
| `corexPod.*` | Sidecar pod config (resources, capabilities, sysctls) |
| `diskCache.enabled` | Toggle Varnish disk cache sidecar |
| `haproxyData.persistence` | PVC for shared haproxy-data volume |
| `certs.persistence` | PVC for certificates |
| `postgres.enabled` | In-cluster PostgreSQL (StatefulSet) vs external |
| `valkey.enabled` | In-cluster Valkey (StatefulSet) vs external |
| `cap.enabled` | CAPTCHA service |
| `frontend.service` | Frontend Service type and ports |
| `corexService` | HAProxy Service (LoadBalancer/NodePort/ClusterIP) |
| `mcpGateway.enabled` | MCP Gateway sidecar |
| `mcpServer.enabled` | MCP Server sidecar |
| `ingress.enabled` | Ingress resource |
| `env.*` | Non-secret env vars for the api container |
| `secrets.*` | Secret env vars (or use `existingSecret`) |

## Backward Compatibility

The Docker Compose deployment is fully preserved:

- `docker-compose.yml` is unchanged.
- `deploy.py --target docker` (the default) uses the exact same rsync +
  `docker compose build/up` flow as before.
- The backend's `DockerRuntime` is a verbatim extraction of the original
  Docker SDK calls — same arguments, same timeout handling, same behavior.
- When `COREX_RUNTIME=auto` (default) and no K8s service account token is
  present, the Docker SDK path is used exactly as before.
- Parity tests (`backend/tests/test_runtime_docker_parity.py`) verify that
  `DockerRuntime` produces identical behavior to the original inline code.
