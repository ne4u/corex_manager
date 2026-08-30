#!/bin/sh
set -e

# Create a minimal starting HAProxy configuration if it does not exist.
# The Data Plane API will later manage and replace this file.
create_minimal_config() {
    mkdir -p /app/data

    # Data Plane API credentials — warn if enabled but not provided.
    local dp_user="${DATAPLANEAPI_USER:-admin}"
    local dp_pass="${DATAPLANEAPI_PASS}"
    if [ "${DATAPLANE_API_ENABLED:-false}" = "true" ] && [ -z "$dp_pass" ]; then
        echo "WARNING: DATAPLANE_API_ENABLED=true but DATAPLANEAPI_PASS is not set." >&2
        echo "         The Data Plane API will not authenticate. Set DATAPLANE_API_PASSWORD" >&2
        echo "         in your .env file." >&2
    fi
    # Default to a placeholder that will never match if no password is set
    dp_pass="${dp_pass:-disabled-no-access}"

    # Stats auth — require credentials if HAPROXY_STATS_USER/PASS are set
    local stats_auth=""
    if [ -n "${HAPROXY_STATS_USER:-}" ] && [ -n "${HAPROXY_STATS_PASS:-}" ]; then
        stats_auth="    stats auth ${HAPROXY_STATS_USER}:${HAPROXY_STATS_PASS}"
    fi

    cat > /app/data/haproxy.cfg <<EOF
global
    pidfile /var/run/haproxy.pid
    stats socket /var/run/haproxy.sock mode 600 expose-fd listeners level admin
    stats timeout 30s

defaults
    mode http
    timeout connect 5s
    timeout client 50s
    timeout server 50s

userlist dataplane-api
    user ${dp_user} insecure-password ${dp_pass}

listen stats
    bind *:8404
    stats enable
    stats uri /
    stats refresh 10s
${stats_auth}
EOF
}

if [ ! -f /app/data/haproxy.cfg ]; then
    create_minimal_config
fi

# Ensure volume mount points are writable by the haproxy user after setuid
chown haproxy:haproxy /var/run /app/data

# Empty geo_country and geo_asn maps for HAProxy map_ip (populated by GeoIpDownloader)
touch /app/data/geo_country.map
touch /app/data/geo_asn.map

# ACME HTTP-01 challenge webroot (acme.sh --webroot writes challenge files here)
mkdir -p /app/data/acme-webroot/.well-known/acme-challenge

# If the existing config is invalid, back it up and start with a safe minimal config
if ! haproxy -c -f /app/data/haproxy.cfg; then
    echo "haproxy: /app/data/haproxy.cfg is invalid, backing up and using minimal config"
    mv /app/data/haproxy.cfg /app/data/haproxy.cfg.broken.$(date +%s)
    create_minimal_config
fi

# Pre-create Data Plane API config so it doesn't exit after generating it on first start.
# See haproxytech/dataplaneapi#403
if [ "${DATAPLANE_API_ENABLED:-false}" = "true" ]; then
    # Generate a self-signed TLS cert for the Data Plane API if none exists.
    # For production, mount CA-signed certs at these paths.
    DP_TLS_DIR=/etc/haproxy/tls
    DP_CERT=$DP_TLS_DIR/dataplane.crt
    DP_KEY=$DP_TLS_DIR/dataplane.key
    if [ ! -f "$DP_CERT" ] || [ ! -f "$DP_KEY" ]; then
        mkdir -p "$DP_TLS_DIR"
        openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout "$DP_KEY" -out "$DP_CERT" -days 365 \
            -subj "/CN=haproxy" \
            -addext "subjectAltName=DNS:haproxy,DNS:localhost,IP:127.0.0.1" \
            2>/dev/null
        chmod 600 "$DP_KEY"
    fi

    if [ ! -f /etc/haproxy/dataplaneapi.yaml ]; then
        cat > /etc/haproxy/dataplaneapi.yaml <<YAML
name: haproxy-dataplaneapi
config_version: 2
dataplaneapi:
  host: 0.0.0.0
  port: 5555
  scheme:
    - https
  tls_cert_file: $DP_CERT
  tls_key_file: $DP_KEY
haproxy:
  config_file: /app/data/haproxy.cfg
  haproxy_bin: /usr/local/sbin/haproxy
  master_runtime: /var/run/haproxy-master.sock
  master_worker_mode: true
  reload:
    reload_delay: 5
    reload_strategy: custom
    reload_cmd: "kill -SIGUSR2 1"
    restart_cmd: "kill -SIGUSR2 1"
    reload_retention: 5
YAML
    fi

    mkdir -p /var/log
    (
        # Wait for the HAProxy master runtime socket before starting dataplaneapi
        i=0
        while [ "$i" -lt 30 ]; do
            [ -S /var/run/haproxy-master.sock ] && break
            sleep 0.5
            i=$((i+1))
        done
        # Start in a new session so HAProxy's process-group signals don't kill it
        setsid sh -c '/usr/local/bin/dataplaneapi \
            --host=0.0.0.0 \
            --port=5555 \
            --scheme=https \
            --tls-cert-file='"$DP_CERT"' \
            --tls-key-file='"$DP_KEY"' \
            --config-file=/app/data/haproxy.cfg \
            --haproxy-bin=/usr/local/sbin/haproxy \
            --master-runtime=/var/run/haproxy-master.sock \
            --master-worker-mode \
            --reload-cmd="kill -SIGUSR2 1" \
            --restart-cmd="kill -SIGUSR2 1" \
            --reload-delay=5 \
            --userlist=dataplane-api \
            --reload-retention=5 \
            --show-system-info \
            2>&1 | tee -a /var/log/dataplaneapi.log'
    ) &
fi

exec haproxy -W -S /var/run/haproxy-master.sock -f /app/data/haproxy.cfg "$@"
