#!/bin/sh
set -e

# Generate a self-signed internal TLS certificate for the backend API if one
# does not already exist. This encrypts traffic on the internal Docker network
# between nginx and the backend. For production, mount your own CA-signed certs
# at the same paths (BACKEND_TLS_CERT / BACKEND_TLS_KEY).
INTERNAL_CERT_DIR="${BACKEND_TLS_CERT_DIR:-/app/certs/internal}"
CERT_FILE="${BACKEND_TLS_CERT:-$INTERNAL_CERT_DIR/api.crt}"
KEY_FILE="${BACKEND_TLS_KEY:-$INTERNAL_CERT_DIR/api.key}"

if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
    echo "Generating self-signed internal TLS certificate for backend API..."
    mkdir -p "$INTERNAL_CERT_DIR"
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$KEY_FILE" \
        -out "$CERT_FILE" \
        -days 365 \
        -subj "/CN=api" \
        -addext "subjectAltName=DNS:api,DNS:localhost,IP:127.0.0.1" \
        2>/dev/null
    chmod 600 "$KEY_FILE"
    echo "Internal TLS certificate written to $CERT_FILE"
fi

exec uvicorn app.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --ssl-keyfile "$KEY_FILE" \
    --ssl-certfile "$CERT_FILE" \
    "$@"
