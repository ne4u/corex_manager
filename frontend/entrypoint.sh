#!/bin/sh
set -e

# Generate a self-signed TLS certificate for the frontend nginx server if one
# does not already exist. For production, mount your CA-signed certs at
# /etc/nginx/tls/frontend.crt and /etc/nginx/tls/frontend.key.
TLS_DIR=/etc/nginx/tls
CERT_FILE=$TLS_DIR/frontend.crt
KEY_FILE=$TLS_DIR/frontend.key

if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
    echo "Generating self-signed TLS certificate for frontend..."
    mkdir -p "$TLS_DIR"
    openssl req -x509 -newkey rsa:4096 -nodes \
        -keyout "$KEY_FILE" \
        -out "$CERT_FILE" \
        -days 365 \
        -subj "/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
        2>/dev/null
    chmod 600 "$KEY_FILE"
fi

exec "$@"
