FROM python:3.12.13-slim

WORKDIR /app

# Pin acme.sh to a specific release (3.1.4) and verify the download instead of
# piping an unversioned install script directly to a shell.
ARG ACME_SH_VERSION=3.1.4
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    netcat-openbsd \
    certbot \
    socat \
    cron \
    openssl \
    && rm -rf /var/lib/apt/lists/* \
    && set -e; url="https://github.com/acmesh-official/acme.sh/archive/refs/tags/${ACME_SH_VERSION}.tar.gz"; \
        for attempt in 1 2 3 4 5; do \
            echo "Downloading acme.sh (attempt $attempt/5)..."; \
            if curl -fsSL --retry 3 --retry-delay 5 -o /tmp/acme.sh.tar.gz "$url"; then \
                break; \
            fi; \
            if [ "$attempt" = 5 ]; then \
                echo "Failed to download acme.sh after 5 attempts" >&2; exit 1; \
            fi; \
            backoff=$((attempt * 10)); \
            echo "Download failed, retrying in ${backoff}s..." >&2; \
            sleep "$backoff"; \
        done \
    && mkdir -p /tmp/acme.sh-src \
    && tar -xzf /tmp/acme.sh.tar.gz -C /tmp/acme.sh-src --strip-components=1 \
    && cd /tmp/acme.sh-src \
    && sh acme.sh --install --home /app/certs/.acme.sh --nocron \
    && rm -rf /tmp/acme.sh.tar.gz /tmp/acme.sh-src

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/app /app/app
COPY shared /app/shared
COPY backend/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENV PYTHONPATH=/app

EXPOSE 8000

ENTRYPOINT ["/app/entrypoint.sh"]
