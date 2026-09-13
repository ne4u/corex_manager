FROM python:3.14-alpine

WORKDIR /app

# Pin acme.sh to a specific release (3.1.4) and verify the download instead of
# piping an unversioned install script directly to a shell.
# certbot comes from requirements.txt (pinned + DNS plugins); Alpine's certbot
# apk would pull in a second system Python. cron is unused — renewals are
# driven by the app's task loop, and busybox crond is built in if ever needed.
# tzdata is required for zoneinfo.available_timezones() (Alpine ships none).
ARG ACME_SH_VERSION=3.1.4
RUN apk add --no-cache \
    curl \
    netcat-openbsd \
    socat \
    openssl \
    tzdata \
    && apk upgrade --no-cache \
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
# PyYAML 6.0.1 and maxminddb publish no musllinux wheels, so they build from
# source — install a throwaway toolchain, then remove it. Note: do NOT add
# python3-dev — that's Alpine's system Python 3.12 headers, not this image's
# Python 3.14.
RUN apk add --no-cache --virtual .build-deps \
    build-base \
    yaml-dev \
    && pip install --no-cache-dir -r requirements.txt \
    && apk del .build-deps

COPY backend/app /app/app
COPY shared /app/shared
COPY mcp-gateway /app/mcp-gateway
COPY backend/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENV PYTHONPATH=/app

EXPOSE 8000

ENTRYPOINT ["/app/entrypoint.sh"]
