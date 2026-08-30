# Stage 1: Build the haproxy-geoip2 Rust Lua module
# The module is a cdylib (.so) that HAProxy loads via lua-load-per-thread.
# Built against musl (alpine) so the ABI matches the HAProxy runtime image.
FROM rust:1.91-alpine AS geoip2-builder
RUN apk add --no-cache musl-dev
WORKDIR /build
COPY haproxy/geoip2/ ./
RUN cargo build --release -p haproxy-geoip2-module

# Stage 1b: Build the haproxy-compression Rust Lua module (brotli + zstd).
# Same musl/alpine toolchain as geoip2; produces a cdylib loaded via
# lua-load-per-thread when brotli or zstd compression is enabled.
FROM rust:1.91-alpine AS compression-builder
RUN apk add --no-cache musl-dev
WORKDIR /build
COPY haproxy/compression/ ./
RUN cargo build --release -p haproxy-compression-module

# Stage 1c: Build the haproxy-resp-transform Rust Lua module (response body
# rewrite/inject/mask). Same musl/alpine toolchain; produces a cdylib loaded
# via the combined modules.lua loader when response transforms are enabled.
FROM rust:1.91-alpine AS resp-transform-builder
RUN apk add --no-cache musl-dev
WORKDIR /build
COPY haproxy/resp_transform/ ./
RUN cargo build --release -p haproxy_resp_transform_module

# Stage 1d: Build the haproxy-api-armor Rust Lua module (body parsing, GraphQL
# analysis, schema validation, JWT validation). Shared workspace with 4 crates
# (body_parser, graphql, schema_validator, jwt_validator) + a combined module
# cdylib. Loaded via the combined modules.lua loader when API Armor is enabled.
FROM rust:1.91-alpine AS api-armor-builder
RUN apk add --no-cache musl-dev
WORKDIR /build
COPY haproxy/api-armor/ ./
RUN cargo build --release -p haproxy-api-armor-module

# Stage 1e: Build the haproxy-img-2-webp Rust Lua module (on-the-fly
# JPEG/PNG/GIF to WebP conversion). Same musl/alpine toolchain; produces a
# cdylib loaded via the combined modules.lua loader when image conversion is
# enabled in Global Options. The image and webp crates require a C compiler
# and make for libwebp-sys; musl-dev + build-base cover this.
FROM rust:1.91-alpine AS img-2-webp-builder
RUN apk add --no-cache musl-dev build-base make
WORKDIR /build
COPY haproxy/img_2_webp/ ./
RUN cargo build --release -p haproxy-img-2-webp-module

# Stage 1f: Build the haproxy-req-fp Rust Lua module (HTTP request
# fingerprinting). Same musl/alpine toolchain; produces a cdylib loaded via
# the combined modules.lua loader when request fingerprinting is enabled in
# Global Options. API Armor depends on this module's txn subfields.
FROM rust:1.91-alpine AS req-fp-builder
RUN apk add --no-cache musl-dev
WORKDIR /build
COPY haproxy/req_fp/ ./
RUN cargo build --release -p haproxy-req-fp-module

# Stage 2: HAProxy runtime
FROM haproxytech/haproxy-alpine:3.4

USER root
ARG DATAPLANEAPI_VERSION=3.4.2
# dataplaneapi release arch is auto-detected from BuildKit's TARGETARCH
# (amd64->x86_64, 386->i386; arm64/arm/ppc64le/s390x match as-is). Set
# DATAPLANEAPI_ARCH (e.g. linux_arm64) to override. Requires BuildKit
# (DOCKER_BUILDKIT=1, default on modern Docker) for TARGETARCH injection;
# falls back to linux_x86_64 when TARGETARCH is unavailable.
ARG TARGETARCH
ARG DATAPLANEAPI_ARCH=

RUN apk add --no-cache ca-certificates curl tar util-linux lua5.4 openssl \
    && apk upgrade --no-cache \
    && mkdir -p /tmp/dataplaneapi /usr/local/bin \
    && if [ -n "$DATAPLANEAPI_ARCH" ]; then \
         dp_arch="$DATAPLANEAPI_ARCH"; \
       else \
         case "${TARGETARCH:-amd64}" in \
           amd64) dp_arch=linux_x86_64 ;; \
           386) dp_arch=linux_i386 ;; \
           *) dp_arch="linux_${TARGETARCH:-amd64}" ;; \
         esac; \
       fi \
    && curl -L -o /tmp/dataplaneapi/dataplaneapi.tar.gz \
        "https://github.com/haproxytech/dataplaneapi/releases/download/v${DATAPLANEAPI_VERSION}/dataplaneapi_${DATAPLANEAPI_VERSION}_${dp_arch}.tar.gz" \
    && tar -xzf /tmp/dataplaneapi/dataplaneapi.tar.gz -C /tmp/dataplaneapi \
    && cp /tmp/dataplaneapi/dataplaneapi /usr/local/bin/dataplaneapi \
    && chmod +x /usr/local/bin/dataplaneapi \
    && rm -rf /tmp/dataplaneapi

COPY haproxy/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# JA4 fingerprint Lua script for security rules
COPY haproxy/lua/ja4.lua /etc/haproxy/ja4.lua

# ACME HTTP-01 challenge file server (reads from shared webroot volume)
COPY haproxy/lua/acme.lua /etc/haproxy/acme.lua

# Risk Scoring engine: pure-Lua script providing risk_capture + risk_compute
# actions. Derives metadata fields from req_fp vars + sums per-rule points.
COPY haproxy/lua/risk_score.lua /etc/haproxy/risk_score.lua

# Captcha context store: stores challenge rule context in Valkey (server-side)
# and returns an opaque token, so internal rule details aren't exposed in URLs.
COPY haproxy/lua/captcha_ctx.lua /etc/haproxy/captcha_ctx.lua

# haproxy-geoip2 Rust Lua module (built in Stage 1)
# The .so is loaded via lua-prepend-path + lua-load-per-thread in the generated config.
COPY --from=geoip2-builder /build/target/release/libhaproxy_geoip2_module.so /etc/haproxy/haproxy_geoip2_module.so

# haproxy-compression Rust Lua module (brotli + zstd, built in Stage 1b)
# The .so is loaded via lua-prepend-path + lua-load-per-thread in the generated
# config when brotli or zstd compression is enabled on any listener.
COPY --from=compression-builder /build/target/release/libhaproxy_compression_module.so /etc/haproxy/haproxy_compression_module.so

# Compression module Lua loader (require + register the lua.compress filter)
COPY haproxy/compression/lua/compress.lua /etc/haproxy/compress.lua

# haproxy-resp-transform Rust Lua module (response body rewrite/inject/mask,
# built in Stage 1c). The .so is loaded via the combined modules.lua loader
# when response transforms are enabled in Global Options.
COPY --from=resp-transform-builder /build/target/release/libhaproxy_resp_transform_module.so /etc/haproxy/haproxy_resp_transform_module.so

# Response transform Lua loader (RESP-over-core.tcp() Valkey client + Rust
# module registration; dofile-ed by the generated modules.lua with Valkey
# connection params injected from backend settings/env).
COPY haproxy/resp_transform/lua/resp_transform.lua /etc/haproxy/resp_transform.lua

# haproxy-api-armor Rust Lua module (body parsing, GraphQL analysis, schema
# validation, JWT validation, built in Stage 1d). The .so is loaded via the
# combined modules.lua loader when API Armor is enabled in Global Options.
COPY --from=api-armor-builder /build/target/release/libhaproxy_api_armor_module.so /etc/haproxy/haproxy_api_armor_module.so

# haproxy-img-2-webp Rust Lua module (on-the-fly JPEG/PNG/GIF to WebP,
# built in Stage 1e). The .so is loaded via the combined modules.lua loader
# when image conversion is enabled in Global Options.
COPY --from=img-2-webp-builder /build/target/release/libhaproxy_img_2_webp_module.so /etc/haproxy/haproxy_img_2_webp_module.so

# Image conversion module Lua loader (require + register the lua.img_2_webp
# filter). dofile-ed by the generated modules.lua when image conversion is on.
COPY haproxy/img_2_webp/lua/img_2_webp.lua /etc/haproxy/img_2_webp.lua

# haproxy-req-fp Rust Lua module (HTTP request fingerprinting, built in
# Stage 1f). The .so is loaded via the combined modules.lua loader when
# request fingerprinting is enabled in Global Options. API Armor depends
# on this module's txn subfields (req_fp_ctype, req_fp_method, etc.).
COPY --from=req-fp-builder /build/target/release/libhaproxy_req_fp_module.so /etc/haproxy/haproxy_req_fp_module.so

# Pre-create directories for runtime config and certs
RUN mkdir -p /app/data /app/data/api-armor /app/certs /var/run /etc/haproxy && chown -R haproxy:haproxy /app /var/run /etc/haproxy

# Data Plane API credentials — must be provided at runtime via environment
# variables or Docker secrets. No defaults are baked into the image.
# DATAPLANEAPI_USER and DATAPLANEAPI_PASS are consumed by entrypoint.sh.

EXPOSE 80 443/tcp 443/udp 8404 5555

USER haproxy

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD []
