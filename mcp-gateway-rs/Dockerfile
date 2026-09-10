FROM rust:1.98-slim AS builder

WORKDIR /build

# Install build dependencies.
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace manifest and crate manifests first for layer caching.
COPY Cargo.toml Cargo.lock ./
COPY crates/core/Cargo.toml crates/core/Cargo.toml
COPY crates/scan/Cargo.toml crates/scan/Cargo.toml
COPY crates/policy/Cargo.toml crates/policy/Cargo.toml
COPY crates/proxy/Cargo.toml crates/proxy/Cargo.toml
COPY crates/gateway/Cargo.toml crates/gateway/Cargo.toml

# Create stub source files so dependencies can be cached.
RUN mkdir -p crates/core/src crates/scan/src crates/policy/src crates/proxy/src crates/gateway/src && \
    echo "fn main() {}" > crates/gateway/src/main.rs && \
    touch crates/core/src/lib.rs crates/scan/src/lib.rs crates/policy/src/lib.rs crates/proxy/src/lib.rs

# Build dependencies only (cached layer).
RUN cargo build --release --bin mcp-gateway || true

# Copy actual source code.
COPY crates/ crates/

# Build the gateway binary.
RUN touch crates/core/src/lib.rs crates/scan/src/lib.rs crates/policy/src/lib.rs crates/proxy/src/lib.rs && \
    cargo build --release --bin mcp-gateway

# --- Runtime stage ---
# Must match the builder's Debian version (Trixie) to avoid glibc mismatch.
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3t64 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /build/target/release/mcp-gateway /app/mcp-gateway

RUN mkdir -p /app/data/mcp

EXPOSE 8089

ENV MCP_GATEWAY_BIND=0.0.0.0:8089
ENV MCP_CONFIG_PATH=/app/data/mcp/config.bundle.json
ENV MCP_EVENTS_LOG_PATH=/app/data/mcp/events.ndjson
ENV RUST_LOG=info

CMD ["/app/mcp-gateway"]
