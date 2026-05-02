# Multi-stage Rust build for Signet
# Supports both self-hosted and multi-tenant modes

FROM rust:1.85-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace manifests first for dependency caching
COPY Cargo.toml Cargo.lock ./
COPY crates/signet-core/Cargo.toml crates/signet-core/
COPY crates/signet-vault/Cargo.toml crates/signet-vault/
COPY crates/signet-policy/Cargo.toml crates/signet-policy/
COPY crates/signet-notify/Cargo.toml crates/signet-notify/
COPY crates/signet-cred/Cargo.toml crates/signet-cred/
COPY crates/signet-proof/Cargo.toml crates/signet-proof/
COPY crates/signet-sdk/Cargo.toml crates/signet-sdk/
COPY crates/signet-mcp/Cargo.toml crates/signet-mcp/
COPY crates/signet/Cargo.toml crates/signet/

# Create stub source files for dependency caching
RUN for d in signet-core signet-vault signet-policy signet-notify signet-cred signet-proof signet-sdk signet-mcp; do \
        mkdir -p crates/$d/src && echo "// stub" > crates/$d/src/lib.rs; \
    done && \
    mkdir -p crates/signet/src && \
    echo "fn main() {}" > crates/signet/src/main.rs && \
    echo "// stub" > crates/signet/src/lib.rs

# Build dependencies only (cache layer)
RUN cargo build --release 2>/dev/null || true

# Copy actual source
COPY crates/ crates/

# Touch source files to invalidate the stub builds
RUN find crates/ -name "*.rs" -exec touch {} +

# Build release binary
RUN cargo build --release --bin signet

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r signet && useradd -r -g signet -d /home/signet -m signet

COPY --from=builder /app/target/release/signet /usr/local/bin/signet

# Create vault directory
RUN mkdir -p /home/signet/.signet/vault && \
    chown -R signet:signet /home/signet/.signet

USER signet
WORKDIR /home/signet

# Default: HTTP multi-tenant mode
ENV SIGNET_HOSTING_MODE=multi_tenant

EXPOSE 3000

ENTRYPOINT ["signet"]
CMD ["serve", "--transport", "http", "--bind", "0.0.0.0", "--port", "3000"]
