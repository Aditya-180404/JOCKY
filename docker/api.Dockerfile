# Backend API Dockerfile
FROM rust:latest AS builder

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace Cargo.toml and source
COPY Cargo.toml Cargo.lock ./
COPY apps/api ./apps/api
COPY compiler ./compiler
COPY runtime ./runtime
COPY packages/shared-types ./packages/shared-types
COPY services/compiler-worker ./services/compiler-worker

# Build the API
RUN cargo build --release --bin traceforge-api

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/traceforge-api /usr/local/bin/traceforge-api

EXPOSE 8080

CMD ["traceforge-api"]