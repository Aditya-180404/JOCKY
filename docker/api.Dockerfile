# API Dockerfile - jocky compiler API
FROM rust:latest AS builder

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Use rust backend instead of LLVM for Docker builds
ENV JOCKY_BACKEND=rust

# Copy workspace Cargo.toml and source
COPY Cargo.toml Cargo.lock ./
COPY apps/api ./apps/api
COPY compiler ./compiler
COPY runtime ./runtime
COPY services/compiler-worker ./services/compiler-worker
COPY packages/shared-types ./packages/shared-types

# Build the API
RUN cargo build --release --bin jocky-api

# Runtime stage
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/jocky-api /usr/local/bin/jocky-api

EXPOSE 8080

CMD ["jocky-api"]