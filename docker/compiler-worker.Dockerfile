# Compiler Worker Dockerfile - jockey compiler worker
FROM rust:latest AS builder

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    clang \
    lld \
    llvm \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace Cargo.toml and source
COPY Cargo.toml Cargo.lock ./
COPY compiler ./compiler
COPY runtime ./runtime
COPY packages/shared-types ./packages/shared-types
COPY services/compiler-worker ./services/compiler-worker

# Build the compiler worker
RUN cargo build --release --bin jockey-compiler-worker

# Runtime stage
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    clang \
    lld \
    llvm \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/jockey-compiler-worker /usr/local/bin/jockey-compiler-worker

CMD ["jockey-compiler-worker"]