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

# Runtime stage with full compilation toolchain (enables on-demand native builds)
FROM rust:slim

WORKDIR /app

# Install compilation toolchain & libraries for Linux and Windows cross-compilation
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl-dev \
    pkg-config \
    gcc \
    libc6-dev \
    mingw-w64 \
    && rm -rf /var/lib/apt/lists/* \
    && rustup target add x86_64-pc-windows-gnu

# Copy jocky-api binary
COPY --from=builder /app/target/release/jocky-api /usr/local/bin/jocky-api

# Copy runtime crates and workspace config for dynamic compilation
COPY --from=builder /app/runtime /app/runtime
COPY --from=builder /app/compiler /app/compiler
COPY --from=builder /app/Cargo.toml /app/Cargo.toml
COPY --from=builder /app/Cargo.lock /app/Cargo.lock

# Copy cargo registry cache so compilations are fast and don't re-download from crates.io
COPY --from=builder /usr/local/cargo/registry /usr/local/cargo/registry

ENV JOCKY_BACKEND=rust
ENV JOCKY_RUNTIME_DIR=/app/runtime
ENV RUST_LOG=info

EXPOSE 8080

CMD ["jocky-api"]