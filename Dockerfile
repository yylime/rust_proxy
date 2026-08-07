# Builds the linux/amd64 release binary.
#
# Usage (on Apple Silicon use --platform to force amd64):
#   docker build --platform linux/amd64 -t rust-proxy-server:build .
#
# The binary ends up at /app/target/release/rust-proxy-server inside the image.

FROM rust:1.86-slim AS builder

# aws-lc-sys / ring need a C toolchain and cmake.
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake clang pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release

FROM debian:stable-slim

COPY --from=builder /app/target/release/rust-proxy-server /usr/local/bin/rust-proxy-server

EXPOSE 443/udp 443/tcp 8443/tcp

ENTRYPOINT ["/usr/local/bin/rust-proxy-server"]

