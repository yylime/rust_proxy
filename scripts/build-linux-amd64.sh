#!/usr/bin/env bash
# Build a linux/amd64 binary from macOS and copy it to the current directory.
#
# Requirements: Docker Desktop (with Rosetta / emulation support).
set -euo pipefail

cd "$(dirname "$0")/.."

echo "Building linux/amd64 image..."
docker build --platform linux/amd64 -t rust-proxy-server:build .

echo "Extracting binary..."
container=$(docker create rust-proxy-server:build)
docker cp "$container":/app/target/release/rust-proxy-server ./rust-proxy-server-linux-amd64
docker rm "$container" >/dev/null

echo "Done: ./rust-proxy-server-linux-amd64"

