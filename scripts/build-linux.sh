#!/bin/sh
# Build molt-web for linux x86_64 in an amd64 rust container (needs docker; pulls rust:1 once).
set -e
cd "$(dirname "$0")/.."
docker run --rm --platform linux/amd64 -v "$PWD":/src -w /src -v molt-web-cargo:/usr/local/cargo/registry rust:1 \
  cargo build --release --target-dir target/linux-amd64
echo "binary: target/linux-amd64/release/molt-web"
