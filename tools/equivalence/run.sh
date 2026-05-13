#!/usr/bin/env bash
# Build + run the equivalence fuzz harness.
set -e
cd "$(dirname "$0")"
make clean >/dev/null 2>&1 || true
make
K="${1:-1000}"
SEED="${2:-42}"
./harness "$K" "$SEED"
