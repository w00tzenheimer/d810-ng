#!/usr/bin/env bash
#
# Build the restructuring lab DLL locally via Docker (MinGW C + llvm-ml64 MASM),
# fully isolated from libobfuscated.
#
# Isolation guarantees (why this is safe where the libobfuscated build is not):
#   * The container mounts ONLY this lab dir (writable) + samples/include
#     (read-only). It physically cannot reach samples/Makefile, samples/masm/,
#     or samples/bins/libobfuscated.dll.
#   * This lab's Makefile only ever writes build/ and bins/ inside the lab dir.
#   * No throwaway-/tmp copy is needed -- there is nothing shared to clobber.
#
# After building, the uniquely-named DLL is copied into samples/bins/ so the
# existing dump harness / D810_TEST_BINARY can resolve it. That copy never
# touches libobfuscated.dll.
#
# Usage:  samples/restructuring_lab/build_lab.sh
set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAMPLES="$(cd "$LAB_DIR/.." && pwd)"
IMAGE="restructuring-lab"
OUT="restructuring_lab.dll"

command -v docker >/dev/null 2>&1 || { echo "[lab] docker is required" >&2; exit 1; }

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "[lab] building $IMAGE image from Dockerfile.lab ..."
  docker build -t "$IMAGE" -f "$LAB_DIR/Dockerfile.lab" "$LAB_DIR"
fi

echo "[lab] building $OUT (C via mingw clang, MASM via llvm-ml64) ..."
docker run --rm \
  -v "$LAB_DIR":/work \
  -v "$SAMPLES/include":/include:ro \
  "$IMAGE" make clean all

DLL="$LAB_DIR/bins/$OUT"
[ -f "$DLL" ] || { echo "[lab] build produced no $OUT" >&2; exit 1; }

# Record libobfuscated's hash before/after the copy to prove non-interference.
LIBO="$SAMPLES/bins/libobfuscated.dll"
before=""; [ -f "$LIBO" ] && before="$(shasum -a 256 "$LIBO" | cut -d' ' -f1)"

/bin/cp -f "$DLL" "$SAMPLES/bins/$OUT"
echo "[lab] wrote $SAMPLES/bins/$OUT ($(wc -c < "$SAMPLES/bins/$OUT") bytes)"

if [ -n "$before" ]; then
  after="$(shasum -a 256 "$LIBO" | cut -d' ' -f1)"
  [ "$before" = "$after" ] && echo "[lab] libobfuscated.dll untouched (sha256 $after)" \
    || echo "[lab] WARNING: libobfuscated.dll hash changed!" >&2
fi
