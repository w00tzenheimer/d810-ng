#!/usr/bin/env bash
#
# Rebuild the Hex-Rays structuring lab binary:
#   samples/src/c/hexrays_structuring_lab.c  ->  samples/bins/hexrays_structuring_lab.dll
#
# Why this script exists (every line is a trap learned the hard way):
#   1. The lab has NO separate build -- its fixtures live in the samples C file and compile
#      into a dedicated DLL via the samples Makefile.
#   2. SRCS MUST be overridden to *only* the lab file. The full `src/c/*.c` glob fails to
#      cross-compile because sibling samples use MSVC intrinsics (e.g. sub_7FFB206BBD50.c's
#      `__security_cookie`) -- the committed binaries were built on a Windows/MSVC host.
#   3. The build runs in a docker image (debian + clang + lld + mingw-w64); a host macОS
#      Apple-clang build also fails on those siblings and lacks the mingw runtime.
#   4. `make BINARY_NAME=<anything>` STILL runs `rm -f bins/libobfuscated.dll` in its clean
#      step, so we build in a throwaway /tmp copy -- otherwise it deletes the shared binary
#      every other test depends on. (To recover: git checkout -- samples/bins/libobfuscated.dll)
#   5. The shell's `cp` is often aliased to `cp -i`; use `/bin/cp -f` for the final copy.
#
# Usage:  tools/hexrays_structuring_lab/build_lab_binary.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SAMPLES="$REPO_ROOT/samples"
LAB_SRC="src/c/hexrays_structuring_lab.c"
OUT="hexrays_structuring_lab.dll"
IMAGE="win-build"

command -v docker >/dev/null 2>&1 || { echo "[lab] docker is required" >&2; exit 1; }
[ -f "$SAMPLES/$LAB_SRC" ] || { echo "[lab] missing $SAMPLES/$LAB_SRC" >&2; exit 1; }

# Cross-compile image (debian + clang + lld + mingw-w64). The samples Makefile generates the
# same image on demand; build it explicitly here so the script is self-contained.
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "[lab] building $IMAGE docker image from samples/Dockerfile.windows ..."
  docker build -t "$IMAGE" -f "$SAMPLES/Dockerfile.windows" "$SAMPLES"
fi

# Build in a throwaway copy so the Makefile clean step cannot touch the real shared binary.
BUILD="$(mktemp -d "${TMPDIR:-/tmp}/lab_build.XXXXXX")"
trap 'rm -rf "$BUILD"' EXIT
cp -r "$SAMPLES" "$BUILD/samples"

echo "[lab] cross-compiling $OUT (only $LAB_SRC) ..."
docker run --rm -v "$BUILD/samples":/work "$IMAGE" \
  make TARGET_OS=windows MINGW_SYSROOT=/usr BINARY_NAME=hexrays_structuring_lab SRCS="$LAB_SRC"

DLL="$BUILD/samples/bins/$OUT"
[ -f "$DLL" ] || { echo "[lab] build produced no $OUT" >&2; exit 1; }
/bin/cp -f "$DLL" "$SAMPLES/bins/$OUT"
echo "[lab] wrote $SAMPLES/bins/$OUT ($(wc -c < "$SAMPLES/bins/$OUT") bytes)"

# Sanity: the shared binary the Makefile likes to delete must still be present.
[ -f "$SAMPLES/bins/libobfuscated.dll" ] || echo "[lab] WARNING: libobfuscated.dll missing -- run: git checkout -- samples/bins/libobfuscated.dll" >&2
