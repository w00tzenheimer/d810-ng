#!/usr/bin/env bash
# stage_cobra_bake_context.sh - put the published d810-cobra wheel and its
# verification into a Docker build context.
#
# Usage:
#   stage_cobra_bake_context.sh <context-dir> <arch|platform> <wheel-source-dir>
#
# <arch|platform> accepts either a machine name (aarch64, x86_64) or a Docker
# platform (linux/arm64, linux/amd64); the wheel is native code, so the image's
# platform decides which one is staged.  Exactly ONE wheel is staged: shipping
# both would put the wrong architecture's megabytes into the image's COPY layer
# and would let the bake step pick the wrong file if `uname -m` ever lies.
#
# The build context assembled by the image build script holds only the IDA
# resource directory, so anything the Dockerfile needs must be placed here
# first.  Staging is idempotent and refuses to install bytes whose sha256 is
# not the published one - the hash is checked here, on the host, and AGAIN
# inside the image, because a context can be assembled by hand.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=cobra_identity.sh
. "$HERE/cobra_identity.sh"

die() { echo "ERROR: $*" >&2; exit 1; }

CONTEXT="${1:?usage: stage_cobra_bake_context.sh <context-dir> <arch|platform> <wheel-source-dir>}"
ARCH_OR_PLATFORM="${2:?missing arch/platform}"
WHEEL_SOURCE_DIR="${3:?missing wheel source dir}"

[ -d "$CONTEXT" ] || die "no such build context: $CONTEXT"

ARCH="$(cobra_bake_arch_for_platform "$ARCH_OR_PLATFORM")" \
  || die "unsupported architecture/platform: $ARCH_OR_PLATFORM (expected aarch64/x86_64 or linux/arm64/linux/amd64)"
WHEEL_NAME="$(cobra_bake_wheel_for_arch "$ARCH")"
EXPECTED_SHA="$(cobra_bake_sha256_for_arch "$ARCH")"

WHEEL="$WHEEL_SOURCE_DIR/$WHEEL_NAME"
[ -f "$WHEEL" ] || die "published d810-cobra wheel not found: $WHEEL"

if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL_SHA="$(sha256sum "$WHEEL" | cut -d' ' -f1)"
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL_SHA="$(shasum -a 256 "$WHEEL" | cut -d' ' -f1)"
else
  die "neither sha256sum nor shasum is on PATH; cannot verify $WHEEL_NAME"
fi

# An identical filename does not imply identical bytes: the preflight wheels
# built before the release share both name and size with the published ones.
[ "$ACTUAL_SHA" = "$EXPECTED_SHA" ] \
  || die "$WHEEL hashes to $ACTUAL_SHA, published d810-cobra $COBRA_BAKE_VERSION ($ARCH) is $EXPECTED_SHA"

STAGE="$CONTEXT/cobra-bake"
rm -rf "$STAGE"
mkdir -p "$STAGE"
cp "$WHEEL" "$STAGE/$WHEEL_NAME"
cp "$HERE/verify_cobra_install.py" "$STAGE/verify_cobra_install.py"
printf '%s  %s\n' "$EXPECTED_SHA" "$WHEEL_NAME" > "$STAGE/SHA256SUMS"

echo "[cobra-bake] staged $WHEEL_NAME ($ARCH, sha256 ${EXPECTED_SHA:0:12}) at $STAGE"
