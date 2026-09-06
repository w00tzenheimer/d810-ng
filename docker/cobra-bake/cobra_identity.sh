#!/usr/bin/env bash
# cobra_identity.sh - the one published identity of d810-cobra, for shells.
#
# Sourced by the image build script and by the context-staging helper so the
# bake, the labels and the post-build verification cannot drift apart.  The
# hashes are the PUBLISHED PyPI artifacts of d810-cobra 0.1.5.  The preflight
# wheels built before the release share their filenames and sizes but not
# their bytes; they are provenance evidence only and are never accepted here.

COBRA_BAKE_VERSION="0.1.5"
# Build/tag commit of the published release (tag v0.1.5).
COBRA_BAKE_TAG_COMMIT="73b405c106d78e1fdc7576b217de39b7dcd0ddb3"
# CoBRA core (third_party/cobra) commit the release was built over.
COBRA_BAKE_CORE_COMMIT="72f616f822f538a0cfbea3c880f9d1e68bb9a8f1"
# d810-cobra source revision the runner pins for source builds.  The baked
# image must name it so a baked run and a source run are comparable.
COBRA_BAKE_PARENT_COMMIT="3b3c406270f1efd8e222f0b05040ae4e074b27d5"

COBRA_BAKE_SHA256_AARCH64="2c85ffe14a1f3c1d2b750790332a7c0a5e911b35f7fc041ebedcd6532382c63c"
COBRA_BAKE_SHA256_X86_64="352133fd4f91227518714735b463b978760650b5f30c71f5276c0bccb90cb72c"

COBRA_BAKE_WHEEL_AARCH64="d810_cobra-${COBRA_BAKE_VERSION}-cp313-cp313-manylinux_2_26_aarch64.manylinux_2_28_aarch64.whl"
COBRA_BAKE_WHEEL_X86_64="d810_cobra-${COBRA_BAKE_VERSION}-cp313-cp313-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl"

# cobra_bake_arch_for_platform linux/arm64 -> aarch64
cobra_bake_arch_for_platform() {
  case "$1" in
    linux/arm64|linux/arm64/*|arm64|aarch64) printf 'aarch64\n' ;;
    linux/amd64|linux/amd64/*|amd64|x86_64)  printf 'x86_64\n' ;;
    *) return 1 ;;
  esac
}

cobra_bake_wheel_for_arch() {
  case "$1" in
    aarch64) printf '%s\n' "$COBRA_BAKE_WHEEL_AARCH64" ;;
    x86_64)  printf '%s\n' "$COBRA_BAKE_WHEEL_X86_64" ;;
    *) return 1 ;;
  esac
}

cobra_bake_sha256_for_arch() {
  case "$1" in
    aarch64) printf '%s\n' "$COBRA_BAKE_SHA256_AARCH64" ;;
    x86_64)  printf '%s\n' "$COBRA_BAKE_SHA256_X86_64" ;;
    *) return 1 ;;
  esac
}

# cobra_bake_label_mismatch <arch> <version> <sha256> <tag> <core> <parent>
#
# Prints every disagreement between an image's org.d810.cobra.* labels and the
# published identity, one per line, and returns 1 when there is any.  A build
# that succeeds proves nothing about which --build-arg values took effect, so
# the build script compares the labels it asked for against what it got.
cobra_bake_label_mismatch() {
  local arch="$1" version="$2" sha="$3" tag="$4" core="$5" parent="$6"
  local expected_sha found=0
  if ! expected_sha="$(cobra_bake_sha256_for_arch "$arch")"; then
    printf 'arch(unsupported %s)\n' "$arch"
    return 1
  fi
  [ "$version" = "$COBRA_BAKE_VERSION" ] || { printf 'version(want %s got %s)\n' "$COBRA_BAKE_VERSION" "${version:-<empty>}"; found=1; }
  [ "$sha" = "$expected_sha" ]           || { printf 'wheel_sha256(want %s got %s)\n' "$expected_sha" "${sha:-<empty>}"; found=1; }
  [ "$tag" = "$COBRA_BAKE_TAG_COMMIT" ]  || { printf 'tag_commit(want %s got %s)\n' "$COBRA_BAKE_TAG_COMMIT" "${tag:-<empty>}"; found=1; }
  [ "$core" = "$COBRA_BAKE_CORE_COMMIT" ]|| { printf 'core_commit(want %s got %s)\n' "$COBRA_BAKE_CORE_COMMIT" "${core:-<empty>}"; found=1; }
  [ "$parent" = "$COBRA_BAKE_PARENT_COMMIT" ] || { printf 'parent_commit(want %s got %s)\n' "$COBRA_BAKE_PARENT_COMMIT" "${parent:-<empty>}"; found=1; }
  [ "$found" -eq 0 ]
}

# cobra_bake_labels_absent <version> <sha256> <tag> <core> <parent>
#
# True when an image claims no CoBRA identity at all.  A vanilla image must be
# in exactly this state: a partial label set would let a consumer believe a
# published wheel is installed when nothing is.
cobra_bake_labels_absent() {
  local value
  for value in "$@"; do
    case "$value" in
      ""|"<no value>") ;;
      *) return 1 ;;
    esac
  done
  return 0
}
