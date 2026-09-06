#!/usr/bin/env bash
# cobra_identity.sh - the one published identity of d810-cobra, for shells.
#
# Sourced by the image build script and by the context-staging helper so the
# bake, the labels and the post-build verification cannot drift apart.
#
# It declares NOTHING itself: every value is read from published_identity
# beside it, which the Docker test runner and the tests of both read too.
# A hash rotation is one edit, in one file, or it is a test failure.
#
# Reading a data file rather than sourcing one is deliberate: a malformed row
# must fail closed, not execute.

COBRA_BAKE_IDENTITY_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/published_identity"

_cobra_bake_load_identity() {
  local arch sha version tag core parent wheel rows=0
  if [ ! -r "$COBRA_BAKE_IDENTITY_FILE" ]; then
    echo "ERROR: the published d810-cobra identity is unreadable: $COBRA_BAKE_IDENTITY_FILE" >&2
    return 1
  fi
  COBRA_BAKE_VERSION=""
  while read -r arch sha version tag core parent wheel; do
    case "$arch" in ""|\#*) continue ;; esac
    if [ -z "$wheel" ] || [ -n "${sha//[0-9a-f]/}" ] || [ "${#sha}" -ne 64 ]; then
      echo "ERROR: malformed row in $COBRA_BAKE_IDENTITY_FILE: $arch $sha" >&2
      return 1
    fi
    case "$arch" in
      aarch64)
        COBRA_BAKE_SHA256_AARCH64="$sha"
        COBRA_BAKE_WHEEL_AARCH64="$wheel"
        ;;
      x86_64)
        COBRA_BAKE_SHA256_X86_64="$sha"
        COBRA_BAKE_WHEEL_X86_64="$wheel"
        ;;
      *)
        echo "ERROR: unsupported architecture in $COBRA_BAKE_IDENTITY_FILE: $arch" >&2
        return 1
        ;;
    esac
    # Every row describes the same release; a row that disagrees is a drift
    # this file exists to prevent, so refuse rather than pick a winner.
    if [ -n "$COBRA_BAKE_VERSION" ] && { [ "$version" != "$COBRA_BAKE_VERSION" ] \
      || [ "$tag" != "$COBRA_BAKE_TAG_COMMIT" ] \
      || [ "$core" != "$COBRA_BAKE_CORE_COMMIT" ] \
      || [ "$parent" != "$COBRA_BAKE_PARENT_COMMIT" ]; }; then
      echo "ERROR: $COBRA_BAKE_IDENTITY_FILE describes more than one release" >&2
      return 1
    fi
    COBRA_BAKE_VERSION="$version"
    COBRA_BAKE_TAG_COMMIT="$tag"
    COBRA_BAKE_CORE_COMMIT="$core"
    COBRA_BAKE_PARENT_COMMIT="$parent"
    rows=$((rows + 1))
  done < "$COBRA_BAKE_IDENTITY_FILE"
  if [ "$rows" -ne 2 ] || [ -z "$COBRA_BAKE_SHA256_AARCH64" ] || [ -z "$COBRA_BAKE_SHA256_X86_64" ]; then
    echo "ERROR: $COBRA_BAKE_IDENTITY_FILE must name exactly one aarch64 and one x86_64 wheel" >&2
    return 1
  fi
}

_cobra_bake_load_identity || return 1 2>/dev/null || exit 1

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
