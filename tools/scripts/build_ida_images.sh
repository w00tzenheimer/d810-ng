#!/usr/bin/env bash
# build_ida_images.sh — build the full IDA image matrix for a new IDA release.
#
# Produces four images from one Dockerfile, plus a `latest` alias per repo:
#
#   idapro-<VER>:cli               vanilla, no X11        (SPEEDUPS=0 MODE=cli)
#   idapro-<VER>:x11               vanilla + X11          (SPEEDUPS=0 MODE=x11)
#   idapro-<VER>:latest            -> :cli
#   idapro-<VER>-speedups:cli      d810 tests + gdb       (SPEEDUPS=1 MODE=cli)
#   idapro-<VER>-speedups:x11      d810 tests + gdb + X11 (SPEEDUPS=1 MODE=x11)
#   idapro-<VER>-speedups:latest   -> :cli
#
# Usage:
#   tools/scripts/build_ida_images.sh -f _gitless/resource/Dockerfile.slim
#   tools/scripts/build_ida_images.sh -f <dockerfile> -v 9.5
#   tools/scripts/build_ida_images.sh -f <dockerfile> --only speedups --dry-run
#
# Options:
#   -f, --dockerfile PATH   Dockerfile to build from.                 (required)
#   -v, --version VER       IDA version, e.g. 9.5. Auto-detected from the
#                           Dockerfile's `idaX.Y.run` reference if omitted.
#   -r, --resource-dir DIR  Directory holding idaX.Y.run and friends.
#                           Default: <repo>/_gitless/resource/<VER>
#   -a, --add-path REL      Path the Dockerfile ADDs, relative to the build
#                           context. Auto-detected from the ADD line.
#   -c, --context DIR       Use this build context verbatim instead of building
#                           a minimal one. Warning: the repo root is ~20GB.
#       --only WHICH        vanilla | speedups | all   (default: all)
#       --no-verify         Skip the post-build checks.
#       --no-cache          Pass --no-cache to docker build.
#       --dry-run           Print what would run, build nothing.
#   -h, --help              This text.
#
# Why a minimal context: the Dockerfile does `ADD ./_gitless/resource/<VER>`,
# which forces the context to the repo root. That root is ~20GB with no
# .dockerignore, so every build would ship 20GB to the daemon. This script
# instead assembles a throwaway context containing only the resource directory,
# reproducing the same relative path the ADD expects. On APFS the copy is a
# clone, so it costs nothing.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

DOCKERFILE=""
VERSION=""
RESOURCE_DIR=""
ADD_PATH=""
CONTEXT=""
ONLY="all"
VERIFY=1
NO_CACHE=""
DRY_RUN=0

die() { echo "ERROR: $*" >&2; exit 1; }
note() { echo "[build] $*"; }

usage() { sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//; $d'; }

while [ $# -gt 0 ]; do
  case "$1" in
    -f|--dockerfile)   DOCKERFILE="${2:?}"; shift 2 ;;
    -v|--version)      VERSION="${2:?}"; shift 2 ;;
    -r|--resource-dir) RESOURCE_DIR="${2:?}"; shift 2 ;;
    -a|--add-path)     ADD_PATH="${2:?}"; shift 2 ;;
    -c|--context)      CONTEXT="${2:?}"; shift 2 ;;
    --only)            ONLY="${2:?}"; shift 2 ;;
    --no-verify)       VERIFY=0; shift ;;
    --no-cache)        NO_CACHE="--no-cache"; shift ;;
    --dry-run)         DRY_RUN=1; shift ;;
    -h|--help)         usage; exit 0 ;;
    *)                 die "unknown option: $1 (try --help)" ;;
  esac
done

[ -n "$DOCKERFILE" ] || die "--dockerfile is required (try --help)"
[ -f "$DOCKERFILE" ] || die "no such Dockerfile: $DOCKERFILE"
DOCKERFILE="$(cd "$(dirname "$DOCKERFILE")" && pwd)/$(basename "$DOCKERFILE")"

case "$ONLY" in all|vanilla|speedups) ;; *) die "--only must be all|vanilla|speedups" ;; esac

# ---------------------------------------------------------------------------
# Version: prefer the flag, else read it out of the Dockerfile's installer name
# ---------------------------------------------------------------------------
if [ -z "$VERSION" ]; then
  # Parameterized Dockerfiles carry `ARG IDA_VERSION=<x.y>`; older ones only
  # mention the installer by name.
  VERSION="$(grep -oE '^[[:space:]]*ARG[[:space:]]+IDA_VERSION=[0-9]+\.[0-9]+' "$DOCKERFILE" \
             | head -1 | sed -E 's/.*=//' || true)"
  [ -n "$VERSION" ] || VERSION="$(grep -oE 'ida[0-9]+\.[0-9]+\.run' "$DOCKERFILE" \
             | head -1 | sed -E 's/^ida(.*)\.run$/\1/' || true)"
  [ -n "$VERSION" ] || die "could not detect the IDA version from $DOCKERFILE; pass --version"
  note "detected IDA version $VERSION from the Dockerfile"
fi

[ -n "$RESOURCE_DIR" ] || RESOURCE_DIR="$REPO_ROOT/_gitless/resource/$VERSION"
[ -d "$RESOURCE_DIR" ] || die "resource dir not found: $RESOURCE_DIR (pass --resource-dir)"

INSTALLER="$RESOURCE_DIR/ida${VERSION}.run"
[ -f "$INSTALLER" ] || die "installer not found: $INSTALLER"
for f in idakeygen.py idareggen.py entrypoint.sh; do
  [ -f "$RESOURCE_DIR/$f" ] || die "missing required resource: $RESOURCE_DIR/$f"
done

# ---------------------------------------------------------------------------
# Build context
# ---------------------------------------------------------------------------
# The ADD line tells us where the resource dir must live inside the context.
if [ -z "$ADD_PATH" ]; then
  ADD_PATH="$(grep -E '^[[:space:]]*ADD[[:space:]]' "$DOCKERFILE" | head -1 | awk '{print $2}' | sed 's#^\./##' || true)"
  ADD_PATH="${ADD_PATH//\$\{IDA_VERSION\}/$VERSION}"
  [ -n "$ADD_PATH" ] || die "could not detect the ADD path; pass --add-path"
fi

CLEANUP_CONTEXT=0
if [ -z "$CONTEXT" ]; then
  CONTEXT="$(mktemp -d "${TMPDIR:-/tmp}"/ida-build-ctx.XXXXXX)"
  CLEANUP_CONTEXT=1
  mkdir -p "$CONTEXT/$(dirname "$ADD_PATH")"
  # -c asks APFS for a clone (instant, no extra disk); fall back for other FSes.
  cp -Rc "$RESOURCE_DIR" "$CONTEXT/$ADD_PATH" 2>/dev/null \
    || cp -R "$RESOURCE_DIR" "$CONTEXT/$ADD_PATH"
  note "minimal context at $CONTEXT ($(du -sh "$CONTEXT" | cut -f1)), resources at ./$ADD_PATH"
else
  [ -d "$CONTEXT" ] || die "no such context dir: $CONTEXT"
  note "using caller-supplied context: $CONTEXT"
fi

cleanup() { [ "$CLEANUP_CONTEXT" -eq 1 ] && [ -n "${CONTEXT:-}" ] && rm -rf "$CONTEXT"; }
trap cleanup EXIT

VANILLA_REPO="idapro-${VERSION}"
SPEEDUP_REPO="idapro-${VERSION}-speedups"

# variant rows: <repo> <tag> <speedups> <mode>
VARIANTS=()
if [ "$ONLY" = "all" ] || [ "$ONLY" = "vanilla" ]; then
  VARIANTS+=("$VANILLA_REPO cli 0 cli" "$VANILLA_REPO x11 0 x11")
fi
if [ "$ONLY" = "all" ] || [ "$ONLY" = "speedups" ]; then
  VARIANTS+=("$SPEEDUP_REPO cli 1 cli" "$SPEEDUP_REPO x11 1 x11")
fi

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
# Ordered cli-then-x11 per repo so the shared IDA install stage is built once
# and every later variant is a cache hit on it.
BUILT=()
for row in "${VARIANTS[@]}"; do
  read -r repo tag speedups mode <<<"$row"
  ref="${repo}:${tag}"

  args=(build)
  [ -n "$NO_CACHE" ] && args+=("$NO_CACHE")
  args+=(-f "$DOCKERFILE"
         --build-arg "IDA_VERSION=${VERSION}"
         --build-arg "MODE=${mode}"
         --build-arg "SPEEDUPS=${speedups}")
  # keep every flag ahead of the positional context path
  #
  # run_ida_gui_docker.sh refuses any image whose org.d810.gui-runtime is not
  # exactly x11-dev-emulation-z3-v1, so the speedups x11 image has to claim
  # that contract to be usable as a GUI runtime. The vanilla x11 image must
  # NOT claim it -- it has no z3 and no speedups, and a launcher that trusted
  # the label would fail deep inside d810's import instead of at the gate.
  if [ "$mode" = "x11" ]; then
    if [ "$speedups" = "1" ]; then
      args+=(--build-arg "D810_GUI_RUNTIME_LABEL=x11-dev-emulation-z3-v1")
    else
      args+=(--build-arg "D810_GUI_RUNTIME_LABEL=x11")
    fi
  fi
  args+=(-t "$ref" "$CONTEXT")

  if [ "$DRY_RUN" -eq 1 ]; then
    echo "docker ${args[*]}"
    continue
  fi

  note "building $ref (MODE=$mode SPEEDUPS=$speedups) ..."
  docker "${args[@]}"
  BUILT+=("$ref")
done

if [ "$DRY_RUN" -eq 1 ]; then
  echo "docker tag ${VANILLA_REPO}:cli ${VANILLA_REPO}:latest"
  echo "docker tag ${SPEEDUP_REPO}:cli ${SPEEDUP_REPO}:latest"
  exit 0
fi

# `latest` follows cli: it is the daily-driver shape for scripting and CI.
for repo in "$VANILLA_REPO" "$SPEEDUP_REPO"; do
  if docker image inspect "${repo}:cli" >/dev/null 2>&1; then
    docker tag "${repo}:cli" "${repo}:latest"
    note "tagged ${repo}:latest -> ${repo}:cli"
  fi
done

# ---------------------------------------------------------------------------
# Verify — build success alone does not prove the args took effect
# ---------------------------------------------------------------------------
if [ "$VERIFY" -eq 1 ] && [ "${#BUILT[@]}" -gt 0 ]; then
  echo
  note "verifying:"
  printf '  %-34s %-9s %-8s %-9s %-7s %-5s %s\n' IMAGE SPEEDUPS X11LIBS PYTEST IDALIB GDB GUI
  failures=0
  for ref in "${BUILT[@]}"; do
    want_speedups="0"; case "$ref" in *-speedups:*) want_speedups="1" ;; esac
    want_x11="0";      case "$ref" in *:x11)       want_x11="1" ;; esac

    got_speedups="$(docker image inspect --format '{{ index .Config.Labels "org.d810.speedups" }}' "$ref" 2>/dev/null || echo '?')"
    got_x11="$(docker run --rm --entrypoint sh "$ref" -c "dpkg -l libxcb-cursor0 2>/dev/null | grep -c '^ii' || true" 2>/dev/null | tr -dc '0-9' | head -c1)"
    got_x11="${got_x11:-0}"
    if docker run --rm "$ref" -c "import pytest" >/dev/null 2>&1; then got_pytest="yes"; else got_pytest="no"; fi
    if docker run --rm "$ref" -c "import idapro, idaapi; print(idaapi.IDA_SDK_VERSION)" >/dev/null 2>&1; then got_idalib="ok"; else got_idalib="FAIL"; fi
    # gdb rides along with SPEEDUPS=1; the vanilla images stay without it
    if docker run --rm --entrypoint sh "$ref" -c "command -v gdb" >/dev/null 2>&1; then got_gdb="yes"; else got_gdb="no"; fi

    # An x11 image whose apt list is short still builds and still links Qt; the
    # GUI binary only fails at launch, and ldd is the cheap way to see it here
    # rather than in front of an X server.
    if [ "$want_x11" = "1" ]; then
      missing_libs="$(docker run --rm --entrypoint sh "$ref" \
        -c "ldd /app/ida/ida 2>/dev/null | grep -c 'not found' || true" 2>/dev/null | tr -dc '0-9')"
      missing_libs="${missing_libs:-0}"
      if [ "$missing_libs" = "0" ]; then got_gui="ok"; else got_gui="MISSING($missing_libs)"; fi
    else
      got_gui="n/a"
    fi

    want_pytest="no"; [ "$want_speedups" = "1" ] && want_pytest="yes"
    want_gdb="$want_pytest"

    # The GUI launcher gates on this exact string, so a wrong value here is a
    # build that succeeds and then gets refused at run time.
    want_gui_label=""
    if [ "$want_x11" = "1" ]; then
      if [ "$want_speedups" = "1" ]; then want_gui_label="x11-dev-emulation-z3-v1"; else want_gui_label="x11"; fi
    fi
    got_gui_label="$(docker image inspect --format '{{ index .Config.Labels "org.d810.gui-runtime" }}' "$ref" 2>/dev/null || echo '?')"

    status=""
    [ "$got_gui_label" = "$want_gui_label" ] || status="$status gui-label(want '$want_gui_label' got '$got_gui_label')"
    [ "$got_speedups" = "$want_speedups" ] || status="$status speedups(want $want_speedups)"
    [ "$got_x11" = "$want_x11" ]           || status="$status x11libs(want $want_x11)"
    [ "$got_pytest" = "$want_pytest" ]     || status="$status pytest(want $want_pytest)"
    [ "$got_idalib" = "ok" ]               || status="$status idalib"
    [ "$got_gdb" = "$want_gdb" ]           || status="$status gdb(want $want_gdb)"
    case "$got_gui" in MISSING*) status="$status gui-libs" ;; esac

    printf '  %-34s %-9s %-8s %-9s %-7s %-5s %s%s\n' "$ref" "$got_speedups" "$got_x11" "$got_pytest" "$got_idalib" "$got_gdb" "$got_gui" \
      "$( [ -n "$status" ] && echo "   MISMATCH:$status" )"
    [ -n "$status" ] && failures=$((failures + 1))
  done
  echo
  if [ "$failures" -gt 0 ]; then
    die "$failures image(s) did not match the expected configuration"
  fi
  note "all images verified"
fi

echo
docker images --format '{{.Repository}}:{{.Tag}}\t{{.ID}}\t{{.Size}}' \
  | grep -E "^idapro-${VERSION}(-speedups)?:" | sort || true
