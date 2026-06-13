#!/usr/bin/env bash
# warm_gate.sh — persistent-container DSL gate for fast convergence loops.
#
# The normal run_system_tests_docker.sh runs `pip install -e .[dev]` +
# speedups.install on EVERY invocation (~30-90s of each ~2.5min gate). For an
# editable install on a mounted volume, that reinstall is redundant: source edits
# are picked up live (PYTHONPATH=/work/src + the -e symlink). This helper boots ONE
# container, installs ONCE, then runs the gate via `docker exec` — cutting each
# iteration to well under a minute.
#
# Usage (run from the worktree root):
#   tools/scripts/warm_gate.sh up                 # boot + one-time setup
#   tools/scripts/warm_gate.sh gate <out> [args]  # run pytest into the warm box
#   tools/scripts/warm_gate.sh dsl  <out>         # shortcut: full DSL suite
#   tools/scripts/warm_gate.sh hard <out>         # shortcut: the 6 hard cases only
#   tools/scripts/warm_gate.sh status
#   tools/scripts/warm_gate.sh down
#
# NOTE: warm container assumes PURE-PYTHON edits between gates (true for the CFF
# convergence). If a dependency or the Cython speedups change, re-run `up` (or
# `setup`) to reinstall.
set -euo pipefail

WORK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NAME="${D810_WARM_NAME:-d810-warm}"
IMAGE="${D810_DOCKER_IMAGE:-idapro-9.3}"
MEMORY="${D810_DOCKER_MEMORY:-4g}"
MEM_BYTES=4294967296
PYBIN="/app/ida/.venv/bin/python"
PIPBIN="/app/ida/.venv/bin/pip"
ENV_IDA='IDA_PREFIX=/app/ida IDA_INSTALL_DIR=/app/ida D810_LIBCLANG_PATH=/app/ida/libclang.so'
ENV_PY='PYTHONPATH=/work/src:/app/ida/python:$PYTHONPATH'
ENV_TEST="D810_NO_CYTHON=${D810_NO_CYTHON:-1} D810_TEST_BINARY=${D810_TEST_BINARY:-libobfuscated.dll} D810_MEMORY_LIMIT_BYTES=${MEM_BYTES}"
DSL='tests/system/e2e/test_libdeobfuscated_dsl.py'
HARD='high_fan_in_pattern or switch_case_ollvm_pattern or nested_deep or _hodur_func or unwrap_loops or hardened_cond_chain_simple or abc_xor_dispatch'

_exists() { docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qx "$NAME"; }
_running() { docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$NAME"; }

_setup() {
  echo "[warm] one-time setup (pip install -e .[dev] + speedups) ..."
  docker exec "$NAME" bash -lc "export $ENV_IDA $ENV_PY && $PIPBIN install -e .[dev] -q && $PYBIN -m d810.speedups.install" \
    && echo "[warm] setup complete."
}

cmd="${1:-}"; shift || true
case "$cmd" in
  up)
    if _running; then echo "[warm] $NAME already running."; else
      _exists && docker rm -f "$NAME" >/dev/null 2>&1 || true
      mkdir -p "$WORK_DIR/.tmp/logs"
      echo "[warm] booting $NAME ($IMAGE) ..."
      docker run -d --name "$NAME" \
        --add-host files.pythonhosted.org:151.101.0.223 \
        --memory "$MEMORY" -e "D810_MEMORY_LIMIT_BYTES=${MEM_BYTES}" \
        -v "${WORK_DIR}:/work" -v "${WORK_DIR}/.tmp/logs:/root/.idapro/logs" \
        -w /work --entrypoint /bin/bash "$IMAGE" -lc "sleep infinity" >/dev/null
      _setup
    fi
    ;;
  setup) _running || { echo "[warm] not up; run 'up' first" >&2; exit 1; }; _setup ;;
  gate|dsl|hard)
    _running || { echo "[warm] not up; run 'up' first" >&2; exit 1; }
    out="${1:?usage: $0 $cmd <out.txt> [pytest args]}"; shift || true
    if [ "$cmd" = "dsl" ]; then set -- "$DSL" -v -rs; fi
    if [ "$cmd" = "hard" ]; then set -- "$DSL" -k "$HARD" -v -rs; fi
    [ "$#" -eq 0 ] && set -- "$DSL" -v -rs
    # shell-quote each arg so a multi-word -k expression survives the remote bash -lc parse
    qargs=""; for a in "$@"; do qargs+=" $(printf '%q' "$a")"; done
    echo "[warm] gate -> .tmp/$out : pytest$qargs"
    docker exec \
      -e IDA_PREFIX=/app/ida -e IDA_INSTALL_DIR=/app/ida -e D810_LIBCLANG_PATH=/app/ida/libclang.so \
      -e PYTHONPATH=/work/src:/app/ida/python \
      -e D810_NO_CYTHON="${D810_NO_CYTHON:-1}" -e D810_TEST_BINARY="${D810_TEST_BINARY:-libobfuscated.dll}" \
      -e D810_MEMORY_LIMIT_BYTES="$MEM_BYTES" \
      "$NAME" bash -lc ": > /work/.tmp/$out; $PYBIN -m pytest$qargs > /work/.tmp/$out 2>&1; tail -1 /work/.tmp/$out"
    ;;
  status) _running && echo "[warm] $NAME running" || { _exists && echo "[warm] $NAME stopped" || echo "[warm] $NAME absent"; } ;;
  down) _exists && docker rm -f "$NAME" >/dev/null 2>&1 && echo "[warm] removed $NAME" || echo "[warm] nothing to remove" ;;
  *) echo "usage: $0 {up|setup|gate <out> [args]|dsl <out>|hard <out>|status|down}" >&2; exit 1 ;;
esac
