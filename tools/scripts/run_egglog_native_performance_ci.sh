#!/usr/bin/env bash
# Capture comparable Egglog native-performance receipts for CI.
#
# This is intentionally test-only: production defaults remain untouched. The
# generated JSONL files preserve the raw E2E and corpus receipts for both AST
# runtimes, including candidate identities, image metadata, and stage coverage.
set -euo pipefail

if [ -n "${D810_REPO_ROOT:-}" ]; then
  REPO_ROOT="$(cd "$D810_REPO_ROOT" && pwd)"
else
  REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fi
RUNNER="$REPO_ROOT/tools/scripts/run_system_tests_docker.sh"
ARTIFACT_DIR="${D810_EGGLOG_PERF_ARTIFACT_DIR:-$REPO_ROOT/.tmp/egglog-native-performance}"
IMAGE="${D810_DOCKER_IMAGE:-idapro-9.4-speedups:cli}"
COMPARISON="$ARTIFACT_DIR/comparison.json"
COMPARISON_TMP="$ARTIFACT_DIR/.comparison.json.tmp"

mkdir -p "$ARTIFACT_DIR"
rm -f "$COMPARISON" "$COMPARISON_TMP"
trap 'rm -f "$COMPARISON_TMP"' EXIT

for MODE in 1 0; do
  if [ "$MODE" = 1 ]; then
    LABEL=python
  else
    LABEL=cython
  fi
  LOG="$ARTIFACT_DIR/$LABEL.log"
  RECEIPTS="$ARTIFACT_DIR/$LABEL.receipts.jsonl"

  : > "$LOG"
  D810_DOCKER_IMAGE="$IMAGE" D810_NO_CYTHON="$MODE" "$RUNNER" test -- \
    tests/system/e2e/test_egglog_add_spike.py \
    tests/system/e2e/test_egglog_mba_families_spike.py \
    -q -s | tee -a "$LOG"
  D810_DOCKER_IMAGE="$IMAGE" D810_NO_CYTHON="$MODE" "$RUNNER" test -- \
    tests/system/runtime/backends/test_egglog_mba_performance.py \
    -q -m profile -s | tee -a "$LOG"

  rg '^EGGLOG_(MBA_NATIVE|MBA_REAL_CORPUS|MBA_CORPUS_PERFORMANCE)_RECEIPT=' "$LOG" \
    | sed 's/^[^=]*=//' > "$RECEIPTS"
  [ -s "$RECEIPTS" ] || {
    echo "ERROR: no Egglog performance receipts were emitted for $LABEL" >&2
    exit 1
  }
done

"${PYTHON:-python3}" "$REPO_ROOT/tools/scripts/compare_egglog_native_performance_receipts.py" \
  --python "$ARTIFACT_DIR/python.receipts.jsonl" \
  --cython "$ARTIFACT_DIR/cython.receipts.jsonl" \
  --output "$COMPARISON_TMP"
mv -f "$COMPARISON_TMP" "$COMPARISON"
trap - EXIT

echo "Wrote Egglog native performance receipts to $ARTIFACT_DIR"
