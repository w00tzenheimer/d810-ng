#!/bin/bash
set -u

WORKTREE=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -w|--worktree)
      WORKTREE="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 2
      ;;
  esac
done

if [ -z "$WORKTREE" ]; then
  echo "Usage: $0 -w WORKTREE" >&2
  exit 2
fi

REPO_ROOT="$(git rev-parse --show-toplevel)"
HARNESS="$REPO_ROOT/tools/scripts/run_system_tests_docker.sh"
WORKTREE_PATH="$REPO_ROOT/.worktrees/$WORKTREE"
CASE_ROOT="$WORKTREE_PATH/.tmp/preparation-process-death"

case "$CASE_ROOT" in
  "$WORKTREE_PATH"/.tmp/preparation-process-death) ;;
  *) echo "Refusing unsafe case root: $CASE_ROOT" >&2; exit 2 ;;
esac

rm -rf "$CASE_ROOT"
mkdir -p "$CASE_ROOT"

for CUT in SCRIPT_RUNNING CAPTURE_PENDING; do
  CASE_DIR="/work/.tmp/preparation-process-death/$CUT"
  HOST_CASE_DIR="$CASE_ROOT/$CUT"
  mkdir -p "$HOST_CASE_DIR"

  set +e
  "$HARNESS" exec -w "$WORKTREE" -- \
    /app/ida/.venv/bin/python \
    tests/system/e2e/preparation_process_death_worker.py \
    --phase write --cut "$CUT" --case-dir "$CASE_DIR" \
    >"$HOST_CASE_DIR/write.log" 2>&1
  WRITE_STATUS=$?
  set -e
  if [ "$WRITE_STATUS" -ne 91 ]; then
    echo "$CUT writer exited $WRITE_STATUS instead of 91" >&2
    tail -80 "$HOST_CASE_DIR/write.log" >&2
    exit 1
  fi

  "$HARNESS" exec -w "$WORKTREE" -- \
    /app/ida/.venv/bin/python \
    tests/system/e2e/preparation_process_death_worker.py \
    --phase recover --cut "$CUT" --case-dir "$CASE_DIR" \
    >"$HOST_CASE_DIR/recover.log" 2>&1
  echo "$CUT: process death recovered exactly"
done
