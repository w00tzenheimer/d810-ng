#!/bin/bash
# Run d810 tests via Docker: either docker-compose (unit/integration/all) or
# a single image (system tests / pseudocode dump). Paths are repo-relative.
#
# Usage:
#   Compose mode (same as test_with_docker.sh):
#     ./docker_tests.sh unit [service]
#     ./docker_tests.sh integration [service]
#     ./docker_tests.sh all [service]
#   Image mode (same as run_system_tests_docker.sh):
#     ./docker_tests.sh system [--worktree REL]
#     ./docker_tests.sh dump [OPTIONS] [-- PYTEST_ARGS...]
#
# Compose:
#   unit          Run unit tests only (no IDA)
#   integration   Run system tests with coverage (needs test binary)
#   all           unit then integration
#   service       idapro-tests or idapro-tests-9.2 (default: idapro-tests)
#
# Image:
#   system        pytest tests/system -v (optional --worktree REL)
#   dump          Dump pseudocode e2e; options:
#     -f, --function NAME   --dump-function-pseudocode
#     -m, --maturity LIST   --dump-microcode-maturity (comma-separated)
#     -p, --project NAME    --dump-project
#     -o, --out FILE        redirect to .tmp/FILE
#     -w, --worktree REL    worktree under WORKTREE_ROOT
#     -l, --logs            mount .tmp/logs at /root/.idapro/logs
#     --                    extra args to pytest
#
# Environment:
#   D810_REPO_ROOT       Repo root (default: git rev-parse --show-toplevel)
#   D810_WORKTREE_ROOT  Worktree dir under repo (default: .worktrees)
#   D810_DOCKER_IMAGE   Image for system/dump (default: idapro-9.3)
#   D810_NO_CYTHON      Passed into container for system/dump (e.g. 1)
#   D810_TEST_BINARY    Passed into container (e.g. libobfuscated.dll)
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Repo root
if [ -n "${D810_REPO_ROOT}" ]; then
  REPO_ROOT="${D810_REPO_ROOT}"
else
  REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || true
  if [ -z "${REPO_ROOT}" ]; then
    echo "ERROR: Not inside a git repo and D810_REPO_ROOT not set." >&2
    exit 1
  fi
fi
REPO_ROOT="$(cd "$REPO_ROOT" && pwd)"

CMD="${1:-}"
shift || true

case "$CMD" in
  unit|integration|all)
    # Compose mode (test_with_docker.sh)
    SERVICE="${1:-idapro-tests}"
    if [[ "$SERVICE" != "idapro-tests" && "$SERVICE" != "idapro-tests-9.2" ]]; then
      echo -e "${RED}ERROR: Invalid service. Must be 'idapro-tests' or 'idapro-tests-9.2'${NC}" >&2
      exit 1
    fi
    if [ ! -f "${REPO_ROOT}/docker-compose.yml" ]; then
      echo -e "${RED}ERROR: docker-compose.yml not found${NC}" >&2
      exit 1
    fi
    [ ! -f "${REPO_ROOT}/.env" ] && touch "${REPO_ROOT}/.env"

    echo "======================================================================"
    echo "D810-NG Docker Test Runner (compose)"
    echo "======================================================================"
    echo -e "${BLUE}Service:${NC}    $SERVICE"
    echo -e "${BLUE}Test Type:${NC}  $CMD"
    echo "======================================================================"

    run_unit() {
      echo ""
      echo -e "${GREEN}=========================================${NC}"
      echo -e "${GREEN}Running Unit Tests...${NC}"
      echo -e "${GREEN}=========================================${NC}"
      ( cd "${REPO_ROOT}" && docker compose run --rm --entrypoint bash "$SERVICE" -c "
        set -e
        pip install -e .[dev]
        echo '========================================='
        echo 'Running unit tests (no IDA required)...'
        echo '========================================='
        PYTHONPATH=src pytest tests/unit/ -v --tb=short
      " )
    }

    run_integration() {
      echo ""
      echo -e "${GREEN}=========================================${NC}"
      echo -e "${GREEN}Running Integration Tests...${NC}"
      echo -e "${GREEN}=========================================${NC}"
      ( cd "${REPO_ROOT}" && docker compose run --rm --entrypoint bash "$SERVICE" -c "
        set -e
        pip install -e .[dev]
        if [ ! -f samples/bins/libobfuscated.dll ]; then
          echo 'Test binary not found, skipping integration tests'
          exit 0
        fi
        echo '========================================='
        echo 'Running integration tests with pytest...'
        echo '========================================='
        pytest tests/system -v --tb=short --cov=src/d810 --cov-report=term-missing --cov-report=html --cov-report=xml --cov-append
      " )
    }

    if [ "$CMD" = "unit" ]; then
      run_unit
    elif [ "$CMD" = "integration" ]; then
      run_integration
    else
      run_unit
      EXIT_UNIT=$?
      run_integration
      EXIT_INT=$?
      if [ $EXIT_UNIT -ne 0 ] || [ $EXIT_INT -ne 0 ]; then
        echo ""
        echo -e "${RED}======================================================================"
        echo -e "SOME TESTS FAILED"
        echo -e "======================================================================${NC}" >&2
        exit 1
      fi
    fi

    echo ""
    echo -e "${BLUE}=========================================${NC}"
    echo -e "${BLUE}Docker Logs${NC}"
    echo -e "${BLUE}=========================================${NC}"
    ( cd "${REPO_ROOT}" && docker compose logs --tail=50 )
    echo ""
    echo -e "${GREEN}======================================================================"
    echo -e "ALL TESTS PASSED"
    echo -e "======================================================================${NC}"
    exit 0
    ;;

  system|dump)
    # Image mode: delegate to run_system_tests_docker.sh (same repo root)
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    RUNNER="${SCRIPT_DIR}/run_system_tests_docker.sh"
    if [ ! -x "$RUNNER" ]; then
      echo "ERROR: run_system_tests_docker.sh not found or not executable: $RUNNER" >&2
      exit 1
    fi
    export D810_REPO_ROOT="$REPO_ROOT"
    exec "$RUNNER" "$CMD" "$@"
    ;;

  *)
    echo "Usage: $0 unit [service] | integration [service] | all [service] | system [--worktree REL] | dump [OPTIONS] [-- PYTEST_ARGS...]" >&2
    echo "  unit | integration | all  = docker-compose (service: idapro-tests or idapro-tests-9.2)" >&2
    echo "  system | dump             = single image (run_system_tests_docker.sh)" >&2
    exit 1
    ;;
esac
