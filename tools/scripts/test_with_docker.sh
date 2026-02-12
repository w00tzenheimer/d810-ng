#!/bin/bash
# Run d810-ng tests using Docker (same as CI)
#
# This script runs tests in the same Docker environment as GitHub Actions,
# allowing you to reproduce CI results locally.
#
# Usage:
#   ./test_with_docker.sh [service] [test-type]
#
# Arguments:
#   service     Docker service to use: idapro-tests or idapro-tests-9.2 (default: idapro-tests)
#   test-type   Type of tests: unit, integration, or all (default: all)
#
# Examples:
#   ./test_with_docker.sh                          # Run all tests with IDA Pro 8.x
#   ./test_with_docker.sh idapro-tests-9.2        # Run all tests with IDA Pro 9.2
#   ./test_with_docker.sh idapro-tests unit       # Run only unit tests
#   ./test_with_docker.sh idapro-tests-9.2 integration  # Run only integration tests with IDA 9.2

set -e  # Exit on error

# Configuration
SERVICE="${1:-idapro-tests}"
TEST_TYPE="${2:-all}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "======================================================================"
echo "D810-NG Docker Test Runner"
echo "======================================================================"
echo -e "${BLUE}Service:${NC}    $SERVICE"
echo -e "${BLUE}Test Type:${NC}  $TEST_TYPE"
echo "======================================================================"

# Validate service
if [[ "$SERVICE" != "idapro-tests" && "$SERVICE" != "idapro-tests-9.2" ]]; then
    echo -e "${RED}ERROR: Invalid service. Must be 'idapro-tests' or 'idapro-tests-9.2'${NC}"
    exit 1
fi

# Validate test type
if [[ "$TEST_TYPE" != "unit" && "$TEST_TYPE" != "integration" && "$TEST_TYPE" != "all" ]]; then
    echo -e "${RED}ERROR: Invalid test type. Must be 'unit', 'integration', or 'all'${NC}"
    exit 1
fi

# Check if docker-compose.yml exists
if [ ! -f docker-compose.yml ]; then
    echo -e "${RED}ERROR: docker-compose.yml not found${NC}"
    exit 1
fi

# Create .env if it doesn't exist
if [ ! -f .env ]; then
    echo "Creating .env file..."
    touch .env
fi

# Function to run unit tests
run_unit_tests() {
    echo ""
    echo -e "${GREEN}=========================================${NC}"
    echo -e "${GREEN}Running Unit Tests...${NC}"
    echo -e "${GREEN}=========================================${NC}"
    docker compose run --rm --entrypoint bash "$SERVICE" -c "
        set -e
        pip install -e .[dev]

        # Run unit tests (no IDA required)
        echo '========================================='
        echo 'Running unit tests (no IDA required)...'
        echo '========================================='
        PYTHONPATH=src pytest tests/unit/ -v --tb=short
    "
}

# Function to run integration tests
run_integration_tests() {
    echo ""
    echo -e "${GREEN}=========================================${NC}"
    echo -e "${GREEN}Running Integration Tests...${NC}"
    echo -e "${GREEN}=========================================${NC}"
    docker compose run --rm --entrypoint bash "$SERVICE" -c "
        set -e
        pip install -e .[dev]

        # Check if test binary exists
        if [ ! -f samples/bins/libobfuscated.dll ]; then
            echo '⚠ Test binary not found, skipping integration tests'
            exit 0
        fi

        # Run integration tests with pytest
        # IDAProTestCase will handle opening the database
        echo ''
        echo '========================================='
        echo 'Running integration tests with pytest...'
        echo '========================================='
        pytest tests/system -v --tb=short --cov=src/d810 --cov-report=term-missing --cov-report=html --cov-report=xml --cov-append
    "
}

# Run tests based on type
case "$TEST_TYPE" in
    unit)
        run_unit_tests
        ;;
    integration)
        run_integration_tests
        ;;
    all)
        run_unit_tests
        EXIT_CODE_UNIT=$?

        run_integration_tests
        EXIT_CODE_INTEGRATION=$?

        # Check results
        if [ $EXIT_CODE_UNIT -ne 0 ] || [ $EXIT_CODE_INTEGRATION -ne 0 ]; then
            echo ""
            echo -e "${RED}======================================================================"
            echo -e "SOME TESTS FAILED"
            echo -e "======================================================================${NC}"
            exit 1
        fi
        ;;
esac

# Show docker logs
echo ""
echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}Docker Logs${NC}"
echo -e "${BLUE}=========================================${NC}"
docker compose logs --tail=50

echo ""
echo -e "${GREEN}======================================================================"
echo -e "ALL TESTS PASSED ✓"
echo -e "======================================================================${NC}"

exit 0
