#!/bin/bash
# Script to run tests in Docker container
# Usage: ./scripts/run-tests.sh [test|test-verify|test-all]
# Note: Tests are mounted as a volume, not included in the image

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_DIR"

# Default to running all tests
TEST_COMMAND="${1:-test-all}"

echo "=========================================="
echo "Running tests in Docker container"
echo "Command: $TEST_COMMAND"
echo "Note: Tests are mounted as volume"
echo "=========================================="
echo ""

# Check that tests directory exists
if [ ! -d "tests" ]; then
    echo "Error: tests directory not found in $PROJECT_DIR"
    exit 1
fi

# Build the image if it doesn't exist
if ! docker images | grep -q "nms-sync:test"; then
    echo "Building test image..."
    docker-compose -f docker-compose.yml -f docker-compose.test.yml build test
fi

# Run tests
case "$TEST_COMMAND" in
    test)
        echo "Running pytest..."
        docker-compose -f docker-compose.yml -f docker-compose.test.yml run --rm test
        ;;
    test-verify)
        echo "Running implementation verification..."
        docker-compose -f docker-compose.yml -f docker-compose.test.yml run --rm test-verify
        ;;
    test-all)
        echo "Running all test suites..."
        docker-compose -f docker-compose.yml -f docker-compose.test.yml run --rm test-all
        ;;
    *)
        echo "Usage: $0 [test|test-verify|test-all]"
        echo ""
        echo "Commands:"
        echo "  test        - Run pytest tests"
        echo "  test-verify - Run implementation verification"
        echo "  test-all    - Run verification + pytest with coverage"
        exit 1
        ;;
esac

echo ""
echo "=========================================="
echo "Tests completed!"
echo "=========================================="

