#!/bin/bash
# Alternative script to run tests in running container
# Usage: ./scripts/test-in-container.sh [test-command]
# Note: You must copy tests into the container first or mount them as a volume

set -e

CONTAINER_NAME="${CONTAINER_NAME:-nms-sync}"
TEST_COMMAND="${1:-test}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "Running tests in container: $CONTAINER_NAME"
echo "Command: $TEST_COMMAND"
echo ""

# Check if container is running
if ! docker ps | grep -q "$CONTAINER_NAME"; then
    echo "Error: Container '$CONTAINER_NAME' is not running"
    echo "Start it with: docker-compose up -d"
    exit 1
fi

# Check if tests exist in container, if not copy them
if ! docker exec "$CONTAINER_NAME" test -d /app/tests; then
    echo "Tests directory not found in container. Copying tests..."
    docker cp "$PROJECT_DIR/tests" "$CONTAINER_NAME:/app/tests"
    echo "Tests copied successfully."
fi

# Run test command in container
docker exec "$CONTAINER_NAME" /entrypoint.sh "$TEST_COMMAND"

echo ""
echo "Tests completed!"

