#!/bin/bash
# Script to copy tests into a running container
# Usage: ./scripts/copy-tests-to-container.sh [container-name]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CONTAINER_NAME="${1:-nms-sync}"

echo "Copying tests to container: $CONTAINER_NAME"
echo ""

# Check if container is running
if ! docker ps | grep -q "$CONTAINER_NAME"; then
    echo "Error: Container '$CONTAINER_NAME' is not running"
    echo "Start it with: docker-compose up -d"
    exit 1
fi

# Check if tests directory exists
if [ ! -d "$PROJECT_DIR/tests" ]; then
    echo "Error: tests directory not found in $PROJECT_DIR"
    exit 1
fi

# Copy tests into container
echo "Copying tests directory..."
docker cp "$PROJECT_DIR/tests" "$CONTAINER_NAME:/app/tests"

echo ""
echo "Tests copied successfully!"
echo "You can now run tests with: docker exec $CONTAINER_NAME /entrypoint.sh test"

