#!/bin/bash
set -e

# Entrypoint script for Docker container
# Supports running tests or the main application

if [ "$1" = "test" ]; then
    echo "Running pytest tests..."
    if [ ! -d "tests" ]; then
        echo "Error: tests directory not found. Mount tests as volume or copy them into the container."
        echo "Example: docker cp tests/ container_name:/app/tests/"
        exit 1
    fi
    shift
    python -m pytest tests/ -v "$@"
    exit $?
elif [ "$1" = "test-verify" ]; then
    echo "Running implementation verification..."
    if [ ! -f "tests/verify_implementation.py" ]; then
        echo "Error: tests/verify_implementation.py not found. Mount tests as volume or copy them into the container."
        echo "Example: docker cp tests/ container_name:/app/tests/"
        exit 1
    fi
    python tests/verify_implementation.py
    exit $?
elif [ "$1" = "test-all" ]; then
    echo "Running all test suites..."
    if [ ! -d "tests" ]; then
        echo "Error: tests directory not found. Mount tests as volume or copy them into the container."
        echo "Example: docker cp tests/ container_name:/app/tests/"
        exit 1
    fi
    echo ""
    echo "1. Implementation Verification"
    echo "-------------------------------"
    if [ -f "tests/verify_implementation.py" ]; then
        python tests/verify_implementation.py
    else
        echo "Warning: tests/verify_implementation.py not found, skipping..."
    fi
    echo ""
    echo "2. Pytest Tests with Coverage"
    echo "-------------------------------"
    python -m pytest tests/ -v --cov=app --cov-report=term-missing
    exit $?
else
    # Default: run the main application
    exec "$@"
fi

