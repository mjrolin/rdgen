#!/bin/bash
# test_docker.sh - Test RDGen Docker deployment
# Usage: ./test_docker.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== RDGen Docker Test ==="
echo "Project directory: $PROJECT_DIR"
echo ""

cd "$PROJECT_DIR"

# Create test .env if not exists
if [ ! -f .env ]; then
    echo "Creating test .env file..."
    cp .env.example .env
    # Leave GITHUB_TOKEN empty for mock mode
    sed -i 's/GITHUB_TOKEN=.*/GITHUB_TOKEN=/' .env
fi

echo "Step 1: Building Docker images..."
docker-compose build --no-cache

echo ""
echo "Step 2: Starting containers..."
docker-compose up -d

echo ""
echo "Step 3: Waiting for services to start..."
sleep 15

echo ""
echo "Step 4: Checking container status..."
docker-compose ps

echo ""
echo "Step 5: Checking service logs..."
echo "--- Backend logs ---"
docker-compose logs --tail=20 backend

echo ""
echo "--- Frontend logs ---"
docker-compose logs --tail=20 frontend

echo ""
echo "Step 6: Running API tests..."
"$SCRIPT_DIR/test_deployment.sh" "http://localhost:5000" || true

echo ""
echo "Step 7: Cleanup (optional)..."
read -p "Stop containers? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    docker-compose down
    echo "Containers stopped."
else
    echo "Containers still running. Stop with: docker-compose down"
fi

echo ""
echo "=== Docker Test Complete ==="
