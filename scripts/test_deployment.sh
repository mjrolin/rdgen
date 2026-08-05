#!/bin/bash
# test_deployment.sh - Test RDGen deployment
# Usage: ./test_deployment.sh [base_url]

set -e

BASE_URL="${1:-http://localhost:5000}"
PASSED=0
FAILED=0

echo "=== RDGen Deployment Test Suite ==="
echo "Base URL: $BASE_URL"
echo ""

# Helper function
test_endpoint() {
    local name="$1"
    local method="$2"
    local endpoint="$3"
    local expected_status="$4"
    local data="$5"

    echo -n "Testing: $name... "

    if [ "$method" = "GET" ]; then
        status=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL$endpoint")
    else
        status=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" \
            -H "Content-Type: application/json" \
            -d "$data" \
            "$BASE_URL$endpoint")
    fi

    if [ "$status" = "$expected_status" ]; then
        echo "PASS (HTTP $status)"
        ((PASSED++))
    else
        echo "FAIL (HTTP $status, expected $expected_status)"
        ((FAILED++))
    fi
}

# Test cases
echo "--- Health Checks ---"
test_endpoint "Health endpoint" "GET" "/api/health" "200"
test_endpoint "Root endpoint" "GET" "/" "200"

echo ""
echo "--- API Endpoints ---"
test_endpoint "List jobs" "GET" "/api/jobs" "200"
test_endpoint "Invalid job status" "GET" "/api/status/invalid-uuid" "404"
test_endpoint "Invalid artifact" "GET" "/api/artifact/invalid-uuid" "404"

echo ""
echo "--- Build Request (Mock Mode) ---"

# Test build request
BUILD_RESPONSE=$(curl -s -X POST \
    -H "Content-Type: application/json" \
    -d '{
        "platform": "windows",
        "version": "1.4.2",
        "configName": "TestBuild",
        "appName": "Test App",
        "filename": "testbuild",
        "host": "test.example.com",
        "key": "testkey123",
        "connectionDirection": "Both",
        "disableInstallation": false,
        "disableSettings": false
    }' \
    "$BASE_URL/api/build")

if echo "$BUILD_RESPONSE" | grep -q '"success":true'; then
    echo "Build request: PASS"
    ((PASSED++))

    # Extract job ID
    JOB_ID=$(echo "$BUILD_RESPONSE" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

    if [ -n "$JOB_ID" ]; then
        echo "Job ID: $JOB_ID"

        # Wait and check status
        sleep 2
        test_endpoint "Job status check" "GET" "/api/status/$JOB_ID" "200"
    fi
else
    echo "Build request: FAIL"
    echo "Response: $BUILD_RESPONSE"
    ((FAILED++))
fi

echo ""
echo "--- File Upload ---"

# Create temp test image
TEST_IMAGE="/tmp/test_icon.png"
echo -n "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==" | base64 -d > "$TEST_IMAGE"

UPLOAD_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST \
    -F "file=@$TEST_IMAGE" \
    "$BASE_URL/api/upload/icon")

if [ "$UPLOAD_STATUS" = "200" ]; then
    echo "Icon upload: PASS (HTTP $UPLOAD_STATUS)"
    ((PASSED++))
else
    echo "Icon upload: FAIL (HTTP $UPLOAD_STATUS)"
    ((FAILED++))
fi

rm -f "$TEST_IMAGE"

echo ""
echo "=== Test Summary ==="
echo "Passed: $PASSED"
echo "Failed: $FAILED"
echo ""

if [ $FAILED -eq 0 ]; then
    echo "All tests passed!"
    exit 0
else
    echo "Some tests failed."
    exit 1
fi
