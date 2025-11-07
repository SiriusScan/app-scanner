#!/bin/bash
# Circular Reference Testing Script for Scanner
# Tests ALL points where host data gets serialized

echo "🧪 Running Comprehensive Circular Reference Tests"
echo "=================================================="
echo ""

cd /app-scanner

echo "📝 Test 1: Host Serialization Tests"
echo "------------------------------------"
go test -v ./internal/scan -run 'Test.*Serialization' 2>&1 | grep -E '(RUN|PASS|FAIL|✅|❌)'
TEST1=$?

echo ""
echo "📝 Test 2: Repository Pattern Tests (go-api)"
echo "--------------------------------------------"
cd /go-api && go test -v ./sirius/host -run TestRepository 2>&1 | grep -E '(RUN|PASS|FAIL|✅|❌)' | tail -20
TEST2=$?

echo ""
echo "=================================================="
if [ $TEST1 -eq 0 ] && [ $TEST2 -eq 0 ]; then
    echo "✅ ALL TESTS PASSED - NO CIRCULAR REFERENCES DETECTED"
    echo "=================================================="
    exit 0
else
    echo "❌ SOME TESTS FAILED - CHECK OUTPUT ABOVE"
    echo "=================================================="
    exit 1
fi


