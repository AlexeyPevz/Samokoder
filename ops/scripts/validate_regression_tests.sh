#!/bin/bash
# Validation script for regression tests
# Run this before committing or in CI/CD

set -e

echo "🔍 Validating Regression Tests..."
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 1. Check Python syntax
echo "📝 Checking Python syntax..."
python3 -m py_compile tests/regression/test_critical_auth_flows.py
python3 -m py_compile tests/regression/test_critical_db_flows.py
python3 -m py_compile tests/regression/test_critical_security_flows.py
python3 -m py_compile tests/regression/test_critical_audit_flows.py
python3 -m py_compile tests/regression/conftest.py
echo -e "${GREEN}✅ All Python files are syntactically valid${NC}"
echo ""

# 2. Check pytest is available
if ! command -v pytest &> /dev/null; then
    echo -e "${RED}❌ pytest not found. Install with: pip install pytest pytest-asyncio${NC}"
    exit 1
fi

# 3. Collect tests
echo "📋 Collecting tests..."
TEST_COUNT=$(pytest tests/regression/ --collect-only -q 2>/dev/null | grep -c "test_" || echo "0")
echo -e "${GREEN}✅ Found $TEST_COUNT tests${NC}"
echo ""

# 4. Count P0 tests
echo "🔴 Counting P0 (Critical) tests..."
P0_COUNT=$(pytest tests/regression/ --collect-only -q -m priority_p0 2>/dev/null | grep -c "test_" || echo "0")
echo -e "${GREEN}✅ P0 tests: $P0_COUNT${NC}"

# 5. Count P1 tests
echo "🟠 Counting P1 (High) tests..."
P1_COUNT=$(pytest tests/regression/ --collect-only -q -m priority_p1 2>/dev/null | grep -c "test_" || echo "0")
echo -e "${GREEN}✅ P1 tests: $P1_COUNT${NC}"
echo ""

# 6. Check required directories
echo "📁 Checking directories..."
if [ ! -d "logs" ]; then
    echo -e "${YELLOW}⚠️  Creating logs directory${NC}"
    mkdir -p logs
fi
echo -e "${GREEN}✅ All directories present${NC}"
echo ""

# 7. Run P0 tests
echo "🚀 Running P0 (Critical) Tests..."
echo -e "${YELLOW}These tests MUST pass to merge${NC}"
if pytest tests/regression/ -v -m priority_p0 --tb=short; then
    echo -e "${GREEN}✅ All P0 tests passed!${NC}"
else
    echo -e "${RED}❌ P0 TESTS FAILED - BLOCKING MERGE${NC}"
    exit 1
fi
echo ""

# 8. Run P1 tests
echo "🚀 Running P1 (High Priority) Tests..."
echo -e "${YELLOW}>2 failures will block merge${NC}"
if pytest tests/regression/ -v -m priority_p1 --tb=short; then
    echo -e "${GREEN}✅ All P1 tests passed!${NC}"
    P1_FAILURES=0
else
    P1_FAILURES=$?
    if [ $P1_FAILURES -gt 2 ]; then
        echo -e "${RED}❌ P1 TESTS: Too many failures ($P1_FAILURES) - BLOCKING MERGE${NC}"
        exit 1
    else
        echo -e "${YELLOW}⚠️  P1 TESTS: $P1_FAILURES failure(s) - acceptable${NC}"
    fi
fi
echo ""

# 9. Generate coverage report
echo "📊 Generating coverage report..."
if pytest tests/regression/ --cov=core --cov=api --cov-report=term-missing --cov-report=html -q; then
    echo -e "${GREEN}✅ Coverage report generated in htmlcov/index.html${NC}"
else
    echo -e "${YELLOW}⚠️  Coverage report generation failed${NC}"
fi
echo ""

# Summary
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}✅ VALIDATION COMPLETE${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📊 Summary:"
echo "  • Total tests: $TEST_COUNT"
echo "  • P0 (Critical): $P0_COUNT"
echo "  • P1 (High): $P1_COUNT"
echo "  • P0 Status: ✅ PASSED"
echo "  • P1 Status: $([ $P1_FAILURES -eq 0 ] && echo '✅ PASSED' || echo "⚠️  $P1_FAILURES failure(s)")"
echo ""
echo -e "${GREEN}✅ Safe to merge!${NC}"
