#!/bin/bash
#
# Smoke Test Script для Samokoder
# Проверяет что все критичные сервисы работают после deployment
#
# Использование: ./smoke-test.sh [--verbose]
#

set -e

# Цвета
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Флаги
VERBOSE=false
if [[ "$1" == "--verbose" ]]; then
    VERBOSE=true
fi

# Функции логирования
log_info() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_test() {
    echo -e "${BLUE}[→]${NC} $1"
}

# Счётчики
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# Функция для выполнения теста
run_test() {
    local test_name="$1"
    local test_command="$2"
    
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    log_test "Test $TESTS_TOTAL: $test_name"
    
    if $VERBOSE; then
        echo "  Command: $test_command"
    fi
    
    if eval "$test_command" >/dev/null 2>&1; then
        log_info "$test_name - PASSED"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        log_error "$test_name - FAILED"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        if $VERBOSE; then
            echo "  Error output:"
            eval "$test_command" 2>&1 | sed 's/^/    /'
        fi
        return 1
    fi
}

echo "========================================"
echo "  Samokoder Smoke Tests"
echo "========================================"
echo ""

# ==================== Docker Containers ====================
echo "📦 Checking Docker containers..."
echo ""

run_test "API container running" \
    "docker ps --filter 'name=samokoder-api' --filter 'status=running' | grep -q samokoder-api"

run_test "Database container running" \
    "docker ps --filter 'name=samokoder-db' --filter 'status=running' | grep -q samokoder-db"

run_test "Redis container running" \
    "docker ps --filter 'name=samokoder-redis' --filter 'status=running' | grep -q samokoder-redis"

run_test "Prometheus container running" \
    "docker ps --filter 'name=samokoder-prometheus' --filter 'status=running' | grep -q samokoder-prometheus"

run_test "Grafana container running" \
    "docker ps --filter 'name=samokoder-grafana' --filter 'status=running' | grep -q samokoder-grafana"

run_test "AlertManager container running" \
    "docker ps --filter 'name=samokoder-alertmanager' --filter 'status=running' | grep -q samokoder-alertmanager"

echo ""

# ==================== Health Checks ====================
echo "🏥 Checking service health endpoints..."
echo ""

run_test "API health endpoint" \
    "curl -sf http://localhost:8000/health | grep -q '\"status\"'"

run_test "API root endpoint" \
    "curl -sf http://localhost:8000/ | grep -q 'Samokoder'"

run_test "Prometheus UI accessible" \
    "curl -sf http://localhost:9090/-/healthy"

run_test "Grafana UI accessible" \
    "curl -sf http://localhost:3000/api/health | grep -q 'ok'"

run_test "AlertManager UI accessible" \
    "curl -sf http://localhost:9093/-/healthy"

echo ""

# ==================== Metrics ====================
echo "📊 Checking metrics endpoints..."
echo ""

run_test "API exports Prometheus metrics" \
    "curl -sf http://localhost:8000/metrics | grep -q 'samokoder'"

run_test "Prometheus has API target" \
    "curl -sf http://localhost:9090/api/v1/targets | grep -q 'samokoder-api'"

run_test "PostgreSQL exporter running" \
    "curl -sf http://localhost:9187/metrics | grep -q 'pg_'"

run_test "Redis exporter running" \
    "curl -sf http://localhost:9121/metrics | grep -q 'redis_'"

echo ""

# ==================== Database ====================
echo "💾 Checking database connectivity..."
echo ""

run_test "PostgreSQL accepts connections" \
    "docker exec samokoder-db pg_isready -U \${POSTGRES_USER:-user}"

run_test "Redis accepts connections" \
    "docker exec samokoder-redis redis-cli ping | grep -q 'PONG'"

echo ""

# ==================== Prometheus Targets ====================
echo "🎯 Checking Prometheus targets status..."
echo ""

run_test "All Prometheus targets UP" \
    "curl -sf http://localhost:9090/api/v1/targets | grep -q '\"health\":\"up\"'"

echo ""

# ==================== Alert Rules ====================
echo "🚨 Checking Prometheus alert rules..."
echo ""

run_test "Alert rules loaded" \
    "curl -sf http://localhost:9090/api/v1/rules | grep -q 'APIDown'"

echo ""

# ==================== Summary ====================
echo "========================================"
echo "  Test Results Summary"
echo "========================================"
echo ""
echo -e "Total tests:  $TESTS_TOTAL"
echo -e "${GREEN}Passed:       $TESTS_PASSED${NC}"
echo -e "${RED}Failed:       $TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    log_info "✅ All smoke tests PASSED! System is healthy."
    echo ""
    echo "🚀 Production readiness checklist:"
    echo "   [ ] SECRET_KEY and APP_SECRET_KEY are unique (not defaults)"
    echo "   [ ] Telegram bot configured for alerts"
    echo "   [ ] Backup cron job configured"
    echo "   [ ] SSL certificates configured (for production domain)"
    echo "   [ ] Firewall rules configured"
    echo ""
    exit 0
else
    log_error "❌ Some smoke tests FAILED. Please investigate before deploying to production."
    echo ""
    echo "💡 Troubleshooting:"
    echo "   1. Check container logs: docker-compose logs -f [service-name]"
    echo "   2. Verify .env configuration"
    echo "   3. Run with --verbose flag for detailed error output"
    echo ""
    exit 1
fi
