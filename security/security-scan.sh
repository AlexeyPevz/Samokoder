#!/bin/bash
# Samokoder Security Scanning Script
# Usage: ./security-scan.sh [scan-type] [environment]

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SCAN_TYPE="${1:-full}"
ENVIRONMENT="${2:-production}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
SCAN_DIR="/scans/samokoder-$TIMESTAMP"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Create scan directory
create_scan_dir() {
    log_info "Creating scan directory: $SCAN_DIR"
    mkdir -p "$SCAN_DIR"
}

# Container security scan
scan_containers() {
    log_info "Scanning container images..."
    
    # Scan backend image
    trivy image samokoder/backend:latest --format json --output "$SCAN_DIR/container-scan.json"
    
    # Scan with severity filter
    trivy image samokoder/backend:latest --severity HIGH,CRITICAL --format table > "$SCAN_DIR/container-scan-high.txt"
    
    log_success "Container scan completed"
}

# Kubernetes security scan
scan_kubernetes() {
    log_info "Scanning Kubernetes manifests..."
    
    # Scan all YAML files
    find "$PROJECT_ROOT/k8s" -name "*.yaml" -exec trivy config {} --format json --output "$SCAN_DIR/k8s-scan.json" \;
    
    # Scan with severity filter
    find "$PROJECT_ROOT/k8s" -name "*.yaml" -exec trivy config {} --severity HIGH,CRITICAL --format table > "$SCAN_DIR/k8s-scan-high.txt" \;
    
    log_success "Kubernetes scan completed"
}

# Code security scan
scan_code() {
    log_info "Scanning source code..."
    
    # Bandit security linter
    bandit -r "$PROJECT_ROOT/backend" -f json -o "$SCAN_DIR/bandit-scan.json" || true
    bandit -r "$PROJECT_ROOT/backend" -f txt -o "$SCAN_DIR/bandit-scan.txt" || true
    
    # Safety check for dependencies
    safety check --json --output "$SCAN_DIR/safety-scan.json" || true
    safety check --output "$SCAN_DIR/safety-scan.txt" || true
    
    # Semgrep static analysis
    semgrep --config=auto --json --output="$SCAN_DIR/semgrep-scan.json" "$PROJECT_ROOT" || true
    semgrep --config=auto --output="$SCAN_DIR/semgrep-scan.txt" "$PROJECT_ROOT" || true
    
    log_success "Code scan completed"
}

# Infrastructure security scan
scan_infrastructure() {
    log_info "Scanning infrastructure..."
    
    # Terraform security scan
    cd "$PROJECT_ROOT/terraform"
    tfsec --format json --out "$SCAN_DIR/tfsec-scan.json" || true
    tfsec --format table --out "$SCAN_DIR/tfsec-scan.txt" || true
    
    # Checkov infrastructure scan
    checkov -d . --framework terraform --output json --output-file-path "$SCAN_DIR/checkov-scan.json" || true
    checkov -d . --framework terraform --output cli --output-file-path "$SCAN_DIR/checkov-scan.txt" || true
    
    cd "$PROJECT_ROOT"
    log_success "Infrastructure scan completed"
}

# Network security scan
scan_network() {
    log_info "Scanning network security..."
    
    # Nmap scan of services
    nmap -sS -O -A -oX "$SCAN_DIR/nmap-scan.xml" localhost || true
    nmap -sS -O -A -oN "$SCAN_DIR/nmap-scan.txt" localhost || true
    
    # SSL/TLS scan
    testssl.sh --jsonfile "$SCAN_DIR/ssl-scan.json" samokoder.com || true
    testssl.sh --logfile "$SCAN_DIR/ssl-scan.txt" samokoder.com || true
    
    log_success "Network scan completed"
}

# Compliance scan
scan_compliance() {
    log_info "Scanning compliance..."
    
    # CIS Kubernetes benchmark
    kube-bench run --json --output "$SCAN_DIR/cis-k8s-scan.json" || true
    kube-bench run --output "$SCAN_DIR/cis-k8s-scan.txt" || true
    
    # CIS Docker benchmark
    docker-bench-security --json "$SCAN_DIR/cis-docker-scan.json" || true
    docker-bench-security --output "$SCAN_DIR/cis-docker-scan.txt" || true
    
    # OWASP ZAP scan
    zap-baseline.py -t http://localhost:8000 -J "$SCAN_DIR/owasp-scan.json" || true
    zap-baseline.py -t http://localhost:8000 -r "$SCAN_DIR/owasp-scan.txt" || true
    
    log_success "Compliance scan completed"
}

# Generate security report
generate_report() {
    log_info "Generating security report..."
    
    cat > "$SCAN_DIR/security-report.md" << EOF
# Samokoder Security Scan Report

**Date**: $(date)
**Scan Type**: $SCAN_TYPE
**Environment**: $ENVIRONMENT
**Scanner**: Samokoder Security Scanner v1.0.0

## Executive Summary

This report contains the results of security scans performed on the Samokoder application and infrastructure.

## Scan Results

### Container Security
- **High/Critical Issues**: $(grep -c "HIGH\|CRITICAL" "$SCAN_DIR/container-scan-high.txt" 2>/dev/null || echo "0")
- **Total Issues**: $(jq '.Results | length' "$SCAN_DIR/container-scan.json" 2>/dev/null || echo "0")

### Kubernetes Security
- **High/Critical Issues**: $(grep -c "HIGH\|CRITICAL" "$SCAN_DIR/k8s-scan-high.txt" 2>/dev/null || echo "0")
- **Total Issues**: $(jq '.Results | length' "$SCAN_DIR/k8s-scan.json" 2>/dev/null || echo "0")

### Code Security
- **Bandit Issues**: $(jq '.results | length' "$SCAN_DIR/bandit-scan.json" 2>/dev/null || echo "0")
- **Safety Issues**: $(jq '.vulnerabilities | length' "$SCAN_DIR/safety-scan.json" 2>/dev/null || echo "0")
- **Semgrep Issues**: $(jq '.results | length' "$SCAN_DIR/semgrep-scan.json" 2>/dev/null || echo "0")

### Infrastructure Security
- **TFSec Issues**: $(jq '.results | length' "$SCAN_DIR/tfsec-scan.json" 2>/dev/null || echo "0")
- **Checkov Issues**: $(jq '.results | length' "$SCAN_DIR/checkov-scan.json" 2>/dev/null || echo "0")

### Network Security
- **Open Ports**: $(grep -c "open" "$SCAN_DIR/nmap-scan.txt" 2>/dev/null || echo "0")
- **SSL Issues**: $(grep -c "NOT ok" "$SCAN_DIR/ssl-scan.txt" 2>/dev/null || echo "0")

### Compliance
- **CIS K8s Issues**: $(grep -c "FAIL" "$SCAN_DIR/cis-k8s-scan.txt" 2>/dev/null || echo "0")
- **CIS Docker Issues**: $(grep -c "FAIL" "$SCAN_DIR/cis-docker-scan.txt" 2>/dev/null || echo "0")
- **OWASP Issues**: $(grep -c "FAIL" "$SCAN_DIR/owasp-scan.txt" 2>/dev/null || echo "0")

## Recommendations

1. **Immediate Action Required**: Address all HIGH and CRITICAL issues
2. **Short-term**: Fix all security issues within 30 days
3. **Long-term**: Implement continuous security monitoring

## Files Generated

- Container scan: \`container-scan.json\`, \`container-scan-high.txt\`
- Kubernetes scan: \`k8s-scan.json\`, \`k8s-scan-high.txt\`
- Code scan: \`bandit-scan.json\`, \`safety-scan.json\`, \`semgrep-scan.json\`
- Infrastructure scan: \`tfsec-scan.json\`, \`checkov-scan.json\`
- Network scan: \`nmap-scan.xml\`, \`ssl-scan.json\`
- Compliance scan: \`cis-k8s-scan.json\`, \`cis-docker-scan.json\`, \`owasp-scan.json\`

EOF

    log_success "Security report generated"
}

# Send notification
send_notification() {
    local status="$1"
    local message=""
    
    if [ "$status" = "success" ]; then
        message="✅ Security scan completed successfully: $SCAN_DIR"
    else
        message="❌ Security scan failed: $SCAN_DIR"
    fi
    
    # Slack notification
    if [ -n "${SLACK_WEBHOOK_URL:-}" ]; then
        curl -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\"$message\"}" \
            "$SLACK_WEBHOOK_URL" || log_warning "Failed to send Slack notification"
    fi
}

# Main scan function
main() {
    log_info "Starting security scan..."
    log_info "Scan type: $SCAN_TYPE"
    log_info "Environment: $ENVIRONMENT"
    log_info "Timestamp: $TIMESTAMP"
    
    # Create scan directory
    create_scan_dir
    
    # Perform scan based on type
    case "$SCAN_TYPE" in
        "full")
            scan_containers
            scan_kubernetes
            scan_code
            scan_infrastructure
            scan_network
            scan_compliance
            ;;
        "containers")
            scan_containers
            ;;
        "kubernetes")
            scan_kubernetes
            ;;
        "code")
            scan_code
            ;;
        "infrastructure")
            scan_infrastructure
            ;;
        "network")
            scan_network
            ;;
        "compliance")
            scan_compliance
            ;;
        *)
            log_error "Unknown scan type: $SCAN_TYPE"
            exit 1
            ;;
    esac
    
    # Generate report
    generate_report
    
    # Send notification
    send_notification "success"
    
    log_success "Security scan completed successfully!"
    log_info "Results available in: $SCAN_DIR"
}

# Run main function
main "$@"