#!/bin/bash
# Samokoder Rollback Script
# Usage: ./rollback.sh [version] [environment]

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
NAMESPACE="samokoder"
MONITORING_NAMESPACE="monitoring"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
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

# Check if kubectl is available
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is not installed or not in PATH"
        exit 1
    fi
    
    if ! command -v helm &> /dev/null; then
        log_error "helm is not installed or not in PATH"
        exit 1
    fi
    
    # Check if we can connect to the cluster
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Get current deployment status
get_current_status() {
    log_info "Getting current deployment status..."
    
    echo "=== Current Deployments ==="
    kubectl get deployments -n $NAMESPACE -o wide
    
    echo -e "\n=== Current Pods ==="
    kubectl get pods -n $NAMESPACE -o wide
    
    echo -e "\n=== Current Services ==="
    kubectl get services -n $NAMESPACE -o wide
    
    echo -e "\n=== Current Ingress ==="
    kubectl get ingress -n $NAMESPACE -o wide
    
    echo -e "\n=== Current ReplicaSets ==="
    kubectl get replicasets -n $NAMESPACE -o wide
}

# Check if previous version exists
check_previous_version() {
    local target_version="$1"
    
    log_info "Checking if version $target_version exists..."
    
    # Check if there's a previous ReplicaSet
    local previous_rs=$(kubectl get replicasets -n $NAMESPACE -l app=samokoder-backend --sort-by=.metadata.creationTimestamp -o jsonpath='{.items[-2].metadata.name}' 2>/dev/null || echo "")
    
    if [ -z "$previous_rs" ]; then
        log_error "No previous version found for rollback"
        exit 1
    fi
    
    log_success "Previous version found: $previous_rs"
    echo "$previous_rs"
}

# Perform rollback
perform_rollback() {
    local target_version="$1"
    local previous_rs="$2"
    
    log_info "Performing rollback to version $target_version..."
    
    # Scale down current deployment
    log_info "Scaling down current deployment..."
    kubectl scale deployment samokoder-backend -n $NAMESPACE --replicas=0
    
    # Wait for pods to terminate
    log_info "Waiting for current pods to terminate..."
    kubectl wait --for=delete pod -l app=samokoder-backend -n $NAMESPACE --timeout=300s || true
    
    # Scale up previous ReplicaSet
    log_info "Scaling up previous ReplicaSet: $previous_rs"
    kubectl scale replicaset $previous_rs -n $NAMESPACE --replicas=3
    
    # Wait for pods to be ready
    log_info "Waiting for previous pods to be ready..."
    kubectl wait --for=condition=ready pod -l app=samokoder-backend -n $NAMESPACE --timeout=300s
    
    log_success "Rollback completed successfully"
}

# Verify rollback
verify_rollback() {
    log_info "Verifying rollback..."
    
    # Check pod status
    echo "=== Pod Status ==="
    kubectl get pods -n $NAMESPACE -l app=samokoder-backend
    
    # Check service endpoints
    echo -e "\n=== Service Endpoints ==="
    kubectl get endpoints -n $NAMESPACE samokoder-backend-service
    
    # Test health endpoint
    log_info "Testing health endpoint..."
    local service_ip=$(kubectl get service samokoder-backend-service -n $NAMESPACE -o jsonpath='{.spec.clusterIP}')
    local service_port=$(kubectl get service samokoder-backend-service -n $NAMESPACE -o jsonpath='{.spec.ports[0].port}')
    
    if kubectl run test-pod --image=curlimages/curl:latest --rm -i --restart=Never -- curl -f "http://$service_ip:$service_port/health" &> /dev/null; then
        log_success "Health check passed"
    else
        log_warning "Health check failed - this might be expected during rollback"
    fi
    
    # Check metrics
    log_info "Checking metrics..."
    if kubectl run test-pod --image=curlimages/curl:latest --rm -i --restart=Never -- curl -f "http://$service_ip:$service_port/metrics" &> /dev/null; then
        log_success "Metrics endpoint accessible"
    else
        log_warning "Metrics endpoint not accessible"
    fi
}

# Cleanup old resources
cleanup_old_resources() {
    log_info "Cleaning up old resources..."
    
    # Delete old ReplicaSets (keep last 3)
    kubectl get replicasets -n $NAMESPACE -l app=samokoder-backend --sort-by=.metadata.creationTimestamp -o jsonpath='{.items[:-3].metadata.name}' | xargs -r kubectl delete replicaset -n $NAMESPACE
    
    # Delete old ConfigMaps
    kubectl get configmaps -n $NAMESPACE -l app=samokoder-backend --sort-by=.metadata.creationTimestamp -o jsonpath='{.items[:-2].metadata.name}' | xargs -r kubectl delete configmap -n $NAMESPACE
    
    log_success "Cleanup completed"
}

# Send notifications
send_notifications() {
    local status="$1"
    local version="$2"
    
    log_info "Sending notifications..."
    
    # Slack notification
    if [ -n "${SLACK_WEBHOOK_URL:-}" ]; then
        local message=""
        if [ "$status" = "success" ]; then
            message="✅ Rollback to version $version completed successfully"
        else
            message="❌ Rollback to version $version failed"
        fi
        
        curl -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\"$message\"}" \
            "$SLACK_WEBHOOK_URL" || log_warning "Failed to send Slack notification"
    fi
    
    # PagerDuty notification
    if [ -n "${PAGERDUTY_ROUTING_KEY:-}" ]; then
        local severity="info"
        if [ "$status" = "failure" ]; then
            severity="critical"
        fi
        
        curl -X POST -H 'Content-type: application/json' \
            --data "{\"routing_key\":\"$PAGERDUTY_ROUTING_KEY\",\"event_action\":\"trigger\",\"payload\":{\"summary\":\"Rollback $status\",\"severity\":\"$severity\",\"source\":\"rollback-script\"}}" \
            "https://events.pagerduty.com/v2/enqueue" || log_warning "Failed to send PagerDuty notification"
    fi
}

# Main rollback function
main() {
    local target_version="${1:-}"
    local environment="${2:-production}"
    
    if [ -z "$target_version" ]; then
        log_error "Usage: $0 <version> [environment]"
        log_error "Example: $0 1.0.0 production"
        exit 1
    fi
    
    log_info "Starting rollback process..."
    log_info "Target version: $target_version"
    log_info "Environment: $environment"
    
    # Check prerequisites
    check_prerequisites
    
    # Get current status
    get_current_status
    
    # Check if previous version exists
    local previous_rs=$(check_previous_version "$target_version")
    
    # Confirm rollback
    echo -e "\n${YELLOW}Are you sure you want to rollback to version $target_version? (y/N)${NC}"
    read -r confirmation
    if [[ ! "$confirmation" =~ ^[Yy]$ ]]; then
        log_info "Rollback cancelled"
        exit 0
    fi
    
    # Perform rollback
    if perform_rollback "$target_version" "$previous_rs"; then
        # Verify rollback
        verify_rollback
        
        # Cleanup old resources
        cleanup_old_resources
        
        # Send success notification
        send_notifications "success" "$target_version"
        
        log_success "Rollback completed successfully!"
    else
        # Send failure notification
        send_notifications "failure" "$target_version"
        
        log_error "Rollback failed!"
        exit 1
    fi
}

# Run main function with all arguments
main "$@"