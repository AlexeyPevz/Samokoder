#!/bin/bash
# Samokoder Blue-Green Deployment Script
# Usage: ./blue-green-deploy.sh [version] [environment]

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
NAMESPACE="samokoder"
VERSION="${1:-latest}"
ENVIRONMENT="${2:-production}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

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

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is not installed or not in PATH"
        exit 1
    fi
    
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Determine current and new colors
determine_colors() {
    log_info "Determining deployment colors..."
    
    # Check if blue deployment exists
    if kubectl get deployment samokoder-backend-blue -n $NAMESPACE &> /dev/null; then
        CURRENT_COLOR="blue"
        NEW_COLOR="green"
    elif kubectl get deployment samokoder-backend-green -n $NAMESPACE &> /dev/null; then
        CURRENT_COLOR="green"
        NEW_COLOR="blue"
    else
        # First deployment, start with blue
        CURRENT_COLOR=""
        NEW_COLOR="blue"
    fi
    
    log_info "Current color: $CURRENT_COLOR"
    log_info "New color: $NEW_COLOR"
}

# Deploy new version
deploy_new_version() {
    log_info "Deploying new version $VERSION with color $NEW_COLOR..."
    
    # Create new deployment
    kubectl create deployment samokoder-backend-$NEW_COLOR \
        --image=samokoder/backend:$VERSION \
        --replicas=3 \
        --namespace=$NAMESPACE \
        --dry-run=client -o yaml | kubectl apply -f -
    
    # Create new service
    kubectl create service clusterip samokoder-backend-$NEW_COLOR-service \
        --tcp=8000:8000 \
        --tcp=9090:9090 \
        --namespace=$NAMESPACE \
        --dry-run=client -o yaml | kubectl apply -f -
    
    # Wait for deployment to be ready
    log_info "Waiting for new deployment to be ready..."
    kubectl wait --for=condition=available --timeout=300s \
        deployment/samokoder-backend-$NEW_COLOR -n $NAMESPACE
    
    log_success "New version deployed successfully"
}

# Run smoke tests
run_smoke_tests() {
    log_info "Running smoke tests on new deployment..."
    
    # Get service endpoint
    SERVICE_IP=$(kubectl get service samokoder-backend-$NEW_COLOR-service -n $NAMESPACE -o jsonpath='{.spec.clusterIP}')
    SERVICE_PORT=$(kubectl get service samokoder-backend-$NEW_COLOR-service -n $NAMESPACE -o jsonpath='{.spec.ports[0].port}')
    
    # Test health endpoint
    if kubectl run test-pod --image=curlimages/curl:latest --rm -i --restart=Never -- \
        curl -f "http://$SERVICE_IP:$SERVICE_PORT/health" &> /dev/null; then
        log_success "Health check passed"
    else
        log_error "Health check failed"
        return 1
    fi
    
    # Test API endpoint
    if kubectl run test-pod --image=curlimages/curl:latest --rm -i --restart=Never -- \
        curl -f "http://$SERVICE_IP:$SERVICE_PORT/api/health" &> /dev/null; then
        log_success "API check passed"
    else
        log_error "API check failed"
        return 1
    fi
    
    # Test metrics endpoint
    if kubectl run test-pod --image=curlimages/curl:latest --rm -i --restart=Never -- \
        curl -f "http://$SERVICE_IP:$SERVICE_PORT/metrics" &> /dev/null; then
        log_success "Metrics check passed"
    else
        log_warning "Metrics check failed (non-critical)"
    fi
    
    log_success "Smoke tests completed successfully"
}

# Switch traffic to new version
switch_traffic() {
    log_info "Switching traffic to new version..."
    
    # Update main service to point to new deployment
    kubectl patch service samokoder-backend-service -n $NAMESPACE -p '{"spec":{"selector":{"app":"samokoder-backend-'$NEW_COLOR'"}}}'
    
    # Wait for traffic to switch
    sleep 10
    
    log_success "Traffic switched to new version"
}

# Verify traffic switch
verify_traffic_switch() {
    log_info "Verifying traffic switch..."
    
    # Get main service endpoint
    SERVICE_IP=$(kubectl get service samokoder-backend-service -n $NAMESPACE -o jsonpath='{.spec.clusterIP}')
    SERVICE_PORT=$(kubectl get service samokoder-backend-service -n $NAMESPACE -o jsonpath='{.spec.ports[0].port}')
    
    # Test main service
    if kubectl run test-pod --image=curlimages/curl:latest --rm -i --restart=Never -- \
        curl -f "http://$SERVICE_IP:$SERVICE_PORT/health" &> /dev/null; then
        log_success "Traffic switch verified"
    else
        log_error "Traffic switch verification failed"
        return 1
    fi
}

# Cleanup old version
cleanup_old_version() {
    if [ -n "$CURRENT_COLOR" ]; then
        log_info "Cleaning up old version ($CURRENT_COLOR)..."
        
        # Scale down old deployment
        kubectl scale deployment samokoder-backend-$CURRENT_COLOR -n $NAMESPACE --replicas=0
        
        # Wait for pods to terminate
        kubectl wait --for=delete pod -l app=samokoder-backend-$CURRENT_COLOR -n $NAMESPACE --timeout=300s || true
        
        # Delete old deployment
        kubectl delete deployment samokoder-backend-$CURRENT_COLOR -n $NAMESPACE
        
        # Delete old service
        kubectl delete service samokoder-backend-$CURRENT_COLOR-service -n $NAMESPACE
        
        log_success "Old version cleaned up"
    else
        log_info "No old version to clean up"
    fi
}

# Rollback if needed
rollback() {
    log_error "Deployment failed, rolling back..."
    
    # Switch traffic back to old version
    if [ -n "$CURRENT_COLOR" ]; then
        kubectl patch service samokoder-backend-service -n $NAMESPACE -p '{"spec":{"selector":{"app":"samokoder-backend-'$CURRENT_COLOR'"}}}'
        log_info "Traffic switched back to old version"
    fi
    
    # Delete new deployment
    kubectl delete deployment samokoder-backend-$NEW_COLOR -n $NAMESPACE
    kubectl delete service samokoder-backend-$NEW_COLOR-service -n $NAMESPACE
    
    log_warning "Rollback completed"
}

# Send notification
send_notification() {
    local status="$1"
    local message=""
    
    if [ "$status" = "success" ]; then
        message="✅ Blue-green deployment successful: $VERSION ($NEW_COLOR)"
    else
        message="❌ Blue-green deployment failed: $VERSION ($NEW_COLOR)"
    fi
    
    # Slack notification
    if [ -n "${SLACK_WEBHOOK_URL:-}" ]; then
        curl -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\"$message\"}" \
            "$SLACK_WEBHOOK_URL" || log_warning "Failed to send Slack notification"
    fi
}

# Main deployment function
main() {
    log_info "Starting blue-green deployment..."
    log_info "Version: $VERSION"
    log_info "Environment: $ENVIRONMENT"
    log_info "Timestamp: $TIMESTAMP"
    
    # Check prerequisites
    check_prerequisites
    
    # Determine colors
    determine_colors
    
    # Deploy new version
    if deploy_new_version; then
        # Run smoke tests
        if run_smoke_tests; then
            # Switch traffic
            if switch_traffic; then
                # Verify traffic switch
                if verify_traffic_switch; then
                    # Cleanup old version
                    cleanup_old_version
                    
                    # Send success notification
                    send_notification "success"
                    
                    log_success "Blue-green deployment completed successfully!"
                else
                    rollback
                    send_notification "failure"
                    exit 1
                fi
            else
                rollback
                send_notification "failure"
                exit 1
            fi
        else
            rollback
            send_notification "failure"
            exit 1
        fi
    else
        rollback
        send_notification "failure"
        exit 1
    fi
}

# Run main function
main "$@"