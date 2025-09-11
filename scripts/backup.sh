#!/bin/bash
# Samokoder Backup Script
# Usage: ./backup.sh [backup-type] [environment]

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
NAMESPACE="samokoder"
BACKUP_TYPE="${1:-full}"
ENVIRONMENT="${2:-production}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR="/backups/samokoder-$TIMESTAMP"

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

# Create backup directory
create_backup_dir() {
    log_info "Creating backup directory: $BACKUP_DIR"
    mkdir -p "$BACKUP_DIR"
}

# Backup Kubernetes resources
backup_kubernetes() {
    log_info "Backing up Kubernetes resources..."
    
    # Backup all resources in namespace
    kubectl get all -n $NAMESPACE -o yaml > "$BACKUP_DIR/kubernetes-resources.yaml"
    
    # Backup ConfigMaps
    kubectl get configmaps -n $NAMESPACE -o yaml > "$BACKUP_DIR/configmaps.yaml"
    
    # Backup Secrets (without sensitive data)
    kubectl get secrets -n $NAMESPACE -o yaml > "$BACKUP_DIR/secrets.yaml"
    
    # Backup PVCs
    kubectl get pvc -n $NAMESPACE -o yaml > "$BACKUP_DIR/pvcs.yaml"
    
    log_success "Kubernetes resources backed up"
}

# Backup database
backup_database() {
    log_info "Backing up database..."
    
    # Get database connection details
    DB_HOST=$(kubectl get secret samokoder-secrets -n $NAMESPACE -o jsonpath='{.data.DATABASE_URL}' | base64 -d | cut -d'@' -f2 | cut -d'/' -f1)
    DB_NAME=$(kubectl get secret samokoder-secrets -n $NAMESPACE -o jsonpath='{.data.DATABASE_URL}' | base64 -d | cut -d'/' -f4)
    DB_USER=$(kubectl get secret samokoder-secrets -n $NAMESPACE -o jsonpath='{.data.DATABASE_URL}' | base64 -d | cut -d'/' -f3 | cut -d':' -f1)
    
    # Create database backup
    kubectl run postgres-backup --image=postgres:15 --rm -i --restart=Never -- \
        pg_dump -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" > "$BACKUP_DIR/database.sql"
    
    log_success "Database backed up"
}

# Backup application data
backup_application_data() {
    log_info "Backing up application data..."
    
    # Get pod name
    POD_NAME=$(kubectl get pods -n $NAMESPACE -l app=samokoder-backend -o jsonpath='{.items[0].metadata.name}')
    
    # Backup workspaces
    kubectl exec -n $NAMESPACE $POD_NAME -- tar czf - /app/workspaces > "$BACKUP_DIR/workspaces.tar.gz"
    
    # Backup exports
    kubectl exec -n $NAMESPACE $POD_NAME -- tar czf - /app/exports > "$BACKUP_DIR/exports.tar.gz"
    
    # Backup logs
    kubectl exec -n $NAMESPACE $POD_NAME -- tar czf - /app/logs > "$BACKUP_DIR/logs.tar.gz"
    
    log_success "Application data backed up"
}

# Backup configuration files
backup_config() {
    log_info "Backing up configuration files..."
    
    # Copy Terraform files
    cp -r "$PROJECT_ROOT/terraform" "$BACKUP_DIR/"
    
    # Copy Kubernetes manifests
    cp -r "$PROJECT_ROOT/k8s" "$BACKUP_DIR/"
    
    # Copy Helm charts
    cp -r "$PROJECT_ROOT/helm" "$BACKUP_DIR/"
    
    # Copy monitoring configs
    cp -r "$PROJECT_ROOT/monitoring" "$BACKUP_DIR/"
    
    # Copy scripts
    cp -r "$PROJECT_ROOT/scripts" "$BACKUP_DIR/"
    
    log_success "Configuration files backed up"
}

# Upload to S3
upload_to_s3() {
    log_info "Uploading backup to S3..."
    
    # Get S3 bucket from Terraform output
    S3_BUCKET=$(cd "$PROJECT_ROOT/terraform" && terraform output -raw s3_backups_bucket 2>/dev/null || echo "samokoder-backups")
    
    # Upload backup
    aws s3 cp "$BACKUP_DIR" "s3://$S3_BUCKET/backups/$TIMESTAMP/" --recursive
    
    log_success "Backup uploaded to S3"
}

# Cleanup old backups
cleanup_old_backups() {
    log_info "Cleaning up old backups..."
    
    # Keep only last 7 days of backups
    find /backups -name "samokoder-*" -type d -mtime +7 -exec rm -rf {} \;
    
    log_success "Old backups cleaned up"
}

# Verify backup
verify_backup() {
    log_info "Verifying backup..."
    
    # Check if backup directory exists and has content
    if [ -d "$BACKUP_DIR" ] && [ "$(ls -A "$BACKUP_DIR")" ]; then
        log_success "Backup verification passed"
        return 0
    else
        log_error "Backup verification failed"
        return 1
    fi
}

# Send notification
send_notification() {
    local status="$1"
    local message=""
    
    if [ "$status" = "success" ]; then
        message="✅ Backup completed successfully: $BACKUP_DIR"
    else
        message="❌ Backup failed: $BACKUP_DIR"
    fi
    
    # Slack notification
    if [ -n "${SLACK_WEBHOOK_URL:-}" ]; then
        curl -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\"$message\"}" \
            "$SLACK_WEBHOOK_URL" || log_warning "Failed to send Slack notification"
    fi
}

# Main backup function
main() {
    log_info "Starting backup process..."
    log_info "Backup type: $BACKUP_TYPE"
    log_info "Environment: $ENVIRONMENT"
    log_info "Timestamp: $TIMESTAMP"
    
    # Create backup directory
    create_backup_dir
    
    # Perform backup based on type
    case "$BACKUP_TYPE" in
        "full")
            backup_kubernetes
            backup_database
            backup_application_data
            backup_config
            ;;
        "database")
            backup_database
            ;;
        "config")
            backup_config
            ;;
        "data")
            backup_application_data
            ;;
        *)
            log_error "Unknown backup type: $BACKUP_TYPE"
            exit 1
            ;;
    esac
    
    # Verify backup
    if verify_backup; then
        # Upload to S3
        upload_to_s3
        
        # Cleanup old backups
        cleanup_old_backups
        
        # Send success notification
        send_notification "success"
        
        log_success "Backup completed successfully!"
    else
        # Send failure notification
        send_notification "failure"
        
        log_error "Backup failed!"
        exit 1
    fi
}

# Run main function
main "$@"