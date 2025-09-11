# Samokoder Rollback Plan

## 🚨 Emergency Rollback Procedures

### Quick Reference
- **Rollback Script**: `./scripts/rollback.sh <version> <environment>`
- **Emergency Contact**: +1-555-SAMOKODER
- **Slack Channel**: #samokoder-alerts
- **PagerDuty**: samokoder-oncall

---

## 📋 Pre-Rollback Checklist

### 1. Verify Issue Severity
- [ ] Confirm the issue is production-affecting
- [ ] Check if it's a data corruption issue (requires special handling)
- [ ] Verify if it's a performance degradation vs. complete outage
- [ ] Document the current error state

### 2. Gather Information
- [ ] Check current deployment version: `kubectl get deployment samokoder-backend -n samokoder -o jsonpath='{.spec.template.spec.containers[0].image}'`
- [ ] Check pod status: `kubectl get pods -n samokoder -l app=samokoder-backend`
- [ ] Check service endpoints: `kubectl get endpoints -n samokoder samokoder-backend-service`
- [ ] Check recent logs: `kubectl logs -n samokoder -l app=samokoder-backend --tail=100`

### 3. Notify Stakeholders
- [ ] Send immediate notification to #samokoder-alerts
- [ ] Notify on-call engineer via PagerDuty
- [ ] Update status page if applicable
- [ ] Notify customer support team

---

## 🔄 Rollback Procedures

### Option 1: Automated Rollback (Recommended)

```bash
# 1. Navigate to project directory
cd /workspace

# 2. Execute rollback script
./scripts/rollback.sh 1.0.0 production

# 3. Verify rollback success
kubectl get pods -n samokoder -l app=samokoder-backend
kubectl get deployment samokoder-backend -n samokoder
```

### Option 2: Manual Rollback

#### Step 1: Scale Down Current Deployment
```bash
kubectl scale deployment samokoder-backend -n samokoder --replicas=0
kubectl wait --for=delete pod -l app=samokoder-backend -n samokoder --timeout=300s
```

#### Step 2: Identify Previous Version
```bash
# List all ReplicaSets
kubectl get replicasets -n samokoder -l app=samokoder-backend --sort-by=.metadata.creationTimestamp

# Get the previous ReplicaSet name
PREVIOUS_RS=$(kubectl get replicasets -n samokoder -l app=samokoder-backend --sort-by=.metadata.creationTimestamp -o jsonpath='{.items[-2].metadata.name}')
echo "Previous ReplicaSet: $PREVIOUS_RS"
```

#### Step 3: Scale Up Previous Version
```bash
kubectl scale replicaset $PREVIOUS_RS -n samokoder --replicas=3
kubectl wait --for=condition=ready pod -l app=samokoder-backend -n samokoder --timeout=300s
```

#### Step 4: Verify Rollback
```bash
# Check pod status
kubectl get pods -n samokoder -l app=samokoder-backend

# Test health endpoint
SERVICE_IP=$(kubectl get service samokoder-backend-service -n samokoder -o jsonpath='{.spec.clusterIP}')
SERVICE_PORT=$(kubectl get service samokoder-backend-service -n samokoder -o jsonpath='{.spec.ports[0].port}')
kubectl run test-pod --image=curlimages/curl:latest --rm -i --restart=Never -- curl -f "http://$SERVICE_IP:$SERVICE_PORT/health"
```

### Option 3: Helm Rollback

```bash
# 1. List Helm releases
helm list -n samokoder

# 2. Get release history
helm history samokoder -n samokoder

# 3. Rollback to previous version
helm rollback samokoder 1 -n samokoder

# 4. Verify rollback
helm status samokoder -n samokoder
```

---

## 🔍 Post-Rollback Verification

### 1. Health Checks
```bash
# Check pod status
kubectl get pods -n samokoder -l app=samokoder-backend

# Check service endpoints
kubectl get endpoints -n samokoder samokoder-backend-service

# Test health endpoint
kubectl run test-pod --image=curlimages/curl:latest --rm -i --restart=Never -- curl -f "http://$SERVICE_IP:$SERVICE_PORT/health"

# Test API endpoint
kubectl run test-pod --image=curlimages/curl:latest --rm -i --restart=Never -- curl -f "http://$SERVICE_IP:$SERVICE_PORT/api/health"
```

### 2. Performance Verification
```bash
# Check metrics endpoint
kubectl run test-pod --image=curlimages/curl:latest --rm -i --restart=Never -- curl -f "http://$SERVICE_IP:$SERVICE_PORT/metrics"

# Check HPA status
kubectl get hpa -n samokoder

# Check resource usage
kubectl top pods -n samokoder -l app=samokoder-backend
```

### 3. Database Verification
```bash
# Check database connectivity
kubectl run test-pod --image=postgres:15 --rm -i --restart=Never -- psql -h $DB_HOST -U $DB_USER -d $DB_NAME -c "SELECT 1;"

# Check Redis connectivity
kubectl run test-pod --image=redis:7 --rm -i --restart=Never -- redis-cli -h $REDIS_HOST ping
```

---

## 🚨 Emergency Procedures

### Complete Service Outage
1. **Immediate Actions**:
   - Scale down current deployment to 0 replicas
   - Scale up previous known-good version
   - Check all external dependencies (DB, Redis, etc.)

2. **Verification**:
   - Test all critical endpoints
   - Verify data integrity
   - Check for data corruption

3. **Communication**:
   - Update status page immediately
   - Notify all stakeholders
   - Begin incident response procedures

### Data Corruption Suspected
1. **Immediate Actions**:
   - **DO NOT** perform automated rollback
   - Scale down current deployment
   - Preserve current state for investigation
   - Contact database team immediately

2. **Investigation**:
   - Check database backups
   - Verify data integrity
   - Identify corruption scope

3. **Recovery**:
   - Restore from backup if necessary
   - Implement data repair procedures
   - Coordinate with data team

---

## 📊 Monitoring and Alerts

### Key Metrics to Monitor
- **Latency**: P95 < 500ms (Warning), P95 < 1000ms (Critical)
- **Traffic**: < 100 RPS (Warning), < 500 RPS (Critical)
- **Errors**: < 1% (Warning), < 5% (Critical)
- **Saturation**: CPU < 70% (Warning), CPU < 90% (Critical)

### Alert Channels
- **Slack**: #samokoder-alerts
- **PagerDuty**: samokoder-oncall
- **Email**: alerts@samokoder.com
- **SMS**: +1-555-SAMOKODER

---

## 🔧 Troubleshooting Common Issues

### Rollback Fails
1. Check if previous version exists
2. Verify cluster connectivity
3. Check resource constraints
4. Review pod logs for errors

### Health Checks Fail
1. Check pod status and logs
2. Verify service endpoints
3. Check network policies
4. Verify resource limits

### Performance Issues After Rollback
1. Check resource usage
2. Verify HPA configuration
3. Check for resource contention
4. Review recent changes

---

## 📝 Documentation and Communication

### Post-Rollback Actions
1. **Document the incident**:
   - Root cause analysis
   - Timeline of events
   - Actions taken
   - Lessons learned

2. **Update stakeholders**:
   - Send post-incident report
   - Update status page
   - Notify customer support

3. **Follow-up actions**:
   - Schedule post-mortem meeting
   - Update runbooks if needed
   - Implement preventive measures

### Communication Templates

#### Slack Notification
```
🚨 INCIDENT: Samokoder Production Rollback
Status: In Progress
Affected: Production environment
Action: Rolling back to version 1.0.0
ETA: 5 minutes
Updates: #samokoder-alerts
```

#### Status Page Update
```
We are currently experiencing issues with our production environment. 
We are performing a rollback to restore service. 
Estimated resolution time: 10 minutes.
```

---

## 🎯 Success Criteria

### Rollback is considered successful when:
- [ ] All pods are running and ready
- [ ] Health checks pass
- [ ] API endpoints respond correctly
- [ ] Performance metrics are within normal ranges
- [ ] No critical errors in logs
- [ ] All stakeholders are notified

### Rollback is considered failed when:
- [ ] Pods fail to start after 5 minutes
- [ ] Health checks fail after 3 attempts
- [ ] Critical errors persist
- [ ] Data corruption is detected
- [ ] Service is still unavailable after 10 minutes

---

## 📞 Emergency Contacts

| Role | Name | Phone | Slack | Email |
|------|------|-------|-------|-------|
| On-Call Engineer | John Doe | +1-555-0001 | @john.doe | john@samokoder.com |
| DevOps Lead | Jane Smith | +1-555-0002 | @jane.smith | jane@samokoder.com |
| Database Admin | Bob Johnson | +1-555-0003 | @bob.johnson | bob@samokoder.com |
| Security Lead | Alice Brown | +1-555-0004 | @alice.brown | alice@samokoder.com |

---

## 🔗 Related Documentation

- [Incident Response Plan](./incident-response.md)
- [Deployment Procedures](./deployment-procedures.md)
- [Monitoring Runbooks](./monitoring-runbooks.md)
- [Database Recovery Procedures](./database-recovery.md)
- [Security Incident Response](./security-incident-response.md)

---

**Last Updated**: 2024-12-19  
**Version**: 1.0.0  
**Next Review**: 2025-01-19