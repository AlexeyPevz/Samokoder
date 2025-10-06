# 📊 Samokoder Monitoring Dashboard - Quick Reference Guide

## 🎯 Обзор

Этот документ содержит quick reference guide по мониторингу платформы Samokoder с использованием Four Golden Signals подхода.

---

## 📈 Доступ к дашбордам

### Grafana UI
- **URL:** `http://localhost:3000`
- **Логин:** `admin`
- **Пароль:** из `.env` переменной `GRAFANA_ADMIN_PASSWORD`

### Главные дашборды:

1. **Four Golden Signals** (РЕКОМЕНДУЕТСЯ)
   - URL: `http://localhost:3000/d/samokoder-golden-signals`
   - Comprehensive view с SLO tracking

2. **Original Overview** (legacy)
   - URL: `http://localhost:3000/d/samokoder-overview`
   - Basic metrics (можно удалить)

### Prometheus
- **URL:** `http://localhost:9090`
- Query interface для ad-hoc queries

### AlertManager
- **URL:** `http://localhost:9093`
- Active alerts и silences

---

## 🔥 Four Golden Signals - Quick Check

### 1️⃣ TRAFFIC (Трафик)

**Что смотреть:**
- Текущий RPS (requests per second)
- Тренд: растет/падает/стабилен

**Нормальные значения:**
- Development: 1-10 RPS
- Production: зависит от нагрузки

**Alerts:**
- Нет автоматических алертов (informational metric)

**PromQL query:**
```promql
sum(rate(samokoder_http_requests_total[5m]))
```

---

### 2️⃣ LATENCY (Задержка)

**Что смотреть:**
- P95 latency (95% запросов быстрее этого значения)
- P99 latency для worst-case

**🎯 SLO Target:** P95 < 2 seconds

**Thresholds:**
- 🟢 GREEN: < 2s (within SLO)
- 🟡 YELLOW: 2-5s (degraded)
- 🔴 RED: > 5s (critical)

**Alerts:**
- `HighLatency`: если P95 > 5s в течение 10 минут
- `LatencySLOViolation`: если P95 > 2s в течение 10 минут

**PromQL query:**
```promql
histogram_quantile(0.95, 
  rate(samokoder_http_request_duration_seconds_bucket[5m])
)
```

---

### 3️⃣ ERRORS (Ошибки)

**Что смотреть:**
- Error rate % (5xx responses)
- Error budget remaining

**🎯 SLO Target:** Error rate < 1%

**Thresholds:**
- 🟢 GREEN: < 1% (within SLO)
- 🟡 YELLOW: 1-5% (elevated)
- 🔴 RED: > 5% (critical)

**Alerts:**
- `HighErrorRate`: если > 5% в течение 5 минут
- `ErrorBudgetCritical`: если error budget < 10%

**PromQL query:**
```promql
(
  sum(rate(samokoder_http_requests_total{status=~"5.."}[5m]))
  /
  sum(rate(samokoder_http_requests_total[5m]))
) * 100
```

---

### 4️⃣ SATURATION (Насыщение ресурсов)

**Что смотреть:**

#### CPU
- **Threshold:** 🟢 < 70% | 🟡 70-90% | 🔴 > 90%
- **Alert:** `HighCPUUsage` если > 80% в течение 10 минут

#### Memory
- **Threshold:** 🟢 < 80% | 🟡 80-90% | 🔴 > 90%
- **Alert:** `HighMemoryUsage` если > 85% в течение 10 минут

#### Disk
- **Threshold:** 🟢 < 80% | 🟡 80-90% | 🔴 > 90%
- **Alert:** `LowDiskSpace` если free < 10% в течение 5 минут

#### File Descriptors
- **Threshold:** 🟢 < 70% | 🟡 70-85% | 🔴 > 85%
- **Alert:** `HighFileDescriptorUsage` если > 80%

#### Database Connection Pool
- **Threshold:** 🟢 < 70% | 🟡 70-80% | 🔴 > 80%
- **Alert:** `DatabaseConnectionPoolSaturated` если > 80%

#### Network Connections
- **Threshold:** 🟢 < 1000 | 🟡 1000-5000 | 🔴 > 5000
- **Alert:** `HighNetworkConnections` если > 5000

**PromQL queries:**
```promql
# CPU
samokoder_system_cpu_usage_percent

# Memory
(samokoder_system_memory_usage_bytes{type="used"} 
  / samokoder_system_memory_usage_bytes{type="total"}) * 100

# File Descriptors
(samokoder_file_descriptors_open / samokoder_file_descriptors_max) * 100

# DB Pool
samokoder_db_connection_pool_saturation_percent
```

---

## 🎯 SLO Dashboard

### Error Budget Tracking

**Визуализация:** 3 gauge panels

#### 1. Availability Budget
- **Target:** 99.9% uptime
- **Monthly budget:** 43.2 minutes downtime
- **Color coding:**
  - 🔴 RED: < 20% budget remaining
  - 🟡 YELLOW: 20-50%
  - 🟢 GREEN: > 50%

#### 2. Latency Budget
- **Target:** P95 < 2 seconds
- **Budget:** 5% requests can exceed
- **Color coding:** same as above

#### 3. Error Rate Budget
- **Target:** < 1% error rate
- **Budget:** 1% of requests can fail
- **Color coding:** same as above

### Availability Timeline

**Панель:** "Availability: Current vs Target"
- Синяя линия: текущая availability
- Красная линия: SLO target (0.999)
- Если синяя ниже красной → SLO violation

---

## 🚨 Common Alert Scenarios

### Scenario 1: API Down

**Alert:** `APIDown`
**Severity:** 🔴 Critical

**Symptoms:**
- Dashboard показывает Traffic = 0
- Latency gauge N/A
- Error rate 100% или N/A

**Immediate actions:**
1. Check API container: `docker ps | grep samokoder-api`
2. Check logs: `docker logs samokoder-api --tail 100`
3. Check health: `curl http://localhost:8000/health`
4. If needed, restart: `docker-compose restart api`
5. If still down, consider rollback: `./ops/scripts/rollback.sh --service=api --auto`

**Escalation:** If not resolved in 15 minutes → page on-call

---

### Scenario 2: High Latency

**Alert:** `HighLatency` or `LatencySLOViolation`
**Severity:** 🟡 Warning (🔴 Critical if SLO violated)

**Symptoms:**
- Latency gauge in YELLOW or RED
- P95 > 2s (SLO violation)

**Investigate:**
1. Check saturation metrics (CPU, Memory, DB connections)
2. Check database latency: look at "DB Query Latency P95" panel
3. Check LLM latency: look at "LLM Latency by Provider" panel
4. Check if specific endpoints slow: look at "API Percentiles" panel

**Common causes:**
- Database queries slow → optimize queries
- LLM provider slow → check provider status
- Resource saturation → scale up or optimize

---

### Scenario 3: High Error Rate

**Alert:** `HighErrorRate`
**Severity:** 🟡 Warning → 🔴 Critical if sustained

**Symptoms:**
- Error gauge in RED
- Error rate > 5%
- Error budget depleting

**Investigate:**
1. Check "5xx Errors by Status" panel - which status codes?
2. Check logs for error messages
3. Check recent deployments - did we just deploy?
4. Check database errors panel
5. Check LLM errors panel

**Common causes:**
- Recent bad deployment → rollback
- Database connection issues → check DB health
- LLM provider issues → check provider status
- Configuration error → check .env

**Mitigation:**
```bash
# If recent deployment caused it
./ops/scripts/rollback.sh --service=api --auto

# Check what changed
git log --oneline -5
```

---

### Scenario 4: Resource Saturation

**Alert:** `HighCPUUsage`, `HighMemoryUsage`, `DatabaseConnectionPoolSaturated`
**Severity:** 🟡 Warning

**Symptoms:**
- Saturation gauges in YELLOW/RED
- Performance degradation

**Investigate:**
1. Check which resource is saturated
2. Look for trends - sudden spike or gradual increase?
3. Check if caused by traffic increase

**CPU Saturation:**
```bash
# Check container stats
docker stats samokoder-api --no-stream

# Check what's consuming CPU
docker exec samokoder-api top -bn1 | head -20
```

**Memory Saturation:**
```bash
# Check memory usage
docker stats samokoder-api --no-stream

# May need to increase container limits in docker-compose.yml
```

**DB Connection Pool Saturation:**
```bash
# Check active connections
docker exec samokoder-db psql -U user -d samokoder -c \
  "SELECT count(*) FROM pg_stat_activity WHERE state = 'active';"

# May need to increase pool size in config
```

---

### Scenario 5: Error Budget Exhausted

**Alert:** `ErrorBudgetCritical`
**Severity:** 🔴 Critical

**Symptoms:**
- Error budget gauge < 10%
- Availability dropping

**Actions:**
1. **STOP deployments** - we're out of error budget
2. Identify root cause of recent errors/downtime
3. Focus on stability over new features
4. Schedule post-mortem meeting

**Communication:**
```
Subject: Error Budget Critically Low - Deployment Freeze

Team,

Our error budget is at X%. We need to:
1. Pause all non-critical deployments
2. Focus on stability improvements
3. Investigate recent incidents

Error budget will reset on [date].
```

---

## 📋 Daily Health Check Checklist

### Morning Check (5 minutes)

- [ ] Open Four Golden Signals dashboard
- [ ] Check all 4 golden signals are 🟢 GREEN
- [ ] Check error budgets are > 50%
- [ ] Check no critical alerts firing in AlertManager
- [ ] Review any warnings from overnight

### Before Deployment (3 minutes)

- [ ] Current error rate < 1%
- [ ] Current latency P95 < 1.5s (buffer room)
- [ ] Error budget > 25%
- [ ] No saturation warnings
- [ ] All services healthy

### After Deployment (10 minutes)

- [ ] Run smoke tests: `./ops/scripts/smoke-test.sh`
- [ ] Monitor dashboard for 10 minutes
- [ ] Error rate stable or decreasing
- [ ] Latency P95 not increasing
- [ ] No new alerts firing
- [ ] If any issues → immediate rollback

---

## 🔧 Useful PromQL Queries

### Top 10 slowest endpoints
```promql
topk(10, 
  histogram_quantile(0.95, 
    sum(rate(samokoder_http_request_duration_seconds_bucket[5m])) 
    by (endpoint, le)
  )
)
```

### Request rate by endpoint
```promql
sum(rate(samokoder_http_requests_total[5m])) by (endpoint)
```

### Error rate by endpoint
```promql
sum(rate(samokoder_http_requests_total{status=~"5.."}[5m])) by (endpoint)
```

### LLM cost (tokens/hour)
```promql
sum(rate(samokoder_llm_tokens_consumed_total[1h])) by (provider) * 3600
```

### Current availability (last hour)
```promql
1 - (
  sum(rate(samokoder_http_requests_total{status=~"5.."}[1h]))
  /
  sum(rate(samokoder_http_requests_total[1h]))
)
```

---

## 📞 Contacts & Escalation

| Severity | Contact | Response Time |
|----------|---------|---------------|
| 🔴 Critical | On-call engineer (PagerDuty) | 15 minutes |
| 🟡 Warning | DevOps team (Telegram) | 2 hours |
| 🔵 Info | #ops-alerts (Slack) | Best effort |

**On-call rotation:** Check PagerDuty schedule

---

## 🔗 Quick Links

- **Grafana:** http://localhost:3000/d/samokoder-golden-signals
- **Prometheus:** http://localhost:9090
- **AlertManager:** http://localhost:9093
- **API Health:** http://localhost:8000/health
- **API Metrics:** http://localhost:8000/metrics

**Documentation:**
- [DevOps Audit Report](./DEVOPS_AUDIT_REPORT.md)
- [Rollback Procedure](./ops/runbooks/rollback-procedure.md)
- [Disaster Recovery](./ops/runbooks/disaster_recovery.md)
- [Monitoring Operations](./ops/runbooks/monitoring_operations.md)

---

## 🎓 Training Resources

### For new team members:

1. **Read first:**
   - This guide (15 min)
   - [Site Reliability Engineering Book - Chapter 4: Service Level Objectives](https://sre.google/sre-book/service-level-objectives/)

2. **Hands-on:**
   - Access Grafana and explore dashboard (30 min)
   - Simulate alert: `curl -X POST http://localhost:9093/api/v1/alerts ...`
   - Practice rollback: `./ops/scripts/rollback.sh --dry-run --service=api --auto`

3. **Shadow on-call:**
   - First incident: shadow experienced engineer
   - Second incident: lead with backup
   - Third incident: independent (with escalation path)

---

**Последнее обновление:** 2025-10-06  
**Версия:** 1.0
