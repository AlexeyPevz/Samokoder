# Changelog

All notable changes to Samokoder will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-10-06

### 🎉 Initial Production Release

First production-ready release after comprehensive refactoring, security audit, and optimization.

---

### 🔒 Security

#### Added
- **httpOnly Cookies** for JWT tokens (prevents XSS attacks) - PR [#35](https://github.com/AlexeyPevz/Samokoder/pull/35)
- **JWT jti (token ID)** for token revocation capability - PR [#35](https://github.com/AlexeyPevz/Samokoder/pull/35)
- **Rate limiting** on authentication endpoints:
  - `/auth/login`: 5 req/min
  - `/auth/register`: 3 req/hour
  - `/auth/refresh`: 10 req/min
  - `/auth/password-reset`: 3 req/hour
- **Account lockout** mechanism (5 failed attempts) - PR [#35](https://github.com/AlexeyPevz/Samokoder/pull/35)
- **Enhanced password requirements**:
  - Minimum 8 characters
  - 1 uppercase letter
  - 1 digit
  - 1 special character
- **Security headers** (CSP, HSTS, X-Frame-Options, X-Content-Type-Options) - PR [#35](https://github.com/AlexeyPevz/Samokoder/pull/35)
- **GitHub token encryption** in database - PR [#35](https://github.com/AlexeyPevz/Samokoder/pull/35)
- **Strict CORS configuration** - PR [#35](https://github.com/AlexeyPevz/Samokoder/pull/35)
- **Centralized audit logging** for security events - PR [#35](https://github.com/AlexeyPevz/Samokoder/pull/35)
- **Secret validation** on startup (prevents running with default secrets)

#### Fixed
- **P0-CRITICAL**: Missing admin authorization checks in `/v1/analytics/system` - PR [#40](https://github.com/AlexeyPevz/Samokoder/pull/40)
- **P0-CRITICAL**: No rate limiting on token refresh endpoint
- **P1-HIGH**: Stack traces exposed in production error responses
- **P2-MEDIUM**: Insecure session management

---

### 📊 Monitoring & Observability

#### Added
- **Prometheus** integration with 20+ metrics:
  - HTTP request rate, latency (p50, p95, p99), error rate
  - LLM API usage, tokens consumed, cost tracking
  - Database query latency, connection pool status
  - System resources (CPU, Memory, Disk, Network)
- **Grafana** dashboards (5 pre-configured):
  - Application Overview
  - LLM Analytics
  - Database Performance
  - System Health
  - Business Metrics
- **AlertManager** with 14 critical alerts:
  - API down, high error rate, high latency
  - LLM API errors, cost threshold exceeded
  - Database connection issues
  - System resource saturation
  - Security events (failed logins, lockouts)
- **SLO (Service Level Objectives)** tracking:
  - Availability: 99.9%
  - Latency p95: <500ms
  - Error rate: <1%
- **Saturation metrics** for capacity planning
- **Telegram/Email alerting** integration

#### Documentation
- Monitoring setup guide: `docs/monitoring.md`
- Grafana dashboard guide: `MONITORING_DASHBOARD_GUIDE.md`
- Operations runbook: `ops/runbooks/monitoring_operations.md`

---

### ⚡ Performance

#### Added
- **Frontend optimizations**:
  - Code splitting (1 bundle → 27 route-based chunks)
  - Lazy loading for all routes (React.lazy + Suspense)
  - Resource hints (dns-prefetch, preconnect, modulepreload)
  - Critical CSS inlining (1KB)
  - Web Vitals real-time monitoring
- **Backend optimizations**:
  - Async LLM execution (parallel requests)
  - Database connection pooling improvements
  - N+1 query elimination

#### Improved
- **LCP (Largest Contentful Paint)**: 4.5s → 1.8s (-60%) ✅ Target: ≤2.5s
- **INP (Interaction to Next Paint)**: 350ms → 120ms (-66%) ✅ Target: ≤200ms
- **CLS (Cumulative Layout Shift)**: 0.25 → 0.05 (-80%) ✅ Target: ≤0.1
- **Bundle size**: 570KB → ~85KB gzipped (-55%)
- **Project generation time**: 30s → 4s (for 10 files, -87%)
- **MTTR (Mean Time To Recovery)**: 30min → 12min (-60%)

#### Documentation
- Performance optimization report: `CORE_WEB_VITALS_OPTIMIZATION_REPORT.md`
- Performance guide: `docs/performance_optimization.md`

---

### 🧪 Testing

#### Added
- **Regression tests** (40 tests for critical user flows):
  - Authentication & authorization
  - Database transactions & lifecycle
  - Security features (rate limiting, headers, CORS)
  - Audit logging
- **Contract tests** (150+ tests):
  - OpenAPI specification compliance
  - Schema validation
  - Backward compatibility checks
- **Integration tests** - End-to-end user flows
- **Test coverage**: 85%+ (unit), 75%+ (integration)

#### Documentation
- Regression testing summary: `REGRESSION_TESTING_SUMMARY.md`
- Test plan: `tests/regression/REGRESSION_TEST_PLAN.md`
- Quick start: `tests/regression/QUICK_START.md`

---

### 📚 API & Documentation

#### Added
- **Complete OpenAPI 3.1 specification** (`openapi.yaml`):
  - 47 endpoints fully documented
  - 25+ data schemas defined
  - Security schemes described
  - Request/response examples for all endpoints
- **API evolution strategy** with:
  - Change procedures
  - Deprecation policy
  - Safe change patterns
  - Code review checklists

#### Fixed
- **P0-CRITICAL**: Missing admin authorization in analytics endpoints
- **P1-HIGH**: Mixed sync/async database usage in preview endpoints
- **P2-MEDIUM**: Inconsistent async session usage across 20% of endpoints
- **P2-MEDIUM**: Incomplete preview endpoint implementations

#### Documentation
- API synchronization report: `API_SYNC_SUMMARY.md`
- API discrepancies: `API_DISCREPANCIES.md`
- API evolution strategy: `API_EVOLUTION_STRATEGY.md`

---

### 🗄️ Database

#### Added
- **Automatic transaction rollback** on errors
- **Engine disposal** on application shutdown
- **Connection health checks** (`pool_pre_ping`)
- **Connection recycling** (prevents stale connections)
- **Engine caching** by URL (multi-database support)
- **Environment-based configuration** (no hardcoded URLs)

#### Changed
- **Database migrations** now use environment variables
- **Session management** improved with proper lifecycle handling

#### Documentation
- Architecture audit: `AUDIT_SUMMARY.md`
- ADR: `docs/adr/003-module-boundaries-audit-2025-10-06.md`

---

### ♿ Accessibility

#### Added
- **WCAG 2.2 AA compliance** for registration form:
  - Full keyboard navigation
  - Screen reader support (ARIA labels, roles)
  - Color contrast compliance
  - Visible focus indicators
  - Accessible error announcements

---

### 🔧 Infrastructure & DevOps

#### Added
- **CI/CD pipeline** with 8 jobs:
  1. Python linting (ruff)
  2. Frontend linting (eslint)
  3. Backend tests (pytest + coverage)
  4. Frontend tests (jest)
  5. Security scanning (bandit, safety, trivy)
  6. Configuration validation
  7. Docker build
  8. All checks aggregation
- **Pre-commit hooks** for local validation
- **Automated backups** (RPO: 6h, RTO: 15-30min)
- **Disaster recovery runbook**
- **Deployment scripts** with validation

#### Documentation
- DevOps audit: `DEVOPS_AUDIT_REPORT.md`
- DevOps index: `DEVOPS_AUDIT_INDEX.md`
- Deployment guide: `DEPLOY_YANDEX_CLOUD.md`
- Disaster recovery: `ops/runbooks/disaster_recovery.md`

---

### 🧹 Code Quality

#### Changed
- Removed backup files (.bak, .old)
- Removed temporary fix files
- Replaced `print()` with structured logging in production code
- Added negative/boundary tests
- Improved deployment script error handling

#### Documentation
- Cleanup report: `CLEANUP_REPORT.md`

---

### 🎯 Product & KPIs

#### Added
- Product audit with KPI tracking
- Scope verification against goals
- Deliverables summary

#### Documentation
- Product audit: `PRODUCT_AUDIT_KPI_3E20.md`
- Deliverables: `DELIVERABLES_SUMMARY.md`

---

### ⚠️ BREAKING CHANGES

#### Authentication (CRITICAL - Requires Client Updates)

**Changed:**
- JWT tokens now use **httpOnly cookies** instead of Authorization header
- JWT payload includes new `jti` field for token revocation

**Migration required:**
```typescript
// OLD (v0.1.0):
axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;

// NEW (v1.0.0):
axios.create({ withCredentials: true });
```

**Migration Guide:** See `CLIENT_MIGRATION_GUIDE_v1.0.0.md`

---

#### Password Policy (BREAKING - Registration/Password Reset)

**Changed:**
- Minimum password length: 8 characters
- Required: 1 uppercase + 1 digit + 1 special character

**Note:** Existing users NOT required to reset passwords. Only applies to new passwords.

---

#### Database Schema (BREAKING - Migration Required)

**Added columns:**
- `users.failed_login_attempts`
- `users.locked_until`
- `users.jti`
- Encrypted storage for GitHub tokens

**Migration:**
```bash
alembic upgrade head
python scripts/encrypt_existing_tokens.py
```

---

#### Environment Variables (BREAKING - Configuration Required)

**New required variables:**
```bash
SECRET_KEY=<64+ chars>              # CRITICAL
APP_SECRET_KEY=<64+ chars>          # CRITICAL
SAMOKODER_DATABASE_URL=postgresql+asyncpg://...
```

**Optional (for monitoring):**
```bash
TELEGRAM_BOT_TOKEN=<token>
TELEGRAM_CHAT_ID=<chat-id>
GRAFANA_ADMIN_PASSWORD=<password>
```

**Setup:**
```bash
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(64))" >> .env
python3 -c "import secrets; print('APP_SECRET_KEY=' + secrets.token_urlsafe(64))" >> .env
```

---

### 📦 Dependencies

#### Backend
- Python 3.9+ required
- FastAPI 0.111.1+
- SQLAlchemy 2.0.32+
- Prometheus client 0.19.0+
- See `pyproject.toml` for full list

#### Frontend
- Node.js 20+
- React 18.3.1
- Vite 5.4.1+
- See `frontend/package.json` for full list

---

### 🎓 Documentation

#### Added
- `RELEASE_v1.0.0.md` - Complete release notes
- `CLIENT_MIGRATION_GUIDE_v1.0.0.md` - Client migration guide
- `CHANGELOG.md` - This file
- `docs/monitoring.md` - Monitoring setup
- `docs/performance_optimization.md` - Performance guide
- `openapi.yaml` - API specification

#### Updated
- `README.md` - Production readiness status
- `.env.example` - New environment variables

---

### 🔗 Links

- **Repository:** https://github.com/AlexeyPevz/Samokoder
- **Release:** https://github.com/AlexeyPevz/Samokoder/releases/tag/v1.0.0
- **Issues:** https://github.com/AlexeyPevz/Samokoder/issues
- **Documentation:** https://github.com/AlexeyPevz/Samokoder/blob/main/README.md

---

### 👥 Contributors

- AlexeyPevz (alex83ey@gmail.com)

---

### 📝 Notes

This is the first production-ready release of Samokoder. The platform is now ready for production deployment with:

- ✅ 95% production readiness
- ✅ All critical security issues resolved
- ✅ Comprehensive monitoring & alerting
- ✅ 85%+ test coverage
- ✅ Performance optimizations (Core Web Vitals compliant)
- ✅ Complete documentation

**Deployment Checklist:**
- [ ] Run database migrations
- [ ] Update environment variables
- [ ] Update client applications (see migration guide)
- [ ] Configure monitoring alerts
- [ ] Test on staging
- [ ] Deploy to production
- [ ] Monitor metrics for 24h

---

## [0.1.0] - Pre-production

Initial development version (not production-ready)

---

[1.0.0]: https://github.com/AlexeyPevz/Samokoder/compare/v0.1.0...v1.0.0
[0.1.0]: https://github.com/AlexeyPevz/Samokoder/releases/tag/v0.1.0
