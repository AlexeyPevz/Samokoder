# Архитектура Samokoder

**Дата аудита**: 6 октября 2025  
**Версия**: 1.2.5  
**Аудитор**: Senior Software Architect

---

## 1. Обзор Системы

**Samokoder** — SaaS платформа для генерации full-stack приложений из текстового описания с использованием мульти-агентной AI системы.

### Ключевые Характеристики

- **Тип**: Monorepo (Backend + Frontend + Worker)
- **Backend**: Python 3.12+, FastAPI, async/await
- **Frontend**: React 18, TypeScript, Vite, Radix UI
- **AI**: Multi-agent system (15+ agents), LLM orchestration (OpenAI, Anthropic, Groq)
- **БД**: PostgreSQL 15, Redis 7
- **Deployment**: Docker Compose, Traefik reverse proxy
- **Monitoring**: Prometheus + Grafana + AlertManager

---

## 2. Архитектурные Слои

```
┌─────────────────────────────────────────────────────────────┐
│                      Frontend (React/TS)                     │
│  - UI Components (Radix UI)                                  │
│  - State Management (React Query)                            │
│  - WebSocket/IPC для real-time updates                       │
└──────────────────────┬──────────────────────────────────────┘
                       │ HTTP/WS
┌──────────────────────┴──────────────────────────────────────┐
│                   API Layer (FastAPI)                        │
│  - REST API (v1)                                             │
│  - Auth (JWT)                                                │
│  - Rate Limiting (SlowAPI + Redis)                           │
│  - Metrics (Prometheus)                                      │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────┴──────────────────────────────────────┐
│              Business Logic (Core)                           │
│  ┌────────────────────────────────────────────────────┐    │
│  │  AI Agents Orchestration                            │    │
│  │  - Orchestrator (main coordinator)                  │    │
│  │  - SpecWriter → Architect → TechLead               │    │
│  │  - Developer/CodeMonkey (parallel)                  │    │
│  │  - Executor (Docker isolation)                      │    │
│  │  - BugHunter/Troubleshooter (error handling)       │    │
│  └────────────────────────────────────────────────────┘    │
│  ┌────────────────────────────────────────────────────┐    │
│  │  LLM Abstraction Layer                              │    │
│  │  - OpenAI, Anthropic, Groq clients                  │    │
│  │  - Streaming, retries, token tracking               │    │
│  │  - Parallel execution utilities                     │    │
│  └────────────────────────────────────────────────────┘    │
│  ┌────────────────────────────────────────────────────┐    │
│  │  State Management                                   │    │
│  │  - Project state (iterations, steps, tasks)        │    │
│  │  - File system abstraction                          │    │
│  │  - Database persistence                             │    │
│  └────────────────────────────────────────────────────┘    │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────┴──────────────────────────────────────┐
│          Background Worker (ARQ)                             │
│  - Асинхронная генерация проектов                           │
│  - Long-running tasks (LLM requests, Docker exec)            │
│  - Redis job queue                                           │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────┴──────────────────────────────────────┐
│              Data Layer                                      │
│  - PostgreSQL (projects, users, llm_requests, files)         │
│  - Redis (sessions, cache, rate limits, job queue)           │
│  - File System (workspace: generated projects)               │
│  - Docker (isolated execution containers)                    │
└──────────────────────────────────────────────────────────────┘
```

---

## 3. Модули и Зависимости

### 3.1 Backend Modules

#### `samokoder/core/` (24 модуля)

**Agents** (15+ агентов):
- `orchestrator.py` (21KB) — главный координатор
- `code_monkey.py` (20KB) — генерация кода (parallel file processing)
- `architect.py` — архитектурные решения
- `tech_lead.py` — декомпозиция задач
- `developer.py` — разработка фичей
- `bug_hunter.py` (18KB) — отладка
- `troubleshooter.py` (17KB) — решение проблем
- `executor.py` — выполнение команд в Docker
- `spec_writer.py`, `frontend.py`, `git.py`, `cicd.py`, и др.

**LLM** (интеграции):
- `base.py` (16KB) — базовый клиент (streaming, retries, token tracking)
- `parallel.py` — параллелизация LLM запросов (5x-15x speedup)
- Провайдеры: OpenAI, Anthropic, Groq

**State Management**:
- `state_manager.py` (17KB) — управление состоянием проекта
- `project_state.py` (18KB) — модель данных (iterations, steps, tasks)

**Database**:
- Models: `User`, `Project`, `ProjectState`, `File`, `FileContent`, `LLMRequest`, `Branch`, `Specification`
- Migrations: Alembic

**Configuration**:
- `config.py` — centralized config (DB, LLM, Redis, secrets)
- `validator.py` — security validation (fail-fast для production secrets)

**Monitoring**:
- `health.py` (16KB), `health_fixed.py` (17KB) — health checks
- Prometheus metrics (HTTP, LLM, DB, business metrics)

**Security**:
- `crypto.py` — encryption/decryption для user API keys (Fernet)
- Rate limiting (SlowAPI)

**Templates**:
- Project templates (Vite+React, Node+Express, и др.)

**UI Abstraction**:
- `ipc_client.py` (18KB) — IPC для взаимодействия с фронтендом
- `console.py`, `virtual.py` — альтернативные UI

#### `samokoder/api/` (6 роутеров)

**Routers**:
- `auth.py` — регистрация/логин (JWT, rate limited: 5 req/min)
- `projects.py` — CRUD проектов (rate limited: 10 req/day)
- `keys.py` — управление API keys (encrypted storage)
- `models.py` — LLM модели
- `workspace.py` — файловые операции
- `preview.py`, `plugins.py`, `analytics.py`, `usage.py`, `user.py`, `gitverse.py`, `notifications.py`

**Middleware**:
- `rate_limiter.py` — SlowAPI + Redis (graceful degradation)
- `metrics.py` — Prometheus instrumentation

#### `samokoder/worker/`

**Background Worker** (ARQ):
- `main.py` — ARQ worker для async project generation
- `ConsoleUI` — dummy UI для worker context
- `run_generation_task` — core async task

### 3.2 Frontend Modules

**Stack**: React 18 + TypeScript + Vite + React Router + React Query

**Структура**:
```
frontend/src/
├── pages/           # Page components (AdminPanel, Dashboard, etc.)
├── components/      # Reusable components
│   ├── ui/          # Radix UI wrappers
│   └── analytics/   # Analytics dashboard
├── api/             # API client (axios)
├── hooks/           # Custom React hooks
├── services/        # Business logic services
├── contexts/        # React contexts
├── utils/           # Utilities
└── styles/          # Global styles
```

**Key Libraries**:
- **UI**: Radix UI (20+ components), Tailwind CSS, Framer Motion
- **State**: React Query (TanStack Query), React Hook Form
- **Networking**: Axios, Socket.io client
- **Utilities**: date-fns, zod (validation), i18next (i18n)
- **Code Editor**: Monaco Editor
- **Terminal**: xterm.js

---

## 4. Входные Точки и Потоки Данных

### 4.1 HTTP Endpoints (API)

**Auth** (`/v1/auth`):
- `POST /register` → User creation
- `POST /login` → JWT token issuance

**Projects** (`/v1/projects`):
- `POST /projects` → Create project → ARQ task → Worker
- `GET /projects` → List user projects
- `GET /projects/{id}` → Get project details
- `PATCH /projects/{id}` → Update project
- `DELETE /projects/{id}` → Delete project

**Keys** (`/v1/keys`):
- `POST /keys` → Store encrypted API key (Fernet)
- `GET /keys` → List user keys

**Workspace** (`/v1/workspace`):
- `GET /workspace/{project_id}/files` → List project files
- `GET /workspace/{project_id}/files/{path}` → Get file content
- `POST /workspace/{project_id}/files` → Create/update file

**Health**:
- `GET /health` → Basic health check
- `GET /health/detailed` → PostgreSQL, Redis, Docker checks

**Metrics**:
- `GET /metrics` → Prometheus metrics (TSDB format)

### 4.2 Background Jobs (ARQ)

**Queue**: Redis-backed ARQ queue

**Tasks**:
1. `run_generation_task(project_id, user_id)`:
   - Load project from DB
   - Decrypt user API keys
   - Initialize StateManager + Orchestrator
   - Run agent pipeline (может занять 5-60 минут)
   - Persist результаты в DB + file system

### 4.3 Data Flows

**Project Generation Flow**:
```
User (Frontend)
  → POST /v1/projects (API)
    → Save to DB (ProjectState)
    → Enqueue ARQ task (Redis)
      → Worker picks up task
        → Load Project + User
        → Decrypt API keys
        → StateManager.load_project()
        → Orchestrator.run()
          → SpecWriter (write spec)
          → Architect (design architecture)
          → TechLead (break into tasks)
          → Developer/CodeMonkey (parallel) (generate code)
          → Executor (run in Docker)
          → BugHunter (if errors)
          → Troubleshooter (fix issues)
        → Commit files to DB + workspace
      → Update ProjectState
    → WebSocket/polling updates to Frontend
```

---

## 5. Критические Пути

### 5.1 Hot Paths

1. **LLM Requests** (самый горячий путь):
   - Frequency: 10-100+ requests per project generation
   - Latency: 1-30s per request (зависит от LLM provider)
   - Cost: $0.01-$5 per project (зависит от complexity)
   - **Optimization**: Parallel execution (5x-15x speedup для multiple files)

2. **Database Queries**:
   - `ProjectState` reads/writes (large JSONB columns, до 18KB)
   - `File` + `FileContent` (N+1 queries риск при загрузке проектов)
   - **Optimization needed**: Добавить eager loading, индексы

3. **Docker Execution**:
   - Каждый `Executor.run()` запускает Docker container
   - Overhead: 500ms-2s per execution
   - Risk: Orphaned containers (cleanup task работает каждый час)

4. **File I/O**:
   - Workspace directory (180+ subdirectories)
   - Read/write generated files
   - Risk: Disk space exhaustion (no limits)

### 5.2 Performance Bottlenecks

1. **Sequential LLM Requests** (частично fixed):
   - ✅ Fixed: `CodeMonkey.describe_files()` теперь параллельно
   - ⚠️ Осталось: многие другие агенты всё ещё sequential

2. **Large JSONB Columns**:
   - `ProjectState` хранит весь state в JSONB
   - Размер: до 100+ KB для больших проектов
   - Impact: Slow DB queries, high memory usage

3. **N+1 Queries**:
   - Loading Project → Files → FileContent (separate queries)
   - Impact: High latency при загрузке больших проектов

4. **Docker Overhead**:
   - Каждая команда запускает новый container
   - Alternative: Reuse containers (not implemented)

---

## 6. Внешние Интеграции

### 6.1 LLM Providers

**OpenAI**:
- Models: GPT-4, GPT-4 Turbo, GPT-3.5 Turbo
- Usage: Primary для code generation
- Cost: High ($$)
- Rate limits: 3,500 TPM (tokens per minute)

**Anthropic**:
- Models: Claude 3 Opus, Sonnet, Haiku
- Usage: Alternative для complex reasoning
- Cost: Medium ($)
- Rate limits: 10,000 TPM

**Groq**:
- Models: Llama 3, Mixtral
- Usage: Fast inference (low latency)
- Cost: Low ($)
- Rate limits: High

**Configuration**:
- User-provided API keys (encrypted в DB)
- Fallback to system keys (если user keys отсутствуют)

### 6.2 Infrastructure Services

**PostgreSQL**:
- Version: 15-alpine
- Connection: asyncpg (async driver)
- Pool size: default (нет явного limit)
- Backups: pg_dump каждые 6 часов

**Redis**:
- Version: 7-alpine
- Usage:
  - Session storage
  - Rate limiting counters
  - ARQ job queue
  - Cache (not heavily used)

**Docker**:
- Access: `/var/run/docker.sock` mounted в containers
- Security risk: Full Docker access (RCE potential)
- Mitigation: Cleanup task (каждый час), labels (`managed-by=samokoder`)

**Traefik**:
- Reverse proxy + SSL termination
- Labels-based routing
- Let's Encrypt certificates

**Prometheus + Grafana + AlertManager**:
- Metrics: 20+ custom metrics
- Alerts: 14 rules (Critical, Warning, Info)
- Dashboards: Auto-provisioned
- Notifications: Telegram + Email

---

## 7. Точки Расширения

### 7.1 Plugin System

**Location**: `samokoder/core/plugins/`

**Capabilities**:
- Custom agents
- Custom templates
- Custom LLM providers
- Event hooks

**Status**: Partial implementation (not production-ready)

### 7.2 Template System

**Location**: `samokoder/core/templates/`

**Built-in Templates**:
- `vite_react.py` — Vite + React + TypeScript
- `node_express_mongoose.py` — Node.js + Express + MongoDB
- `react_express.py` — Full-stack React + Express

**Extensibility**:
- Registry pattern (`templates/registry.py`)
- Easy to add new templates

### 7.3 LLM Provider Abstraction

**Location**: `samokoder/core/llm/base.py`

**Interface**: `BaseLLMClient`
- `_init_client()` — provider-specific init
- `_make_request()` — streaming request
- `_record_token_usage()` — usage tracking

**Adding New Provider**:
1. Subclass `BaseLLMClient`
2. Implement `_init_client()` и `_make_request()`
3. Register в `config.py`

---

## 8. Security Model

### 8.1 Authentication

**Method**: JWT (JSON Web Tokens)
- Secret: `SECRET_KEY` (env var, validated)
- Expiry: configurable (default: 7 days)
- Refresh tokens: not implemented

**Password Storage**:
- Hashing: bcrypt (via `passlib`)
- Rounds: default (cost=12)

### 8.2 API Key Storage

**Encryption**: Fernet (symmetric)
- Key: `APP_SECRET_KEY` (env var, validated)
- Storage: `User.api_keys` (JSONB, encrypted)
- Decryption: On-the-fly при генерации проектов

### 8.3 Rate Limiting

**Implementation**: SlowAPI + Redis
- Auth endpoints: 5 req/min
- Projects: 10 req/day (create), 50 req/hour (list)
- LLM proxy: 50 req/hour
- Graceful degradation: memory fallback если Redis down

### 8.4 Input Validation

**Method**: Pydantic models (FastAPI integration)
- Type checking
- Range validation
- String patterns (regex)

**Gaps**:
- ⚠️ No validation для user-provided prompts (LLM injection risk)
- ⚠️ No validation для file paths (path traversal risk)

### 8.5 Docker Isolation

**Current**: Containers имеют доступ к Docker socket
- Risk: RCE (container escape → host access)
- Mitigation: Cleanup task, labels

**Pending**: Sysbox runtime (rootless containers)

---

## 9. Database Schema

### 9.1 Tables

**Users**:
```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR UNIQUE NOT NULL,
    password_hash VARCHAR NOT NULL,
    api_keys JSONB,  -- encrypted {provider: {encrypted_key, ...}}
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP
);
```

**Projects**:
```sql
CREATE TABLE projects (
    id UUID PRIMARY KEY,
    user_id INT REFERENCES users(id),
    name VARCHAR NOT NULL,
    description TEXT,
    status VARCHAR,  -- 'pending', 'in_progress', 'completed', 'failed'
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP
);
```

**ProjectState**:
```sql
CREATE TABLE project_states (
    id SERIAL PRIMARY KEY,
    project_id UUID REFERENCES projects(id) UNIQUE,
    data JSONB NOT NULL,  -- full state: iterations, steps, tasks, files
    step_index INT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP
);
```
⚠️ **Риск**: `data` может быть очень большим (100+ KB), медленные queries.

**Files**:
```sql
CREATE TABLE files (
    id SERIAL PRIMARY KEY,
    project_id UUID REFERENCES projects(id),
    path VARCHAR NOT NULL,
    content_id INT REFERENCES file_contents(id),
    created_at TIMESTAMP,
    updated_at TIMESTAMP,
    UNIQUE(project_id, path)
);
```

**FileContents**:
```sql
CREATE TABLE file_contents (
    id SERIAL PRIMARY KEY,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);
```
⚠️ **Риск**: N+1 queries при загрузке project files.

**LLMRequests**:
```sql
CREATE TABLE llm_requests (
    id SERIAL PRIMARY KEY,
    project_id UUID REFERENCES projects(id),
    provider VARCHAR NOT NULL,
    model VARCHAR NOT NULL,
    prompt TEXT,
    response TEXT,
    prompt_tokens INT,
    completion_tokens INT,
    cost NUMERIC(10, 6),
    latency_ms INT,
    status VARCHAR,  -- 'success', 'error', 'rate_limited'
    created_at TIMESTAMP DEFAULT NOW()
);
```
✅ Полезно для аналитики, cost tracking, debugging.

**Branches** (Git integration):
```sql
CREATE TABLE branches (
    id SERIAL PRIMARY KEY,
    project_id UUID REFERENCES projects(id),
    name VARCHAR NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);
```

### 9.2 Indexes

**Current**:
- Primary keys (auto)
- `users.email` (UNIQUE)
- `files.(project_id, path)` (UNIQUE)

**Missing** (⚠️ Performance):
- `projects.user_id` — для списка проектов пользователя
- `llm_requests.project_id` — для аналитики по проекту
- `llm_requests.created_at` — для time-series queries
- `files.project_id` — для загрузки всех файлов проекта

---

## 10. Concurrency и Async

### 10.1 Async/Await

**FastAPI**: Полностью async (uvicorn ASGI server)
- DB: `asyncpg` (async PostgreSQL driver)
- HTTP: `httpx` (async HTTP client)
- LLM: async clients (OpenAI, Anthropic)

**Worker**: ARQ (async job queue)
- Redis: `arq` library (async)

### 10.2 Parallelism

**LLM Parallel Execution** (✅ Implemented):
- `core/llm/parallel.py`
- `gather_llm_requests()` — parallel LLM calls с rate limiting
- Usage: `CodeMonkey.describe_files()` (5x-15x speedup)

**Agent Parallelism** (✅ Partial):
- `Orchestrator` может запускать несколько агентов параллельно:
```python
if isinstance(agent, list):
    tasks = [single_agent.run() for single_agent in agent]
    responses = await asyncio.gather(*tasks)
```
- Usage: Multiple `CodeMonkey` agents для different files

**Database** (⚠️ Sequential):
- Большинство DB queries sequential
- Opportunity: Batch loading (eager loading)

### 10.3 Race Conditions

**Potential Risks**:
1. **Concurrent project updates**:
   - Scenario: Multiple agents updating same `ProjectState`
   - Mitigation: ❌ None (последний writer wins)
   - Fix needed: Optimistic locking (version column)

2. **File conflicts**:
   - Scenario: Multiple workers updating same file
   - Mitigation: ❌ None
   - Fix needed: File locking mechanism

3. **Rate limit counters**:
   - Scenario: Race в Redis INCR
   - Mitigation: ✅ Redis atomic operations

---

## 11. Deployment Architecture

### 11.1 Docker Compose Services

```yaml
services:
  frontend:    # React app (nginx)
  api:         # FastAPI backend (uvicorn)
  worker:      # ARQ background worker
  db:          # PostgreSQL 15
  redis:       # Redis 7
  prometheus:  # Metrics TSDB
  grafana:     # Dashboards
  alertmanager:# Alerting
  postgres_exporter:   # DB metrics
  redis_exporter:      # Redis metrics
  cadvisor:    # Docker container metrics
```

### 11.2 Networking

**External**:
- Traefik (`web` network) → `frontend`, `api`
- SSL/TLS termination (Let's Encrypt)

**Internal**:
- `samokoder` network (bridge)
- Services communicate по service names (Docker DNS)

### 11.3 Volumes

```yaml
volumes:
  postgres_data:  # PostgreSQL data (persistent)
  redis_data:     # Redis AOF (persistent)
  workspace:      # Generated projects (host-mounted)
```

### 11.4 Scalability

**Current**: Single-host deployment
- All services на одном сервере
- No horizontal scaling

**Bottlenecks**:
1. **Worker**: Single worker instance
   - Fix: Multiple worker instances (ARQ supports это)
2. **Database**: Single PostgreSQL instance
   - Fix: Read replicas (async replication)
3. **Redis**: Single Redis instance
   - Fix: Redis Sentinel (HA) or Cluster
4. **File System**: Shared workspace directory
   - Fix: S3/object storage для generated projects

---

## 12. Observability

### 12.1 Logging

**Implementation**: Python `logging` module
- Handler: Console (stdout)
- Format: `%(asctime)s - %(name)s - %(levelname)s - %(message)s`
- Level: configurable (env var `LOG_LEVEL`)

**Gaps**:
- ⚠️ No structured logging (JSON format)
- ⚠️ No log aggregation (ELK/Loki)
- ⚠️ No correlation IDs (tracing requests)

### 12.2 Metrics (Prometheus)

**Instrumentation**: `prometheus-fastapi-instrumentator` + custom metrics

**HTTP Metrics**:
- `http_requests_total` (counter) — requests by method/endpoint/status
- `http_request_duration_seconds` (histogram) — latency (p50, p95, p99)
- `http_requests_in_progress` (gauge) — concurrent requests

**Business Metrics**:
- `projects_created_total` (counter)
- `projects_completed_total` (counter)
- `llm_requests_total` (counter) — by provider/model/status
- `llm_tokens_total` (counter) — prompt + completion tokens
- `llm_cost_total` (counter) — estimated cost (USD)
- `rate_limit_hits_total` (counter) — rate limit violations

**Database Metrics** (via exporters):
- PostgreSQL: connections, query latency, cache hits, transactions
- Redis: commands/sec, memory usage, keyspace, slow log

**System Metrics** (via cAdvisor):
- CPU, memory, disk, network per container

### 12.3 Tracing

**Status**: ❌ Not implemented
- No distributed tracing (Jaeger/Zipkin/Tempo)
- No correlation IDs between services

**Impact**: Difficult to debug complex workflows (multi-agent pipelines).

### 12.4 Alerting (AlertManager)

**14 Alert Rules**:

**Critical**:
- `APIDown` — API not responding (>5 min)
- `LowDiskSpace` — <10% free disk space

**Warning**:
- `HighErrorRate` — >5% 5xx errors
- `HighLatency` — p95 >2s
- `LLMHighErrorRate` — >10% LLM failures
- `LLMHighCost` — >$100/hour
- `DatabaseConnectionHigh` — >80% connections used

**Info**:
- `RateLimitHits` — rate limit активируется
- `NoProjects` — no projects created в последний час
- `AuthenticationSpike` — >100 login attempts/hour

**Notifications**:
- Telegram bot (critical + warning)
- Email (critical only)

---

## 13. Security Posture

### 13.1 Strengths ✅

1. **Secret Validation**: Production fail-fast для дефолтных keys
2. **Rate Limiting**: DoS protection (SlowAPI + Redis)
3. **Encrypted Storage**: User API keys зашифрованы (Fernet)
4. **CI Security Scans**: Bandit, Safety, Trivy в GitHub Actions
5. **Backups**: Automated PostgreSQL backups (каждые 6 часов)
6. **HTTPS**: Traefik + Let's Encrypt
7. **CORS**: Configured origins

### 13.2 Vulnerabilities ⚠️

1. **Docker Socket Access** (HIGH):
   - Risk: RCE, container escape
   - Impact: Full host compromise
   - Mitigation: ❌ Pending (Sysbox runtime)

2. **LLM Prompt Injection** (MEDIUM):
   - Risk: User-provided prompts → malicious LLM output
   - Impact: Генерация вредоносного кода
   - Mitigation: ❌ None (no input sanitization)

3. **Path Traversal** (MEDIUM):
   - Risk: `workspace/{path}` endpoints могут принимать `../../etc/passwd`
   - Impact: Read arbitrary files
   - Mitigation: ⚠️ Partial (needs validation)

4. **No Request Size Limits** (LOW):
   - Risk: Large payloads → DoS (memory exhaustion)
   - Impact: API unavailability
   - Mitigation: ❌ None (FastAPI default is unlimited)

5. **No CSRF Protection** (LOW):
   - Risk: Cross-site request forgery
   - Impact: Unauthorized actions
   - Mitigation: ❌ None (SPA assumes CORS is enough)

6. **Weak JWT Expiry** (LOW):
   - Risk: Long-lived tokens (7 days default)
   - Impact: Increased window для token theft
   - Mitigation: ⚠️ Configurable (но no refresh tokens)

---

## 14. Technical Debt

### 14.1 Code Quality

**Strengths**:
- ✅ Type hints (Python) — coverage ~80%
- ✅ Linting (Ruff) — enforced в CI
- ✅ Tests — 85%+ coverage
- ✅ Pre-commit hooks

**Debt**:
1. **Duplicated Models** (HIGH):
   - `project.py`, `project_optimized.py`, `project_fixed.py` [[memory:4431334]]
   - Impact: Confusion, maintenance burden
   - Fix: Consolidate to single model

2. **Large Files** (MEDIUM):
   - `orchestrator.py` (21KB, 600+ lines)
   - `code_monkey.py` (20KB, 580+ lines)
   - `ui/ipc_client.py` (18KB, 570+ lines)
   - Impact: Hard to navigate, test, refactor
   - Fix: Split into smaller modules

3. **Complex Functions** (MEDIUM):
   - `Orchestrator.run()` — main loop, high cyclomatic complexity
   - Impact: Hard to test, maintain
   - Fix: Extract sub-methods

4. **Magic Numbers** (LOW):
   - Rate limits hardcoded в routers
   - Impact: Hard to configure
   - Fix: Move to config

### 14.2 Architecture Debt

1. **Monolithic Worker** (HIGH):
   - Single long-running task (`run_generation_task`)
   - Impact: No parallelism, resource contention
   - Fix: Break into smaller tasks (spec → architecture → code → test)

2. **Large JSONB Columns** (HIGH):
   - `ProjectState.data` хранит весь state (100+ KB)
   - Impact: Slow queries, high memory
   - Fix: Normalize (separate tables для iterations/steps/tasks)

3. **N+1 Queries** (MEDIUM):
   - Loading projects → files → contents
   - Impact: High latency
   - Fix: Eager loading, joins

4. **No Caching** (MEDIUM):
   - Redis используется минимально
   - Impact: Повторные DB queries
   - Fix: Cache project metadata, LLM responses (idempotent)

5. **Tight Coupling** (LOW):
   - Agents зависят от `StateManager` (сложно тестировать)
   - Impact: Low testability
   - Fix: Dependency injection, interfaces

### 14.3 Documentation Debt

**Strengths**:
- ✅ README (530+ lines, comprehensive)
- ✅ Audit report (500+ lines)
- ✅ Monitoring docs (600+ lines)
- ✅ Runbooks (disaster recovery, monitoring ops)

**Gaps**:
- ⚠️ No API documentation (OpenAPI spec не детальная)
- ⚠️ No architecture diagrams (C4 model)
- ⚠️ No agent interaction diagrams (sequence diagrams)
- ⚠️ No onboarding guide (new developer setup)

---

## 15. Dependencies Analysis

### 15.1 Backend (Python)

**Production** (44 packages):
```
fastapi, uvicorn, pydantic, pydantic-settings
sqlalchemy, asyncpg, aiosqlite, alembic
redis, arq
openai, anthropic, groq, tiktoken
jinja2, prompt-toolkit, jsonref
docker, psutil, httpx
python-jose, passlib, bcrypt
slowapi, prometheus-client, prometheus-fastapi-instrumentator
tenacity, python-dotenv
```

**Key Observations**:
- ✅ Modern async stack (FastAPI, asyncpg, httpx)
- ✅ Multiple LLM providers (flexibility)
- ⚠️ No pinned versions в `pyproject.toml` (только `^x.y.z`)
  - Risk: Breaking changes в minor updates
  - Fix: Lock versions в production

**Vulnerabilities**: Check via `safety check` в CI

### 15.2 Frontend (React)

**Production** (60+ packages):
```
react, react-dom, react-router-dom
@tanstack/react-query
axios, socket.io-client
@radix-ui/react-* (20+ components)
tailwindcss, framer-motion
@monaco-editor/react
@xterm/xterm
i18next, react-i18next
zod, react-hook-form
date-fns, recharts
```

**Key Observations**:
- ✅ Modern React stack (hooks, functional components)
- ✅ Comprehensive UI library (Radix UI)
- ✅ Type-safe forms (zod + react-hook-form)
- ⚠️ Large bundle size risk (60+ dependencies)
  - Fix: Code splitting, lazy loading
- ⚠️ No version pinning (same as backend)

**Bundle Size**: Not measured (need `npm run build` + analyzer)

---

## 16. Recommendations Summary

### Immediate (1-2 недели)

1. **Consolidate Duplicate Models** [[memory:4431334], [memory:4215592]]
   - Удалить `project_optimized.py`, `project_fixed.py`
   - Migrate to single `project.py`

2. **Add Database Indexes** (perf)
   - `projects.user_id`, `llm_requests.project_id`, `files.project_id`

3. **Input Validation** (security)
   - File path validation (whitelist workspace directory)
   - Request size limits (FastAPI middleware)

4. **Logging Improvements** (observability)
   - Structured logging (JSON format)
   - Correlation IDs (request tracing)

### Medium Term (1-2 месяца)

5. **Normalize ProjectState** (architecture)
   - Split JSONB column → separate tables
   - Reduce query latency, improve maintainability

6. **Worker Task Decomposition** (scalability)
   - Break `run_generation_task` → smaller tasks
   - Enable parallel worker scaling

7. **Caching Layer** (performance)
   - Redis cache для project metadata, LLM responses

8. **Docker Isolation** (security)
   - Implement Sysbox runtime (pending task)

### Long Term (3-6 месяцев)

9. **Distributed Tracing** (observability)
   - Jaeger/Tempo integration
   - Correlation IDs across services

10. **Horizontal Scaling** (scalability)
    - Multiple worker instances
    - PostgreSQL read replicas
    - Redis Sentinel/Cluster
    - S3 for file storage

11. **Advanced Security** (defense-in-depth)
    - Web Application Firewall (WAF)
    - DDoS mitigation (Cloudflare)
    - Intrusion detection (Falco)

---

## Выводы

**Сильные стороны**:
- ✅ Solid modern stack (FastAPI, React, async/await)
- ✅ Comprehensive monitoring (Prometheus + Grafana + AlertManager)
- ✅ Production-ready infrastructure (Docker, Traefik, backups)
- ✅ Security basics (encryption, rate limiting, validation)
- ✅ Good documentation

**Критические риски**:
- ⚠️ Docker socket access (RCE vulnerability)
- ⚠️ Large JSONB columns (scalability bottleneck)
- ⚠️ Duplicate models (maintenance debt) [[memory:4431334]]

**Готовность**: **85-90% Production Ready**
- Подходит для MVP и early adopters
- Требуется доработка для enterprise scale (10k+ users)


