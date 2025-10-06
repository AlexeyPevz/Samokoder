# Доменная Модель Samokoder

**Дата**: 6 октября 2025

---

## Bounded Contexts

### 1. User Management Context

**Сущности**:
- **User** — пользователь платформы
  - Атрибуты: `id`, `email`, `password_hash`, `api_keys` (encrypted JSONB)
  - Инварианты:
    - Email уникален
    - Password хешируется bcrypt (cost=12)
    - API keys зашифрованы Fernet (APP_SECRET_KEY)

**Команды**:
- `RegisterUser(email, password)` — регистрация нового пользователя
- `AuthenticateUser(email, password)` → JWT token
- `StoreAPIKey(user_id, provider, api_key)` — сохранение encrypted key (BYOK)
- `RevokeAPIKey(user_id, provider)` — удаление ключа

**События**:
- `UserRegistered(user_id, email)`
- `UserAuthenticated(user_id, timestamp)`
- `APIKeyStored(user_id, provider)`

---

### 2. Project Management Context

**Сущности**:
- **Project** — проект для генерации
  - Атрибуты: `id`, `user_id`, `name`, `description`, `folder_name`, `created_at`
  - Инварианты:
    - Project принадлежит одному User
    - folder_name генерируется из name (slugify)

- **Branch** — ветка проекта (git-like)
  - Атрибуты: `id`, `project_id`, `name` (default: "main")
  - Инварианты:
    - Branch принадлежит одному Project
    - name уникален в пределах project_id

- **ProjectState** — снапшот состояния генерации
  - Атрибуты: `id`, `branch_id`, `step_index`, `data` (JSONB)
  - Инварианты:
    - Каждый step имеет уникальный ProjectState
    - `data` содержит: iterations, steps, tasks, files, epics

**Команды**:
- `CreateProject(user_id, name, description)` → project_id
- `StartGeneration(project_id)` → enqueue ARQ task
- `UpdateProjectState(branch_id, step_index, data)` — сохранение прогресса
- `DeleteProject(project_id)` — cascade delete (branches, states, files)

**События**:
- `ProjectCreated(project_id, user_id)`
- `GenerationStarted(project_id)`
- `GenerationStepCompleted(project_id, step_index)`
- `GenerationCompleted(project_id)`
- `GenerationFailed(project_id, error)`

---

### 3. Code Generation Context (Core Domain)

**Агрегаты**:
- **Generation Pipeline** — основной процесс генерации
  - Stages:
    1. **Specification** (SpecWriter) → requirements analysis
    2. **Architecture** (Architect) → tech stack, structure
    3. **Task Breakdown** (TechLead) → decomposition
    4. **Development** (Developer/CodeMonkey) → parallel code gen
    5. **Execution** (Executor) → Docker container testing
    6. **Debugging** (BugHunter/Troubleshooter) → error fixing

**Value Objects**:
- **Iteration** — итерация разработки
  - Атрибуты: `description`, `user_stories`, `status`
  - Status: `pending`, `in_progress`, `completed`, `failed`

- **Step** — шаг в рамках итерации
  - Атрибуты: `type`, `content`, `related_files`
  - Type: `command`, `save_file`, `human_intervention`

- **Task** — декомпозированная задача
  - Атрибуты: `description`, `instructions`, `files`, `status`
  - Status: `pending`, `in_progress`, `done`

**Команды**:
- `GenerateSpecification(project_id, user_input)` → Specification
- `DesignArchitecture(specification)` → Architecture
- `BreakdownTasks(architecture)` → list[Task]
- `GenerateCode(task)` → list[File]
- `ExecuteCommand(command, container)` → ExecutionResult
- `DebugError(error, context)` → Fix

**События**:
- `SpecificationGenerated(project_id, spec)`
- `ArchitectureDesigned(project_id, architecture)`
- `TasksCreated(project_id, tasks[])`
- `CodeGenerated(project_id, files[])`
- `CommandExecuted(project_id, command, result)`
- `ErrorDetected(project_id, error)`
- `ErrorFixed(project_id, fix)`

---

### 4. LLM Integration Context

**Сущности**:
- **LLMRequest** — запрос к LLM
  - Атрибуты: `id`, `project_id`, `provider`, `model`, `prompt`, `response`, `prompt_tokens`, `completion_tokens`, `cost`, `latency_ms`, `status`, `created_at`
  - Status: `success`, `error`, `rate_limited`

- **Conversation** — контекст диалога с LLM
  - Атрибуты: `messages[]`, `temperature`, `max_tokens`

**Value Objects**:
- **ProviderConfig** — конфигурация провайдера
  - Атрибуты: `api_key`, `base_url`, `timeout`, `model`
  - Providers: OpenAI, Anthropic, Groq

**Команды**:
- `SendLLMRequest(conversation, provider, model)` → response
- `StreamLLMResponse(conversation)` → async stream
- `ParallelLLMRequests(conversations[])` → responses[]
- `RecordTokenUsage(user_id, model, tokens, cost)`

**События**:
- `LLMRequestSent(request_id, provider, model)`
- `LLMResponseReceived(request_id, tokens, latency_ms)`
- `LLMError(request_id, error_type, message)`
- `RateLimitHit(provider, retry_after)`

---

### 5. File Management Context

**Сущности**:
- **File** — файл проекта
  - Атрибуты: `id`, `project_id`, `path`, `content_id`, `created_at`, `updated_at`
  - Инварианты:
    - (project_id, path) уникальны
    - path относительный внутри workspace

- **FileContent** — содержимое файла
  - Атрибуты: `id`, `content` (TEXT)
  - Инварианты:
    - Content immutable (new version = new row)

**Команды**:
- `SaveFile(project_id, path, content)` → file_id
- `ReadFile(project_id, path)` → content
- `ListFiles(project_id)` → list[File]
- `DeleteFile(project_id, path)`

**События**:
- `FileCreated(project_id, path)`
- `FileUpdated(project_id, path, old_content_id, new_content_id)`
- `FileDeleted(project_id, path)`

---

### 6. Execution Context

**Сущности**:
- **ExecutionLog** — лог выполнения команды
  - Атрибуты: `id`, `project_id`, `command`, `stdout`, `stderr`, `exit_code`, `created_at`

- **Container** — Docker контейнер для изолированного выполнения
  - Атрибуты: `id`, `image`, `labels`, `status`
  - Labels: `managed-by=samokoder`, `project_id`, `creation_timestamp`

**Команды**:
- `CreateContainer(project_id, workspace_path)` → container
- `ExecuteCommand(container, command, timeout)` → ExecutionLog
- `StopContainer(container_id)`
- `CleanupOrphanedContainers(max_age)` — background task

**События**:
- `ContainerCreated(container_id, project_id)`
- `CommandExecuted(container_id, command, exit_code)`
- `CommandTimeout(container_id, command, duration)`
- `ContainerStopped(container_id)`

---

## Инварианты (Бизнес-Правила)

### User Context
1. Email уникален в системе
2. Password минимум 8 символов (enforced на UI)
3. API keys хранятся только в зашифрованном виде
4. JWT tokens истекают через 7 дней (configurable)

### Project Context
5. Project принадлежит одному User (multi-tenant isolation)
6. folder_name генерируется автоматически, не редактируется пользователем
7. Удаление Project каскадно удаляет все связанные данные (branches, states, files)
8. ProjectState immutable (новый step = новая запись)

### Code Generation Context
9. Generation pipeline выполняется последовательно (spec → arch → tasks → code → exec)
10. Parallel agents (CodeMonkey) работают только на независимых файлах
11. BugHunter активируется только при ошибках (exit_code != 0)
12. Максимум 3 попытки fixing одной ошибки (hardcoded)

### LLM Context
13. Rate limiting: auth=5 req/min, projects=10/day, llm=50/hour
14. LLM retries: max 3 попытки при network errors
15. Token tracking обязателен для cost monitoring
16. User API keys приоритетнее system keys

### File Context
17. File paths относительные (no absolute paths)
18. Path traversal запрещен (должна быть валидация, но не полностью реализована)
19. FileContent immutable (history preservation)

### Execution Context
20. Containers изолированы (network=none по умолчанию — не реализовано)
21. Containers cleanup через 24 часа после создания
22. Command timeout: 300 seconds (configurable)

---

## Агрегаты и Границы

### Агрегат: Project
- **Root**: Project
- **Entities**: Branch, ProjectState, File, FileContent
- **Consistency**: Сильная (single transaction для создания/удаления)
- **Access**: Только через Project root

### Агрегат: Generation Pipeline
- **Root**: ProjectState (current step)
- **Value Objects**: Iteration, Step, Task
- **Consistency**: Eventual (async worker)
- **Access**: Через Orchestrator agent

### Агрегат: User
- **Root**: User
- **Value Objects**: APIKey (в JSONB)
- **Consistency**: Сильная (single transaction)
- **Access**: Через User service

---

## События и Интеграция

### Event Sourcing (Partial)
- `LLMRequest` хранится как event log (append-only)
- `ExecutionLog` хранится как event log
- `ProjectState` — snapshots (не полный event sourcing)

### Асинхронная Обработка
- **Queue**: Redis (ARQ)
- **Tasks**:
  - `run_generation_task(project_id, user_id)` — long-running (5-60 min)
  - `cleanup_orphaned_containers()` — periodic (hourly)

### WebSocket Updates (Planned, не полностью реализовано)
- Frontend подписывается на updates по project_id
- Backend отправляет:
  - `ProjectStateUpdated(step_index, progress)`
  - `StepCompleted(step_index)`
  - `GenerationCompleted()`

---

## Bounded Context Map

```
┌──────────────────┐
│  User Management │
└────────┬─────────┘
         │ provides
         ▼
┌──────────────────┐      triggers      ┌──────────────────┐
│Project Management├──────────────────>│ Code Generation  │
└────────┬─────────┘                    └────────┬─────────┘
         │ uses                                  │ uses
         ▼                                       ▼
┌──────────────────┐                    ┌──────────────────┐
│File Management   │                    │ LLM Integration  │
└──────────────────┘                    └──────────────────┘
                                                 │ uses
                                                 ▼
                                        ┌──────────────────┐
                                        │ Execution        │
                                        └──────────────────┘
```

**Relationships**:
- **User Management** → **Project Management**: User owns Projects (1:N)
- **Project Management** → **Code Generation**: Project triggers generation pipeline (1:1 per run)
- **Code Generation** → **LLM Integration**: Agents call LLM (N:M)
- **Code Generation** → **Execution**: Agents execute commands in containers (N:M)
- **Code Generation** → **File Management**: Agents create/update files (N:M)

---

## Anti-Corruption Layers

### LLM Providers ACL
- **Interface**: `BaseLLMClient`
- **Implementations**: OpenAIClient, AnthropicClient, GroqClient
- **Purpose**: Изолировать доменную логику от provider-specific APIs

### Docker ACL
- **Interface**: `ProcessManager`
- **Purpose**: Абстракция над Docker API, потенциальная замена на Kubernetes

### File System ACL
- **Interface**: `FileSystemInterface` (VFS)
- **Implementations**: LocalFileSystem, (planned: S3FileSystem)
- **Purpose**: Переход на object storage для scalability

---

## Выводы

**Сильные стороны**:
- ✅ Чёткое разделение bounded contexts
- ✅ Event log для LLM requests (observability)
- ✅ Multi-tenant isolation (user_id FK)
- ✅ BYOK реализован (encrypted API keys)

**Улучшения**:
- ⚠️ Нет полного Event Sourcing (только partial)
- ⚠️ ProjectState.data (JSONB) — анемичная модель (нарушает DDD)
- ⚠️ Слабая типизация domain events (нет enum/classes)
- ⚠️ Отсутствие CQRS (read/write не разделены)

**Рекомендации для 10k users/mo**:
1. Нормализовать ProjectState (вынести iterations, steps, tasks в отдельные таблицы)
2. Реализовать полный Event Sourcing для Generation Pipeline
3. Добавить Read Models (CQRS) для быстрых queries
4. Реализовать Saga pattern для long-running generation tasks

