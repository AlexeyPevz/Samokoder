# Детальные находки (Фаза 4)

Нотация: [СЕРЬЁЗНОСТЬ] Краткое название — файл:строки — описание → рекомендация.

## Безопасность
- [Critical] Доступ к docker.sock (даже ro) — `docker-compose.yml:39,92`: повышенный риск RCE/контейнерного побега. → Изолировать executor в rootless среде (Sysbox/K8s), убрать сокет; если необходимо — sidecar REST proxy с RBAC.
- [High] Превью запускает произвольные dev-команды — `api/routers/preview.py:33-48` и `core/proc/process_manager.py:214-291`: хотя есть таймаут и управление процессами, нет ограничений ресурсов/сетей/whitelist команд. → Запускать превью в контейнере с `network=none`, cgroup‑ограничения, явный allow‑list сценариев (npm run dev/preview), аудит путей.
- [Medium] httpx без явных таймаутов — `core/telemetry/__init__.py:349-351`, `api/routers/auth.py:387`, `core/agents/external_docs.py:74,139,387-389`: rely на transport retries, но нет timeouts. → Задать `timeout=httpx.Timeout(connect=5, read=30, write=30, pool=5)`.
- [Medium] CSP допускает `'unsafe-inline'/'unsafe-eval'` — `core/api/middleware/security_headers.py:21-31`: нужно смягчение для dev, ужесточение для prod. → Для prod убрать inline/eval; использовать nonce/hashed scripts.
- [Medium] WS аутентификация по query‑token — `api/routers/workspace.py:19-41`: токен в URL/логах. → Перейти на header/cookie или короткоживущие одноразовые WS‑токены.
- [Low] Телеметрия phone‑home без таймаута — `core/telemetry/__init__.py:349-351`: риск зависания. → Добавить таймаут и флаг отключения по умолчанию в self‑hosted.

## Производительность
- [High] ProjectState JSONB — крупные записи, риск медленных запросов — см. `docs/architecture.md:285-293`. → Довести нормализацию (миграции `20251007_normalize_project_state.py`) до использования в коде; ввести eager loading/partial fetch.
- [High] N+1 при загрузке файлов — `docs/architecture.md:290-293`, модели `core/db/models/file*.py`. → Добавить `selectinload/joinedload`, индексы уже есть в миграции `20251006_add_performance_indexes.py`.
- [Medium] Отсутствуют явные timeouts при внешних HTTP — см. секцию безопасности. → Ввести глобальные константы таймаутов и retry‑политику (tenacity/HTTPTransport retries присутствуют частично).
- [Medium] Процессы превью — неиспользование контейнеров → contention на хосте. → Контейнеризация превью/ограничения CPU/mem.

## Надёжность
- [Medium] Очистка контейнеров раз в час — `api/main.py:41-69`: есть риск накопления, если labels/creation_timestamp отсутствуют. → Добавить TTL‑labels и fallback‑GC по именованию, метрики orphaned‑containers.
- [Medium] Телеметрия отправки без timeouts/блокировок — см. выше. → Асинхронные fire‑and‑forget с ограничением времени, circuit breaker.
- [Low] В `ProcessManager.run_command` таймаут максимум 300с, но нет эксплицитной метрики отказов. → Инкремент счётчиков отказов/таймаутов, логирование контекста.

## DevEx/DevOps
- [High] Инструменты аудита недоступны в среде (cloc/pip‑audit/eslint/depcruise/dot). → В CI это покрыто; для локального аудита добавить make‑цели и dev‑container.
- [Medium] CSP dev/prod различия не разведены. → Переменные окружения или отдельный профиль.
- [Low] Нет .editorconfig и унификации форматирования фронта (присутствует eslint, но не автоформат). → Добавить Prettier/EditorConfig.

## Стоимость
- [Medium] LLM запросы без кэша — `docs/architecture.md:946-947` рекомендует кэш. → Ввести кэш ответов по (prompt/model/settings) для детерминированных участков.
- [Low] Нет лимитов на размер workspace — риск роста диска. → Политика ретенции/квоты, очистка старых превью и артефактов.
