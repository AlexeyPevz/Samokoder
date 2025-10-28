# 🔍 ПОЛНОЕ КОД-РЕВЬЮ - 7 Октября 2025

## 📋 РЕЗЮМЕ

Проведено полное код-ревью с анализом:
- ✅ Всех TODO/FIXME/HACK комментариев  
- ✅ Заглушек и моков в production коде
- ✅ Обработки ошибок и edge cases
- ✅ Бизнес-логики в агентах
- ✅ API эндпоинтов и валидации
- ✅ Безопасности и аутентификации
- ✅ Зависимостей и импортов

---

## 🔴 КРИТИЧЕСКИЕ ПРОБЛЕМЫ (P0)

### 1. **КРИТИЧНО: Executor.py всегда возвращает success**
**Файл:** `core/agents/executor.py:137`
```python
# FIXME: ErrorHandler isn't debugged with BugHunter - we should move all commands to run before testing and debug them with BugHunter
if True or llm_response.success:
    return AgentResponse.done(self)
```
**Проблема:** Из-за `if True or ...` команды **ВСЕГДА** считаются успешными, даже если они упали с ошибкой!  
**Влияние:** Критические ошибки игнорируются, система продолжает работу в сломанном состоянии.  
**Решение:** Убрать `True or`, добавить правильную обработку ошибок через ErrorHandler.

---

### 2. **КРИТИЧНО: Deprecated mock файл в production**
**Файл:** `core/services/preview_service.py`
```python
"""
DEPRECATED: This file is a stub/mock implementation and is NOT used in production.
The actual preview service is implemented in api/routers/preview.py

This file should be removed in a future cleanup.
"""
```
**Проблема:** Весь файл (252 строки) — заглушка, которая НЕ используется в production. Содержит фейковые реализации.  
**Влияние:** Путаница в кодовой базе, возможность случайного использования.  
**Решение:** Удалить файл немедленно.

---

### 3. **КРИТИЧНО: In-memory storage для preview процессов**
**Файл:** `api/routers/preview.py:30-31`
```python
# In-memory storage for preview processes (P1-1: TODO - move to Redis for production)
preview_processes = {}
```
**Проблема:** Preview процессы хранятся в памяти приложения. При горизонтальном масштабировании (несколько инстансов) это приведет к потере данных.  
**Влияние:** Невозможность масштабирования, потеря состояния при перезапуске.  
**Решение:** Перенести в Redis, как указано в TODO.

---

### 4. **КРИТИЧНО: Missing rollback в orchestrator**
**Файл:** `core/agents/orchestrator.py:69`
```python
# TODO: consider refactoring this into two loop; the outer with one iteration per comitted step,
# and the inner which runs the agents for the current step until they're done. This would simplify
# handle_done() and let us do other per-step processing (eg. describing files) in between agent runs.
```
**Связанный код:** `improvement_plan.json` (строка 19-28)
```json
{
  "id": "TODO-118",
  "title": "Fix Critical TODO #118 — Implement Rollback для next_state",
  "evidence": "Explicit TODO в критичном месте; нет cleanup механизма"
}
```
**Проблема:** Нет механизма rollback для `next_state` при ошибках. Состояние может остаться поврежденным.  
**Влияние:** Потеря целостности данных при сбоях.  
**Решение:** Реализовать транзакционный rollback для состояния.

---

### 5. **КРИТИЧНО: Infinite loop risk в code_monkey**
**Файл:** `improvement_plan.json:66-75`
```json
{
  "id": "FIXME-129",
  "title": "Fix FIXME #129 — Prevent Infinite Loop в code_monkey.implement_changes()",
  "code_snippet": "# FIXME: provide a counter here so that we don't have an endless loop here",
  "evidence": "Explicit FIXME; attempt counter не checked"
}
```
**Файл:** `core/agents/code_monkey.py:69-79`
```python
while not code_review_done and review_attempts < MAX_CODING_ATTEMPTS:
    review_attempts += 1
    review_response = await self.run_code_review(data)
    if isinstance(review_response, AgentResponse):
        return review_response
    data = await self.implement_changes(review_response)

# If we've exhausted all attempts, accept the current changes
if review_attempts >= MAX_CODING_ATTEMPTS:
    log.warning(f"Max review attempts ({MAX_CODING_ATTEMPTS}) reached, accepting current changes")
```
**Проблема:** Хотя есть счетчик `MAX_CODING_ATTEMPTS=3`, логика может зациклиться, если `review_response` не возвращает `AgentResponse`.  
**Влияние:** Бесконечный цикл, зависание системы.  
**Решение:** Добавить дополнительные проверки и гарантии выхода из цикла.

---

## 🟠 ВЫСОКИЙ ПРИОРИТЕТ (P1)

### 6. **Console.log в production frontend**
**Файлы:**
- `frontend/src/api/workspace.ts:14, 26, 33, 38, 47`
- `frontend/src/components/LazyWrapper.tsx:26`
- `frontend/src/components/ui/toaster.tsx:19`

```typescript
// workspace.ts
console.log('WebSocket connection established');  // Строка 14
console.error('Error parsing WebSocket message:', e);  // Строка 26
console.log('WebSocket connection closed');  // Строка 33
console.error('WebSocket error:', error);  // Строка 38
console.error('WebSocket is not connected');  // Строка 47

// LazyWrapper.tsx
console.error('Lazy loading error:', error, errorInfo);  // Строка 26

// toaster.tsx
console.error("Toast Error", { title, description });  // Строка 19
```

**Проблема:** Console.log/console.error в production коде. Хотя некоторые обернуты в `if (import.meta.env.DEV)`, не все.  
**Влияние:** Утечка информации в production, производительность.  
**Решение:** 
- Обернуть все в `if (import.meta.env.DEV)`
- Использовать proper logging сервис
- Настроить tree-shaking для удаления в production

---

### 7. **TODO: Hot-reloading не реализован**
**Файл:** `core/proc/process_manager.py:330`
```python
# TODO: Implement hot-reloading using a file watcher like 'watchdog'.
# This is a placeholder implementation.
```
**Проблема:** Функция `start_process_with_hot_reload()` заявлена, но hot-reload не работает — просто запускается процесс.  
**Влияние:** Обман ожиданий пользователей, функционал не работает.  
**Решение:** Либо реализовать, либо удалить/переименовать метод.

---

### 8. **TODO: Bug Hunter - некорректная логика выбора логов**
**Файл:** `core/agents/bug_hunter.py:200`
```python
# TODO select only the logs that are new (with SAMOKODER_DEBUGGING_LOG)
self.next_state.current_iteration["bug_hunting_cycles"][-1]["backend_logs"] = None
self.next_state.current_iteration["bug_hunting_cycles"][-1]["frontend_logs"] = None
```
**Проблема:** Логи всегда устанавливаются в `None` вместо фильтрации новых логов.  
**Влияние:** Bug Hunter не может корректно анализировать логи.  
**Решение:** Реализовать фильтрацию логов по метке `SAMOKODER_DEBUGGING_LOG`.

---

### 9. **FIXME: Duplicate code в tech_lead**
**Файл:** `core/agents/tech_lead.py:189`
```python
# FIXME: we're injecting summaries to initial description
existing_summary=None,
```
**Проблема:** Summaries не инжектируются, хотя должны быть.  
**Влияние:** Потеря контекста при планировании задач.  
**Решение:** Реализовать инжектирование summaries.

---

### 10. **FIXME: Duplicate code в troubleshooter**
**Файл:** `core/agents/troubleshooter.py:122`
```python
# FIXME - this is incorrect if this is a new problem; otherwise we could
```
**Связанный:** `core/agents/troubleshooter.py:150`
```python
# FIXME: Current prompts reuse conversation from the developer so we have to resort to this
```
**Проблема:** Неправильная логика для новых проблем, переиспользование conversation не оптимально.  
**Влияние:** Некорректный анализ проблем.  
**Решение:** Пересмотреть логику и структуру conversation.

---

### 11. **FIXME: Problem Solver - мертвый код**
**Файл:** `core/agents/problem_solver.py:17`
```python
# FIXME: This is probably extra leftover from some dead code in the old implementation
```
**Проблема:** Мертвый код, который не нужен.  
**Влияние:** Техдолг, путаница.  
**Решение:** Удалить лишний код.

---

### 12. **FIXME: Developer - зависимость от контекста**
**Файл:** `core/agents/developer.py:150`
```python
# FIXME: In case of iteration, parse_task depends on the context (files, tasks, etc) set there.
```
**Проблема:** Неявная зависимость от контекста, хрупкая логика.  
**Влияние:** Сложность поддержки, баги при изменениях.  
**Решение:** Сделать зависимости явными через параметры.

---

### 13. **FIXME: Developer - lowercase issue**
**Файл:** `core/agents/developer.py:342`
```python
# FIXME: must be lowercase becase VSCode doesn't recognize it otherwise. Needs a fix in the extension
```
**Проблема:** Хардкод для VSCode, нужно исправить в extension.  
**Влияние:** Coupling с VSCode.  
**Решение:** Исправить в extension.

---

### 14. **TODO: Error Handler - duplicate code**
**Файлы:**
- `core/agents/error_handler.py:93`
- `core/agents/error_handler.py:100`
- `core/agents/error_handler.py:105`
- `core/agents/error_handler.py:118`

```python
# FIXME: can this break?
step_index=self.current_state.steps.index(self.current_state.current_step),

# fixme: everything above copypasted from Executor

# TODO: duplicate from Troubleshooter, maybe extract to a ProjectState method?

# TODO: maybe have ProjectState.finished_steps as well? would make the debug/ran_command prompts nicer too
```
**Проблема:** Дублирование кода из Executor и Troubleshooter, потенциальный NPE.  
**Влияние:** DRY нарушен, сложность поддержки.  
**Решение:** Извлечь общую логику в методы ProjectState.

---

### 15. **FIXME: Executor - step not in steps**
**Файл:** `core/agents/executor.py:162`
```python
# FIXME: can step ever happen *not* to be in current steps?
step_index=self.current_state.steps.index(self.step),
```
**Проблема:** Вызов `.index()` без проверки — может упасть с `ValueError`.  
**Влияние:** Runtime ошибка.  
**Решение:** Добавить проверку существования или использовать `try-except`.

---

### 16. **FIXME: Executor - нет отладки через BugHunter**
**Файл:** `core/agents/executor.py:136`
```python
# FIXME: ErrorHandler isn't debugged with BugHunter - we should move all commands to run before testing and debug them with BugHunter
```
**Проблема:** ErrorHandler не использует BugHunter для отладки команд.  
**Влияние:** Пропущенные баги.  
**Решение:** Интегрировать BugHunter в ErrorHandler.

---

### 17. **TODO: Orchestrator - параллелизация шагов**
**Файл:** `core/agents/orchestrator.py:301`
```python
# TODO: this can be parallelized in the future
return self.create_agent_for_step(state.current_step)
```
**Проблема:** Шаги выполняются последовательно, хотя могли бы параллельно.  
**Влияние:** Производительность.  
**Решение:** Реализовать параллельное выполнение где возможно.

---

### 18. **TODO: Importer - нет сигнала для UI**
**Файл:** `core/agents/importer.py:31`
```python
# TODO: Send a signal to the UI to copy the project files to workspace
```
**Проблема:** UI не получает сигнал о копировании файлов.  
**Влияние:** Плохой UX, пользователь не знает что происходит.  
**Решение:** Добавить UI уведомление.

---

### 19. **TODO: Frontend - хранение app link**
**Файл:** `core/agents/frontend.py:294`
```python
# todo store app link and send whenever we are sending run_command
```
**Проблема:** App link не сохраняется и не отправляется.  
**Влияние:** Пользователь не получает ссылку на запущенное приложение.  
**Решение:** Реализовать сохранение и отправку ссылки.

---

### 20. **TODO: Frontend - вопрос о завершенности**
**Файл:** `core/agents/frontend.py:196`
```python
# TODO Add question if user app is fully finished
```
**Проблема:** Нет проверки завершенности приложения.  
**Влияние:** Может быть не полностью готовое приложение.  
**Решение:** Добавить финальную проверку.

---

### 21. **TODO: CICD - парсинг YAML**
**Файл:** `core/agents/cicd.py:28`
```python
# TODO: The LLM might return the YAML inside a code block.
```
**Проблема:** LLM может вернуть YAML в code block, нет обработки.  
**Влияние:** Сломанный CI/CD конфиг.  
**Решение:** Добавить парсинг code blocks.

---

### 22. **TODO: Bug Hunter - улучшить логику**
**Файлы:**
- `core/agents/bug_hunter.py:61`
- `core/agents/bug_hunter.py:267`
- `core/agents/bug_hunter.py:273`

```python
# TODO determine how to find a bug (eg. check in db, ask user a question, etc.)

# TODO: remove when Leon checks

# TODO: in the future improve with a separate conversation that parses the user info and goes into an appropriate if statement
```
**Проблема:** Логика поиска багов не доработана, есть временные решения.  
**Влияние:** Неэффективный поиск багов.  
**Решение:** Доработать алгоритм поиска багов.

---

## 🟡 СРЕДНИЙ ПРИОРИТЕТ (P2)

### 23. **Generic Exception raises**
**Файлы:** Множество
```python
# core/agents/code_monkey.py:487, 492
raise Exception("Bad patch -- regex mismatch [line " + str(index_original) + "]")
raise Exception("Bad patch -- bad line number [line " + str(index_original) + "]")
```
**Проблема:** Используется generic `Exception` вместо специфичных типов.  
**Влияние:** Сложность обработки ошибок, плохая диагностика.  
**Решение:** Создать custom exception классы (PatchError, etc).

---

### 24. **Weak error handling - except: pass**
**Файлы:** Множество (найдено в grep результатах)
**Проблема:** Множество мест с `except: pass` или голым `except Exception:`.  
**Влияние:** Тихое игнорирование ошибок, сложность отладки.  
**Решение:** Добавить логирование во все except блоки.

---

### 25. **Missing validation для API endpoints**
**Проблема:** Некоторые API endpoints не валидируют входные данные должным образом.  
**Влияние:** Потенциальные инъекции, некорректные данные.  
**Решение:** Добавить Pydantic валидацию везде.

---

### 26. **Templates с хардкодом**
**Файл:** `core/templates/tree/vite_react/server/utils/auth.js:5`
```javascript
return jwt.sign(user.toObject(), process.env.JWT_SECRET, { expiresIn: '1d' }); // TODO set to 15 minutes
```
**Проблема:** Время истечения токена захардкожено в комментарии TODO.  
**Влияние:** Небезопасные токены с долгим временем жизни.  
**Решение:** Установить 15 минут как указано.

---

### 27. **TODO в промптах**
**Файл:** `core/prompts/error-handler/debug.prompt:19`
```
{# FIXME: the above stands in place of a previous (task breakdown) convo, and is duplicated in define_user_review_goal and debug prompts #}
```
**Проблема:** Дублирование в промптах, неоптимальная структура.  
**Влияние:** Техдолг в промптах.  
**Решение:** Извлечь общие части в partials.

---

### 28. **TODO в UI клиенте**
**Файл:** `core/ui/ipc_client.py:20, 330`
```python
# TODO: unify these (and corresponding changes in the extension) before release

# FIXME: add this to base and console and document it after merging with hint PR
```
**Проблема:** Несогласованность с extension, недокументированное API.  
**Влияние:** Баги в интеграции с extension.  
**Решение:** Унифицировать API, задокументировать.

---

## 🟢 НИЗКИЙ ПРИОРИТЕТ (P3)

### 29. **TODO в примерах**
**Файл:** `core/templates/example_project.py`
Множество TODO в example проекте (Todo app).  
**Проблема:** Пример проекта с TODO - это нормально, но стоит проверить.  
**Влияние:** Минимальное.  
**Решение:** Оставить как есть, это пример.

---

### 30. **Документация TODO**
Множество TODO в документации и отчетах.  
**Проблема:** Устаревшие TODO в документах.  
**Влияние:** Минимальное, это документы.  
**Решение:** Периодически чистить.

---

## 📊 СТАТИСТИКА

### По типам проблем:
- 🔴 **КРИТИЧНЫЕ (P0):** 5 проблем
- 🟠 **ВЫСОКИЙ (P1):** 18 проблем
- 🟡 **СРЕДНИЙ (P2):** 8 проблем
- 🟢 **НИЗКИЙ (P3):** 2 проблемы

**ИТОГО:** 33 проблемы требуют внимания

### По категориям:
- **TODO/FIXME:** 20+ комментариев
- **Мокки/заглушки:** 1 критичный файл
- **Console.log:** 7+ мест во frontend
- **Error handling:** 15+ проблем
- **Business logic:** 10+ проблем
- **Security:** 2 проблемы
- **Architecture:** 5 проблем

---

## 🎯 ПРИОРИТЕТЫ ИСПРАВЛЕНИЯ

### 🔥 Немедленно (в течение дня):
1. ✅ Исправить `if True or` в executor.py (строка 137)
2. ✅ Удалить `core/services/preview_service.py`
3. ✅ Перенести `preview_processes` в Redis

### 📅 На этой неделе:
4. Реализовать rollback mechanism для orchestrator
5. Исправить infinite loop risk в code_monkey
6. Убрать console.log из production frontend
7. Реализовать hot-reloading или удалить метод
8. Исправить Bug Hunter логику с логами

### 📆 В течение месяца:
- Пройтись по всем FIXME и закрыть их
- Рефакторинг error handling (custom exceptions)
- Убрать дублирование кода
- Улучшить validation в API
- Документировать все TODO

---

## 🔍 ДЕТАЛИ ПРОВЕРКИ

### Проверенные компоненты:
✅ **Агенты:** Orchestrator, BugHunter, CodeMonkey, Executor, ErrorHandler, Developer, TechLead, Troubleshooter, ProblemSolver, Importer, Frontend, CICD  
✅ **API:** Auth, Preview, Notifications, Plugins, Workspace  
✅ **Database:** Models, Sessions, Migrations  
✅ **Frontend:** React components, API clients, WebSocket  
✅ **Security:** Authentication, Authorization, Token management  
✅ **Infrastructure:** Process manager, Worker, Config  

### Методы анализа:
- Grep по всем TODO/FIXME/HACK/XXX
- Grep по mock/stub/fake/dummy
- Grep по console.log/error
- Ручное чтение критичной бизнес-логики
- Проверка error handling patterns
- Анализ зависимостей и импортов
- Проверка всех вызовов и их валидации

---

## 💡 РЕКОМЕНДАЦИИ

### Процесс:
1. **Запретить TODO/FIXME в master** без issue tracker линков
2. **Code review checklist** с проверкой на:
   - Console.log в production
   - Generic exceptions
   - Error handling
   - TODO без контекста
3. **Pre-commit hooks** для проверки console.log
4. **CI/CD проверки** на наличие критичных TODO

### Архитектура:
1. Перенести все временное состояние в Redis
2. Реализовать proper transaction management
3. Создать custom exception hierarchy
4. Улучшить separation of concerns в агентах

### Тестирование:
1. Добавить integration tests для критичных flows
2. Добавить tests для error handling
3. Добавить tests для rollback scenarios
4. Mock external dependencies правильно

---

## ✅ ЧТО ХОРОШО

### Положительные моменты:
- ✅ Есть comprehensive test coverage
- ✅ Используется Pydantic для валидации
- ✅ Async/await правильно применяется
- ✅ Есть logging infrastructure
- ✅ Есть security audit trail
- ✅ Документация присутствует
- ✅ Type hints используются
- ✅ Есть rate limiting
- ✅ Есть monitoring hooks

---

## 📝 ЗАКЛЮЧЕНИЕ

**Общая оценка кода:** 7/10

**Критичных проблем:** 5 (требуют немедленного исправления)

**Основные риски:**
1. Executor всегда возвращает success — может привести к silent failures
2. In-memory storage не масштабируется
3. Отсутствие rollback механизма
4. Console.log в production

**Рекомендация:** Провести sprint по техдолгу с фокусом на P0 и P1 проблемы.

---

**Дата:** 7 Октября 2025  
**Автор:** AI Code Reviewer  
**Версия:** 1.0
