# Полный Code Review Report
**Дата:** 2025-10-07  
**Охват:** Полное ревью кодовой базы - баги, ошибки, заглушки, моки, TODO, FIXME, бизнес-логика, зависимости

## 🔴 КРИТИЧЕСКИЕ ПРОБЛЕМЫ (P0 - требуют немедленного исправления)

### 1. 🐛 **Missing log import в `api/routers/preview.py`**
**Файл:** `api/routers/preview.py`  
**Строки:** 160, 238  
**Проблема:**
```python
log.debug(f"TTL guard cleanup failed...")  # line 160
log.debug(f"Container cleanup failed: {e}")  # line 238
```
Используется `log.debug()`, но импорт отсутствует. **Это вызовет NameError в runtime**.

**Решение:**
```python
from samokoder.core.log import get_logger
log = get_logger(__name__)
```

**Риск:** HIGH - runtime crash при очистке preview контейнеров

---

### 2. 🔄 **Sync DB usage в async контексте (5 файлов)**
**Проблема:** Использование `next(get_db())` в async функциях блокирует event loop.

**Файлы:**
1. `core/services/preview_service.py:28`
   ```python
   db: Session = next(get_db())  # ❌ Sync в async
   ```
2. `core/services/notification_service.py:137`
3. `core/llm/base.py:113`
4. `core/services/error_detection.py:82`
5. `core/agents/error_fixing.py:35`

**Решение:** Использовать `get_async_db()`:
```python
async with SessionManager() as session:
    # async operations
```

**Риск:** HIGH - блокирует event loop, degraded performance

---

### 3. 🔁 **Потенциальный infinite loop в `code_monkey.py`**
**Файл:** `core/agents/code_monkey.py:129`  
**Строка:** Найден FIXME комментарий:
```python
# FIXME: provide a counter here so that we don't have an endless loop here
```

**Проблема:** `MAX_CODING_ATTEMPTS` определен, но не enforced. Если LLM генерирует invalid код в цикле, worker зависнет.

**Решение:** Добавить проверку:
```python
if attempt >= MAX_CODING_ATTEMPTS:
    log.warning(f"Max attempts ({MAX_CODING_ATTEMPTS}) reached")
    return {"new_content": response or file_content, "attempt": attempt}
```

**Риск:** HIGH - worker hang, wasted LLM tokens

---

### 4. 🗑️ **Race condition с asyncio.create_task без tracking**
**Файл:** `api/routers/preview.py:164, 182, 201`  
**Проблема:**
```python
asyncio.create_task(_ttl_guard(process, key))  # Не отслеживается
```

TTL guard tasks создаются без tracking. Если endpoint crashes до завершения task, процессы останутся running.

**Решение:**
```python
self._cleanup_tasks = []
task = asyncio.create_task(_ttl_guard(process, key))
self._cleanup_tasks.append(task)
```

**Риск:** MEDIUM - resource leak, orphaned processes

---

### 5. 🧪 **Mock/Stub код в production (`preview_service.py`)**
**Файл:** `core/services/preview_service.py`  
**Проблема:** Весь файл содержит stub реализацию:
```python
# Line 145-149: Симулированный процесс
process = await asyncio.create_subprocess_exec(
    "sleep", "3600",  # ❌ Симулирует long-running process
    ...
)
```

**Статус:** Этот файл НЕ используется в production (используется `api/routers/preview.py` с реальной реализацией).

**Решение:** Удалить `core/services/preview_service.py` или пометить как deprecated.

**Риск:** LOW - файл не используется, но создает confusion

---

## 🟠 ВЫСОКИЙ ПРИОРИТЕТ (P1 - должны быть исправлены в ближайшее время)

### 6. 📝 **117 TODO/FIXME комментариев**
**Критичные TODO:**

1. **`core/agents/orchestrator.py:69`** - Рефакторинг main loop
   ```python
   # TODO: consider refactoring this into two loop
   ```

2. **`core/agents/orchestrator.py:301`** - Параллелизация
   ```python
   # TODO: this can be parallelized in the future
   ```

3. **`core/agents/bug_hunter.py:61`** - Незавершенная логика
   ```python
   # TODO determine how to find a bug
   ```

4. **`core/agents/bug_hunter.py:200`** - Фильтрация логов
   ```python
   # TODO select only the logs that are new (with SAMOKODER_DEBUGGING_LOG)
   ```

5. **`core/proc/process_manager.py:330`** - Hot-reloading не реализован
   ```python
   # TODO: Implement hot-reloading using a file watcher like 'watchdog'.
   ```

6. **`api/routers/plugins.py:12`** - Миграция на async
   ```python
   # TODO: Migrate plugins to async when plugin system is refactored
   ```

7. **`api/routers/preview.py:27`** - In-memory storage
   ```python
   # In-memory storage for preview processes (P1-1: TODO - move to Redis for production)
   ```

**Полный список:** 117 TODO найдено командой grep

**Решение:** Приоритизировать и закрыть критичные TODO (список выше).

---

### 7. ⚠️ **79 bare `except Exception` handlers**
**Проблема:** Использование `except Exception` без specific error handling.

**Примеры:**
1. `core/security/crypto.py:51` - Маскирует Fernet errors
2. `core/services/email_service.py:35` - Email failures не logged правильно
3. `core/disk/vfs.py:183, 196, 274, 286, 328` - File operations
4. `api/routers/preview.py:171` - Fallback без proper logging

**Решение:** Заменить на specific exceptions:
```python
# ❌ Плохо
except Exception as e:
    log.error(f"Error: {e}")

# ✅ Хорошо
except (docker.errors.APIError, docker.errors.NotFound) as e:
    log.error(f"Docker error: {e}")
except Exception as e:
    log.exception(f"Unexpected error: {e}")
    raise
```

**Риск:** MEDIUM - hidden bugs, difficult debugging

---

### 8. 🖥️ **66 console.log в production коде**
**Файлы (выборка):**
- `frontend/src/api/workspace.ts` - 5 instances
- `frontend/src/components/LazyWrapper.tsx` - 1 instance
- `core/templates/tree/vite_react/server/` - Multiple files

**Решение:** Удалить или заменить на proper logging:
```javascript
// ❌ Плохо
console.log('WebSocket connection established');

// ✅ Хорошо (если нужно)
if (process.env.NODE_ENV === 'development') {
  console.log('WebSocket connection established');
}
```

**Риск:** LOW-MEDIUM - information leakage, performance

---

### 9. 🔐 **Password/Token handling в коде**
**Найдено 39 упоминаний в grep, проверены критические:**

✅ **ХОРОШО:**
- `core/security/crypto.py` - Правильное использование Fernet encryption
- `api/routers/auth.py` - Tokens stored in httpOnly cookies
- `core/plugins/github.py` - Encrypted GitHub tokens

⚠️ **ВНИМАНИЕ:**
- `core/services/email_service.py:17, 31` - SMTP password используется напрямую (но это OK для SMTP)
- Убедиться, что все secrets в .env и не committed в git

**Статус:** Mostly OK, security audit уже был проведен

---

## 🟡 СРЕДНИЙ ПРИОРИТЕТ (P2 - желательно исправить)

### 10. 🎭 **130+ NotImplementedError и pass statements**
**Проблема:** Много abstract methods и placeholder code.

**Примеры:**
- `core/disk/vfs.py` - 5 NotImplementedError (abstract base class - OK)
- `core/agents/base.py:227` - NotImplementedError (abstract - OK)
- `core/ui/base.py` - 33 NotImplementedError (abstract - OK)
- `core/workspace/git_manager.py:20, 26, 30, 34` - NotImplementedError ("planned per ADR")
- `core/tasks/queue_service.py:29, 35` - NotImplementedError ("planned per ADR")

**Статус:** Большинство - legitimate abstract methods. НО:

⚠️ **ПРОБЛЕМА:**
- `core/proc/process_manager.py:139` - `pass` в error handler
  ```python
  except ...:
      pass  # ❌ Молча проглатывает ошибку
  ```

**Решение:** Добавить logging в empty except blocks.

---

### 11. 🏗️ **openapi.yaml содержит TODO**
**Файл:** `openapi.yaml`  
**Строки:** 1654, 1798, 2847

```yaml
**⚠️ TODO:** Проверка прав администратора не реализована
```

**Проблема:** Admin check не реализован.

**Статус:** Проверено в `api/routers/auth.py:161` - `require_admin()` **РЕАЛИЗОВАН**.

**Решение:** Обновить openapi.yaml, удалить TODO.

---

### 12. 🗂️ **Дублирование бизнес-логики**
**Найдено:**
1. **Preview service дублирован:**
   - `core/services/preview_service.py` (stub/mock)
   - `api/routers/preview.py` (production)

2. **Agent orchestration логика разбросана:**
   - `core/agents/orchestrator.py` - main orchestration
   - `core/agents/tech_lead.py:189` - FIXME: "we're injecting summaries to initial description"
   - `core/agents/troubleshooter.py:122` - FIXME: "this is incorrect if this is a new problem"

**Решение:** Consolidate логику, удалить дублирование.

---

## 🟢 НИЗКИЙ ПРИОРИТЕТ (P3 - хорошо бы иметь)

### 13. 📦 **Unused imports и dead code**
**Примеры:**
- `core/llm/groq_client.py:4` - `import tiktoken` (может быть неиспользуем, требует проверки)
- Множество test utilities могут быть неиспользуемы

**Решение:** Запустить `ruff check --select F401` для поиска unused imports.

---

### 14. 🎨 **Frontend issues**
**Найдено:**
- `frontend/measure-vitals.html` - Debug/test file, не должен быть в production
- Performance monitoring code может быть overhead

**Решение:** Review frontend build config.

---

## ✅ ЧТО УЖЕ ИСПРАВЛЕНО (по предыдущим аудитам)

Согласно документам в репозитории:
1. ✅ Security audit пройден (SECURITY_AUDIT_REPORT.md)
2. ✅ API discrepancies исправлены (API_DISCREPANCIES.md)
3. ✅ Tier limits реализованы (TIER_LIMITS_IMPLEMENTATION.md)
4. ✅ Rate limiting добавлен
5. ✅ httpOnly cookies для auth tokens
6. ✅ Token revocation реализован
7. ✅ Account lockout после failed attempts

---

## 🎯 БИЗНЕС-ЛОГИКА REVIEW

### Orchestrator Flow (✅ mostly OK)
**Файл:** `core/agents/orchestrator.py`

**Проверено:**
- ✅ State transitions правильные
- ✅ Commit/rollback логика есть (строка 122, 232, 360)
- ⚠️ TODO на строке 69 - рефакторинг main loop (не критично)
- ⚠️ TODO на строке 301 - параллелизация (performance optimization)

**Потенциальная проблема:**
```python
# Line 120-122
if self.next_state and self.next_state != self.current_state:
    log.warning("Uncommitted changes detected in next_state, rolling back")
    await self.state_manager.rollback()
```
✅ Rollback УЖЕ РЕАЛИЗОВАН (improvement_plan.json отмечал как TODO, но он уже есть!)

---

### Authentication Flow (✅ Good)
**Файл:** `api/routers/auth.py`

**Проверено:**
- ✅ Password hashing (bcrypt)
- ✅ JWT with proper expiration
- ✅ Token revocation (jti)
- ✅ Rate limiting
- ✅ Account lockout после 5 failed attempts
- ✅ httpOnly cookies
- ✅ Audit logging

**Нет критичных проблем**

---

### Preview Service (⚠️ Issues)
**Файлы:** `api/routers/preview.py`, `core/services/preview_service.py`

**Проблемы:**
1. ❌ Missing log import (P0)
2. ⚠️ In-memory preview_processes dict (TODO: move to Redis)
3. ⚠️ Async tasks не tracked
4. ✅ Docker security limits OK
5. ✅ TTL guards есть

---

### Bug Hunter (⚠️ TODOs)
**Файл:** `core/agents/bug_hunter.py`

**Проблемы:**
1. TODO line 61 - "determine how to find a bug"
2. TODO line 200 - "select only new logs"
3. TODO line 267, 273 - pair programming improvements

**Статус:** Functional, но есть известные limitations

---

### State Manager (✅ Good)
**Файл:** `core/state/state_manager.py`

**Проверено:**
- ✅ Proper async/await
- ✅ Transaction handling
- ✅ Rollback mechanism
- ✅ File system abstraction (VFS)
- ⚠️ Exception handling в некоторых местах слишком broad

---

## 📊 СТАТИСТИКА

| Категория | Количество | Приоритет |
|-----------|-----------|-----------|
| TODO/FIXME | 117 | P1 |
| Bare except Exception | 79 | P1 |
| console.log | 66 | P1 |
| Sync DB в async | 5 | P0 |
| Missing imports | 1 | P0 |
| NotImplementedError | 130+ | P2 (mostly OK) |
| Mock/stub code | 1 file | P1 |
| Race conditions | 3 | P0 |

---

## 🚀 РЕКОМЕНДАЦИИ ПО ПРИОРИТЕТАМ

### Немедленно (эта неделя):
1. ✅ Добавить log import в `api/routers/preview.py`
2. ✅ Исправить sync DB usage в 5 файлах
3. ✅ Добавить MAX_CODING_ATTEMPTS check в code_monkey
4. ✅ Добавить task tracking для preview TTL guards

### Ближайшие 2 недели:
5. Пройтись по критичным TODO (7 шт из списка выше)
6. Улучшить error handling (заменить bare except на specific)
7. Удалить/пометить mock файлы (preview_service.py)
8. Убрать console.log из production кода

### Средний срок (1 месяц):
9. Рефакторинг orchestrator main loop
10. Параллелизация agent execution
11. Реализовать hot-reloading в process_manager
12. Переместить preview_processes в Redis

### Backlog:
13. Cleanup unused imports
14. Review frontend performance monitoring
15. Consolidate дублированной логики

---

## ✍️ ЗАКЛЮЧЕНИЕ

**Общее состояние кода: ХОРОШЕЕ** ✅

Критичные security issues уже исправлены в предыдущих аудитах. Найденные проблемы в основном:
- Tech debt (TODO/FIXME)
- Code quality (error handling, logging)
- Несколько P0 багов (missing import, sync/async mixing)

**Никаких data corruption или security vulnerabilities не найдено.**

**Рекомендация:** Исправить 5 P0 issues немедленно, затем работать над P1 issues систематически.
