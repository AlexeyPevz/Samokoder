# План Регрессионного Тестирования Критических Пользовательских Потоков

**Дата создания:** 2025-10-06  
**Ветка:** cursor/regression-testing-critical-user-flows-8823  
**Базовые коммиты:**
- 7b1b7e2 - Security audit and remediation of code (#35)
- efd4cda - Проверка соответствия скоупа целям и KPI (#33)
- 298d1cc - Refactor: Improve DB session management and config (#34)

---

## 🎯 Scope и Классификация

Все тесты классифицированы по критичности для блокировки мёржа:

- **P0 (CRITICAL)** - Критические баги, блокируют мёрж до исправления
- **P1 (HIGH)** - Высокоприоритетные, блокируют мёрж до исправления
- **P2 (MEDIUM)** - Желательно исправить, не блокируют мёрж

---

## 📋 Критические Пользовательские Потоки

### 1. Аутентификация и Авторизация (P0)

#### TC-AUTH-001: Регистрация пользователя с валидацией пароля
**Приоритет:** P0  
**Связанные изменения:**
- `core/api/models/auth.py:36-78` - усиленная валидация паролей
- `api/routers/auth.py:141-168` - endpoint регистрации

**Шаги воспроизведения:**
1. Отправить POST запрос на `/v1/auth/register`
2. С телом: `{"email": "test@example.com", "password": "weak"}`
3. Проверить, что пароль отклонён (422 или 400)
4. Повторить с сильным паролем: `"StrongP@ss123"`
5. Проверить успешную регистрацию (201)

**Ожидаемый результат:**
- Слабые пароли отклоняются с описанием требований
- Сильные пароли принимаются
- Пароль хешируется перед сохранением
- Возвращаются access_token и refresh_token

**Критерии провала:**
- Принят пароль менее 8 символов
- Принят пароль без заглавной буквы
- Принят пароль без спецсимвола
- Принят распространённый пароль (password123)
- Пароль хранится в открытом виде

**Автотест:** `tests/regression/test_critical_auth_flows.py::TestUserRegistration::test_tc_auth_001_password_validation`

---

#### TC-AUTH-002: Вход с httpOnly cookies
**Приоритет:** P0  
**Связанные изменения:**
- `api/routers/auth.py:239-256` - установка httpOnly cookies
- `frontend/src/api/api.ts:9` - withCredentials: true

**Шаги воспроизведения:**
1. Зарегистрировать пользователя
2. Отправить POST на `/v1/auth/login` с данными формы
3. Проверить, что в response установлены cookies `access_token` и `refresh_token`
4. Проверить флаги cookies: `httpOnly=true`, `samesite=strict`
5. Убедиться, что токены не возвращаются в теле ответа (опционально)

**Ожидаемый результат:**
- Cookies устанавливаются с флагом httpOnly
- Cookies имеют корректное время жизни
- В production установлен флаг secure=true
- SameSite=strict для защиты от CSRF

**Критерии провала:**
- Cookies не устанавливаются
- httpOnly=false (уязвимость к XSS)
- secure=false в production (уязвимость к MITM)
- Отсутствует SameSite (уязвимость к CSRF)

**Автотест:** `tests/regression/test_critical_auth_flows.py::TestUserLogin::test_tc_auth_002_httponly_cookies`

---

#### TC-AUTH-003: Rate limiting на refresh token endpoint
**Приоритет:** P0  
**Связанные изменения:**
- `api/routers/auth.py:260-261` - добавлен @limiter.limit декоратор

**Шаги воспроизведения:**
1. Получить refresh_token
2. Отправить 20 последовательных запросов на `/v1/auth/refresh`
3. Проверить, что после N запросов возвращается 429 Too Many Requests
4. Подождать период reset
5. Проверить, что запросы снова работают

**Ожидаемый результат:**
- После превышения лимита возвращается 429
- В заголовках указаны X-RateLimit-* headers
- После периода ожидания лимит сбрасывается

**Критерии провала:**
- Можно отправлять неограниченное количество запросов
- 429 никогда не возвращается
- Нет информации о лимитах в заголовках

**Автотест:** `tests/regression/test_critical_auth_flows.py::TestTokenRefresh::test_tc_auth_003_rate_limiting`

---

#### TC-AUTH-004: JWT содержит jti для отзыва токенов
**Приоритет:** P0  
**Связанные изменения:**
- `api/routers/auth.py:55-67` - добавлен jti в токены
- `core/db/models/revoked_tokens.py` - модель для отозванных токенов

**Шаги воспроизведения:**
1. Войти в систему и получить access_token
2. Декодировать JWT токен (без проверки подписи)
3. Проверить наличие поля `jti` в payload
4. Проверить, что `jti` уникален для каждого токена
5. Проверить, что `jti` имеет формат UUID

**Ожидаемый результат:**
- JWT содержит поле jti
- jti уникален для каждого токена
- jti имеет валидный формат (UUID)

**Критерии провала:**
- jti отсутствует в токене
- jti одинаковый для разных токенов
- jti имеет невалидный формат

**Автотест:** `tests/regression/test_critical_auth_flows.py::TestTokenRevocation::test_tc_auth_004_jwt_has_jti`

---

#### TC-AUTH-005: Logout отзывает токен
**Приоритет:** P0  
**Связанные изменения:**
- `api/routers/auth.py:291-322` - endpoint logout
- `api/routers/auth.py:120-127` - проверка отозванных токенов

**Шаги воспроизведения:**
1. Войти в систему и получить токен
2. Успешно вызвать `/v1/auth/me` с токеном
3. Вызвать POST `/v1/auth/logout` с токеном
4. Попытаться снова вызвать `/v1/auth/me` с тем же токеном
5. Проверить, что возвращается 401 Unauthorized

**Ожидаемый результат:**
- После logout токен больше не валиден
- jti сохранён в таблице revoked_tokens
- Все последующие запросы с этим токеном отклоняются

**Критерии провала:**
- Токен остаётся валидным после logout
- Можно использовать отозванный токен
- jti не сохраняется в БД

**Автотест:** `tests/regression/test_critical_auth_flows.py::TestTokenRevocation::test_tc_auth_005_logout_revokes_token`

---

#### TC-AUTH-006: Account lockout после неудачных попыток входа
**Приоритет:** P0  
**Связанные изменения:**
- `api/routers/auth.py:185-203` - проверка и блокировка аккаунта
- `core/db/models/login_attempts.py` - модель попыток входа

**Шаги воспроизведения:**
1. Создать пользователя с известным паролем
2. Попытаться войти 5 раз с неправильным паролем
3. Проверить, что все 5 попыток вернули 400 Bad Request
4. Попытаться войти 6-й раз (даже с правильным паролем)
5. Проверить, что возвращается 429 Too Many Requests
6. Проверить сообщение о блокировке аккаунта

**Ожидаемый результат:**
- После 5 неудачных попыток аккаунт блокируется
- Возвращается 429 с сообщением о блокировке
- Все попытки логируются в таблицу login_attempts
- Блокировка действует 15 минут

**Критерии провала:**
- Аккаунт не блокируется после 5 попыток
- Можно продолжать брутфорс
- Попытки не логируются
- Блокировка не снимается через 15 минут

**Автотест:** `tests/regression/test_critical_auth_flows.py::TestBruteForceProtection::test_tc_auth_006_account_lockout`

---

### 2. Управление Сессиями БД (P0)

#### TC-DB-001: Транзакция откатывается при ошибке
**Приоритет:** P0  
**Связанные изменения:**
- `core/db/session.py:94-107` - автоматический rollback в __aexit__

**Шаги воспроизведения:**
1. Начать транзакцию через SessionManager.get_session()
2. Создать запись в БД
3. Вызвать исключение внутри контекста
4. Проверить, что запись НЕ сохранилась в БД
5. Проверить, что вызван session.rollback()

**Ожидаемый результат:**
- При исключении транзакция откатывается
- Изменения не сохраняются в БД
- Сессия корректно закрывается

**Критерии провала:**
- Изменения сохраняются при исключении
- Сессия остаётся открытой
- rollback не вызывается
- Возникает утечка соединений

**Автотест:** `tests/regression/test_critical_db_flows.py::TestTransactionManagement::test_tc_db_001_rollback_on_error`

---

#### TC-DB-002: Engine disposal при shutdown
**Приоритет:** P0  
**Связанные изменения:**
- `core/db/session.py:42-50` - функция dispose_engines
- `api/main.py:89-91` - вызов dispose_engines при shutdown

**Шаги воспроизведения:**
1. Запустить приложение
2. Создать несколько DB соединений
3. Проверить, что соединения активны
4. Вызвать shutdown приложения
5. Проверить, что все engines dispose вызван
6. Проверить, что cache очищен

**Ожидаемый результат:**
- При shutdown вызывается dispose для всех engines
- Все соединения закрываются
- Engine cache очищается
- Нет hanging connections

**Критерии провала:**
- Engines не закрываются
- Соединения остаются открытыми
- Cache не очищается
- Утечка ресурсов при shutdown

**Автотест:** `tests/regression/test_critical_db_flows.py::TestSessionLifecycle::test_tc_db_002_engine_disposal`

---

#### TC-DB-003: Pool pre-ping проверяет соединения
**Приоритет:** P1  
**Связанные изменения:**
- `core/db/session.py:36,117,123` - pool_pre_ping=True

**Шаги воспроизведения:**
1. Создать engine с pool_pre_ping=True
2. Получить соединение из пула
3. Симулировать обрыв соединения (закрыть БД)
4. Попытаться использовать соединение
5. Проверить, что создано новое соединение

**Ожидаемый результат:**
- Мёртвые соединения определяются и пересоздаются
- Не возникает ошибок при использовании пула
- Приложение восстанавливается после сбоев БД

**Критерии провала:**
- Используются мёртвые соединения
- Приложение падает при обрыве соединения
- Нет автоматического восстановления

**Автотест:** `tests/regression/test_critical_db_flows.py::TestConnectionHealth::test_tc_db_003_pool_pre_ping`

---

### 3. Security Headers (P1)

#### TC-SEC-001: Все endpoints возвращают security headers
**Приоритет:** P1  
**Связанные изменения:**
- `core/api/middleware/security_headers.py` - middleware для заголовков
- `api/main.py:99` - добавление middleware

**Шаги воспроизведения:**
1. Вызвать GET `/`
2. Вызвать GET `/v1/auth/me` (защищённый endpoint)
3. Вызвать POST `/v1/auth/register`
4. Для каждого запроса проверить заголовки:
   - Content-Security-Policy
   - X-Frame-Options: DENY
   - X-Content-Type-Options: nosniff
   - X-XSS-Protection
   - Referrer-Policy
   - Permissions-Policy

**Ожидаемый результат:**
- Все endpoints возвращают security headers
- Headers имеют корректные значения
- В production добавлен HSTS

**Критерии провала:**
- Хотя бы один header отсутствует
- Headers имеют слабые значения
- HSTS отсутствует в production

**Автотест:** `tests/regression/test_critical_security_flows.py::TestSecurityHeaders::test_tc_sec_001_all_endpoints_have_headers`

---

#### TC-SEC-002: CSP блокирует inline scripts
**Приоритет:** P1  
**Связанные изменения:**
- `core/api/middleware/security_headers.py:21-31` - CSP конфигурация

**Шаги воспроизведения:**
1. Получить CSP header из любого endpoint
2. Проверить, что `script-src` содержит ограничения
3. Проверить, что `frame-ancestors` установлен в 'none'
4. Проверить, что `default-src` установлен в 'self'

**Ожидаемый результат:**
- CSP содержит строгие правила
- Inline scripts ограничены
- Frame embedding запрещён

**Критерии провала:**
- CSP слишком разрешающий
- Отсутствуют критичные директивы
- Можно внедрить XSS

**Автотест:** `tests/regression/test_critical_security_flows.py::TestSecurityHeaders::test_tc_sec_002_csp_configuration`

---

### 4. Error Handling (P1)

#### TC-ERR-001: Generic errors не раскрывают информацию
**Приоритет:** P1  
**Связанные изменения:**
- `core/api/error_handlers.py:13-41` - generic exception handler
- `api/main.py:106` - регистрация handler

**Шаги воспроизведения:**
1. Вызвать endpoint, который вызовет внутреннее исключение
2. Проверить response body
3. Убедиться, что НЕ раскрывается:
   - Stack trace
   - Пути к файлам
   - Схема БД
   - Внутренние IP адреса
4. Убедиться, что возвращается error_id для отслеживания

**Ожидаемый результат:**
- Возвращается generic сообщение
- Полная ошибка логируется на сервере
- Возвращается error_id для связи с логами
- Нет раскрытия внутренней структуры

**Критерии провала:**
- Раскрываются stack traces
- Видны пути к файлам
- Раскрывается схема БД
- Отсутствует error_id

**Автотест:** `tests/regression/test_critical_security_flows.py::TestErrorHandling::test_tc_err_001_no_information_leakage`

---

#### TC-ERR-002: Validation errors санитизированы
**Приоритет:** P1  
**Связанные изменения:**
- `core/api/error_handlers.py:44-78` - validation exception handler

**Шаги воспроизведения:**
1. Отправить невалидные данные на `/v1/auth/register`
2. Проверить response на 422
3. Проверить, что ошибки санитизированы
4. Проверить, что есть error_id
5. Убедиться, что нет внутренних деталей Pydantic

**Ожидаемый результат:**
- Ошибки валидации понятны пользователю
- Нет раскрытия внутренней структуры моделей
- Есть error_id для отладки

**Критерии провала:**
- Раскрываются внутренние имена полей
- Видны пути к классам Pydantic
- Отсутствует error_id

**Автотест:** `tests/regression/test_critical_security_flows.py::TestErrorHandling::test_tc_err_002_validation_errors_sanitized`

---

### 5. Audit Logging (P1)

#### TC-AUD-001: Все попытки входа логируются
**Приоритет:** P1  
**Связанные изменения:**
- `api/routers/auth.py:209-221,224-234` - логирование попыток
- `core/security/audit_logger.py:58-67` - log_authentication

**Шаги воспроизведения:**
1. Очистить таблицу login_attempts
2. Выполнить успешный вход
3. Выполнить неудачный вход
4. Проверить, что обе попытки записаны в БД
5. Проверить поля: email, ip_address, success, user_agent

**Ожидаемый результат:**
- Успешные входы логируются с success=true
- Неудачные входы логируются с success=false
- Все необходимые поля заполнены
- Timestamp корректен

**Критерии провала:**
- Попытки не логируются
- Отсутствуют критичные поля
- Неправильный статус success

**Автотест:** `tests/regression/test_critical_audit_flows.py::TestAuditLogging::test_tc_aud_001_login_attempts_logged`

---

#### TC-AUD-002: Token revocation логируется
**Приоритет:** P1  
**Связанные изменения:**
- `api/routers/auth.py:315-317` - логирование отзыва токенов
- `core/security/audit_logger.py:105-112` - log_token_revocation

**Шаги воспроизведения:**
1. Войти в систему
2. Вызвать logout
3. Проверить, что событие записано в security_audit.log
4. Проверить поля: user_id, jti, reason="logout"

**Ожидаемый результат:**
- Отзыв токена логируется
- Указан user_id и jti
- Указана причина (logout)

**Критерии провала:**
- Событие не логируется
- Отсутствует jti или user_id
- Нет файла security_audit.log

**Автотест:** `tests/regression/test_critical_audit_flows.py::TestAuditLogging::test_tc_aud_002_token_revocation_logged`

---

## 🔄 Матрица Трассировки

| Test Case ID | Приоритет | Файлы | Строки | Коммит |
|--------------|-----------|-------|--------|--------|
| TC-AUTH-001 | P0 | core/api/models/auth.py | 36-78 | 7b1b7e2 |
| TC-AUTH-002 | P0 | api/routers/auth.py | 239-256 | 7b1b7e2 |
| TC-AUTH-003 | P0 | api/routers/auth.py | 260-261 | 7b1b7e2 |
| TC-AUTH-004 | P0 | api/routers/auth.py | 55-67 | 7b1b7e2 |
| TC-AUTH-005 | P0 | api/routers/auth.py | 291-322 | 7b1b7e2 |
| TC-AUTH-006 | P0 | api/routers/auth.py | 185-203 | 7b1b7e2 |
| TC-DB-001 | P0 | core/db/session.py | 94-107 | 298d1cc |
| TC-DB-002 | P0 | core/db/session.py | 42-50 | 298d1cc |
| TC-DB-003 | P1 | core/db/session.py | 36,117,123 | 298d1cc |
| TC-SEC-001 | P1 | core/api/middleware/security_headers.py | 1-64 | 7b1b7e2 |
| TC-SEC-002 | P1 | core/api/middleware/security_headers.py | 21-31 | 7b1b7e2 |
| TC-ERR-001 | P1 | core/api/error_handlers.py | 13-41 | 7b1b7e2 |
| TC-ERR-002 | P1 | core/api/error_handlers.py | 44-78 | 7b1b7e2 |
| TC-AUD-001 | P1 | api/routers/auth.py | 209-234 | 7b1b7e2 |
| TC-AUD-002 | P1 | api/routers/auth.py | 315-317 | 7b1b7e2 |

---

## 🚦 Критерии Блокировки Мёржа

### ❌ БЛОКИРУЕТ МЁРЖ (P0):
- Хотя бы 1 провальный P0 тест
- Отсутствие автотестов для P0 сценариев
- Регрессия в критических потоках аутентификации
- Утечка данных или информации
- SQL injection возможен
- XSS возможен через httpOnly bypass

### ⚠️ БЛОКИРУЕТ МЁРЖ (P1):
- Более 2 провальных P1 тестов
- Отсутствие security headers
- Information disclosure в ошибках
- Отсутствие audit logging для критичных событий

### ℹ️ НЕ БЛОКИРУЕТ МЁРЖ (P2):
- Провальные P2 тесты (создать задачи на исправление)
- Недостающие не критичные фичи

---

## 📊 Метрики Качества

### Coverage Requirements:
- **P0 flows:** 100% покрытие автотестами
- **P1 flows:** 90%+ покрытие автотестами
- **P2 flows:** 70%+ покрытие автотестами

### Производительность:
- Время выполнения всех регресс-тестов: < 5 минут
- Время выполнения P0 тестов: < 2 минут

### Стабильность:
- Flaky rate: < 1%
- Все тесты должны быть идемпотентными

---

## 🏃 Запуск Тестов

### Все регресс-тесты:
```bash
pytest tests/regression/ -v --tb=short
```

### Только P0 тесты:
```bash
pytest tests/regression/ -v -m "priority_p0"
```

### Только P1 тесты:
```bash
pytest tests/regression/ -v -m "priority_p1"
```

### С отчётом о покрытии:
```bash
pytest tests/regression/ --cov=core --cov=api --cov-report=html
```

### CI/CD Integration:
```yaml
# .github/workflows/regression.yml
- name: Run P0 Regression Tests
  run: |
    pytest tests/regression/ -m priority_p0 --junitxml=results.xml
    if [ $? -ne 0 ]; then
      echo "❌ P0 tests failed - BLOCKING MERGE"
      exit 1
    fi
```

---

## 📝 Заключение

Этот план покрывает все критические пользовательские потоки, затронутые изменениями в коммитах 7b1b7e2, efd4cda, 298d1cc. Каждый тест имеет чёткие шаги воспроизведения, критерии провала и ссылки на конкретные строки кода.

**Статус:** Все автотесты реализованы в директории `tests/regression/`  
**Следующие шаги:**
1. Запустить полный набор регресс-тестов
2. Исправить все P0 и P1 провалы
3. Добиться 100% прохождения P0 тестов перед мёржем
