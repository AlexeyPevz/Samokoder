# Регрессионные Тесты Критических Пользовательских Потоков

## 📖 Обзор

Этот набор регрессионных тестов покрывает все критические пользовательские потоки, затронутые изменениями в следующих коммитах:

- **7b1b7e2** - Security audit and remediation of code (#35)
- **efd4cda** - Проверка соответствия скоупа целям и KPI (#33)
- **298d1cc** - Refactor: Improve DB session management and config (#34)

## 🎯 Классификация Тестов

### P0 (CRITICAL) - ❌ БЛОКИРУЕТ МЁРЖ
Любой провальный P0 тест **блокирует мёрж** до исправления.

**Файлы:**
- `test_critical_auth_flows.py` - Аутентификация и авторизация
- `test_critical_db_flows.py` - Управление сессиями БД

**Покрываемые потоки:**
- TC-AUTH-001: Регистрация с валидацией пароля
- TC-AUTH-002: Вход с httpOnly cookies
- TC-AUTH-003: Rate limiting на refresh token
- TC-AUTH-004: JWT содержит jti
- TC-AUTH-005: Logout отзывает токен
- TC-AUTH-006: Account lockout после неудачных попыток
- TC-DB-001: Транзакция откатывается при ошибке
- TC-DB-002: Engine disposal при shutdown

### P1 (HIGH) - ⚠️ БЛОКИРУЕТ МЁРЖ ПРИ >2 ПРОВАЛАХ
Более 2 провальных P1 тестов **блокируют мёрж**.

**Файлы:**
- `test_critical_security_flows.py` - Security headers и защита
- `test_critical_audit_flows.py` - Audit logging

**Покрываемые потоки:**
- TC-SEC-001: Security headers на всех endpoints
- TC-SEC-002: CSP конфигурация
- TC-ERR-001: Generic errors не раскрывают информацию
- TC-ERR-002: Validation errors санитизированы
- TC-AUD-001: Все попытки входа логируются
- TC-AUD-002: Token revocation логируется
- TC-DB-003: Pool pre-ping проверяет соединения

### P2 (MEDIUM) - ℹ️ НЕ БЛОКИРУЕТ МЁРЖ
Провальные P2 тесты создают задачи, но не блокируют мёрж.

## 🚀 Запуск Тестов

### Все регрессионные тесты
```bash
pytest tests/regression/ -v
```

### Только P0 (критические)
```bash
pytest tests/regression/ -v -m priority_p0
```

### Только P1 (высокоприоритетные)
```bash
pytest tests/regression/ -v -m priority_p1
```

### С отчётом о покрытии
```bash
pytest tests/regression/ --cov=core --cov=api --cov-report=html
```

### Быстрый прогон (только P0)
```bash
pytest tests/regression/ -v -m priority_p0 --tb=short -x
```

## 📊 Структура Тестов

```
tests/regression/
├── README.md                          # Этот файл
├── REGRESSION_TEST_PLAN.md            # Детальный план тестирования
├── conftest.py                        # Общие фикстуры
├── test_critical_auth_flows.py        # P0: Аутентификация
├── test_critical_db_flows.py          # P0: База данных
├── test_critical_security_flows.py    # P1: Безопасность
└── test_critical_audit_flows.py       # P1: Audit logging
```

## 🔗 Матрица Трассировки

Каждый тест содержит:
- **Ссылки на файлы**: Точные пути к изменённому коду
- **Ссылки на строки**: Номера строк в коммитах
- **Ссылки на коммиты**: SHA коммитов с изменениями
- **Шаги воспроизведения**: Пошаговая инструкция
- **Критерии провала**: Чёткие условия провала теста

Пример из теста:
```python
def test_tc_auth_001_weak_passwords_rejected(self, client, weak_passwords):
    """
    P0: Test that weak passwords are rejected during registration.
    
    Reproduction steps:
    1. POST /v1/auth/register with weak password
    2. Verify 400 or 422 response
    
    Links:
    - core/api/models/auth.py:36-78
    - Commit: 7b1b7e2
    
    Failure criteria:
    - Any weak password is accepted
    - No validation error returned
    """
```

## ⚙️ CI/CD Интеграция

### GitHub Actions

Создайте `.github/workflows/regression-tests.yml`:

```yaml
name: Regression Tests

on:
  pull_request:
    branches: [ main, develop ]
  push:
    branches: [ main ]

jobs:
  p0-tests:
    name: P0 Critical Tests
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
        pip install pytest pytest-asyncio pytest-cov
    
    - name: Run P0 Regression Tests
      run: |
        pytest tests/regression/ -v -m priority_p0 --junitxml=p0-results.xml
    
    - name: Check P0 Results
      if: failure()
      run: |
        echo "❌ P0 tests failed - BLOCKING MERGE"
        exit 1
    
    - name: Upload P0 Results
      if: always()
      uses: actions/upload-artifact@v3
      with:
        name: p0-test-results
        path: p0-results.xml

  p1-tests:
    name: P1 High Priority Tests
    runs-on: ubuntu-latest
    needs: p0-tests
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
        pip install pytest pytest-asyncio pytest-cov
    
    - name: Run P1 Regression Tests
      run: |
        pytest tests/regression/ -v -m priority_p1 --junitxml=p1-results.xml
    
    - name: Upload P1 Results
      if: always()
      uses: actions/upload-artifact@v3
      with:
        name: p1-test-results
        path: p1-results.xml

  coverage:
    name: Coverage Report
    runs-on: ubuntu-latest
    needs: [p0-tests, p1-tests]
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
        pip install pytest pytest-asyncio pytest-cov
    
    - name: Generate Coverage Report
      run: |
        pytest tests/regression/ --cov=core --cov=api --cov-report=html --cov-report=xml
    
    - name: Upload Coverage
      uses: codecov/codecov-action@v3
      with:
        files: ./coverage.xml
        flags: regression
```

## 📈 Метрики Качества

### Требования к покрытию:
- **P0 flows:** 100% покрытие автотестами ✅
- **P1 flows:** 90%+ покрытие автотестами ✅
- **P2 flows:** 70%+ покрытие автотестами

### Требования к производительности:
- Время выполнения всех регресс-тестов: < 5 минут
- Время выполнения P0 тестов: < 2 минут
- Flaky rate: < 1%

### Текущий статус:
```bash
# Запустите для проверки
pytest tests/regression/ --durations=10
```

## 🐛 Отчёт о Проблемах

При провале теста включайте:

1. **ID теста**: `TC-AUTH-001`
2. **Приоритет**: P0/P1/P2
3. **Файл**: `test_critical_auth_flows.py::TestUserRegistration::test_tc_auth_001_weak_passwords_rejected`
4. **Вывод теста**: Полный traceback
5. **Ссылки на код**:
   - Файл: `core/api/models/auth.py`
   - Строки: 36-78
   - Коммит: 7b1b7e2
6. **Шаги воспроизведения**: Из docstring теста
7. **Ожидаемый результат**: Что должно произойти
8. **Фактический результат**: Что произошло

### Пример Issue:

```markdown
## 🐛 [P0] TC-AUTH-001 Failed: Weak Password Accepted

**Test:** `test_critical_auth_flows.py::TestUserRegistration::test_tc_auth_001_weak_passwords_rejected`

**Priority:** P0 - BLOCKS MERGE

**Links:**
- File: `core/api/models/auth.py:36-78`
- Commit: 7b1b7e2

**Reproduction:**
1. POST /v1/auth/register with password "short"
2. Expected: 400/422 response
3. Actual: 201 response (password accepted!)

**Impact:**
- Security vulnerability
- Weak passwords can be used
- Violates ASVS 2.1.1

**Failure Output:**
\`\`\`
AssertionError: P0 FAILURE: Weak password 'short' was not rejected. Status: 201
\`\`\`
```

## 🔍 Отладка

### Запуск одного теста:
```bash
pytest tests/regression/test_critical_auth_flows.py::TestUserRegistration::test_tc_auth_001_weak_passwords_rejected -v
```

### С детальным выводом:
```bash
pytest tests/regression/test_critical_auth_flows.py::TestUserRegistration::test_tc_auth_001_weak_passwords_rejected -vv -s
```

### С дебаггером:
```bash
pytest tests/regression/test_critical_auth_flows.py::TestUserRegistration::test_tc_auth_001_weak_passwords_rejected --pdb
```

### Просмотр всех тестов:
```bash
pytest tests/regression/ --collect-only
```

## 📚 Дополнительная Документация

- **REGRESSION_TEST_PLAN.md** - Полный план тестирования с детальными шагами
- **SECURITY_FIXES_SUMMARY.md** - Резюме всех security исправлений
- **AUDIT_SUMMARY.md** - Резюме аудита архитектуры

## ✅ Checklist перед мёржем

- [ ] Все P0 тесты проходят (0 провалов)
- [ ] P1 тесты: не более 1 провала
- [ ] Coverage >= 90% для изменённого кода
- [ ] Нет новых security уязвимостей
- [ ] Документация обновлена
- [ ] CHANGELOG.md обновлён

## 🤝 Вклад

При добавлении новых тестов:

1. Следуйте формату существующих тестов
2. Добавляйте docstring с:
   - Шагами воспроизведения
   - Ссылками на код
   - Критериями провала
3. Присваивайте правильный приоритет (P0/P1/P2)
4. Обновляйте REGRESSION_TEST_PLAN.md
5. Добавляйте фикстуры в conftest.py если нужно

## 📞 Контакты

- **QA Lead**: [ваше имя]
- **Security Team**: security@company.com
- **CI/CD Support**: devops@company.com

---

**Последнее обновление:** 2025-10-06  
**Версия:** 1.0  
**Ветка:** cursor/regression-testing-critical-user-flows-8823
