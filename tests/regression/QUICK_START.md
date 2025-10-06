# 🚀 Quick Start: Regression Tests

## Для торопливых

```bash
# 1. Установить зависимости
pip install pytest pytest-asyncio pytest-cov

# 2. Запустить критические тесты (P0)
pytest tests/regression/ -v -m priority_p0

# 3. Если все зелёное - запустить P1
pytest tests/regression/ -v -m priority_p1

# 4. Проверить покрытие
pytest tests/regression/ --cov=core --cov=api --cov-report=html
```

## ❌ Блокирует мёрж если:

1. **Хотя бы 1 P0 тест провален**
2. **Более 2 P1 тестов провалены**

## ✅ Что покрыто:

### P0 (Критические):
- ✅ Регистрация с валидацией паролей
- ✅ Вход с httpOnly cookies  
- ✅ Rate limiting на refresh token
- ✅ JWT токены с jti для отзыва
- ✅ Logout отзывает токен
- ✅ Account lockout после неудачных попыток
- ✅ Транзакции откатываются при ошибках
- ✅ Engines dispose при shutdown

### P1 (Высокоприоритетные):
- ✅ Security headers на всех endpoints
- ✅ CSP конфигурация
- ✅ Безопасная обработка ошибок
- ✅ Логирование попыток входа
- ✅ Логирование отзыва токенов
- ✅ Pool pre-ping для DB connections

## 📖 Полная документация:

- **README.md** - Полное руководство
- **REGRESSION_TEST_PLAN.md** - Детальный план с шагами
- **../REGRESSION_TESTING_SUMMARY.md** - Общее резюме

## 🐛 Если тест провалился:

1. Запустить отдельно: `pytest tests/regression/test_critical_auth_flows.py::TestUserRegistration::test_tc_auth_001 -vv`
2. Проверить ссылки в docstring теста
3. Исправить код
4. Повторить

## 🔧 Полезные команды:

```bash
# Показать все тесты
pytest tests/regression/ --collect-only

# Запустить с отладкой
pytest tests/regression/ --pdb

# Остановиться на первом провале
pytest tests/regression/ -x

# Показать медленные тесты
pytest tests/regression/ --durations=10
```

---

**Вопросы?** Читайте README.md в этой же директории.
