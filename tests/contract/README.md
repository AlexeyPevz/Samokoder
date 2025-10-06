# Контрактные тесты API

Этот каталог содержит контрактные тесты, которые проверяют соответствие реализации API спецификации OpenAPI 3.1.

## Назначение

Контрактные тесты гарантируют:
- ✅ Все эндпоинты из спецификации реализованы
- ✅ Реализация соответствует схемам данных
- ✅ Обязательные поля присутствуют в ответах
- ✅ Валидация работает корректно
- ✅ Коды ошибок соответствуют документации

## Структура

```
tests/contract/
├── README.md                      # Этот файл
├── test_openapi_contract.py       # Основные контрактные тесты
├── test_schema_validation.py      # Тесты валидации схем
└── conftest.py                    # Общие фикстуры (если нужны)
```

## Установка зависимостей

```bash
# Установить зависимости для контрактных тестов
pip install -r requirements-test.txt

# Или через poetry
poetry install --with test
```

### Дополнительные зависимости

```txt
# requirements-test.txt
pytest>=7.4.0
pytest-asyncio>=0.21.0
pytest-cov>=4.1.0
httpx>=0.24.0
openapi-spec-validator>=0.6.0
pyyaml>=6.0
```

## Запуск тестов

### Запустить все контрактные тесты

```bash
pytest tests/contract/ -v
```

### Запустить конкретный тестовый файл

```bash
pytest tests/contract/test_openapi_contract.py -v
```

### Запустить конкретный тест

```bash
pytest tests/contract/test_openapi_contract.py::TestAuthenticationEndpoints::test_login_response_schema -v
```

### Запустить с coverage

```bash
pytest tests/contract/ --cov=samokoder.api --cov-report=html
```

### Запустить в параллель (быстрее)

```bash
pytest tests/contract/ -n auto
```

## Категории тестов

### 1. TestOpenAPISpecification
Проверяет валидность самой OpenAPI спецификации:
- Соответствие OpenAPI 3.1 стандарту
- Наличие обязательных метаданных
- Определение схем безопасности
- Полнота определения схем

### 2. TestEndpointCoverage
Проверяет покрытие эндпоинтов:
- Все эндпоинты из спецификации реализованы
- Нет недокументированных эндпоинтов
- HTTP методы соответствуют документации

### 3. TestAuthenticationEndpoints
Тесты эндпоинтов аутентификации:
- `/v1/auth/register` - регистрация
- `/v1/auth/login` - вход
- `/v1/auth/refresh` - обновление токена
- `/v1/auth/logout` - выход
- `/v1/auth/me` - текущий пользователь

### 4. TestProjectEndpoints
Тесты эндпоинтов проектов:
- `GET /v1/projects` - список проектов
- `POST /v1/projects` - создание проекта
- `GET /v1/projects/{id}` - детали проекта
- `PUT /v1/projects/{id}` - обновление проекта
- `DELETE /v1/projects/{id}` - удаление проекта

### 5. TestApiKeysEndpoints
Тесты эндпоинтов API ключей:
- `GET /v1/keys` - список ключей
- `POST /v1/keys` - добавление ключа
- `DELETE /v1/keys/{provider}` - удаление ключа
- `PUT /v1/keys/{provider}/settings` - настройки ключа

### 6. TestModelsEndpoints
Тесты эндпоинтов моделей:
- `GET /v1/models` - все модели
- `GET /v1/models/{provider}` - модели провайдера

### 7. TestHealthEndpoints
Тесты health check эндпоинтов:
- `GET /health` - простая проверка
- `GET /health/` - полная проверка
- `GET /health/status` - статус
- `GET /health/components/{name}` - компонент
- `GET /health/metrics` - метрики

### 8. TestErrorResponses
Тесты схем ошибок:
- 401 Unauthorized
- 404 Not Found
- 422 Validation Error

### 9. TestAuthSchemas
Тесты схем аутентификации:
- RegisterRequest валидация
- LoginRequest валидация
- AuthResponse структура
- Валидация паролей

### 10. TestProjectSchemas
Тесты схем проектов:
- ProjectCreateRequest
- ProjectUpdateRequest
- ProjectResponse
- Ограничения полей

## Фикстуры

### `openapi_spec`
Загружает и валидирует OpenAPI спецификацию из `openapi.yaml`.

### `client`
Создает тестовый HTTP клиент для FastAPI приложения.

### `test_user`
Создает тестового пользователя в БД для аутентификации.

### `auth_headers`
Возвращает headers с JWT токеном для аутентифицированных запросов.

### `test_project`
Создает тестовый проект для текущего пользователя.

## Примеры использования

### Проверить конкретный эндпоинт

```python
def test_my_endpoint(client, auth_headers):
    """Проверить, что мой эндпоинт работает правильно."""
    response = client.get(
        "/v1/my-endpoint",
        headers=auth_headers
    )
    
    assert response.status_code == 200
    data = response.json()
    
    # Проверить обязательные поля
    assert "field1" in data
    assert "field2" in data
    
    # Проверить типы данных
    assert isinstance(data["field1"], str)
    assert isinstance(data["field2"], int)
```

### Проверить схему ответа

```python
from samokoder.core.api.models.mymodels import MyResponse

def test_response_schema(client, auth_headers):
    """Проверить, что ответ соответствует схеме."""
    response = client.get("/v1/endpoint", headers=auth_headers)
    
    # Pydantic автоматически валидирует
    my_response = MyResponse(**response.json())
    
    assert my_response.field1 is not None
```

### Проверить ошибки валидации

```python
def test_validation_error(client, auth_headers):
    """Проверить, что валидация работает."""
    response = client.post(
        "/v1/endpoint",
        headers=auth_headers,
        json={"invalid": "data"}
    )
    
    assert response.status_code == 422
    error = response.json()
    
    assert "detail" in error
    assert isinstance(error["detail"], list)
    assert len(error["detail"]) > 0
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Contract Tests

on: [push, pull_request]

jobs:
  contract-tests:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    
    - name: Install dependencies
      run: |
        pip install -r requirements-test.txt
    
    - name: Run contract tests
      run: |
        pytest tests/contract/ -v --cov --cov-report=xml
    
    - name: Upload coverage
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.xml
```

## Troubleshooting

### Тест падает с "405 Method Not Allowed"

**Проблема:** Эндпоинт не реализован или URL неправильный.

**Решение:** Проверить, что эндпоинт добавлен в роутер и URL правильный.

### Тест падает с "Schema validation error"

**Проблема:** OpenAPI спецификация невалидна.

**Решение:** Проверить `openapi.yaml` с помощью валидатора:
```bash
openapi-spec-validator openapi.yaml
```

### Тесты не находят openapi.yaml

**Проблема:** Файл не в ожидаемом месте.

**Решение:** Убедиться, что `openapi.yaml` находится в корне проекта:
```
project/
├── openapi.yaml        # Здесь
├── tests/
│   └── contract/
└── ...
```

### Фикстуры не работают

**Проблема:** conftest.py не в правильном месте.

**Решение:** Создать `tests/conftest.py` с общими фикстурами или проверить путь импорта.

## Best Practices

1. **Один тест - одна проверка**
   - Делать тесты атомарными
   - Легче найти проблему при падении

2. **Использовать фикстуры**
   - Переиспользовать общий код
   - Упрощает поддержку

3. **Явные assert сообщения**
   ```python
   assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
   ```

4. **Тестировать edge cases**
   - Пустые значения
   - Максимальные/минимальные значения
   - Невалидные данные

5. **Cleanup после тестов**
   - Использовать transactional fixtures
   - Не оставлять тестовые данные в БД

## Дополнительные ресурсы

- [OpenAPI Specification](https://spec.openapis.org/oas/v3.1.0)
- [pytest Documentation](https://docs.pytest.org/)
- [FastAPI Testing](https://fastapi.tiangolo.com/tutorial/testing/)
- [Contract Testing Guide](https://martinfowler.com/bliki/ContractTest.html)

## Контакты

Вопросы и предложения:
- **Email:** api-owner@samokoder.io
- **Slack:** #api-testing
- **Issues:** GitHub Issues
