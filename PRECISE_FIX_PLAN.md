# ТОЧНЫЙ ПЛАН ИСПРАВЛЕНИЯ API РАСХОЖДЕНИЙ

## Критический анализ завершен

Обнаружено **15+ критических расхождений** между OpenAPI спецификацией и реальной реализацией. Требуется серьезная работа, а не поверхностные исправления.

## ПЛАН ИСПРАВЛЕНИЙ

### Фаза 1: Критические исправления структур ответов

#### 1.1 Исправить POST /api/auth/login
**Файл**: `backend/main.py:239-289`

**Текущая реализация**:
```python
return {
    "message": "Успешный вход",
    "user": response.user,
    "session": response.session
}
```

**Исправление**:
```python
return {
    "success": True,
    "message": "Успешный вход",
    "user": {
        "id": response.user.id,
        "email": response.user.email,
        "subscription_tier": "free",
        "subscription_status": "active", 
        "api_credits_balance": 100.50,
        "created_at": response.user.created_at,
        "updated_at": response.user.created_at
    },
    "access_token": response.session.access_token,
    "token_type": "bearer",
    "expires_in": 3600
}
```

#### 1.2 Исправить POST /api/auth/register
**Файл**: `backend/main.py:291-359`

**Текущая реализация**:
```python
return {
    "message": "Пользователь успешно зарегистрирован",
    "user": {...},
    "access_token": ...,
    "token_type": "bearer"
}
```

**Исправление**:
```python
return {
    "success": True,
    "message": "Пользователь успешно зарегистрирован",
    "user_id": response.user.id,
    "email": user_data["email"]
}
```

#### 1.3 Исправить GET /api/projects
**Файл**: `backend/main.py:384-425`

**Проблемы**:
1. Игнорирует параметры запроса
2. Неправильная структура ответа

**Исправление**:
```python
@app.get("/api/projects")
async def get_projects(
    current_user: dict = Depends(get_current_user),
    limit: int = Query(10, ge=1, le=100),
    offset: int = Query(0, ge=0),
    status: Optional[str] = Query(None),
    search: Optional[str] = Query(None, max_length=100)
):
    # ... логика с использованием параметров ...
    
    return {
        "projects": projects_with_status,
        "total_count": total_count,
        "page": (offset // limit) + 1,
        "limit": limit
    }
```

#### 1.4 Исправить POST /api/ai/chat
**Файл**: `backend/main.py:865-958`

**Проблемы**:
1. Принимает `dict` вместо `ChatRequest`
2. Неправильная структура ответа

**Исправление**:
```python
@app.post("/api/ai/chat")
async def ai_chat(
    chat_request: ChatRequest,  # ✅ Используем Pydantic модель
    current_user: dict = Depends(get_current_user)
):
    # ... логика ...
    
    return {
        "content": response.content,
        "provider": response.provider.value,
        "model": response.model,
        "usage": {  # ✅ Используем usage объект
            "prompt_tokens": response.prompt_tokens,
            "completion_tokens": response.completion_tokens,
            "total_tokens": response.tokens_used,
            "prompt_cost": response.prompt_cost,
            "completion_cost": response.completion_cost,
            "total_cost": response.cost_usd
        },
        "response_time": response.response_time
    }
```

### Фаза 2: Подключение отсутствующих эндпоинтов

#### 2.1 Подключить projects роутер
**Файл**: `backend/main.py`

**Добавить**:
```python
from backend.api.projects import router as projects_router
app.include_router(projects_router, prefix="/api/projects", tags=["Projects"])
```

**Удалить дублирующие эндпоинты** из main.py:
- `GET /api/projects` (строки 384-425)
- `POST /api/projects` (строки 427-533)  
- `GET /api/projects/{project_id}` (строки 535-580)
- `DELETE /api/projects/{project_id}` (строки 582-625)

#### 2.2 Подключить ai роутер
**Файл**: `backend/main.py`

**Добавить**:
```python
from backend.api.ai import router as ai_router
app.include_router(ai_router, prefix="/api/ai", tags=["AI"])
```

**Удалить дублирующие эндпоинты** из main.py:
- `POST /api/ai/chat` (строки 865-958)
- `GET /api/ai/usage` (строки 960-985)
- `GET /api/ai/providers` (строки 987-1026)
- `POST /api/ai/validate-keys` (строки 1028-1050)

#### 2.3 Подключить health роутер
**Файл**: `backend/main.py`

**Уже подключен**, но нужно удалить дублирующие эндпоинты:
- `GET /health` (строки 194-209)
- `GET /health/detailed` (строки 221-235)

### Фаза 3: Исправление спецификации

#### 3.1 Удалить несуществующие эндпоинты
**Файл**: `api/openapi_spec.yaml`

**Удалить**:
- `GET /api/auth/me` (строки 197-215) - эндпоинт не существует

#### 3.2 Исправить структуры ответов
**Файл**: `api/openapi_spec.yaml`

**Исправить LoginResponse** (строки 1829-1871):
```yaml
LoginResponse:
  type: object
  required:
    - success
    - message
    - user
    - access_token
    - token_type
    - expires_in
  properties:
    success:
      type: boolean
      example: true
    message:
      type: string
      example: "Успешный вход"
    user:
      $ref: '#/components/schemas/UserResponse'
    access_token:
      type: string
      example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    token_type:
      type: string
      example: "bearer"
    expires_in:
      type: integer
      example: 3600
```

**Исправить RegisterResponse** (строки 1874-1899):
```yaml
RegisterResponse:
  type: object
  required:
    - success
    - message
    - user_id
    - email
  properties:
    success:
      type: boolean
      example: true
    message:
      type: string
      example: "Пользователь успешно зарегистрирован"
    user_id:
      type: string
      format: uuid
      example: "123e4567-e89b-12d3-a456-426614174000"
    email:
      type: string
      format: email
      example: "newuser@example.com"
```

### Фаза 4: Создание точных тестов

#### 4.1 Тесты реальных структур данных
**Файл**: `tests/test_real_contracts.py`

```python
def test_login_returns_correct_structure():
    """Тест что login возвращает правильную структуру"""
    response = client.post("/api/auth/login", json={
        "email": "test@example.com",
        "password": "password123"
    })
    
    data = response.json()
    
    # Проверяем РЕАЛЬНУЮ структуру
    assert "success" in data
    assert "message" in data
    assert "user" in data
    assert "access_token" in data
    assert "token_type" in data
    assert "expires_in" in data
    
    # Проверяем структуру user
    user = data["user"]
    assert "id" in user
    assert "email" in user
    assert "subscription_tier" in user
    assert "subscription_status" in user
    assert "api_credits_balance" in user
```

#### 4.2 Тесты параметров запроса
**Файл**: `tests/test_real_contracts.py`

```python
def test_projects_uses_query_params():
    """Тест что projects использует параметры запроса"""
    response = client.get("/api/projects?limit=5&offset=10&status=draft&search=test")
    
    data = response.json()
    
    # Проверяем что параметры используются
    assert data["limit"] == 5
    assert data["page"] == 3  # (offset // limit) + 1
    assert len(data["projects"]) <= 5
```

## ВРЕМЕННЫЕ РАМКИ

- **Фаза 1**: 3 дня - исправление структур ответов
- **Фаза 2**: 2 дня - подключение роутеров
- **Фаза 3**: 1 день - исправление спецификации  
- **Фаза 4**: 2 дня - создание тестов
- **Тестирование**: 1 день

**Общий срок**: 9 дней

## КОНТРОЛЬ КАЧЕСТВА

1. **Каждое исправление** должно быть протестировано
2. **Все тесты** должны проходить
3. **Спецификация** должна точно соответствовать реализации
4. **Обратная совместимость** должна быть сохранена

## РИСКИ

1. **Breaking changes** - возможны при исправлении структур ответов
2. **Потеря функциональности** - при удалении дублирующих эндпоинтов
3. **Производительность** - при добавлении валидации параметров

## МИТИГАЦИЯ

1. **Поэтапное внедрение** - исправления по одному
2. **Тщательное тестирование** - после каждого изменения
3. **Мониторинг** - отслеживание ошибок в продакшене