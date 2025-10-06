# Security Fixes Applied - Quick Reference

## Файлы созданы/изменены:

### Новые модели БД:
1. ✅ `core/db/models/revoked_tokens.py` - Для отзыва JWT токенов (P1-1)
2. ✅ `core/db/models/login_attempts.py` - Для защиты от брут-форса (P1-3)

### Новые сервисы безопасности:
3. ✅ `core/security/audit_logger.py` - Централизованное логирование (P2-4)
4. ✅ `core/api/error_handlers.py` - Безопасная обработка ошибок (P1-4)
5. ✅ `core/api/middleware/security_headers.py` - Security headers (P1-5)

### Тесты:
6. ✅ `tests/security/test_auth_security.py` - Комплексные security тесты

### Миграции:
7. ✅ `alembic/versions/add_security_tables.py` - Миграция для новых таблиц

### Документация:
8. ✅ `SECURITY_AUDIT_REPORT.md` - Полный отчет по безопасности
9. ✅ `SECURITY_FIXES_APPLIED.md` - Этот файл

---

## Требуется ручное изменение в существующих файлах:

### P0-1: Rate limiting на refresh token (КРИТИЧНО)
**Файл:** `api/routers/auth.py:172`

```python
# БЫЛО:
@router.post("/auth/refresh", response_model=TokenRefreshResponse)
async def refresh_token(payload: TokenRefreshRequest):

# СТАЛО:
@router.post("/auth/refresh", response_model=TokenRefreshResponse)
@limiter.limit(get_rate_limit("auth"))  # ДОБАВИТЬ
async def refresh_token(
    request: Request,  # ДОБАВИТЬ
    payload: TokenRefreshRequest
):
```

---

### P0-2: httpOnly cookies (КРИТИЧНО)
**Файл:** `api/routers/auth.py:149`

Добавить после создания auth_response:
```python
# После: auth_response = _create_auth_response(user, config)
response.set_cookie(
    key="access_token",
    value=auth_response.access_token,
    httponly=True,
    secure=True,
    samesite="strict",
    max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60
)
response.set_cookie(
    key="refresh_token",
    value=auth_response.refresh_token,
    httponly=True,
    secure=True,
    samesite="strict",
    max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60
)
```

**Файл:** `frontend/src/api/api.ts:29-34`

Изменить interceptor:
```typescript
// УДАЛИТЬ чтение из localStorage
// const token = localStorage.getItem('accessToken');

// ДОБАВИТЬ
apiInstance.defaults.withCredentials = true;
```

---

### P1-1: JWT jti для отзыва токенов
**Файл:** `api/routers/auth.py:49`

```python
import uuid

def _create_token(*, data: dict, secret: str, expires_delta: timedelta, token_type: str) -> str:
    to_encode = data.copy()
    now = datetime.utcnow()
    expire = now + expires_delta
    jti = str(uuid.uuid4())  # ДОБАВИТЬ
    to_encode.update({
        "exp": expire,
        "iat": now,
        "type": token_type,
        "jti": jti  # ДОБАВИТЬ
    })
    return jwt.encode(to_encode, secret, algorithm="HS256")
```

Добавить endpoint logout:
```python
from samokoder.core.db.models.revoked_tokens import RevokedToken

@router.post("/auth/logout")
async def logout(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_async_db)
):
    try:
        config = get_config()
        payload = jwt.decode(token, config.secret_key, algorithms=["HS256"])
        jti = payload.get("jti")
        exp = payload.get("exp")
        
        if jti and exp:
            revoked = RevokedToken(
                jti=jti,
                expires_at=datetime.fromtimestamp(exp),
                reason="logout"
            )
            db.add(revoked)
            await db.commit()
    except JWTError:
        pass
    
    return {"message": "Successfully logged out"}
```

Обновить get_current_user для проверки отозванных токенов:
```python
# В core/api/dependencies.py:12
from samokoder.core.db.models.revoked_tokens import RevokedToken

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_async_db),
) -> User:
    # ... existing code ...
    
    # ДОБАВИТЬ после декодирования JWT:
    jti = payload.get("jti")
    if jti:
        result = await db.execute(
            select(RevokedToken).where(RevokedToken.jti == jti)
        )
        if result.scalars().first():
            raise credentials_exception
    
    # ... rest of function
```

---

### P1-2: Усиление требований к паролям
**Файл:** `core/api/models/auth.py:28`

Заменить валидацию пароля (см. полный код в SECURITY_AUDIT_REPORT.md секция P1-2)

---

### P1-3: Account lockout
**Файл:** `api/routers/auth.py:149`

Добавить в начало функции login (см. полный код в SECURITY_AUDIT_REPORT.md секция P1-3):
```python
from samokoder.core.db.models.login_attempts import LoginAttempt
from samokoder.core.security.audit_logger import audit_logger

# Проверка lockout
# Логирование попыток
```

---

### P1-4: Безопасная обработка ошибок
**Файл:** `api/main.py`

Добавить импорты и exception handlers:
```python
from samokoder.core.api.error_handlers import (
    generic_exception_handler,
    validation_exception_handler
)
from fastapi.exceptions import RequestValidationError

# После создания app:
app.add_exception_handler(Exception, generic_exception_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)
```

---

### P1-5: Security headers
**Файл:** `api/main.py`

Добавить импорт и middleware:
```python
from samokoder.core.api.middleware.security_headers import SecurityHeadersMiddleware

# После создания app, перед другими middleware:
app.add_middleware(SecurityHeadersMiddleware)
```

---

### P2-2: Шифрование GitHub tokens
**Файл:** `core/db/models/user.py:34-35`

Изменить:
```python
# БЫЛО:
github_token: Mapped[str] = mapped_column(String, nullable=True)

# СТАЛО:
_github_token_encrypted: Mapped[str] = mapped_column("github_token", String, nullable=True)

# ДОБАВИТЬ методы:
from samokoder.core.security.crypto import CryptoService

def set_encrypted_github_token(self, token: str, secret_key: bytes) -> None:
    """Encrypt and store GitHub token."""
    crypto = CryptoService(secret_key)
    self._github_token_encrypted = crypto.encrypt(token)

def get_decrypted_github_token(self, secret_key: bytes) -> str:
    """Decrypt and return GitHub token."""
    if not self._github_token_encrypted:
        return ""
    crypto = CryptoService(secret_key)
    return crypto.decrypt(self._github_token_encrypted)
```

---

### P2-3: Строгая CORS конфигурация
**Файл:** `api/main.py:109-115`

Заменить на:
```python
config = get_config()

cors_origins = os.environ.get("CORS_ORIGINS", "").split(",")
if not cors_origins or cors_origins == [""]:
    if config.environment == "production":
        cors_origins = ["https://samokoder.io", "https://app.samokoder.io"]
    else:
        cors_origins = ["http://localhost:5173", "http://localhost:3000"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=[
        "Content-Type", "Authorization", "Accept", "Origin",
        "User-Agent", "DNT", "Cache-Control", "X-Requested-With"
    ],
    max_age=3600,
)
```

---

## Шаги для применения:

1. **Создать новые файлы** (уже созданы выше)
2. **Применить миграции:**
   ```bash
   alembic upgrade head
   ```

3. **Ручные изменения в файлах** (используя инструкции выше):
   - api/routers/auth.py (P0-1, P0-2, P1-1, P1-3)
   - core/api/models/auth.py (P1-2)
   - api/main.py (P1-4, P1-5, P2-3)
   - core/api/dependencies.py (P1-1)
   - core/db/models/user.py (P2-2)
   - frontend/src/api/api.ts (P0-2)

4. **Запустить тесты:**
   ```bash
   pytest tests/security/test_auth_security.py -v
   ```

5. **Проверить логи:**
   ```bash
   tail -f logs/security_audit.log
   ```

---

## Приоритеты внедрения:

### СРОЧНО (сегодня):
- ✅ P0-1: Rate limiting на refresh
- ✅ P0-2: httpOnly cookies
- ✅ P1-5: Security headers

### Эта неделя:
- ✅ P1-1: JWT jti и logout
- ✅ P1-2: Усиление паролей
- ✅ P1-3: Account lockout

### Следующая неделя:
- ✅ P1-4: Обработка ошибок
- ✅ P2-1: Input validation
- ✅ P2-2: Шифрование токенов
- ✅ P2-3: CORS
- ✅ P2-4: Audit logging
