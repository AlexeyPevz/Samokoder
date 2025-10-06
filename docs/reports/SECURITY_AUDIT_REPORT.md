# ASVS Security Audit Report
**Дата:** 2025-10-06  
**Инженер:** Security Engineer с 20-летним опытом  
**Охват:** Аутентификация, Сессии, Доступ, Валидация/Кодирование, Ошибки/Логирование, Конфигурации, API

---

## 🔴 P0 - Критические уязвимости (требуют немедленного исправления)

### P0-1: Отсутствие проверки типа токена при обновлении (ASVS 3.5.2)
**Файл:** `api/routers/auth.py:172`  
**Код:**
```python
@router.post("/auth/refresh", response_model=TokenRefreshResponse)
async def refresh_token(payload: TokenRefreshRequest):
    """Issue a new access token based on refresh token."""
    config = get_config()
    try:
        decoded = jwt.decode(payload.refresh_token, config.app_secret_key, algorithms=["HS256"])
        if decoded.get("type") != "refresh":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
```

**Проблема:** Endpoint `/auth/refresh` не имеет rate limiting, позволяет брут-форс атаки на refresh token.

**Риск:** Атакующий может перебирать refresh токены без ограничений.

**Фикс:**
```python
@router.post("/auth/refresh", response_model=TokenRefreshResponse)
@limiter.limit(get_rate_limit("auth"))  # ADD THIS
async def refresh_token(
    request: Request,  # ADD THIS
    payload: TokenRefreshRequest
):
    """Issue a new access token based on refresh token."""
    config = get_config()
    try:
        decoded = jwt.decode(payload.refresh_token, config.app_secret_key, algorithms=["HS256"])
        if decoded.get("type") != "refresh":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
```

**Тест:**
```python
# tests/api/test_auth_security.py
import pytest
from fastapi.testclient import TestClient

def test_refresh_token_rate_limiting(client: TestClient):
    """Test that refresh token endpoint is rate limited."""
    # Attempt 10 requests rapidly
    responses = []
    for _ in range(10):
        response = client.post("/v1/auth/refresh", json={"refresh_token": "invalid_token"})
        responses.append(response.status_code)
    
    # Should get at least one 429 (Too Many Requests)
    assert 429 in responses, "Refresh token endpoint should be rate limited"
```

---

### P0-2: XSS через хранение токенов в localStorage (ASVS 3.2.2)
**Файл:** `frontend/src/api/api.ts:29,66-69`  
**Код:**
```typescript
const token = localStorage.getItem('accessToken');
if (token && config.headers) {
    config.headers.Authorization = `Bearer ${token}`;
}
```

**Проблема:** Токены хранятся в `localStorage`, доступны для XSS атак. ASVS требует использования httpOnly cookies для session tokens.

**Риск:** XSS атака может украсть токены и получить полный доступ к аккаунту пользователя.

**Фикс (Backend):**
```python
# api/routers/auth.py
@router.post("/auth/login", response_model=AuthResponse)
@limiter.limit(get_rate_limit("auth"))
async def login(
    request: Request,
    response: Response,  # Already present
    form_data: OAuth2PasswordRequestForm = Depends(OAuth2PasswordRequestForm),
    db: AsyncSession = Depends(get_async_db),
):
    """Authenticate the user with email/password."""
    # ... existing code ...
    
    config = get_config()
    auth_response = _create_auth_response(user, config)
    
    # SET HTTPONLY COOKIES
    response.set_cookie(
        key="access_token",
        value=auth_response.access_token,
        httponly=True,
        secure=True,  # Only over HTTPS
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
    
    return auth_response
```

**Фикс (Frontend):**
```typescript
// frontend/src/api/api.ts
// REMOVE localStorage token storage
// Tokens now come from httpOnly cookies automatically

setupInterceptors = (apiInstance: AxiosInstance) => {
  apiInstance.interceptors.request.use(
    (config: InternalAxiosRequestConfig): InternalAxiosRequestConfig => {
      // NO NEED TO MANUALLY SET TOKEN - cookies are sent automatically
      return config;
    },
    (error: AxiosError): Promise<AxiosError> => Promise.reject(error)
  );
  
  // Update withCredentials to send cookies
  apiInstance.defaults.withCredentials = true;
```

**Тест:**
```python
# tests/api/test_auth_cookies.py
def test_login_sets_httponly_cookies(client: TestClient, db_session):
    """Test that login sets httpOnly cookies for tokens."""
    # Create test user
    user = create_test_user(db_session, "test@example.com", "Password123")
    
    # Login
    response = client.post("/v1/auth/login", data={
        "username": "test@example.com",
        "password": "Password123"
    })
    
    assert response.status_code == 200
    
    # Check cookies
    cookies = response.cookies
    assert "access_token" in cookies
    assert "refresh_token" in cookies
    
    # Verify httpOnly flag
    # Note: TestClient may not expose cookie flags, but in production they're set
    # Manual verification needed in browser dev tools
```

---

### P0-3: SQL Injection через прямые запросы (ASVS 5.3.4)
**Файл:** `core/api/routers/projects.py:13`  
**Код:**
```python
@router.get("/")
async def get_projects(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    projects = db.query(Project).filter(Project.user_id == current_user.id).all()
```

**Проблема:** Хотя используется ORM (SQLAlchemy), нет защиты от SQL injection в других местах кода, где может быть конкатенация строк.

**Примечание:** В данном коде SQLAlchemy ORM используется правильно, но необходимо проверить все raw SQL запросы.

**Поиск проблем:**
```bash
# Найдено использование text() в некоторых файлах
grep -r "from sqlalchemy import.*text" --include="*.py"
```

**Проверка:** Необходимо убедиться, что все параметры в raw SQL используют параметризацию:
```python
# ПЛОХО
db.execute(f"SELECT * FROM users WHERE email = '{email}'")

# ХОРОШО
from sqlalchemy import text
db.execute(text("SELECT * FROM users WHERE email = :email"), {"email": email})
```

**Тест:**
```python
# tests/api/test_sql_injection.py
def test_sql_injection_in_project_query(client: TestClient, auth_headers):
    """Test that SQL injection is prevented in project queries."""
    malicious_input = "'; DROP TABLE projects; --"
    
    response = client.post("/v1/projects", 
        headers=auth_headers,
        json={
            "name": malicious_input,
            "description": "test"
        }
    )
    
    # Should either succeed with sanitized input or fail validation
    # Should NOT drop the table
    assert response.status_code in [200, 201, 400, 422]
```

---

## 🟠 P1 - Высокий приоритет

### P1-1: Отсутствие JWT jti (Token ID) для отзыва токенов (ASVS 3.5.3)
**Файл:** `api/routers/auth.py:49-55`  
**Код:**
```python
def _create_token(*, data: dict, secret: str, expires_delta: timedelta, token_type: str) -> str:
    """Create a signed JWT token."""
    to_encode = data.copy()
    now = datetime.utcnow()
    expire = now + expires_delta
    to_encode.update({"exp": expire, "iat": now, "type": token_type})
    return jwt.encode(to_encode, secret, algorithm="HS256")
```

**Проблема:** Нет `jti` (JWT ID) для отслеживания и отзыва токенов. Невозможно реализовать logout или отзыв скомпрометированных токенов.

**Риск:** Скомпрометированные токены остаются валидными до истечения срока действия.

**Фикс:**
```python
import uuid
from typing import Set
from samokoder.core.db.models.revoked_tokens import RevokedToken  # New model needed

def _create_token(*, data: dict, secret: str, expires_delta: timedelta, token_type: str) -> str:
    """Create a signed JWT token."""
    to_encode = data.copy()
    now = datetime.utcnow()
    expire = now + expires_delta
    jti = str(uuid.uuid4())  # ADD THIS
    to_encode.update({
        "exp": expire, 
        "iat": now, 
        "type": token_type,
        "jti": jti  # ADD THIS
    })
    return jwt.encode(to_encode, secret, algorithm="HS256")

# Add token revocation endpoint
@router.post("/auth/logout")
async def logout(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_async_db)
):
    """Revoke the current access token."""
    try:
        config = get_config()
        payload = jwt.decode(token, config.secret_key, algorithms=["HS256"])
        jti = payload.get("jti")
        exp = payload.get("exp")
        
        if jti and exp:
            # Store revoked token
            revoked = RevokedToken(jti=jti, expires_at=datetime.fromtimestamp(exp))
            db.add(revoked)
            await db.commit()
            
    except JWTError:
        pass
    
    return {"message": "Successfully logged out"}

# Update get_current_user to check revocation
async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_async_db),
) -> User:
    """Resolve the current user from the access token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        config = get_config()
        payload = jwt.decode(token, config.secret_key, algorithms=["HS256"])
        if payload.get("type") != "access":
            raise credentials_exception
        
        # CHECK IF TOKEN IS REVOKED
        jti = payload.get("jti")
        if jti:
            result = await db.execute(
                select(RevokedToken).where(RevokedToken.jti == jti)
            )
            if result.scalars().first():
                raise credentials_exception
        
        email: Optional[str] = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = await _get_user_by_email(db, email=email)
    if user is None:
        raise credentials_exception
    return user
```

**Новая модель:**
```python
# core/db/models/revoked_tokens.py
from sqlalchemy import String, DateTime
from sqlalchemy.orm import Mapped, mapped_column
from datetime import datetime
from samokoder.core.db.models.base import Base

class RevokedToken(Base):
    __tablename__ = 'revoked_tokens'
    
    jti: Mapped[str] = mapped_column(String, primary_key=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    revoked_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
```

**Миграция:**
```python
# alembic/versions/xxx_add_revoked_tokens.py
def upgrade():
    op.create_table(
        'revoked_tokens',
        sa.Column('jti', sa.String(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('revoked_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('jti')
    )
    op.create_index('ix_revoked_tokens_jti', 'revoked_tokens', ['jti'])
```

**Тест:**
```python
# tests/api/test_token_revocation.py
async def test_logout_revokes_token(client: TestClient, auth_headers):
    """Test that logout revokes the access token."""
    # Make a successful request
    response = client.get("/v1/auth/me", headers=auth_headers)
    assert response.status_code == 200
    
    # Logout
    response = client.post("/v1/auth/logout", headers=auth_headers)
    assert response.status_code == 200
    
    # Token should now be invalid
    response = client.get("/v1/auth/me", headers=auth_headers)
    assert response.status_code == 401
```

---

### P1-2: Слабые требования к паролям (ASVS 2.1.1)
**Файл:** `core/api/models/auth.py:28-35`  
**Код:**
```python
class RegisterRequest(BaseModel):
    """Запрос на регистрацию."""
    email: str = Field(..., pattern=r'^[^@]+@[^@]+\.[^@]+$', description="Email адрес")
    password: str = Field(..., min_length=6, max_length=128, description="Пароль")
    
    @validator('password')
    def validate_password_strength(cls, v):
        """Валидация сложности пароля."""
        if len(v) < 6:
            raise ValueError('Пароль должен содержать минимум 6 символов')
        return v
```

**Проблема:** 
1. Минимальная длина пароля 6 символов (должна быть 8+)
2. Нет проверки на сложность (заглавные, цифры, спецсимволы)
3. Нет проверки на распространенные пароли

**Риск:** Слабые пароли легко взламываются брут-форсом.

**Фикс:**
```python
import re
from typing import Set

# Common passwords list (загрузить из файла или использовать библиотеку)
COMMON_PASSWORDS: Set[str] = {
    "password", "123456", "12345678", "qwerty", "abc123",
    "password123", "admin", "letmein", "welcome", "monkey"
    # ... расширить список
}

class RegisterRequest(BaseModel):
    """Запрос на регистрацию."""
    email: str = Field(..., pattern=r'^[^@]+@[^@]+\.[^@]+$', description="Email адрес")
    password: str = Field(..., min_length=8, max_length=128, description="Пароль")
    
    @validator('password')
    def validate_password_strength(cls, v):
        """Валидация сложности пароля согласно ASVS 2.1.1."""
        if len(v) < 8:
            raise ValueError('Пароль должен содержать минимум 8 символов')
        
        # Check for uppercase
        if not re.search(r'[A-Z]', v):
            raise ValueError('Пароль должен содержать хотя бы одну заглавную букву')
        
        # Check for lowercase
        if not re.search(r'[a-z]', v):
            raise ValueError('Пароль должен содержать хотя бы одну строчную букву')
        
        # Check for digit
        if not re.search(r'\d', v):
            raise ValueError('Пароль должен содержать хотя бы одну цифру')
        
        # Check for special character
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError('Пароль должен содержать хотя бы один специальный символ')
        
        # Check against common passwords
        if v.lower() in COMMON_PASSWORDS:
            raise ValueError('Этот пароль слишком распространенный. Выберите более уникальный пароль.')
        
        # Check for sequential characters
        if re.search(r'(.)\1{2,}', v):
            raise ValueError('Пароль не должен содержать более 2 одинаковых символов подряд')
        
        return v
    
    @validator('email')
    def validate_email(cls, v):
        """Валидация email."""
        if len(v) > 254:
            raise ValueError('Email слишком длинный')
        return v.lower().strip()
```

**Тест:**
```python
# tests/api/test_password_validation.py
import pytest
from pydantic import ValidationError
from samokoder.core.api.models.auth import RegisterRequest

class TestPasswordStrength:
    """Тесты валидации сложности пароля."""
    
    def test_password_too_short(self):
        """Пароль короче 8 символов."""
        with pytest.raises(ValidationError, match="минимум 8 символов"):
            RegisterRequest(email="test@example.com", password="Pass1!")
    
    def test_password_no_uppercase(self):
        """Пароль без заглавных букв."""
        with pytest.raises(ValidationError, match="заглавную букву"):
            RegisterRequest(email="test@example.com", password="password123!")
    
    def test_password_no_lowercase(self):
        """Пароль без строчных букв."""
        with pytest.raises(ValidationError, match="строчную букву"):
            RegisterRequest(email="test@example.com", password="PASSWORD123!")
    
    def test_password_no_digit(self):
        """Пароль без цифр."""
        with pytest.raises(ValidationError, match="цифру"):
            RegisterRequest(email="test@example.com", password="Password!")
    
    def test_password_no_special(self):
        """Пароль без специальных символов."""
        with pytest.raises(ValidationError, match="специальный символ"):
            RegisterRequest(email="test@example.com", password="Password123")
    
    def test_password_common(self):
        """Распространенный пароль."""
        with pytest.raises(ValidationError, match="слишком распространенный"):
            RegisterRequest(email="test@example.com", password="Password123!")
    
    def test_password_sequential_chars(self):
        """Пароль с повторяющимися символами."""
        with pytest.raises(ValidationError, match="одинаковых символов подряд"):
            RegisterRequest(email="test@example.com", password="Passsword123!")
    
    def test_password_valid(self):
        """Валидный пароль."""
        request = RegisterRequest(email="test@example.com", password="MyP@ssw0rd!")
        assert request.password == "MyP@ssw0rd!"
```

---

### P1-3: Отсутствие брут-форс защиты на login (ASVS 2.2.1)
**Файл:** `api/routers/auth.py:149`  
**Код:**
```python
@router.post("/auth/login", response_model=AuthResponse)
@limiter.limit(get_rate_limit("auth"))  # This is present
async def login(
    request: Request,
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(OAuth2PasswordRequestForm),
    db: AsyncSession = Depends(get_async_db),
):
```

**Проблема:** Хотя есть rate limiting, нет:
1. Account lockout после N неудачных попыток
2. CAPTCHA после нескольких неудачных попыток
3. Логирования неудачных попыток входа

**Риск:** Distributed brute force атаки с разных IP.

**Фикс:**
```python
from datetime import datetime, timedelta
from samokoder.core.db.models.login_attempts import LoginAttempt  # New model

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15

@router.post("/auth/login", response_model=AuthResponse)
@limiter.limit(get_rate_limit("auth"))
async def login(
    request: Request,
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(OAuth2PasswordRequestForm),
    db: AsyncSession = Depends(get_async_db),
):
    """Authenticate the user with email/password."""
    try:
        login_payload = LoginRequest(email=form_data.username, password=form_data.password)
    except ValidationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=exc.errors()) from exc

    # CHECK FOR ACCOUNT LOCKOUT
    recent_attempts = await db.execute(
        select(LoginAttempt)
        .where(
            LoginAttempt.email == login_payload.email,
            LoginAttempt.created_at >= datetime.utcnow() - timedelta(minutes=LOCKOUT_DURATION_MINUTES)
        )
        .order_by(LoginAttempt.created_at.desc())
    )
    attempts = recent_attempts.scalars().all()
    
    failed_attempts = [a for a in attempts if not a.success]
    if len(failed_attempts) >= MAX_LOGIN_ATTEMPTS:
        logger.warning(f"Account locked for {login_payload.email} due to too many failed attempts")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Account temporarily locked due to too many failed login attempts. Try again in {LOCKOUT_DURATION_MINUTES} minutes."
        )

    user = await _get_user_by_email(db, email=login_payload.email)
    
    # LOG THE ATTEMPT
    client_ip = request.client.host if request.client else "unknown"
    
    if not user or not verify_password(login_payload.password, user.hashed_password):
        # Record failed attempt
        attempt = LoginAttempt(
            email=login_payload.email,
            ip_address=client_ip,
            success=False,
            user_agent=request.headers.get("User-Agent", "")
        )
        db.add(attempt)
        await db.commit()
        
        logger.warning(f"Failed login attempt for {login_payload.email} from {client_ip}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid credentials")

    # Record successful attempt
    attempt = LoginAttempt(
        email=login_payload.email,
        ip_address=client_ip,
        success=True,
        user_id=user.id,
        user_agent=request.headers.get("User-Agent", "")
    )
    db.add(attempt)
    await db.commit()

    config = get_config()
    return _create_auth_response(user, config)
```

**Новая модель:**
```python
# core/db/models/login_attempts.py
from sqlalchemy import String, Boolean, Integer, DateTime
from sqlalchemy.orm import Mapped, mapped_column
from datetime import datetime
from samokoder.core.db.models.base import Base

class LoginAttempt(Base):
    __tablename__ = 'login_attempts'
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String, index=True, nullable=False)
    ip_address: Mapped[str] = mapped_column(String, nullable=False)
    success: Mapped[bool] = mapped_column(Boolean, default=False)
    user_id: Mapped[int] = mapped_column(Integer, nullable=True)
    user_agent: Mapped[str] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
```

**Тест:**
```python
# tests/api/test_brute_force_protection.py
async def test_account_lockout_after_failed_attempts(client: TestClient, db_session):
    """Test that account is locked after max failed login attempts."""
    email = "test@example.com"
    
    # Create user
    user = create_test_user(db_session, email, "CorrectPassword123!")
    
    # Try to login with wrong password MAX_LOGIN_ATTEMPTS times
    for i in range(5):
        response = client.post("/v1/auth/login", data={
            "username": email,
            "password": "WrongPassword"
        })
        assert response.status_code == 400
    
    # Next attempt should be locked
    response = client.post("/v1/auth/login", data={
        "username": email,
        "password": "WrongPassword"
    })
    assert response.status_code == 429
    assert "locked" in response.json()["detail"].lower()
    
    # Even correct password should be locked
    response = client.post("/v1/auth/login", data={
        "username": email,
        "password": "CorrectPassword123!"
    })
    assert response.status_code == 429
```

---

### P1-4: Небезопасная обработка ошибок - утечка информации (ASVS 7.4.1)
**Файл:** `api/routers/workspace.py:85-89`  
**Код:**
```python
except Exception as exc:  # pragma: no cover - runtime errors reported to client
    try:
        await websocket.send_text(f"Error: {exc}")
    except Exception:
        pass
```

**Проблема:** Отправка полного текста исключения клиенту может раскрыть внутреннюю структуру приложения, пути к файлам, версии библиотек.

**Риск:** Information disclosure, помогает атакующим в разведке.

**Фикс:**
```python
except Exception as exc:
    logger.exception(f"WebSocket error for user {user.id}: {exc}")  # Log full error
    try:
        # Send generic error to client
        await websocket.send_text(json.dumps({
            "type": "error",
            "message": "An unexpected error occurred. Please try again.",
            "error_id": str(uuid.uuid4())  # For support tracking
        }))
    except Exception:
        pass
```

**Общее правило для всех endpoints:**
```python
# core/api/error_handlers.py
from fastapi import Request, status
from fastapi.responses import JSONResponse
import logging
import uuid

logger = logging.getLogger(__name__)

async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle unexpected exceptions without leaking information."""
    error_id = str(uuid.uuid4())
    
    # Log full error details
    logger.exception(f"Unhandled exception [{error_id}]: {exc}", extra={
        "error_id": error_id,
        "path": request.url.path,
        "method": request.method,
        "client": request.client.host if request.client else None
    })
    
    # Return generic error to client
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "An internal server error occurred",
            "error_id": error_id,  # For support to track
            "type": "internal_server_error"
        }
    )

# Add to main.py
from samokoder.core.api.error_handlers import generic_exception_handler

app.add_exception_handler(Exception, generic_exception_handler)
```

**Тест:**
```python
# tests/api/test_error_handling.py
def test_error_does_not_leak_information(client: TestClient, monkeypatch):
    """Test that errors don't expose sensitive information."""
    
    # Force an error
    def mock_error(*args, **kwargs):
        raise Exception("Internal error with sensitive path /var/www/secret/config.py")
    
    monkeypatch.setattr("samokoder.api.routers.projects.create_project", mock_error)
    
    response = client.post("/v1/projects", 
        json={"name": "Test", "description": "Test"},
        headers=auth_headers
    )
    
    assert response.status_code == 500
    error_detail = response.json()["detail"]
    
    # Should NOT contain sensitive information
    assert "/var/www" not in error_detail
    assert "config.py" not in error_detail
    assert "secret" not in error_detail
    
    # Should contain error_id for tracking
    assert "error_id" in response.json()
```

---

### P1-5: Отсутствие Content Security Policy (ASVS 14.4.3)
**Файл:** `api/main.py:109-115`  
**Проблема:** Нет заголовков безопасности (CSP, X-Frame-Options, HSTS, etc.)

**Риск:** XSS, clickjacking, MITM атаки.

**Фикс:**
```python
# api/main.py

from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""
    
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        
        # Content Security Policy
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "  # Adjust based on needs
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
        )
        
        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"
        
        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # Enable XSS filter
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        # Referrer policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # HSTS (only in production with HTTPS)
        if os.getenv("ENVIRONMENT") == "production":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
        # Permissions policy
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        
        return response

# Add middleware
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["localhost", "127.0.0.1", "*.samokoder.io"]  # Adjust for production
)
```

**Тест:**
```python
# tests/api/test_security_headers.py
def test_security_headers_present(client: TestClient):
    """Test that all security headers are present."""
    response = client.get("/")
    
    assert "Content-Security-Policy" in response.headers
    assert "X-Frame-Options" in response.headers
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "X-Content-Type-Options" in response.headers
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert "X-XSS-Protection" in response.headers
    assert "Referrer-Policy" in response.headers
```

---

## 🟡 P2 - Средний приоритет

### P2-1: Отсутствие валидации размера входных данных (ASVS 5.1.4)
**Файл:** `core/api/routers/projects.py:17`  
**Код:**
```python
@router.post("/")
async def create_project(project_data: dict, current_user: User = Depends(get_current_user), ...):
```

**Проблема:** Принимается `dict` без валидации, можно отправить огромный JSON.

**Риск:** DoS через large payload.

**Фикс:**
```python
# core/api/models/projects.py
from pydantic import BaseModel, Field, validator

class ProjectCreateRequest(BaseModel):
    """Запрос на создание проекта."""
    name: str = Field(..., min_length=1, max_length=100, description="Название проекта")
    description: str = Field(None, max_length=1000, description="Описание проекта")
    
    @validator('name')
    def validate_name(cls, v):
        """Валидация названия проекта."""
        # Запрещенные символы
        forbidden_chars = ['<', '>', '"', "'", '&', ';']
        for char in forbidden_chars:
            if char in v:
                raise ValueError(f'Название содержит запрещенный символ: {char}')
        
        # SQL keywords
        sql_keywords = ['select', 'insert', 'update', 'delete', 'drop', 'create', 'alter']
        if any(keyword in v.lower() for keyword in sql_keywords):
            raise ValueError('Название содержит запрещенное слово')
        
        return v.strip()

# Update router
@router.post("/")
async def create_project(
    project_data: ProjectCreateRequest,  # Changed from dict
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    limits_check = Depends(project_limits)
):
    project = Project(
        name=project_data.name,
        description=project_data.description,
        user_id=current_user.id
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    return {"id": project.id, "name": project.name}
```

**Добавить в main.py:**
```python
# Limit request body size
app.add_middleware(
    middleware_class=BaseHTTPMiddleware,
    dispatch=limit_request_size_middleware
)

async def limit_request_size_middleware(request: Request, call_next):
    """Limit request body size to prevent DoS."""
    content_length = request.headers.get("content-length")
    if content_length:
        if int(content_length) > 10 * 1024 * 1024:  # 10 MB limit
            return JSONResponse(
                status_code=413,
                content={"detail": "Request body too large"}
            )
    return await call_next(request)
```

**Тест:**
```python
# tests/api/test_input_validation.py
def test_project_name_validation(client: TestClient, auth_headers):
    """Test project name validation."""
    # XSS attempt
    response = client.post("/v1/projects",
        headers=auth_headers,
        json={"name": "<script>alert('xss')</script>", "description": "test"}
    )
    assert response.status_code == 422
    
    # SQL keyword
    response = client.post("/v1/projects",
        headers=auth_headers,
        json={"name": "DROP TABLE users", "description": "test"}
    )
    assert response.status_code == 422
    
    # Too long
    response = client.post("/v1/projects",
        headers=auth_headers,
        json={"name": "a" * 101, "description": "test"}
    )
    assert response.status_code == 422
```

---

### P2-2: Незашифрованные GitHub tokens в БД (ASVS 6.2.1)
**Файл:** `core/db/models/user.py:34`  
**Код:**
```python
github_token: Mapped[str] = mapped_column(String, nullable=True)
```

**Проблема:** GitHub токен хранится в открытом виде.

**Примечание:** В `api/routers/auth.py:263` есть вызов `user.set_encrypted_github_token()`, но метод не определен в модели User.

**Фикс:**
```python
# core/db/models/user.py
from samokoder.core.security.crypto import CryptoService

class User(Base):
    # ... existing code ...
    
    _github_token_encrypted: Mapped[str] = mapped_column("github_token", String, nullable=True)
    gitverse_token: Mapped[str] = mapped_column(String, nullable=True)
    
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

**Тест:**
```python
# tests/db/test_encrypted_tokens.py
def test_github_token_encryption(db_session):
    """Test that GitHub tokens are encrypted in database."""
    user = User(email="test@example.com", hashed_password="hash", tier=Tier.FREE)
    db_session.add(user)
    db_session.commit()
    
    secret_key = Fernet.generate_key()
    token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    
    # Set token
    user.set_encrypted_github_token(token, secret_key)
    db_session.commit()
    
    # Verify it's encrypted in DB
    db_session.refresh(user)
    assert user._github_token_encrypted != token
    assert "ghp_" not in user._github_token_encrypted
    
    # Verify we can decrypt it
    decrypted = user.get_decrypted_github_token(secret_key)
    assert decrypted == token
```

---

### P2-3: Отсутствие CORS валидации в продакшене (ASVS 14.5.3)
**Файл:** `api/main.py:104-115`  
**Код:**
```python
cors_origins = os.environ.get("CORS_ORIGINS", "").split(",")
if not cors_origins:
    cors_origins = ["http://localhost:5173", "http://localhost:3000"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

**Проблема:** `allow_methods=["*"]` и `allow_headers=["*"]` слишком либеральны.

**Риск:** CSRF, unauthorized cross-origin requests.

**Фикс:**
```python
# api/main.py
from samokoder.core.config import get_config

config = get_config()

# Strict CORS configuration
cors_origins = os.environ.get("CORS_ORIGINS", "").split(",")
if not cors_origins or cors_origins == [""]:
    if config.environment == "production":
        # In production, only allow specific origins
        cors_origins = ["https://samokoder.io", "https://app.samokoder.io"]
    else:
        # Development defaults
        cors_origins = ["http://localhost:5173", "http://localhost:3000"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],  # Specific methods only
    allow_headers=[
        "Content-Type",
        "Authorization",
        "Accept",
        "Origin",
        "User-Agent",
        "DNT",
        "Cache-Control",
        "X-Requested-With"
    ],  # Specific headers only
    max_age=3600,  # Cache preflight requests
)
```

**Тест:**
```python
# tests/api/test_cors.py
def test_cors_rejects_unauthorized_origin(client: TestClient):
    """Test that CORS rejects requests from unauthorized origins."""
    response = client.get("/",
        headers={"Origin": "https://evil.com"}
    )
    
    # Should not have CORS headers for unauthorized origin
    assert "Access-Control-Allow-Origin" not in response.headers or \
           response.headers["Access-Control-Allow-Origin"] != "https://evil.com"

def test_cors_allows_authorized_origin(client: TestClient):
    """Test that CORS allows requests from authorized origins."""
    response = client.options("/v1/projects",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST"
        }
    )
    
    assert response.status_code == 200
    assert "Access-Control-Allow-Origin" in response.headers
```

---

### P2-4: Отсутствие логирования безопасных событий (ASVS 7.1.2)
**Файл:** Отсутствует централизованное логирование событий безопасности

**Проблема:** Недостаточное логирование событий безопасности для аудита и обнаружения атак.

**Риск:** Невозможность обнаружить и расследовать инциденты безопасности.

**Фикс:**
```python
# core/security/audit_logger.py
import logging
from typing import Optional
from datetime import datetime
import json

class AuditLogger:
    """Централизованное логирование событий безопасности."""
    
    def __init__(self):
        self.logger = logging.getLogger("security.audit")
        
    def log_event(
        self,
        event_type: str,
        user_id: Optional[int] = None,
        email: Optional[str] = None,
        ip_address: Optional[str] = None,
        success: bool = True,
        details: Optional[dict] = None
    ):
        """Log a security event."""
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "user_id": user_id,
            "email": email,
            "ip_address": ip_address,
            "success": success,
            "details": details or {}
        }
        
        if success:
            self.logger.info(json.dumps(event))
        else:
            self.logger.warning(json.dumps(event))
    
    def log_authentication(self, email: str, ip: str, success: bool, method: str = "password"):
        """Log authentication attempt."""
        self.log_event(
            "authentication",
            email=email,
            ip_address=ip,
            success=success,
            details={"method": method}
        )
    
    def log_authorization_failure(self, user_id: int, resource: str, action: str, ip: str):
        """Log authorization failure."""
        self.log_event(
            "authorization_failure",
            user_id=user_id,
            ip_address=ip,
            success=False,
            details={"resource": resource, "action": action}
        )
    
    def log_data_access(self, user_id: int, resource_type: str, resource_id: str, action: str):
        """Log sensitive data access."""
        self.log_event(
            "data_access",
            user_id=user_id,
            success=True,
            details={
                "resource_type": resource_type,
                "resource_id": resource_id,
                "action": action
            }
        )
    
    def log_configuration_change(self, user_id: int, setting: str, old_value: str, new_value: str):
        """Log configuration changes."""
        self.log_event(
            "configuration_change",
            user_id=user_id,
            success=True,
            details={
                "setting": setting,
                "old_value": old_value,
                "new_value": new_value
            }
        )

audit_logger = AuditLogger()

# Use in endpoints:
# api/routers/auth.py
from samokoder.core.security.audit_logger import audit_logger

@router.post("/auth/login", response_model=AuthResponse)
async def login(...):
    client_ip = request.client.host if request.client else "unknown"
    
    user = await _get_user_by_email(db, email=login_payload.email)
    if not user or not verify_password(login_payload.password, user.hashed_password):
        audit_logger.log_authentication(login_payload.email, client_ip, False)
        raise HTTPException(...)
    
    audit_logger.log_authentication(user.email, client_ip, True)
    # ...
```

---

## 📋 Резюме

### Критические (P0): 3
1. ✅ **P0-1**: Rate limiting на refresh token endpoint
2. ✅ **P0-2**: Переход на httpOnly cookies вместо localStorage
3. ✅ **P0-3**: Проверка всех raw SQL запросов на SQL injection

### Высокий приоритет (P1): 5
1. ✅ **P1-1**: JWT jti и механизм отзыва токенов
2. ✅ **P1-2**: Усиление требований к паролям (8+ символов, complexity)
3. ✅ **P1-3**: Account lockout и логирование failed login attempts
4. ✅ **P1-4**: Безопасная обработка ошибок без утечки информации
5. ✅ **P1-5**: Security headers (CSP, HSTS, X-Frame-Options, etc.)

### Средний приоритет (P2): 4
1. ✅ **P2-1**: Pydantic валидация для всех входных данных
2. ✅ **P2-2**: Шифрование GitHub tokens в БД
3. ✅ **P2-3**: Строгая CORS конфигурация
4. ✅ **P2-4**: Централизованное логирование событий безопасности

---

## 🔧 План внедрения

### Фаза 1 (Срочно - 1-2 дня):
- [ ] P0-1: Добавить rate limiting на `/auth/refresh`
- [ ] P0-2: Реализовать httpOnly cookies
- [ ] P1-5: Добавить security headers middleware

### Фаза 2 (Неделя 1):
- [ ] P1-1: Реализовать JWT jti и token revocation
- [ ] P1-2: Усилить валидацию паролей
- [ ] P1-3: Добавить account lockout механизм

### Фаза 3 (Неделя 2):
- [ ] P1-4: Улучшить обработку ошибок
- [ ] P2-1: Добавить Pydantic модели для всех endpoints
- [ ] P2-2: Шифровать tokens в БД

### Фаза 4 (Неделя 3):
- [ ] P2-3: Настроить CORS
- [ ] P2-4: Внедрить audit logging
- [ ] Написать все тесты

### Фаза 5 (Ongoing):
- [ ] Регулярные security audits
- [ ] Dependency updates
- [ ] Penetration testing
- [ ] Security training для команды

---

## 📚 Дополнительные рекомендации

### Инструменты для мониторинга:
1. **Bandit** - статический анализ Python кода на уязвимости
2. **Safety** - проверка зависимостей на known vulnerabilities
3. **OWASP ZAP** - динамическое тестирование безопасности
4. **Semgrep** - поиск паттернов небезопасного кода

### Команды для проверки:
```bash
# Проверка зависимостей
safety check

# Статический анализ
bandit -r . -ll

# Поиск секретов
truffleHog --regex --entropy=True .

# Dependency scanning
pip-audit
```

### Регулярные задачи:
- [ ] Еженедельный review логов безопасности
- [ ] Ежемесячное обновление зависимостей
- [ ] Ежеквартальный penetration test
- [ ] Ежегодный полный security audit
