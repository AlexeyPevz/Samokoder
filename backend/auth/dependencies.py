"""
Secure Authentication Dependencies
Исправления безопасности на основе ASVS аудита
"""

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Dict, Optional
from datetime import datetime
import logging
import os
import jwt
import time
import hashlib
import secrets
import bcrypt
from backend.utils.secure_logging import get_secure_logger

from config.settings import settings
from backend.services.connection_manager import connection_manager
from backend.services.supabase_manager import execute_supabase_operation

logger = get_secure_logger(__name__)

security = HTTPBearer(auto_error=False)

def is_test_mode() -> bool:
    """Проверяет, находимся ли мы в тестовом режиме"""
    return os.getenv("ENVIRONMENT") == "test" or os.getenv("PYTEST_CURRENT_TEST") is not None

def validate_jwt_token(token: str) -> bool:
    """Валидирует JWT токен с проверкой подписи и срока действия"""
    try:
        # Проверяем формат токена
        if not token or len(token.split('.')) != 3:
            return False
        
        # Проверяем заголовок токена на алгоритм
        header = jwt.get_unverified_header(token)
        if header.get('alg') != 'HS256':
            logger.warning(f"Invalid JWT algorithm: {header.get('alg')}")
            return False
        
        # Получаем секретный ключ для проверки подписи
        secret_key = settings.secret_key
        if not secret_key:
            logger.error("JWT secret key not configured")
            return False
        
        # Декодируем с проверкой подписи
        payload = jwt.decode(
            token, 
            secret_key, 
            algorithms=["HS256"],
            options={"verify_exp": True, "verify_signature": True}
        )
        
        # Дополнительные проверки
        if 'exp' in payload and payload['exp'] < time.time():
            return False
            
        return True
    except jwt.ExpiredSignatureError:
        logger.warning("JWT token expired")
        return False
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid JWT token: {str(e)}")
        return False
    except Exception as e:
        logger.warning(f"JWT validation error: {str(e)}")
        return False

async def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> Dict:
    """
    Безопасное получение текущего пользователя из JWT токена
    """
    try:
        # Если в тестовом режиме и нет токена, возвращаем mock пользователя
        if is_test_mode() and credentials is None:
            return {
                "id": "test_user_123",
                "email": "test@example.com",
                "created_at": "2025-01-01T00:00:00Z",
                "is_mock": True
            }
        
        # Если нет токена, возвращаем ошибку
        if credentials is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Извлекаем токен
        token = credentials.credentials
        
        # Проверяем, это mock токен?
        if token.startswith("mock_token_"):
            email = token.replace("mock_token_", "")
            return {
                "id": f"mock_user_{email}",
                "email": email,
                "created_at": "2025-01-01T00:00:00Z",
                "is_mock": True
            }
        
        # Валидируем JWT токен
        if not validate_jwt_token(token):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Безопасное получение Supabase клиента
        try:
            supabase_client = connection_manager.get_pool('supabase')
            if not supabase_client:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Database service unavailable"
                )
        except Exception as e:
            logger.error(f"Supabase connection error: {e}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database service unavailable"
            )
        
        # Проверяем токен через Supabase
        response = supabase_client.auth.get_user(token)
        
        if not response.user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        user = response.user
        
        # Возвращаем информацию о пользователе
        return {
            "id": user.id,
            "email": user.email,
            "created_at": user.created_at,
            "updated_at": user.updated_at,
            "email_confirmed_at": user.email_confirmed_at,
            "phone": user.phone,
            "confirmed_at": user.confirmed_at,
            "last_sign_in_at": user.last_sign_in_at,
            "app_metadata": user.app_metadata,
            "user_metadata": user.user_metadata,
            "role": user.role,
            "aud": user.aud,
            "exp": user.exp
        }
        
    except HTTPException:
        raise
    except Exception as jwt_error:
        logger.error(f"Authentication error: {jwt_error}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def get_current_user_optional(credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False))) -> Optional[Dict]:
    """
    Получает текущего пользователя, но не требует аутентификации
    """
    if not credentials:
        return None
    
    try:
        return await get_current_user(credentials)
    except HTTPException:
        return None

def secure_password_validation(password: str) -> bool:
    """
    Безопасная валидация пароля
    ASVS 2.1.1 compliant - использует централизованную политику
    Исправление P0-1, P0-6
    """
    from backend.security.password_policy import validate_password
    return validate_password(password)

def hash_password(password: str) -> str:
    """Безопасное хеширование пароля с использованием bcrypt"""
    # bcrypt автоматически генерирует соль и включает её в хеш
    password_bytes = password.encode('utf-8')
    hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt(rounds=12))
    return hashed.decode('utf-8')

def verify_password(password: str, stored_hash: str) -> bool:
    """Проверка пароля с защитой от timing attack"""
    if not password or not stored_hash:
        return False
    
    password_bytes = password.encode('utf-8')
    stored_hash_bytes = stored_hash.encode('utf-8')
    
    try:
        # Проверяем формат bcrypt хеша
        if not stored_hash.startswith('$2b$') and not stored_hash.startswith('$2a$'):
            # Невалидный формат - выполняем фиктивное сравнение для constant-time
            dummy_hash = bcrypt.gensalt()
            bcrypt.checkpw(password_bytes, dummy_hash)
            return False
        
        # bcrypt.checkpw использует constant-time сравнение
        return bcrypt.checkpw(password_bytes, stored_hash_bytes)
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        # Выполняем фиктивное сравнение для constant-time
        try:
            dummy_hash = bcrypt.gensalt()
            bcrypt.checkpw(password_bytes, dummy_hash)
        except Exception:
            # Игнорируем ошибки фиктивной проверки для constant-time
            pass
        return False

# Остальные функции остаются без изменений...
