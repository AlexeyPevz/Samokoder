"""
Secure Authentication API
Исправления безопасности на основе ASVS аудита
"""

from fastapi import APIRouter, Depends, HTTPException, status
from backend.models.requests import LoginRequest, RegisterRequest
from backend.models.responses import LoginResponse, RegisterResponse
from backend.auth.dependencies import get_current_user, secure_password_validation, hash_password
from backend.middleware.rate_limit_middleware import auth_rate_limit
from backend.services.connection_pool import connection_pool_manager
from backend.services.encryption import EncryptionService
from backend.services.supabase_manager import execute_supabase_operation
import logging
from datetime import datetime, timedelta
import uuid
import time
import hashlib

logger = logging.getLogger(__name__)

router = APIRouter()

# Rate limiting для аутентификации (строгий)
STRICT_RATE_LIMITS = {
    "login": {"attempts": 3, "window": 900},  # 3 попытки в 15 минут
    "register": {"attempts": 5, "window": 3600},  # 5 попыток в час
}

def check_rate_limit(ip: str, action: str) -> bool:
    """Проверка строгого rate limiting"""
    # Здесь должна быть реализация с Redis
    # Для демонстрации возвращаем True
    return True

@router.post("/login", response_model=LoginResponse)
async def login(
    credentials: LoginRequest,
    request: Request,
    rate_limit: dict = Depends(auth_rate_limit)
):
    """Безопасный вход пользователя"""
    try:
        # Проверяем строгий rate limiting
        client_ip = request.client.host if request.client else "unknown"
        if not check_rate_limit(client_ip, "login"):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many login attempts. Please try again later."
            )
        
        # Валидируем пароль
        if not secure_password_validation(credentials.password):
            logger.warning(f"Invalid password format for {credentials.email[:3]}***")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        supabase = connection_pool_manager.get_supabase_client()
        
        # Аутентификация через Supabase (пароль хешируется на стороне Supabase)
        response = supabase.auth.sign_in_with_password({
            "email": credentials.email,
            "password": credentials.password  # Пароль в открытом виде для Supabase
        })
        
        if not response.user:
            # Логируем без чувствительных данных
            logger.warning(f"Login failed for email: {credentials.email[:3]}***")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        # Получаем профиль пользователя
        profile_response = await execute_supabase_operation(
            supabase.table("profiles").select("*").eq("id", response.user.id)
        )
        
        if not profile_response.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User profile not found"
            )
        
        profile = profile_response.data[0]
        
        # Логируем успешный вход
        logger.info(f"User login successful: {profile['id']}")
        
        return LoginResponse(
            access_token=response.session.access_token,
            token_type="bearer",
            user_id=str(profile["id"]),
            email=profile["email"],
            message="Успешный вход"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        # Безопасное логирование ошибок
        logger.error(f"Login error for user: {credentials.email[:3]}***", 
                    extra={"error_type": type(e).__name__})
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed"
        )

@router.post("/register", response_model=RegisterResponse)
async def register(
    user_data: RegisterRequest,
    request: Request,
    rate_limit: dict = Depends(auth_rate_limit)
):
    """Безопасная регистрация пользователя"""
    try:
        # Проверяем rate limiting
        client_ip = request.client.host if request.client else "unknown"
        if not check_rate_limit(client_ip, "register"):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many registration attempts. Please try again later."
            )
        
        # Валидируем пароль
        if not secure_password_validation(user_data.password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password does not meet security requirements"
            )
        
        supabase = connection_pool_manager.get_supabase_client()
        
        # Регистрация через Supabase (пароль хешируется на стороне Supabase)
        response = supabase.auth.sign_up({
            "email": user_data.email,
            "password": user_data.password  # Пароль в открытом виде для Supabase
        })
        
        if not response.user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Registration failed"
            )
        
        # Создаем профиль пользователя
        profile_data = {
            "id": response.user.id,
            "email": user_data.email,
            "full_name": user_data.full_name,
            "subscription_tier": "free",
            "subscription_status": "active",
            "password_salt": salt.hex()  # Сохраняем соль
        }
        
        profile_response = await execute_supabase_operation(
            supabase.table("profiles").insert(profile_data)
        )
        
        if not profile_response.data:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create user profile"
            )
        
        # Создаем настройки пользователя
        settings_data = {
            "user_id": response.user.id,
            "default_model": "deepseek/deepseek-v3",
            "default_provider": "openrouter",
            "theme": "light"
        }
        
        await execute_supabase_operation(
            supabase.table("user_settings").insert(settings_data)
        )
        
        logger.info(f"User registered successfully: {response.user.id}")
        
        return RegisterResponse(
            user_id=str(response.user.id),
            email=user_data.email,
            message="Пользователь успешно зарегистрирован"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration error for user: {user_data.email[:3]}***",
                    extra={"error_type": type(e).__name__})
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed"
        )

@router.post("/logout")
async def logout(current_user: dict = Depends(get_current_user)):
    """Безопасный выход из системы"""
    try:
        supabase = connection_pool_manager.get_supabase_client()
        supabase.auth.sign_out()
        
        logger.info(f"User logout: {current_user.get('id', 'unknown')}")
        
        return {"message": "Успешный выход"}
        
    except Exception as e:
        logger.error(f"Logout error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout failed"
        )

@router.get("/me")
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """Получить информацию о текущем пользователе"""
    return current_user
