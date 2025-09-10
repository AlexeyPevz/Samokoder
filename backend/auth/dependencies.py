from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from supabase import create_client, Client
from typing import Dict, Optional
from datetime import datetime
import logging

from config.settings import settings

logger = logging.getLogger(__name__)

# Supabase клиент для проверки токенов (с проверкой URL)
try:
    supabase: Client = create_client(
        settings.supabase_url, 
        settings.supabase_service_role_key  # Используем service role для проверки токенов
    )
except Exception as e:
    logger.warning(f"Supabase client creation failed: {e}")
    supabase = None

security = HTTPBearer()

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict:
    """
    Получает текущего пользователя из JWT токена
    """
    try:
        # Извлекаем токен
        token = credentials.credentials
        
        # Проверяем токен через Supabase
        if supabase is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Supabase service unavailable",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        response = supabase.auth.get_user(token)
        
        if not response.user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Недействительный токен",
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
        
    except Exception as jwt_error:
        # Supabase может возвращать разные типы ошибок
        if "expired" in str(jwt_error).lower():
            detail = "Токен истек"
        elif "invalid" in str(jwt_error).lower():
            detail = "Недействительный токен"
        else:
            detail = f"Ошибка аутентификации: {str(jwt_error)}"
            
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            headers={"WWW-Authenticate": "Bearer"},
        )

async def get_current_user_optional(credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False))) -> Optional[Dict]:
    """
    Получает текущего пользователя, но не требует аутентификации
    Возвращает None если пользователь не аутентифицирован
    """
    if not credentials:
        return None
    
    try:
        return await get_current_user(credentials)
    except HTTPException:
        return None

def require_subscription_tier(required_tier: str):
    """
    Декоратор для проверки уровня подписки пользователя
    """
    async def check_subscription(current_user: Dict = Depends(get_current_user)) -> Dict:
        try:
            # Получаем профиль пользователя из базы
            if supabase is None:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Supabase service unavailable"
                )
            
            response = supabase.table("profiles").select("subscription_tier").eq("id", current_user["id"]).single().execute()
            
            if not response.data:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Профиль пользователя не найден"
                )
            
            user_tier = response.data["subscription_tier"]
            
            # Определяем приоритет тарифов
            tier_priority = {
                "free": 0,
                "starter": 1,
                "professional": 2,
                "business": 3,
                "enterprise": 4
            }
            
            if tier_priority.get(user_tier, 0) < tier_priority.get(required_tier, 0):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Требуется тариф {required_tier} или выше. Ваш текущий тариф: {user_tier}"
                )
            
            return current_user
            
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Ошибка проверки подписки: {str(e)}"
            )
    
    return check_subscription

def require_api_credits(min_credits: float = 0.01):
    """
    Декоратор для проверки наличия API кредитов
    """
    async def check_credits(current_user: Dict = Depends(get_current_user)) -> Dict:
        try:
            # Получаем баланс кредитов пользователя
            if supabase is None:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Supabase service unavailable"
                )
            
            response = supabase.table("profiles").select("api_credits_balance").eq("id", current_user["id"]).single().execute()
            
            if not response.data:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Профиль пользователя не найден"
                )
            
            credits_balance = response.data["api_credits_balance"] or 0
            
            if credits_balance < min_credits:
                raise HTTPException(
                    status_code=status.HTTP_402_PAYMENT_REQUIRED,
                    detail=f"Недостаточно API кредитов. Требуется: {min_credits}, доступно: {credits_balance}"
                )
            
            return current_user
            
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Ошибка проверки кредитов: {str(e)}"
            )
    
    return check_credits

def validate_user_permissions(required_permissions: list):
    """
    Декоратор для проверки разрешений пользователя
    """
    async def check_permissions(current_user: Dict = Depends(get_current_user)) -> Dict:
        try:
            # Получаем профиль пользователя из базы
            if supabase is None:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Supabase service unavailable"
                )
            
            response = supabase.table("profiles").select("subscription_tier").eq("id", current_user["id"]).single().execute()
            
            if not response.data:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Профиль пользователя не найден"
                )
            
            user_tier = response.data["subscription_tier"]
            
            # Определяем разрешения для каждого тарифа
            tier_permissions = {
                "free": ["basic_chat", "view_files"],
                "starter": ["basic_chat", "view_files", "export_projects"],
                "professional": ["basic_chat", "view_files", "export_projects", "advanced_agents", "custom_models"],
                "business": ["basic_chat", "view_files", "export_projects", "advanced_agents", "custom_models", "team_collaboration"],
                "enterprise": ["basic_chat", "view_files", "export_projects", "advanced_agents", "custom_models", "team_collaboration", "priority_support"]
            }
            
            user_permissions = tier_permissions.get(user_tier, [])
            
            # Проверяем, есть ли у пользователя все необходимые разрешения
            missing_permissions = [perm for perm in required_permissions if perm not in user_permissions]
            
            if missing_permissions:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Недостаточно разрешений. Требуется: {missing_permissions}. Ваш тариф: {user_tier}"
                )
            
            return current_user
            
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Ошибка проверки разрешений: {str(e)}"
            )
    
    return check_permissions

def rate_limit(requests_per_minute: int = 60, requests_per_hour: int = 1000):
    """
    Декоратор для rate limiting с Redis поддержкой
    """
    async def check_rate_limit(
        request: Request,
        current_user: Dict = Depends(get_current_user)
    ) -> Dict:
        from backend.services.rate_limiter import rate_limiter
        
        # Получаем endpoint из запроса
        endpoint = request.url.path
        
        # Проверяем rate limit
        allowed, rate_info = await rate_limiter.check_rate_limit(
            user_id=current_user["id"],
            endpoint=endpoint,
            limit_per_minute=requests_per_minute,
            limit_per_hour=requests_per_hour
        )
        
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "message": "Rate limit exceeded",
                    "minute_requests": rate_info["minute_requests"],
                    "hour_requests": rate_info["hour_requests"],
                    "minute_limit": rate_info["minute_limit"],
                    "hour_limit": rate_info["hour_limit"],
                    "retry_after": 60 if not rate_info["minute_allowed"] else 3600
                },
                headers={
                    "Retry-After": str(60 if not rate_info["minute_allowed"] else 3600),
                    "X-RateLimit-Limit-Minute": str(rate_info["minute_limit"]),
                    "X-RateLimit-Limit-Hour": str(rate_info["hour_limit"]),
                    "X-RateLimit-Remaining-Minute": str(max(0, rate_info["minute_limit"] - rate_info["minute_requests"])),
                    "X-RateLimit-Remaining-Hour": str(max(0, rate_info["hour_limit"] - rate_info["hour_requests"]))
                }
            )
        
        return current_user
    
    return check_rate_limit