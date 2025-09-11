"""
API ключи пользователей
Управление зашифрованными API ключами для AI провайдеров
"""

from fastapi import APIRouter, Depends, HTTPException, status
from backend.auth.dependencies import get_current_user
from backend.models.requests import APIKeyCreateRequest
from backend.models.responses import APIKeyResponse, APIKeyListResponse
from backend.services.encryption_service import get_encryption_service
from supabase import create_client, Client
from typing import List, Dict
import uuid
import logging

logger = logging.getLogger(__name__)

router = APIRouter()

# Получаем клиент Supabase
try:
    from config.settings import settings
    supabase: Client = create_client(
        settings.supabase_url,
        settings.supabase_service_role_key
    )
except Exception as e:
    logger.warning(f"Supabase не настроен: {e}")
    supabase = None

@router.post("/", response_model=APIKeyResponse)
async def create_api_key(
    request: APIKeyCreateRequest,
    current_user: dict = Depends(get_current_user)
):
    """Создать новый API ключ"""
    try:
        if not supabase:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Supabase недоступен"
            )
        
        user_id = current_user["id"]
        encryption_service = get_encryption_service()
        
        # Шифруем API ключ
        encrypted_key = encryption_service.encrypt_api_key(request.api_key, user_id)
        key_last_4 = encryption_service.get_key_last_4(request.api_key)
        
        # Создаем запись в базе данных
        api_key_record = {
            "id": str(uuid.uuid4()),
            "user_id": user_id,
            "provider_name": request.provider.value,
            "key_name": request.key_name,
            "api_key_encrypted": encrypted_key,
            "api_key_last_4": key_last_4,
            "is_active": True
        }
        
        response = supabase.table("user_api_keys").insert(api_key_record).execute()
        
        if not response.data:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Ошибка сохранения API ключа"
            )
        
        logger.info(f"API ключ создан для пользователя {user_id}, провайдер {request.provider.value}")
        
        return APIKeyResponse(
            id=api_key_record["id"],
            provider=request.provider.value,
            key_name=request.key_name,
            key_last_4=key_last_4,
            is_active=True,
            created_at=response.data[0]["created_at"]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Ошибка создания API ключа: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Ошибка создания API ключа: {str(e)}"
        )

@router.get("/", response_model=APIKeyListResponse)
async def get_api_keys(
    current_user: dict = Depends(get_current_user)
):
    """Получить список API ключей пользователя"""
    try:
        if not supabase:
            return APIKeyListResponse(keys=[], total_count=0)
        
        user_id = current_user["id"]
        
        response = supabase.table("user_api_keys").select("*").eq("user_id", user_id).order("created_at", desc=True).execute()
        
        if not response.data:
            return APIKeyListResponse(keys=[], total_count=0)
        
        # Формируем ответ (без зашифрованных ключей)
        keys = []
        for row in response.data:
            keys.append(APIKeyResponse(
                id=row["id"],
                provider=row["provider_name"],
                key_name=row["key_name"],
                key_last_4=row["api_key_last_4"],
                is_active=row["is_active"],
                created_at=row["created_at"]
            ))
        
        return APIKeyListResponse(keys=keys, total_count=len(keys))
        
    except Exception as e:
        logger.error(f"Ошибка получения API ключей: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Ошибка получения API ключей: {str(e)}"
        )

@router.get("/{key_id}", response_model=APIKeyResponse)
async def get_api_key(
    key_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Получить конкретный API ключ"""
    try:
        if not supabase:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Supabase недоступен"
            )
        
        user_id = current_user["id"]
        
        response = supabase.table("user_api_keys").select("*").eq("id", key_id).eq("user_id", user_id).single().execute()
        
        if not response.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="API ключ не найден"
            )
        
        row = response.data
        
        return APIKeyResponse(
            id=row["id"],
            provider=row["provider_name"],
            key_name=row["key_name"],
            key_last_4=row["api_key_last_4"],
            is_active=row["is_active"],
            created_at=row["created_at"]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Ошибка получения API ключа: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Ошибка получения API ключа: {str(e)}"
        )

@router.put("/{key_id}/toggle")
async def toggle_api_key(
    key_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Включить/выключить API ключ"""
    try:
        if not supabase:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Supabase недоступен"
            )
        
        user_id = current_user["id"]
        
        # Получаем текущее состояние ключа
        response = supabase.table("user_api_keys").select("is_active").eq("id", key_id).eq("user_id", user_id).single().execute()
        
        if not response.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="API ключ не найден"
            )
        
        current_status = response.data["is_active"]
        new_status = not current_status
        
        # Обновляем статус
        supabase.table("user_api_keys").update({"is_active": new_status}).eq("id", key_id).execute()
        
        logger.info(f"API ключ {key_id} {'включен' if new_status else 'выключен'}")
        
        return {
            "message": f"API ключ {'включен' if new_status else 'выключен'}",
            "is_active": new_status
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Ошибка переключения API ключа: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Ошибка переключения API ключа: {str(e)}"
        )

@router.delete("/{key_id}")
async def delete_api_key(
    key_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Удалить API ключ"""
    try:
        if not supabase:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Supabase недоступен"
            )
        
        user_id = current_user["id"]
        
        # Проверяем, что ключ принадлежит пользователю
        response = supabase.table("user_api_keys").select("id").eq("id", key_id).eq("user_id", user_id).single().execute()
        
        if not response.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="API ключ не найден"
            )
        
        # Удаляем ключ
        supabase.table("user_api_keys").delete().eq("id", key_id).execute()
        
        logger.info(f"API ключ {key_id} удален")
        
        return {"message": "API ключ удален"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Ошибка удаления API ключа: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Ошибка удаления API ключа: {str(e)}"
        )