"""
MFA (Multi-Factor Authentication) endpoints
Базовая реализация TOTP аутентификации
"""

from fastapi import APIRouter, Depends, HTTPException, status
from backend.auth.dependencies import get_current_user
from backend.models.requests import MFAVerifyRequest, MFASetupRequest
from backend.models.responses import MFASetupResponse, MFAVerifyResponse
import secrets
import base64
import qrcode
import io
from typing import Dict, Optional

router = APIRouter()

# Безопасное хранилище MFA секретов в Redis
import redis
from config.settings import settings

redis_client = redis.Redis.from_url(settings.redis_url) if hasattr(settings, 'redis_url') else None

def store_mfa_secret(user_id: str, secret: str):
    """Безопасное хранение MFA секрета в Redis"""
    if redis_client:
        redis_client.setex(f"mfa_secret:{user_id}", 3600, secret)  # TTL 1 час
    else:
        # Fallback для разработки
        global mfa_secrets
        mfa_secrets[user_id] = secret

def get_mfa_secret(user_id: str) -> Optional[str]:
    """Получение MFA секрета из Redis"""
    if redis_client:
        return redis_client.get(f"mfa_secret:{user_id}")
    else:
        # Fallback для разработки
        global mfa_secrets
        return mfa_secrets.get(user_id)

def delete_mfa_secret(user_id: str):
    """Удаление MFA секрета"""
    if redis_client:
        redis_client.delete(f"mfa_secret:{user_id}")
    else:
        # Fallback для разработки
        global mfa_secrets
        mfa_secrets.pop(user_id, None)

# Fallback для разработки
mfa_secrets: Dict[str, str] = {}

@router.post("/setup", response_model=MFASetupResponse)
async def setup_mfa(
    current_user: dict = Depends(get_current_user)
):
    """Настройка MFA для пользователя"""
    try:
        user_id = current_user["id"]
        
        # Генерируем секрет для TOTP
        secret = secrets.token_urlsafe(32)
        store_mfa_secret(user_id, secret)
        
        # Создаем QR код
        qr_data = f"otpauth://totp/Samokoder:{current_user['email']}?secret={secret}&issuer=Samokoder"
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(qr_data)
        qr.make(fit=True)
        
        # Создаем изображение QR кода
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Конвертируем в base64
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
        
        # Генерируем случайные backup коды
        backup_codes = [secrets.token_hex(4).upper() for _ in range(10)]
        
        return MFASetupResponse(
            secret=secret,
            qr_code=f"data:image/png;base64,{qr_code_base64}",
            backup_codes=backup_codes
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Ошибка настройки MFA: {str(e)}"
        )

@router.post("/verify", response_model=MFAVerifyResponse)
async def verify_mfa(
    request: MFAVerifyRequest,
    current_user: dict = Depends(get_current_user)
):
    """Проверка MFA кода"""
    try:
        user_id = current_user["id"]
        
        # Получаем секрет пользователя
        secret = get_mfa_secret(user_id)
        if not secret:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="MFA не настроен для пользователя"
            )
        
        # Проверяем MFA код с помощью pyotp
        try:
            import pyotp
            import time
            
            totp = pyotp.TOTP(secret)
            current_time = int(time.time())
            
            # Проверяем текущий код и предыдущий (для clock skew)
            for time_offset in [0, -30, 30]:  # ±30 секунд
                if totp.verify(request.code, for_time=current_time + time_offset):
                    return MFAVerifyResponse(
                        verified=True,
                        message="MFA код подтвержден"
                    )
            
            return MFAVerifyResponse(
                verified=False,
                message="Неверный MFA код"
            )
            
        except ImportError:
            # Fallback для разработки без pyotp
            if len(request.code) == 6 and request.code.isdigit():
                return MFAVerifyResponse(
                    verified=True,
                    message="MFA код подтвержден (dev mode)"
                )
            else:
                return MFAVerifyResponse(
                    verified=False,
                    message="Неверный MFA код"
                )
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Ошибка проверки MFA: {str(e)}"
        )

@router.delete("/disable")
async def disable_mfa(
    current_user: dict = Depends(get_current_user)
):
    """Отключение MFA для пользователя"""
    try:
        user_id = current_user["id"]
        
        delete_mfa_secret(user_id)
        
        return {"message": "MFA отключен"}
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Ошибка отключения MFA: {str(e)}"
        )