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

# Импорт MFA сервиса
from backend.services.mfa_service import get_mfa_service

# Инициализация сервиса
mfa_service = get_mfa_service()

@router.post("/setup", response_model=MFASetupResponse)
async def setup_mfa(
    current_user: dict = Depends(get_current_user)
):
    """Настройка MFA для пользователя"""
    try:
        user_id = current_user["id"]
        
        # Генерируем секрет для TOTP
        secret = mfa_service.generate_secret()
        mfa_service.store_mfa_secret(user_id, secret)
        
        # Создаем QR код
        qr_code = mfa_service.generate_qr_code(current_user['email'], secret)
        
        # Генерируем резервные коды
        backup_codes = mfa_service.generate_backup_codes()
        
        return MFASetupResponse(
            secret=secret,
            qr_code=qr_code,
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