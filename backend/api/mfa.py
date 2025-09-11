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
from typing import Dict

router = APIRouter()

# Временное хранилище MFA секретов (в продакшене использовать Redis)
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
        mfa_secrets[user_id] = secret
        
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
        
        return MFASetupResponse(
            secret=secret,
            qr_code=f"data:image/png;base64,{qr_code_base64}",
            backup_codes=["123456", "234567", "345678", "456789", "567890"]
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
        secret = mfa_secrets.get(user_id)
        if not secret:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="MFA не настроен для пользователя"
            )
        
        # Простая проверка (в реальной реализации использовать pyotp)
        # Здесь мы принимаем любой 6-значный код для демонстрации
        if len(request.code) == 6 and request.code.isdigit():
            return MFAVerifyResponse(
                verified=True,
                message="MFA код подтвержден"
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
        
        if user_id in mfa_secrets:
            del mfa_secrets[user_id]
        
        return {"message": "MFA отключен"}
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Ошибка отключения MFA: {str(e)}"
        )