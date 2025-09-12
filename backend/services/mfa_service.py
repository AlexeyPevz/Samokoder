"""
MFA Service
Сервис для управления многофакторной аутентификацией
"""

import logging
import secrets
import base64
import qrcode
import io
from typing import Dict, Optional
import redis
from config.settings import settings

logger = logging.getLogger(__name__)

class MFAService:
    """Сервис для управления MFA"""
    
    def __init__(self):
        self.redis_client = redis.Redis.from_url(settings.redis_url) if hasattr(settings, 'redis_url') else None
        self._fallback_secrets: Dict[str, str] = {}
    
    def store_mfa_secret(self, user_id: str, secret: str):
        """Безопасное хранение MFA секрета"""
        if self.redis_client:
            self.redis_client.setex(f"mfa_secret:{user_id}", 3600, secret)  # TTL 1 час
            logger.debug(f"Stored MFA secret for user {user_id} in Redis")
        else:
            # Fallback для разработки
            self._fallback_secrets[user_id] = secret
            logger.debug(f"Stored MFA secret for user {user_id} in memory (fallback)")
    
    def get_mfa_secret(self, user_id: str) -> Optional[str]:
        """Получение MFA секрета"""
        if self.redis_client:
            secret = self.redis_client.get(f"mfa_secret:{user_id}")
            return secret.decode('utf-8') if secret else None
        else:
            # Fallback для разработки
            return self._fallback_secrets.get(user_id)
    
    def delete_mfa_secret(self, user_id: str):
        """Удаление MFA секрета"""
        if self.redis_client:
            self.redis_client.delete(f"mfa_secret:{user_id}")
            logger.debug(f"Deleted MFA secret for user {user_id} from Redis")
        else:
            # Fallback для разработки
            self._fallback_secrets.pop(user_id, None)
            logger.debug(f"Deleted MFA secret for user {user_id} from memory (fallback)")
    
    def generate_secret(self) -> str:
        """Генерация нового MFA секрета"""
        return base64.b32encode(secrets.token_bytes(20)).decode('utf-8')
    
    def generate_backup_codes(self) -> list[str]:
        """Генерация резервных кодов"""
        return [secrets.token_hex(4).upper() for _ in range(10)]
    
    def generate_qr_code(self, user_id: str, secret: str) -> str:
        """Генерация QR кода для настройки MFA"""
        qr_data = f"otpauth://totp/Samokoder:{user_id}?secret={secret}&issuer=Samokoder"
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(qr_data)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Конвертируем в base64
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        img_str = base64.b64encode(buffer.getvalue()).decode()
        
        return f"data:image/png;base64,{img_str}"

# Глобальный экземпляр сервиса
_mfa_service: Optional[MFAService] = None

def get_mfa_service() -> MFAService:
    """Получить экземпляр MFA сервиса"""
    global _mfa_service
    if _mfa_service is None:
        _mfa_service = MFAService()
    return _mfa_service