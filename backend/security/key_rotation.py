"""
Key Rotation Manager для автоматической ротации ключей
"""
import secrets
import base64
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from backend.security.secrets_manager import secrets_manager

logger = logging.getLogger(__name__)

class KeyRotationManager:
    """Менеджер ротации ключей"""
    
    def __init__(self):
        self.rotation_schedule = {
            'api_encryption_key': timedelta(days=90),
            'jwt_secret': timedelta(days=30),
            'csrf_secret': timedelta(days=60),
            'openrouter_api_key': timedelta(days=180),
            'openai_api_key': timedelta(days=180),
            'anthropic_api_key': timedelta(days=180),
            'groq_api_key': timedelta(days=180)
        }
        self.rotation_history: Dict[str, datetime] = {}
    
    def generate_secure_key(self, key_type: str, length: int = 32) -> str:
        """Генерировать криптографически стойкий ключ"""
        if key_type in ['api_encryption_key', 'jwt_secret', 'csrf_secret']:
            # Для ключей шифрования используем base64
            return base64.urlsafe_b64encode(secrets.token_bytes(length)).decode('utf-8').rstrip('=')
        else:
            # Для API ключей используем hex
            return secrets.token_hex(length)
    
    async def check_rotation_needed(self) -> List[str]:
        """Проверить, какие ключи нуждаются в ротации"""
        keys_to_rotate = []
        
        for key_name, rotation_period in self.rotation_schedule.items():
            last_rotation = await self.get_last_rotation_date(key_name)
            if last_rotation is None:
                # Ключ никогда не ротировался, добавляем в список
                keys_to_rotate.append(key_name)
            elif datetime.now() - last_rotation > rotation_period:
                keys_to_rotate.append(key_name)
        
        return keys_to_rotate
    
    async def get_last_rotation_date(self, key_name: str) -> Optional[datetime]:
        """Получить дату последней ротации ключа"""
        if key_name in self.rotation_history:
            return self.rotation_history[key_name]
        
        # Попробуем получить из секретов
        rotation_date_str = await secrets_manager.get_secret(f"{key_name}_last_rotation")
        if rotation_date_str:
            try:
                return datetime.fromisoformat(rotation_date_str)
            except ValueError:
                logger.warning(f"Invalid rotation date format for {key_name}")
        
        return None
    
    async def rotate_key(self, key_name: str, rotated_by: str = "system") -> bool:
        """Ротировать конкретный ключ"""
        try:
            logger.info(f"Rotating key: {key_name}")
            
            # Генерируем новый ключ
            if key_name in ['api_encryption_key', 'jwt_secret', 'csrf_secret']:
                new_key = self.generate_secure_key(key_name, 32)
            else:
                new_key = self.generate_secure_key(key_name, 24)
            
            # Сохраняем новый ключ
            success = await secrets_manager.set_secret(key_name, new_key)
            if not success:
                logger.error(f"Failed to save new key for {key_name}")
                return False
            
            # Обновляем дату ротации
            rotation_date = datetime.now()
            self.rotation_history[key_name] = rotation_date
            await secrets_manager.set_secret(f"{key_name}_last_rotation", rotation_date.isoformat())
            
            # Логируем ротацию
            await self.log_key_rotation(key_name, rotated_by, rotation_date)
            
            logger.info(f"Successfully rotated key: {key_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to rotate key {key_name}: {e}")
            return False
    
    async def rotate_all_expired_keys(self, rotated_by: str = "system") -> Dict[str, bool]:
        """Ротировать все просроченные ключи"""
        keys_to_rotate = await self.check_rotation_needed()
        results = {}
        
        for key_name in keys_to_rotate:
            results[key_name] = await self.rotate_key(key_name, rotated_by)
        
        return results
    
    async def log_key_rotation(self, key_name: str, rotated_by: str, rotation_date: datetime):
        """Логировать ротацию ключа"""
        log_entry = {
            "event": "key_rotation",
            "key_name": key_name,
            "rotated_by": rotated_by,
            "rotation_date": rotation_date.isoformat(),
            "severity": "info"
        }
        
        # Сохраняем в лог ротации
        rotation_log = await secrets_manager.get_secret("key_rotation_log") or "[]"
        try:
            import json
            logs = json.loads(rotation_log)
            logs.append(log_entry)
            await secrets_manager.set_secret("key_rotation_log", json.dumps(logs, indent=2))
        except Exception as e:
            logger.warning(f"Failed to save rotation log: {e}")
        
        # Логируем в основной лог
        logger.info(f"Key rotated: {key_name} by {rotated_by} at {rotation_date}")
    
    async def get_rotation_status(self) -> Dict[str, Dict[str, any]]:
        """Получить статус ротации всех ключей"""
        status = {}
        
        for key_name, rotation_period in self.rotation_schedule.items():
            last_rotation = await self.get_last_rotation_date(key_name)
            next_rotation = None
            
            if last_rotation:
                next_rotation = last_rotation + rotation_period
                days_until_rotation = (next_rotation - datetime.now()).days
            else:
                days_until_rotation = None
            
            status[key_name] = {
                "last_rotation": last_rotation.isoformat() if last_rotation else None,
                "next_rotation": next_rotation.isoformat() if next_rotation else None,
                "days_until_rotation": days_until_rotation,
                "rotation_period_days": rotation_period.days,
                "needs_rotation": days_until_rotation is None or days_until_rotation <= 0
            }
        
        return status
    
    async def schedule_rotation(self, key_name: str, rotation_date: datetime) -> bool:
        """Запланировать ротацию ключа на определенную дату"""
        try:
            await secrets_manager.set_secret(f"{key_name}_scheduled_rotation", rotation_date.isoformat())
            logger.info(f"Scheduled rotation for {key_name} on {rotation_date}")
            return True
        except Exception as e:
            logger.error(f"Failed to schedule rotation for {key_name}: {e}")
            return False
    
    async def cancel_scheduled_rotation(self, key_name: str) -> bool:
        """Отменить запланированную ротацию"""
        try:
            await secrets_manager.delete_secret(f"{key_name}_scheduled_rotation")
            logger.info(f"Cancelled scheduled rotation for {key_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to cancel scheduled rotation for {key_name}: {e}")
            return False

# Глобальный экземпляр
key_rotation_manager = KeyRotationManager()