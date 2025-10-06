"""
ASVS 2.2.1: Управление блокировкой аккаунтов
Исправление P0-2
"""
from datetime import datetime, timedelta
from typing import Dict, Tuple, Optional, List
import logging
import asyncio

logger = logging.getLogger(__name__)

class AccountLockoutManager:
    """
    ASVS 2.2.1: Управление блокировкой аккаунтов после неудачных попыток входа
    
    Требования ASVS:
    - Блокировка после 5 неудачных попыток
    - Время блокировки: 30 минут
    - Логирование всех попыток
    - Сброс счётчика после успешного входа
    """
    
    def __init__(self):
        self._failed_attempts: Dict[str, List[datetime]] = {}
        self._lockout_times: Dict[str, datetime] = {}
        self._lock = asyncio.Lock()  # Для thread-safety
        
        # ASVS 2.2.1 требования
        self.max_attempts = 5  # Максимум неудачных попыток
        self.lockout_duration = timedelta(minutes=30)  # Время блокировки
        self.attempt_window = timedelta(minutes=15)  # Окно для подсчёта попыток
        
    async def record_failed_attempt(self, email: str) -> Tuple[bool, int, Optional[datetime]]:
        """
        Записывает неудачную попытку входа
        
        Args:
            email: Email пользователя
            
        Returns:
            (is_locked, attempts_left, unlock_time)
            - is_locked: True если аккаунт заблокирован
            - attempts_left: Сколько попыток осталось
            - unlock_time: Время разблокировки (если заблокирован)
        """
        async with self._lock:
            now = datetime.now()
            
            # Инициализируем список попыток
            if email not in self._failed_attempts:
                self._failed_attempts[email] = []
            
            # Удаляем старые попытки (вне окна)
            self._failed_attempts[email] = [
                attempt for attempt in self._failed_attempts[email]
                if now - attempt < self.attempt_window
            ]
            
            # Добавляем новую попытку
            self._failed_attempts[email].append(now)
            
            attempts = len(self._failed_attempts[email])
            
            # Проверяем, достигли ли лимита
            if attempts >= self.max_attempts:
                unlock_time = now + self.lockout_duration
                self._lockout_times[email] = unlock_time
                
                logger.warning(
                    f"Account locked due to {attempts} failed attempts",
                    extra={
                        "email_prefix": email[:3] + "***",
                        "attempts": attempts,
                        "unlock_time": unlock_time.isoformat(),
                        "event": "account_locked"
                    }
                )
                
                return True, 0, unlock_time
            
            attempts_left = self.max_attempts - attempts
            
            logger.info(
                f"Failed login attempt recorded",
                extra={
                    "email_prefix": email[:3] + "***",
                    "attempts": attempts,
                    "attempts_left": attempts_left,
                    "event": "failed_login_attempt"
                }
            )
            
            return False, attempts_left, None
    
    async def is_locked(self, email: str) -> Tuple[bool, Optional[datetime]]:
        """
        Проверяет, заблокирован ли аккаунт
        
        Args:
            email: Email пользователя
            
        Returns:
            (is_locked, unlock_time)
            - is_locked: True если аккаунт заблокирован
            - unlock_time: Время разблокировки
        """
        async with self._lock:
            now = datetime.now()
            
            # Проверяем явную блокировку
            if email in self._lockout_times:
                unlock_time = self._lockout_times[email]
                
                if now < unlock_time:
                    logger.info(
                        f"Account is locked",
                        extra={
                            "email_prefix": email[:3] + "***",
                            "unlock_time": unlock_time.isoformat(),
                            "event": "locked_account_check"
                        }
                    )
                    return True, unlock_time
                else:
                    # Время блокировки истекло - разблокируем
                    del self._lockout_times[email]
                    if email in self._failed_attempts:
                        del self._failed_attempts[email]
                    
                    logger.info(
                        f"Account auto-unlocked after timeout",
                        extra={
                            "email_prefix": email[:3] + "***",
                            "event": "account_auto_unlocked"
                        }
                    )
                    return False, None
            
            # Проверяем количество попыток
            if email in self._failed_attempts:
                recent_attempts = [
                    attempt for attempt in self._failed_attempts[email]
                    if now - attempt < self.attempt_window
                ]
                
                if len(recent_attempts) >= self.max_attempts:
                    # Блокируем
                    unlock_time = max(recent_attempts) + self.lockout_duration
                    self._lockout_times[email] = unlock_time
                    
                    logger.warning(
                        f"Account locked due to threshold",
                        extra={
                            "email_prefix": email[:3] + "***",
                            "attempts": len(recent_attempts),
                            "unlock_time": unlock_time.isoformat(),
                            "event": "account_locked"
                        }
                    )
                    
                    return True, unlock_time
            
            return False, None
    
    async def reset_attempts(self, email: str) -> None:
        """
        Сбрасывает счётчик попыток после успешного входа
        
        Args:
            email: Email пользователя
        """
        async with self._lock:
            if email in self._failed_attempts:
                attempts_before = len(self._failed_attempts[email])
                del self._failed_attempts[email]
                
                logger.info(
                    f"Login attempts counter reset",
                    extra={
                        "email_prefix": email[:3] + "***",
                        "attempts_before_reset": attempts_before,
                        "event": "attempts_reset"
                    }
                )
            
            if email in self._lockout_times:
                del self._lockout_times[email]
                
                logger.info(
                    f"Account lockout removed",
                    extra={
                        "email_prefix": email[:3] + "***",
                        "event": "lockout_removed"
                    }
                )
    
    async def get_lockout_info(self, email: str) -> Dict:
        """
        Получает информацию о блокировке аккаунта
        
        Args:
            email: Email пользователя
            
        Returns:
            Dict с информацией о блокировке
        """
        async with self._lock:
            now = datetime.now()
            
            info = {
                "email": email[:3] + "***",  # Маскируем email
                "is_locked": False,
                "failed_attempts": 0,
                "attempts_left": self.max_attempts,
                "unlock_time": None
            }
            
            # Проверяем блокировку
            is_locked, unlock_time = await self.is_locked(email)
            info["is_locked"] = is_locked
            info["unlock_time"] = unlock_time.isoformat() if unlock_time else None
            
            # Считаем попытки
            if email in self._failed_attempts:
                recent_attempts = [
                    attempt for attempt in self._failed_attempts[email]
                    if now - attempt < self.attempt_window
                ]
                info["failed_attempts"] = len(recent_attempts)
                info["attempts_left"] = max(0, self.max_attempts - len(recent_attempts))
            
            return info
    
    async def cleanup_expired_locks(self) -> int:
        """
        Очищает истекшие блокировки
        
        Returns:
            Количество очищенных блокировок
        """
        async with self._lock:
            now = datetime.now()
            expired = []
            
            for email, unlock_time in self._lockout_times.items():
                if now >= unlock_time:
                    expired.append(email)
            
            for email in expired:
                del self._lockout_times[email]
                if email in self._failed_attempts:
                    del self._failed_attempts[email]
            
            if expired:
                logger.info(
                    f"Cleaned up {len(expired)} expired locks",
                    extra={
                        "count": len(expired),
                        "event": "cleanup_expired_locks"
                    }
                )
            
            return len(expired)

# Глобальный экземпляр
lockout_manager = AccountLockoutManager()

# Удобные функции
async def record_failed_login(email: str) -> Tuple[bool, int, Optional[datetime]]:
    """Записывает неудачную попытку входа"""
    return await lockout_manager.record_failed_attempt(email)

async def is_account_locked(email: str) -> Tuple[bool, Optional[datetime]]:
    """Проверяет блокировку аккаунта"""
    return await lockout_manager.is_locked(email)

async def reset_login_attempts(email: str) -> None:
    """Сбрасывает счётчик попыток"""
    await lockout_manager.reset_attempts(email)

async def get_account_lockout_info(email: str) -> Dict:
    """Получает информацию о блокировке"""
    return await lockout_manager.get_lockout_info(email)
