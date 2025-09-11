"""
Безопасное управление сессиями
Защита от session fixation, hijacking и других атак
"""

import secrets
import time
import hashlib
import hmac
from typing import Dict, Optional, Set, List
from datetime import datetime, timedelta
import logging
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class SessionState(Enum):
    """Состояния сессии"""
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    SUSPICIOUS = "suspicious"

@dataclass
class SessionData:
    """Данные сессии"""
    session_id: str
    user_id: str
    created_at: datetime
    last_activity: datetime
    ip_address: str
    user_agent: str
    state: SessionState
    csrf_token: str
    refresh_count: int = 0
    suspicious_activity: int = 0

class SecureSessionManager:
    """Безопасный менеджер сессий"""
    
    def __init__(self, secret_key: str, session_timeout: int = 3600):
        self.secret_key = secret_key.encode()
        self.session_timeout = session_timeout
        self.sessions: Dict[str, SessionData] = {}
        self.user_sessions: Dict[str, Set[str]] = {}  # user_id -> set of session_ids
        self.revoked_sessions: Set[str] = set()
        
        # Настройки безопасности
        self.max_sessions_per_user = 5
        self.max_inactive_time = 1800  # 30 минут
        self.csrf_token_timeout = 3600  # 1 час
        self.suspicious_threshold = 3
    
    def create_session(self, user_id: str, ip_address: str, user_agent: str) -> str:
        """Создает новую безопасную сессию"""
        # Проверяем лимит сессий для пользователя
        if user_id in self.user_sessions:
            if len(self.user_sessions[user_id]) >= self.max_sessions_per_user:
                # Удаляем самую старую сессию
                oldest_session = min(
                    self.user_sessions[user_id],
                    key=lambda sid: self.sessions[sid].created_at
                )
                self.revoke_session(oldest_session)
        
        # Генерируем уникальный session ID
        session_id = self._generate_session_id()
        
        # Генерируем CSRF токен
        csrf_token = self._generate_csrf_token(session_id)
        
        # Создаем данные сессии
        now = datetime.now()
        session_data = SessionData(
            session_id=session_id,
            user_id=user_id,
            created_at=now,
            last_activity=now,
            ip_address=ip_address,
            user_agent=user_agent,
            state=SessionState.ACTIVE,
            csrf_token=csrf_token
        )
        
        # Сохраняем сессию
        self.sessions[session_id] = session_data
        
        if user_id not in self.user_sessions:
            self.user_sessions[user_id] = set()
        self.user_sessions[user_id].add(session_id)
        
        logger.info(f"Created session {session_id} for user {user_id}")
        return session_id
    
    def validate_session(self, session_id: str, ip_address: str, user_agent: str) -> bool:
        """Валидирует сессию"""
        if not session_id or session_id in self.revoked_sessions:
            return False
        
        session_data = self.sessions.get(session_id)
        if not session_data:
            return False
        
        # Проверяем состояние сессии
        if session_data.state != SessionState.ACTIVE:
            return False
        
        # Проверяем время жизни сессии
        if self._is_session_expired(session_data):
            session_data.state = SessionState.EXPIRED
            return False
        
        # Проверяем IP адрес (может измениться при мобильном интернете)
        if session_data.ip_address != ip_address:
            logger.warning(f"IP address changed for session {session_id}")
            session_data.suspicious_activity += 1
        
        # Проверяем User-Agent
        if session_data.user_agent != user_agent:
            logger.warning(f"User-Agent changed for session {session_id}")
            session_data.suspicious_activity += 1
        
        # Проверяем подозрительную активность
        if session_data.suspicious_activity >= self.suspicious_threshold:
            session_data.state = SessionState.SUSPICIOUS
            logger.warning(f"Session {session_id} marked as suspicious")
            return False
        
        # Обновляем время последней активности
        session_data.last_activity = datetime.now()
        
        return True
    
    def validate_csrf_token(self, session_id: str, csrf_token: str) -> bool:
        """Валидирует CSRF токен"""
        session_data = self.sessions.get(session_id)
        if not session_data:
            return False
        
        if session_data.state != SessionState.ACTIVE:
            return False
        
        # Проверяем CSRF токен
        expected_token = self._generate_csrf_token(session_id)
        return hmac.compare_digest(csrf_token, expected_token)
    
    def refresh_session(self, session_id: str) -> Optional[str]:
        """Обновляет сессию"""
        session_data = self.sessions.get(session_id)
        if not session_data or session_data.state != SessionState.ACTIVE:
            return None
        
        # Проверяем лимит обновлений
        if session_data.refresh_count >= 10:
            logger.warning(f"Session {session_id} exceeded refresh limit")
            self.revoke_session(session_id)
            return None
        
        # Обновляем CSRF токен
        new_csrf_token = self._generate_csrf_token(session_id)
        session_data.csrf_token = new_csrf_token
        session_data.refresh_count += 1
        session_data.last_activity = datetime.now()
        
        logger.info(f"Refreshed session {session_id}")
        return new_csrf_token
    
    def revoke_session(self, session_id: str) -> bool:
        """Отзывает сессию"""
        session_data = self.sessions.get(session_id)
        if not session_data:
            return False
        
        # Помечаем сессию как отозванную
        session_data.state = SessionState.REVOKED
        self.revoked_sessions.add(session_id)
        
        # Удаляем из пользовательских сессий
        user_id = session_data.user_id
        if user_id in self.user_sessions:
            self.user_sessions[user_id].discard(session_id)
            if not self.user_sessions[user_id]:
                del self.user_sessions[user_id]
        
        logger.info(f"Revoked session {session_id}")
        return True
    
    def revoke_user_sessions(self, user_id: str) -> int:
        """Отзывает все сессии пользователя"""
        if user_id not in self.user_sessions:
            return 0
        
        revoked_count = 0
        for session_id in list(self.user_sessions[user_id]):
            if self.revoke_session(session_id):
                revoked_count += 1
        
        logger.info(f"Revoked {revoked_count} sessions for user {user_id}")
        return revoked_count
    
    def cleanup_expired_sessions(self) -> int:
        """Очищает истекшие сессии"""
        now = datetime.now()
        expired_sessions = []
        
        # Создаем копию списка ключей для безопасной итерации
        session_ids = list(self.sessions.keys())
        
        for session_id in session_ids:
            session_data = self.sessions.get(session_id)
            if session_data and self._is_session_expired(session_data):
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            self.revoke_session(session_id)
        
        logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")
        return len(expired_sessions)
    
    def get_session_info(self, session_id: str) -> Optional[Dict]:
        """Получает информацию о сессии (без чувствительных данных)"""
        session_data = self.sessions.get(session_id)
        if not session_data:
            return None
        
        return {
            "session_id": session_id,
            "user_id": session_data.user_id,
            "created_at": session_data.created_at.isoformat(),
            "last_activity": session_data.last_activity.isoformat(),
            "state": session_data.state.value,
            "refresh_count": session_data.refresh_count,
            "suspicious_activity": session_data.suspicious_activity
        }
    
    def get_user_sessions(self, user_id: str) -> List[Dict]:
        """Получает все сессии пользователя"""
        if user_id not in self.user_sessions:
            return []
        
        sessions = []
        for session_id in self.user_sessions[user_id]:
            session_info = self.get_session_info(session_id)
            if session_info:
                sessions.append(session_info)
        
        return sessions
    
    def _generate_session_id(self) -> str:
        """Генерирует уникальный session ID"""
        while True:
            session_id = secrets.token_urlsafe(32)
            if session_id not in self.sessions:
                return session_id
    
    def _generate_csrf_token(self, session_id: str) -> str:
        """Генерирует CSRF токен для сессии"""
        timestamp = str(int(time.time()))
        data = f"{session_id}:{timestamp}"
        signature = hmac.new(
            self.secret_key,
            data.encode(),
            hashlib.sha256
        ).hexdigest()
        return f"{timestamp}:{signature}"
    
    def _is_session_expired(self, session_data: SessionData) -> bool:
        """Проверяет, истекла ли сессия"""
        now = datetime.now()
        
        # Проверяем общий timeout
        if (now - session_data.created_at).total_seconds() > self.session_timeout:
            return True
        
        # Проверяем inactive timeout
        if (now - session_data.last_activity).total_seconds() > self.max_inactive_time:
            return True
        
        return False

# Глобальный экземпляр менеджера сессий
session_manager = SecureSessionManager(
    secret_key="your-secret-key-here",  # Должен быть из настроек
    session_timeout=3600
)

# Удобные функции
def create_session(user_id: str, ip_address: str, user_agent: str) -> str:
    """Создает новую сессию"""
    return session_manager.create_session(user_id, ip_address, user_agent)

def validate_session(session_id: str, ip_address: str, user_agent: str) -> bool:
    """Валидирует сессию"""
    return session_manager.validate_session(session_id, ip_address, user_agent)

def validate_csrf_token(session_id: str, csrf_token: str) -> bool:
    """Валидирует CSRF токен"""
    return session_manager.validate_csrf_token(session_id, csrf_token)

def refresh_session(session_id: str) -> Optional[str]:
    """Обновляет сессию"""
    return session_manager.refresh_session(session_id)

def revoke_session(session_id: str) -> bool:
    """Отзывает сессию"""
    return session_manager.revoke_session(session_id)

def revoke_user_sessions(user_id: str) -> int:
    """Отзывает все сессии пользователя"""
    return session_manager.revoke_user_sessions(user_id)