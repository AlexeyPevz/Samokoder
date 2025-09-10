"""
ASVS V3: Критические исправления управления сессиями (P0)
"""
import secrets
import time
import hashlib
from typing import Dict, Optional, Set
from datetime import datetime, timedelta
from fastapi import HTTPException, status
from backend.core.common_imports import get_logger

logger = get_logger(__name__)

class SessionSecurity:
    """Критические исправления безопасности сессий"""
    
    def __init__(self):
        self.active_sessions: Dict[str, Dict] = {}
        self.session_timeout = 1800  # 30 минут
        self.max_sessions_per_user = 5
        self.session_cleanup_interval = 300  # 5 минут
        self.last_cleanup = time.time()
    
    def generate_secure_session_id(self) -> str:
        """V3.1.1: Генерация безопасного ID сессии"""
        # Используем криптографически стойкий генератор
        return secrets.token_urlsafe(32)
    
    def create_session(self, user_id: str, user_agent: str, ip_address: str) -> str:
        """V3.1.2: Создание безопасной сессии"""
        session_id = self.generate_secure_session_id()
        
        # Проверяем лимит сессий для пользователя
        user_sessions = [s for s in self.active_sessions.values() if s.get('user_id') == user_id]
        if len(user_sessions) >= self.max_sessions_per_user:
            # Удаляем самую старую сессию
            oldest_session = min(user_sessions, key=lambda s: s['created_at'])
            self.invalidate_session(oldest_session['session_id'])
        
        # Создаем новую сессию
        session_data = {
            'session_id': session_id,
            'user_id': user_id,
            'created_at': time.time(),
            'last_activity': time.time(),
            'user_agent': user_agent,
            'ip_address': ip_address,
            'is_active': True,
            'csrf_token': self.generate_csrf_token()
        }
        
        self.active_sessions[session_id] = session_data
        logger.info(f"Session created for user {user_id}")
        
        return session_id
    
    def validate_session(self, session_id: str, user_agent: str, ip_address: str) -> bool:
        """V3.1.3: Валидация сессии"""
        if not session_id or session_id not in self.active_sessions:
            return False
        
        session = self.active_sessions[session_id]
        
        # Проверяем активность сессии
        if not session.get('is_active', False):
            return False
        
        # Проверяем таймаут
        if time.time() - session['last_activity'] > self.session_timeout:
            self.invalidate_session(session_id)
            return False
        
        # Проверяем User-Agent (базовая защита от session hijacking)
        if session.get('user_agent') != user_agent:
            logger.warning(f"User-Agent mismatch for session {session_id}")
            self.invalidate_session(session_id)
            return False
        
        # Проверяем IP адрес (опционально, может быть слишком строго)
        # if session.get('ip_address') != ip_address:
        #     logger.warning(f"IP address mismatch for session {session_id}")
        #     self.invalidate_session(session_id)
        #     return False
        
        # Обновляем время последней активности
        session['last_activity'] = time.time()
        
        return True
    
    def invalidate_session(self, session_id: str) -> bool:
        """V3.1.4: Инвалидация сессии"""
        if session_id in self.active_sessions:
            self.active_sessions[session_id]['is_active'] = False
            del self.active_sessions[session_id]
            logger.info(f"Session {session_id} invalidated")
            return True
        return False
    
    def invalidate_user_sessions(self, user_id: str) -> int:
        """V3.1.5: Инвалидация всех сессий пользователя"""
        sessions_to_remove = []
        
        for session_id, session in self.active_sessions.items():
            if session.get('user_id') == user_id:
                sessions_to_remove.append(session_id)
        
        for session_id in sessions_to_remove:
            self.invalidate_session(session_id)
        
        logger.info(f"Invalidated {len(sessions_to_remove)} sessions for user {user_id}")
        return len(sessions_to_remove)
    
    def generate_csrf_token(self) -> str:
        """V3.1.6: Генерация CSRF токена"""
        return secrets.token_urlsafe(32)
    
    def validate_csrf_token(self, session_id: str, csrf_token: str) -> bool:
        """V3.1.7: Валидация CSRF токена"""
        if not session_id or session_id not in self.active_sessions:
            return False
        
        session = self.active_sessions[session_id]
        stored_token = session.get('csrf_token')
        
        if not stored_token or not csrf_token:
            return False
        
        # Используем constant-time comparison
        return secrets.compare_digest(stored_token, csrf_token)
    
    def rotate_session_id(self, old_session_id: str) -> Optional[str]:
        """V3.1.8: Ротация ID сессии"""
        if old_session_id not in self.active_sessions:
            return None
        
        session = self.active_sessions[old_session_id]
        
        # Создаем новый ID сессии
        new_session_id = self.generate_secure_session_id()
        
        # Обновляем сессию
        session['session_id'] = new_session_id
        session['csrf_token'] = self.generate_csrf_token()
        
        # Перемещаем в новый ключ
        self.active_sessions[new_session_id] = session
        del self.active_sessions[old_session_id]
        
        logger.info(f"Session ID rotated from {old_session_id} to {new_session_id}")
        return new_session_id
    
    def cleanup_expired_sessions(self) -> int:
        """V3.1.9: Очистка истекших сессий"""
        current_time = time.time()
        expired_sessions = []
        
        for session_id, session in self.active_sessions.items():
            if current_time - session['last_activity'] > self.session_timeout:
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            self.invalidate_session(session_id)
        
        self.last_cleanup = current_time
        
        if expired_sessions:
            logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")
        
        return len(expired_sessions)
    
    def get_session_info(self, session_id: str) -> Optional[Dict]:
        """V3.1.10: Получение информации о сессии"""
        if session_id not in self.active_sessions:
            return None
        
        session = self.active_sessions[session_id].copy()
        
        # Удаляем чувствительные данные
        session.pop('csrf_token', None)
        
        return session
    
    def set_session_attribute(self, session_id: str, key: str, value: any) -> bool:
        """V3.1.11: Установка атрибута сессии"""
        if session_id not in self.active_sessions:
            return False
        
        # Запрещаем установку чувствительных атрибутов
        forbidden_keys = ['session_id', 'user_id', 'csrf_token', 'created_at', 'last_activity']
        if key in forbidden_keys:
            return False
        
        self.active_sessions[session_id][key] = value
        return True
    
    def get_session_attribute(self, session_id: str, key: str) -> Optional[any]:
        """V3.1.12: Получение атрибута сессии"""
        if session_id not in self.active_sessions:
            return None
        
        return self.active_sessions[session_id].get(key)
    
    def enforce_session_timeout(self, session_id: str) -> bool:
        """V3.1.13: Принудительное завершение сессии по таймауту"""
        if session_id not in self.active_sessions:
            return False
        
        session = self.active_sessions[session_id]
        current_time = time.time()
        
        if current_time - session['last_activity'] > self.session_timeout:
            self.invalidate_session(session_id)
            return True
        
        return False
    
    def detect_session_anomalies(self, session_id: str, current_user_agent: str, current_ip: str) -> Dict[str, bool]:
        """V3.1.14: Обнаружение аномалий в сессии"""
        if session_id not in self.active_sessions:
            return {'session_not_found': True}
        
        session = self.active_sessions[session_id]
        anomalies = {
            'user_agent_changed': session.get('user_agent') != current_user_agent,
            'ip_address_changed': session.get('ip_address') != current_ip,
            'session_expired': time.time() - session['last_activity'] > self.session_timeout,
            'unusual_activity': False  # Можно добавить более сложную логику
        }
        
        return anomalies
    
    def get_active_sessions_count(self, user_id: str) -> int:
        """V3.1.15: Получение количества активных сессий пользователя"""
        return len([s for s in self.active_sessions.values() if s.get('user_id') == user_id and s.get('is_active', False)])

# Глобальный экземпляр
session_security = SessionSecurity()