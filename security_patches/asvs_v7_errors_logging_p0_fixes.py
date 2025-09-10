"""
ASVS V7: Критические исправления обработки ошибок и логирования (P0)
"""
import logging
import traceback
import time
import hashlib
from typing import Dict, Any, Optional, List
from datetime import datetime
from fastapi import HTTPException, status
from backend.core.common_imports import get_logger

logger = get_logger(__name__)

class ErrorHandlingSecurity:
    """Критические исправления обработки ошибок и логирования"""
    
    def __init__(self):
        self.error_logs: List[Dict[str, Any]] = []
        self.max_log_entries = 10000
        self.sensitive_patterns = [
            'password', 'token', 'key', 'secret', 'credential',
            'ssn', 'social_security', 'credit_card', 'cvv',
            'api_key', 'access_token', 'refresh_token'
        ]
    
    def sanitize_error_message(self, error_message: str) -> str:
        """V7.1.1: Санитизация сообщений об ошибках"""
        if not error_message:
            return "An error occurred"
        
        # Удаляем чувствительную информацию
        sanitized = error_message.lower()
        for pattern in self.sensitive_patterns:
            if pattern in sanitized:
                sanitized = sanitized.replace(pattern, '[REDACTED]')
        
        # Удаляем stack traces из пользовательских сообщений
        lines = sanitized.split('\n')
        filtered_lines = []
        for line in lines:
            if not any(keyword in line for keyword in ['traceback', 'file "', 'line ', 'in ']):
                filtered_lines.append(line)
        
        return '\n'.join(filtered_lines)
    
    def log_security_event(self, event_type: str, user_id: Optional[str], 
                          details: Dict[str, Any], severity: str = "INFO") -> None:
        """V7.1.2: Логирование событий безопасности"""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "user_id": user_id,
            "severity": severity,
            "details": self.sanitize_log_data(details),
            "session_id": details.get('session_id'),
            "ip_address": details.get('ip_address'),
            "user_agent": details.get('user_agent')
        }
        
        # Добавляем в лог
        self.error_logs.append(log_entry)
        
        # Ограничиваем размер лога
        if len(self.error_logs) > self.max_log_entries:
            self.error_logs = self.error_logs[-self.max_log_entries:]
        
        # Логируем в систему
        log_message = f"Security event: {event_type} - {details.get('message', 'No message')}"
        
        if severity == "CRITICAL":
            logger.critical(log_message, extra=log_entry)
        elif severity == "ERROR":
            logger.error(log_message, extra=log_entry)
        elif severity == "WARNING":
            logger.warning(log_message, extra=log_entry)
        else:
            logger.info(log_message, extra=log_entry)
    
    def sanitize_log_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """V7.1.3: Санитизация данных для логирования"""
        sanitized = {}
        
        for key, value in data.items():
            if isinstance(value, str):
                # Проверяем на чувствительные данные
                if any(pattern in key.lower() for pattern in self.sensitive_patterns):
                    sanitized[key] = '[REDACTED]'
                else:
                    sanitized[key] = value
            elif isinstance(value, dict):
                sanitized[key] = self.sanitize_log_data(value)
            else:
                sanitized[key] = value
        
        return sanitized
    
    def handle_authentication_error(self, user_id: Optional[str], error_details: Dict[str, Any]) -> None:
        """V7.1.4: Обработка ошибок аутентификации"""
        self.log_security_event(
            "AUTHENTICATION_FAILURE",
            user_id,
            error_details,
            "WARNING"
        )
    
    def handle_authorization_error(self, user_id: Optional[str], error_details: Dict[str, Any]) -> None:
        """V7.1.5: Обработка ошибок авторизации"""
        self.log_security_event(
            "AUTHORIZATION_FAILURE",
            user_id,
            error_details,
            "WARNING"
        )
    
    def handle_input_validation_error(self, user_id: Optional[str], error_details: Dict[str, Any]) -> None:
        """V7.1.6: Обработка ошибок валидации ввода"""
        self.log_security_event(
            "INPUT_VALIDATION_ERROR",
            user_id,
            error_details,
            "WARNING"
        )
    
    def handle_system_error(self, error_details: Dict[str, Any]) -> None:
        """V7.1.7: Обработка системных ошибок"""
        self.log_security_event(
            "SYSTEM_ERROR",
            None,
            error_details,
            "ERROR"
        )
    
    def handle_security_violation(self, user_id: Optional[str], error_details: Dict[str, Any]) -> None:
        """V7.1.8: Обработка нарушений безопасности"""
        self.log_security_event(
            "SECURITY_VIOLATION",
            user_id,
            error_details,
            "CRITICAL"
        )
    
    def create_safe_error_response(self, error_type: str, user_message: str, 
                                 internal_details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """V7.1.9: Создание безопасного ответа об ошибке"""
        # Логируем внутренние детали
        if internal_details:
            self.log_security_event(
                "ERROR_RESPONSE",
                internal_details.get('user_id'),
                internal_details,
                "ERROR"
            )
        
        # Возвращаем безопасный ответ пользователю
        return {
            "error": error_type,
            "message": self.sanitize_error_message(user_message),
            "timestamp": datetime.utcnow().isoformat(),
            "request_id": self.generate_request_id()
        }
    
    def generate_request_id(self) -> str:
        """V7.1.10: Генерация ID запроса для трекинга"""
        timestamp = str(time.time())
        random_data = str(hash(timestamp))
        return hashlib.md5(f"{timestamp}{random_data}".encode()).hexdigest()[:16]
    
    def log_api_access(self, user_id: Optional[str], endpoint: str, method: str, 
                      status_code: int, response_time: float, details: Dict[str, Any]) -> None:
        """V7.1.11: Логирование доступа к API"""
        log_entry = {
            "endpoint": endpoint,
            "method": method,
            "status_code": status_code,
            "response_time": response_time,
            "message": f"API access: {method} {endpoint} - {status_code}",
            **details
        }
        
        severity = "INFO"
        if status_code >= 400:
            severity = "WARNING"
        if status_code >= 500:
            severity = "ERROR"
        
        self.log_security_event(
            "API_ACCESS",
            user_id,
            log_entry,
            severity
        )
    
    def detect_anomalous_activity(self, user_id: str, activity_data: Dict[str, Any]) -> bool:
        """V7.1.12: Обнаружение аномальной активности"""
        # Простая эвристика для обнаружения аномалий
        recent_activities = [
            log for log in self.error_logs
            if log.get('user_id') == user_id and
            log.get('event_type') in ['AUTHENTICATION_FAILURE', 'AUTHORIZATION_FAILURE', 'SECURITY_VIOLATION']
        ]
        
        # Если за последние 5 минут было более 5 неудачных попыток
        recent_time = time.time() - 300  # 5 минут
        recent_failures = [
            log for log in recent_activities
            if datetime.fromisoformat(log['timestamp']).timestamp() > recent_time
        ]
        
        if len(recent_failures) > 5:
            self.log_security_event(
                "ANOMALOUS_ACTIVITY_DETECTED",
                user_id,
                {
                    "message": "Multiple failed attempts detected",
                    "failure_count": len(recent_failures),
                    "time_window": "5 minutes"
                },
                "CRITICAL"
            )
            return True
        
        return False
    
    def get_security_logs(self, user_id: Optional[str] = None, 
                         event_type: Optional[str] = None,
                         severity: Optional[str] = None,
                         limit: int = 100) -> List[Dict[str, Any]]:
        """V7.1.13: Получение логов безопасности"""
        filtered_logs = self.error_logs
        
        if user_id:
            filtered_logs = [log for log in filtered_logs if log.get('user_id') == user_id]
        
        if event_type:
            filtered_logs = [log for log in filtered_logs if log.get('event_type') == event_type]
        
        if severity:
            filtered_logs = [log for log in filtered_logs if log.get('severity') == severity]
        
        # Сортируем по времени (новые сначала)
        filtered_logs.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return filtered_logs[:limit]
    
    def clear_old_logs(self, days: int = 30) -> int:
        """V7.1.14: Очистка старых логов"""
        cutoff_time = time.time() - (days * 24 * 60 * 60)
        
        old_logs = [
            log for log in self.error_logs
            if datetime.fromisoformat(log['timestamp']).timestamp() < cutoff_time
        ]
        
        self.error_logs = [
            log for log in self.error_logs
            if datetime.fromisoformat(log['timestamp']).timestamp() >= cutoff_time
        ]
        
        return len(old_logs)
    
    def export_security_logs(self, format: str = "json") -> str:
        """V7.1.15: Экспорт логов безопасности"""
        if format == "json":
            import json
            return json.dumps(self.error_logs, indent=2)
        elif format == "csv":
            import csv
            import io
            
            if not self.error_logs:
                return ""
            
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=self.error_logs[0].keys())
            writer.writeheader()
            writer.writerows(self.error_logs)
            return output.getvalue()
        else:
            raise ValueError(f"Unsupported format: {format}")

# Глобальный экземпляр
error_handling = ErrorHandlingSecurity()