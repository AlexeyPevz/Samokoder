"""
ASVS V10: Критические исправления конфигурации (P0)
"""
import os
import json
import hashlib
from typing import Dict, Any, List, Optional
from pathlib import Path
from backend.core.common_imports import get_logger

logger = get_logger(__name__)

class ConfigurationSecurity:
    """Критические исправления конфигурации безопасности"""
    
    def __init__(self):
        self.config_file_path = Path("config/security_config.json")
        self.default_config = self._get_default_security_config()
        self.current_config = self._load_config()
    
    def _get_default_security_config(self) -> Dict[str, Any]:
        """V10.1.1: Получение конфигурации безопасности по умолчанию"""
        return {
            "security": {
                "password_policy": {
                    "min_length": 12,
                    "require_uppercase": True,
                    "require_lowercase": True,
                    "require_numbers": True,
                    "require_special_chars": True,
                    "max_age_days": 90,
                    "history_count": 5
                },
                "session_management": {
                    "timeout_minutes": 30,
                    "max_sessions_per_user": 5,
                    "require_https": True,
                    "secure_cookies": True,
                    "http_only_cookies": True,
                    "same_site": "strict"
                },
                "rate_limiting": {
                    "login_attempts_per_minute": 5,
                    "api_requests_per_minute": 100,
                    "api_requests_per_hour": 1000,
                    "block_duration_minutes": 15
                },
                "encryption": {
                    "algorithm": "AES-256-GCM",
                    "key_rotation_days": 90,
                    "require_tls": True,
                    "min_tls_version": "1.2"
                },
                "logging": {
                    "log_level": "INFO",
                    "log_security_events": True,
                    "log_retention_days": 90,
                    "log_sensitive_data": False
                },
                "cors": {
                    "allowed_origins": [],
                    "allowed_methods": ["GET", "POST", "PUT", "DELETE"],
                    "allowed_headers": ["Content-Type", "Authorization"],
                    "allow_credentials": True
                },
                "headers": {
                    "x_frame_options": "DENY",
                    "x_content_type_options": "nosniff",
                    "x_xss_protection": "1; mode=block",
                    "strict_transport_security": "max-age=31536000; includeSubDomains",
                    "content_security_policy": "default-src 'self'"
                }
            }
        }
    
    def _load_config(self) -> Dict[str, Any]:
        """V10.1.2: Загрузка конфигурации"""
        try:
            if self.config_file_path.exists():
                with open(self.config_file_path, 'r') as f:
                    config = json.load(f)
                    return self._merge_with_defaults(config)
            else:
                logger.warning("Security config file not found, using defaults")
                return self.default_config
        except Exception as e:
            logger.error(f"Failed to load security config: {e}")
            return self.default_config
    
    def _merge_with_defaults(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """V10.1.3: Слияние с конфигурацией по умолчанию"""
        merged = self.default_config.copy()
        
        def deep_merge(default: Dict, override: Dict) -> Dict:
            for key, value in override.items():
                if key in default and isinstance(default[key], dict) and isinstance(value, dict):
                    default[key] = deep_merge(default[key], value)
                else:
                    default[key] = value
            return default
        
        return deep_merge(merged, config)
    
    def validate_config(self) -> List[str]:
        """V10.1.4: Валидация конфигурации"""
        errors = []
        
        # Проверяем парольную политику
        password_policy = self.current_config["security"]["password_policy"]
        if password_policy["min_length"] < 8:
            errors.append("Password minimum length must be at least 8 characters")
        
        if password_policy["max_age_days"] > 365:
            errors.append("Password maximum age should not exceed 365 days")
        
        # Проверяем управление сессиями
        session_config = self.current_config["security"]["session_management"]
        if session_config["timeout_minutes"] > 480:  # 8 hours
            errors.append("Session timeout should not exceed 8 hours")
        
        if not session_config["require_https"]:
            errors.append("HTTPS should be required for sessions")
        
        # Проверяем rate limiting
        rate_config = self.current_config["security"]["rate_limiting"]
        if rate_config["login_attempts_per_minute"] > 10:
            errors.append("Login attempts per minute should not exceed 10")
        
        # Проверяем шифрование
        encryption_config = self.current_config["security"]["encryption"]
        if not encryption_config["require_tls"]:
            errors.append("TLS should be required")
        
        if encryption_config["min_tls_version"] not in ["1.2", "1.3"]:
            errors.append("Minimum TLS version should be 1.2 or 1.3")
        
        return errors
    
    def get_security_headers(self) -> Dict[str, str]:
        """V10.1.5: Получение заголовков безопасности"""
        return self.current_config["security"]["headers"]
    
    def get_cors_config(self) -> Dict[str, Any]:
        """V10.1.6: Получение конфигурации CORS"""
        return self.current_config["security"]["cors"]
    
    def get_password_policy(self) -> Dict[str, Any]:
        """V10.1.7: Получение парольной политики"""
        return self.current_config["security"]["password_policy"]
    
    def get_session_config(self) -> Dict[str, Any]:
        """V10.1.8: Получение конфигурации сессий"""
        return self.current_config["security"]["session_management"]
    
    def get_rate_limiting_config(self) -> Dict[str, Any]:
        """V10.1.9: Получение конфигурации rate limiting"""
        return self.current_config["security"]["rate_limiting"]
    
    def get_encryption_config(self) -> Dict[str, Any]:
        """V10.1.10: Получение конфигурации шифрования"""
        return self.current_config["security"]["encryption"]
    
    def get_logging_config(self) -> Dict[str, Any]:
        """V10.1.11: Получение конфигурации логирования"""
        return self.current_config["security"]["logging"]
    
    def update_config(self, new_config: Dict[str, Any]) -> bool:
        """V10.1.12: Обновление конфигурации"""
        try:
            # Валидируем новую конфигурацию
            temp_config = self._merge_with_defaults(new_config)
            temp_security = ConfigurationSecurity()
            temp_security.current_config = temp_config
            
            errors = temp_security.validate_config()
            if errors:
                logger.error(f"Configuration validation failed: {errors}")
                return False
            
            # Сохраняем конфигурацию
            self.current_config = temp_config
            self._save_config()
            
            logger.info("Security configuration updated successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to update configuration: {e}")
            return False
    
    def _save_config(self) -> None:
        """V10.1.13: Сохранение конфигурации"""
        try:
            # Создаем директорию если не существует
            self.config_file_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Сохраняем конфигурацию
            with open(self.config_file_path, 'w') as f:
                json.dump(self.current_config, f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
    
    def check_environment_security(self) -> List[str]:
        """V10.1.14: Проверка безопасности окружения"""
        issues = []
        
        # Проверяем переменные окружения
        required_env_vars = [
            "DATABASE_URL",
            "JWT_SECRET",
            "ENCRYPTION_KEY"
        ]
        
        for var in required_env_vars:
            if not os.getenv(var):
                issues.append(f"Required environment variable {var} is not set")
        
        # Проверяем режим отладки
        if os.getenv("DEBUG", "false").lower() == "true":
            issues.append("Debug mode should not be enabled in production")
        
        # Проверяем HTTPS
        if not os.getenv("HTTPS_ONLY", "false").lower() == "true":
            issues.append("HTTPS should be enforced in production")
        
        return issues
    
    def generate_security_report(self) -> Dict[str, Any]:
        """V10.1.15: Генерация отчета по безопасности"""
        config_errors = self.validate_config()
        env_issues = self.check_environment_security()
        
        return {
            "timestamp": "2025-01-27T00:00:00Z",
            "configuration_validation": {
                "errors": config_errors,
                "is_valid": len(config_errors) == 0
            },
            "environment_security": {
                "issues": env_issues,
                "is_secure": len(env_issues) == 0
            },
            "security_headers": self.get_security_headers(),
            "password_policy": self.get_password_policy(),
            "session_config": self.get_session_config(),
            "rate_limiting": self.get_rate_limiting_config(),
            "encryption": self.get_encryption_config(),
            "overall_security_score": self._calculate_security_score(config_errors, env_issues)
        }
    
    def _calculate_security_score(self, config_errors: List[str], env_issues: List[str]) -> int:
        """V10.1.16: Расчет оценки безопасности"""
        total_issues = len(config_errors) + len(env_issues)
        
        if total_issues == 0:
            return 100
        elif total_issues <= 2:
            return 90
        elif total_issues <= 5:
            return 75
        elif total_issues <= 10:
            return 60
        else:
            return 30
    
    def backup_config(self) -> str:
        """V10.1.17: Резервное копирование конфигурации"""
        try:
            config_hash = hashlib.md5(json.dumps(self.current_config, sort_keys=True).encode()).hexdigest()
            backup_path = f"config/security_config_backup_{config_hash[:8]}.json"
            
            with open(backup_path, 'w') as f:
                json.dump(self.current_config, f, indent=2)
            
            logger.info(f"Configuration backed up to {backup_path}")
            return backup_path
            
        except Exception as e:
            logger.error(f"Failed to backup configuration: {e}")
            return ""
    
    def restore_config(self, backup_path: str) -> bool:
        """V10.1.18: Восстановление конфигурации из резервной копии"""
        try:
            if not Path(backup_path).exists():
                logger.error(f"Backup file not found: {backup_path}")
                return False
            
            with open(backup_path, 'r') as f:
                backup_config = json.load(f)
            
            return self.update_config(backup_config)
            
        except Exception as e:
            logger.error(f"Failed to restore configuration: {e}")
            return False

# Глобальный экземпляр
config_security = ConfigurationSecurity()