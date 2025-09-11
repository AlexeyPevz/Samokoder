"""
Тесты безопасности конфигурации - рефакторированная версия
Разделены на специализированные классы для лучшей организации
"""

import pytest
import os
import tempfile
from pathlib import Path
from unittest.mock import patch, mock_open
from security_patches.asvs_v10_configuration_p0_fixes import ConfigurationSecurity

class BaseConfigurationTest:
    """Базовый класс для тестов конфигурации"""
    
    @pytest.fixture
    def config_security(self):
        """Создать экземпляр ConfigurationSecurity"""
        return ConfigurationSecurity()

class TestPasswordPolicyConfig(BaseConfigurationTest):
    """Тесты конфигурации парольной политики"""
    
    def test_password_policy(self, config_security):
        """V10.1.7: Тест парольной политики"""
        policy = config_security.get_password_policy()
        
        # Проверяем структуру
        assert "min_length" in policy
        assert "require_uppercase" in policy
        assert "require_lowercase" in policy
        assert "require_numbers" in policy
        assert "require_special_chars" in policy
        assert "max_age_days" in policy
        assert "history_count" in policy
        
        # Проверяем значения
        assert policy["min_length"] >= 8
        assert policy["require_uppercase"] is True
        assert policy["require_lowercase"] is True
        assert policy["require_numbers"] is True
        assert policy["require_special_chars"] is True

class TestSessionConfig(BaseConfigurationTest):
    """Тесты конфигурации сессий"""
    
    def test_session_config(self, config_security):
        """V10.1.8: Тест конфигурации сессий"""
        session_config = config_security.get_session_config()
        
        # Проверяем структуру
        assert "timeout_minutes" in session_config
        assert "max_sessions_per_user" in session_config
        assert "require_https" in session_config
        assert "secure_cookies" in session_config
        assert "http_only_cookies" in session_config
        assert "same_site" in session_config
        
        # Проверяем значения
        assert session_config["require_https"] is True
        assert session_config["secure_cookies"] is True
        assert session_config["http_only_cookies"] is True

class TestRateLimitingConfig(BaseConfigurationTest):
    """Тесты конфигурации rate limiting"""
    
    def test_rate_limiting_config(self, config_security):
        """V10.1.9: Тест конфигурации rate limiting"""
        rate_config = config_security.get_rate_limiting_config()
        
        # Проверяем структуру
        assert "login_attempts_per_minute" in rate_config
        assert "api_requests_per_minute" in rate_config
        assert "api_requests_per_hour" in rate_config
        assert "block_duration_minutes" in rate_config
        
        # Проверяем значения
        assert rate_config["login_attempts_per_minute"] <= 10
        assert rate_config["api_requests_per_minute"] > 0
        assert rate_config["api_requests_per_hour"] > 0

class TestEncryptionConfig(BaseConfigurationTest):
    """Тесты конфигурации шифрования"""
    
    def test_encryption_config(self, config_security):
        """V10.1.10: Тест конфигурации шифрования"""
        encryption_config = config_security.get_encryption_config()
        
        # Проверяем структуру
        assert "algorithm" in encryption_config
        assert "key_rotation_days" in encryption_config
        assert "require_tls" in encryption_config
        assert "min_tls_version" in encryption_config
        
        # Проверяем значения
        assert encryption_config["require_tls"] is True
        assert encryption_config["min_tls_version"] in ["1.2", "1.3"]
        assert "AES" in encryption_config["algorithm"]

class TestLoggingConfig(BaseConfigurationTest):
    """Тесты конфигурации логирования"""
    
    def test_logging_config(self, config_security):
        """V10.1.11: Тест конфигурации логирования"""
        logging_config = config_security.get_logging_config()
        
        # Проверяем структуру
        assert "log_level" in logging_config
        assert "log_security_events" in logging_config
        assert "log_retention_days" in logging_config
        assert "log_sensitive_data" in logging_config
        
        # Проверяем значения
        assert logging_config["log_security_events"] is True
        assert logging_config["log_sensitive_data"] is False
        assert logging_config["log_retention_days"] > 0

class TestCORSConfig(BaseConfigurationTest):
    """Тесты конфигурации CORS"""
    
    def test_cors_config(self, config_security):
        """V10.1.6: Тест конфигурации CORS"""
        cors_config = config_security.get_cors_config()
        
        # Проверяем структуру
        assert "allowed_origins" in cors_config
        assert "allowed_methods" in cors_config
        assert "allowed_headers" in cors_config
        assert "allow_credentials" in cors_config
        
        # Проверяем значения
        assert isinstance(cors_config["allowed_origins"], list)
        assert "GET" in cors_config["allowed_methods"]
        assert "POST" in cors_config["allowed_methods"]
        assert "Authorization" in cors_config["allowed_headers"]

class TestSecurityHeadersConfig(BaseConfigurationTest):
    """Тесты конфигурации заголовков безопасности"""
    
    def test_security_headers(self, config_security):
        """V10.1.5: Тест заголовков безопасности"""
        headers = config_security.get_security_headers()
        
        # Проверяем наличие важных заголовков
        assert "x_frame_options" in headers
        assert "x_content_type_options" in headers
        assert "x_xss_protection" in headers
        assert "strict_transport_security" in headers
        assert "content_security_policy" in headers
        
        # Проверяем значения
        assert headers["x_frame_options"] == "DENY"
        assert headers["x_content_type_options"] == "nosniff"
        assert "nosniff" in headers["x_content_type_options"]

class TestGeneralConfig(BaseConfigurationTest):
    """Тесты общей конфигурации"""
    
    def test_config_loading(self, config_security):
        """V10.1.2: Тест загрузки конфигурации"""
        # Тестируем загрузку конфигурации по умолчанию
        assert config_security.current_config is not None
        assert "security" in config_security.current_config
    
    def test_config_merging(self, config_security):
        """V10.1.3: Тест слияния конфигурации"""
        override_config = {
            "security": {
                "password_policy": {
                    "min_length": 16
                },
                "session_management": {
                    "timeout_minutes": 60
                }
            }
        }
        
        merged = config_security._merge_with_defaults(override_config)
        
        # Проверяем, что переопределенные значения применились
        assert merged["security"]["password_policy"]["min_length"] == 16
        assert merged["security"]["session_management"]["timeout_minutes"] == 60
        
        # Проверяем, что остальные значения остались по умолчанию
        assert merged["security"]["password_policy"]["require_uppercase"] is True
        assert merged["security"]["encryption"]["require_tls"] is True

class TestEnvironmentSecurity(BaseConfigurationTest):
    """Тесты безопасности окружения"""
    
    def test_environment_security_check(self, config_security):
        """V10.1.14: Тест проверки безопасности окружения"""
        with patch.dict(os.environ, {
            "DATABASE_URL": "postgresql://test:test@localhost/test",
            "JWT_SECRET": "test_secret",
            "ENCRYPTION_KEY": "test_key",
            "DEBUG": "false",
            "HTTPS_ONLY": "true"
        }):
            issues = config_security.check_environment_security()
            assert len(issues) == 0
    
    def test_environment_security_issues(self, config_security):
        """V10.1.14: Тест проблем безопасности окружения"""
        with patch.dict(os.environ, {
            "DEBUG": "true",
            "HTTPS_ONLY": "false"
        }, clear=True):
            issues = config_security.check_environment_security()
            assert len(issues) > 0
            assert any("Debug mode" in issue for issue in issues)
            assert any("HTTPS" in issue for issue in issues)

class TestConfigurationSecurity(BaseConfigurationTest):
    """Основные тесты безопасности конфигурации"""
    
    def test_default_security_config(self, config_security):
        """V10.1.1: Тест конфигурации безопасности по умолчанию"""
        default_config = config_security._get_default_security_config()
        
        # Проверяем структуру конфигурации
        assert "security" in default_config
        
        security_config = default_config["security"]
        assert "password_policy" in security_config
        assert "session_management" in security_config
        assert "rate_limiting" in security_config
        assert "encryption" in security_config
        assert "logging" in security_config
        assert "cors" in security_config
        assert "headers" in security_config