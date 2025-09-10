"""
ASVS V10: Тесты безопасности конфигурации
"""
import pytest
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch, mock_open
from security_patches.asvs_v10_configuration_p0_fixes import ConfigurationSecurity

class TestConfigurationSecurity:
    """Тесты безопасности конфигурации"""
    
    @pytest.fixture
    def config_security(self):
        """Создать экземпляр ConfigurationSecurity"""
        return ConfigurationSecurity()
    
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
        
        # Проверяем парольную политику
        password_policy = security_config["password_policy"]
        assert password_policy["min_length"] >= 8
        assert password_policy["require_uppercase"] is True
        assert password_policy["require_lowercase"] is True
        assert password_policy["require_numbers"] is True
        assert password_policy["require_special_chars"] is True
        
        # Проверяем управление сессиями
        session_config = security_config["session_management"]
        assert session_config["require_https"] is True
        assert session_config["secure_cookies"] is True
        assert session_config["http_only_cookies"] is True
        
        # Проверяем шифрование
        encryption_config = security_config["encryption"]
        assert encryption_config["require_tls"] is True
        assert encryption_config["min_tls_version"] in ["1.2", "1.3"]
    
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
    
    def test_config_validation_success(self, config_security):
        """V10.1.4: Тест успешной валидации конфигурации"""
        errors = config_security.validate_config()
        
        # С конфигурацией по умолчанию не должно быть ошибок
        assert len(errors) == 0
    
    def test_config_validation_failure(self, config_security):
        """V10.1.4: Тест неудачной валидации конфигурации"""
        # Создаем небезопасную конфигурацию
        unsafe_config = {
            "security": {
                "password_policy": {
                    "min_length": 4,  # Слишком короткий
                    "max_age_days": 1000  # Слишком долго
                },
                "session_management": {
                    "timeout_minutes": 1000,  # Слишком долго
                    "require_https": False  # Небезопасно
                },
                "rate_limiting": {
                    "login_attempts_per_minute": 100  # Слишком много
                },
                "encryption": {
                    "require_tls": False,  # Небезопасно
                    "min_tls_version": "1.0"  # Устаревшая версия
                }
            }
        }
        
        config_security.current_config = config_security._merge_with_defaults(unsafe_config)
        errors = config_security.validate_config()
        
        # Должны быть ошибки валидации
        assert len(errors) > 0
        assert any("minimum length" in error.lower() for error in errors)
        assert any("https" in error.lower() for error in errors)
        assert any("tls" in error.lower() for error in errors)
    
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
        assert session_config["same_site"] == "strict"
    
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
    
    def test_config_update_success(self, config_security):
        """V10.1.12: Тест успешного обновления конфигурации"""
        new_config = {
            "security": {
                "password_policy": {
                    "min_length": 16
                }
            }
        }
        
        with patch.object(config_security, '_save_config'):
            result = config_security.update_config(new_config)
            assert result is True
            assert config_security.current_config["security"]["password_policy"]["min_length"] == 16
    
    def test_config_update_validation_failure(self, config_security):
        """V10.1.12: Тест неудачного обновления конфигурации из-за валидации"""
        unsafe_config = {
            "security": {
                "password_policy": {
                    "min_length": 4  # Слишком короткий
                }
            }
        }
        
        with patch.object(config_security, '_save_config'):
            result = config_security.update_config(unsafe_config)
            assert result is False
    
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
            assert any("DEBUG" in issue for issue in issues)
            assert any("HTTPS" in issue for issue in issues)
    
    def test_security_report_generation(self, config_security):
        """V10.1.15: Тест генерации отчета по безопасности"""
        with patch.dict(os.environ, {
            "DATABASE_URL": "postgresql://test:test@localhost/test",
            "JWT_SECRET": "test_secret",
            "ENCRYPTION_KEY": "test_key"
        }):
            report = config_security.generate_security_report()
            
            # Проверяем структуру отчета
            assert "timestamp" in report
            assert "configuration_validation" in report
            assert "environment_security" in report
            assert "security_headers" in report
            assert "password_policy" in report
            assert "session_config" in report
            assert "rate_limiting" in report
            assert "encryption" in report
            assert "overall_security_score" in report
            
            # Проверяем валидацию конфигурации
            assert "errors" in report["configuration_validation"]
            assert "is_valid" in report["configuration_validation"]
            
            # Проверяем безопасность окружения
            assert "issues" in report["environment_security"]
            assert "is_secure" in report["environment_security"]
            
            # Проверяем оценку безопасности
            assert isinstance(report["overall_security_score"], int)
            assert 0 <= report["overall_security_score"] <= 100
    
    def test_security_score_calculation(self, config_security):
        """V10.1.16: Тест расчета оценки безопасности"""
        # Без ошибок
        score = config_security._calculate_security_score([], [])
        assert score == 100
        
        # С небольшим количеством ошибок
        score = config_security._calculate_security_score(["error1"], ["issue1"])
        assert score == 90
        
        # С большим количеством ошибок
        score = config_security._calculate_security_score(["error1", "error2", "error3", "error4", "error5"], [])
        assert score == 75
        
        # С очень большим количеством ошибок
        many_errors = ["error"] * 15
        score = config_security._calculate_security_score(many_errors, [])
        assert score == 30
    
    def test_config_backup(self, config_security):
        """V10.1.17: Тест резервного копирования конфигурации"""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_security.config_file_path = Path(temp_dir) / "test_config.json"
            
            backup_path = config_security.backup_config()
            assert backup_path != ""
            assert Path(backup_path).exists()
            
            # Проверяем содержимое резервной копии
            with open(backup_path, 'r') as f:
                backup_data = json.load(f)
                assert "security" in backup_data
    
    def test_config_restore(self, config_security):
        """V10.1.18: Тест восстановления конфигурации"""
        with tempfile.TemporaryDirectory() as temp_dir:
            backup_path = Path(temp_dir) / "backup.json"
            
            # Создаем резервную копию
            backup_config = {
                "security": {
                    "password_policy": {
                        "min_length": 20
                    }
                }
            }
            
            with open(backup_path, 'w') as f:
                json.dump(backup_config, f)
            
            # Восстанавливаем конфигурацию
            with patch.object(config_security, '_save_config'):
                result = config_security.restore_config(str(backup_path))
                assert result is True
                assert config_security.current_config["security"]["password_policy"]["min_length"] == 20
    
    def test_config_restore_file_not_found(self, config_security):
        """V10.1.18: Тест восстановления конфигурации с несуществующим файлом"""
        result = config_security.restore_config("nonexistent.json")
        assert result is False
    
    def test_comprehensive_configuration_flow(self, config_security):
        """V10.1.19: Тест комплексного потока конфигурации"""
        # 1. Проверяем загрузку конфигурации
        assert config_security.current_config is not None
        
        # 2. Валидируем конфигурацию
        errors = config_security.validate_config()
        assert len(errors) == 0
        
        # 3. Получаем различные конфигурации
        headers = config_security.get_security_headers()
        assert len(headers) > 0
        
        cors_config = config_security.get_cors_config()
        assert "allowed_methods" in cors_config
        
        password_policy = config_security.get_password_policy()
        assert password_policy["min_length"] >= 8
        
        # 4. Проверяем окружение
        with patch.dict(os.environ, {
            "DATABASE_URL": "postgresql://test:test@localhost/test",
            "JWT_SECRET": "test_secret",
            "ENCRYPTION_KEY": "test_key"
        }):
            env_issues = config_security.check_environment_security()
            assert len(env_issues) == 0
        
        # 5. Генерируем отчет
        report = config_security.generate_security_report()
        assert report["overall_security_score"] >= 90
        
        # 6. Обновляем конфигурацию
        new_config = {
            "security": {
                "password_policy": {
                    "min_length": 16
                }
            }
        }
        
        with patch.object(config_security, '_save_config'):
            result = config_security.update_config(new_config)
            assert result is True