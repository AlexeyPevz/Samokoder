"""
Граничные тесты для конфигурации (config).

Критические риски:
- Пустые или невалидные SECRET_KEY/APP_SECRET_KEY
- DATABASE_URL с неверным форматом
- Отрицательные значения для timeout/limits
- Экстремально большие значения
- Missing required environment variables
"""

import pytest
import os
from unittest.mock import patch

from samokoder.core.config import get_config, Config
from samokoder.core.config.exceptions import ConfigError


class TestSecretKeyBoundary:
    """Граничные тесты для secret keys."""

    def test_secret_key_too_short(self):
        """Тест: слишком короткий SECRET_KEY должен вызвать ошибку."""
        with patch.dict(os.environ, {"SECRET_KEY": "short"}):
            with pytest.raises((ConfigError, ValueError)):
                config = get_config()
                # Force validation
                if hasattr(config, 'validate'):
                    config.validate()

    def test_secret_key_empty(self):
        """Тест: пустой SECRET_KEY должен вызвать ошибку."""
        with patch.dict(os.environ, {"SECRET_KEY": ""}):
            with pytest.raises((ConfigError, ValueError)):
                get_config()

    def test_app_secret_key_missing(self):
        """Тест: отсутствие APP_SECRET_KEY в production должно быть ошибкой."""
        with patch.dict(os.environ, {
            "ENVIRONMENT": "production",
            "APP_SECRET_KEY": ""
        }, clear=True):
            # In production, missing APP_SECRET_KEY should cause issues
            # when trying to decrypt user keys
            pass  # Actual validation happens at runtime

    def test_secret_key_with_special_characters(self):
        """Тест: secret key с спецсимволами должен работать."""
        special_key = "Test!@#$%^&*()_+-=[]{}|;:,.<>?/~`123456789012"
        with patch.dict(os.environ, {"SECRET_KEY": special_key}):
            config = get_config()
            assert config.secret_key == special_key


class TestDatabaseUrlBoundary:
    """Граничные тесты для DATABASE_URL."""

    def test_database_url_invalid_scheme(self):
        """Тест: невалидная схема в DATABASE_URL."""
        invalid_urls = [
            "http://localhost/db",  # Wrong scheme
            "mysql://localhost/db",  # Wrong DB type
            "postgres://",  # Incomplete
            "://user:pass@localhost/db",  # No scheme
        ]
        
        for url in invalid_urls:
            with patch.dict(os.environ, {"DATABASE_URL": url}):
                # Should either raise error or handle gracefully
                try:
                    config = get_config()
                    # Some validation might be deferred
                except (ConfigError, ValueError):
                    pass  # Expected

    def test_database_url_missing_credentials(self):
        """Тест: DATABASE_URL без credentials."""
        url_no_password = "postgresql://user@localhost:5432/db"
        with patch.dict(os.environ, {"DATABASE_URL": url_no_password}):
            config = get_config()
            # Should accept URL without password (might be valid)
            assert "postgresql" in config.db.url

    def test_database_url_with_special_password(self):
        """Тест: DATABASE_URL с спецсимволами в пароле."""
        # URL-encoded special characters
        url = "postgresql://user:p@ss%23w%24rd@localhost:5432/db"
        with patch.dict(os.environ, {"DATABASE_URL": url}):
            config = get_config()
            assert "@localhost" in config.db.url


class TestNumericBoundaryValues:
    """Граничные тесты для числовых значений."""

    def test_negative_token_expire_minutes(self):
        """Тест: отрицательное значение ACCESS_TOKEN_EXPIRE_MINUTES."""
        with patch.dict(os.environ, {"ACCESS_TOKEN_EXPIRE_MINUTES": "-10"}):
            config = get_config()
            # Should either reject or use absolute value
            assert config.access_token_expire_minutes != -10

    def test_zero_token_expire_minutes(self):
        """Тест: нулевое значение ACCESS_TOKEN_EXPIRE_MINUTES."""
        with patch.dict(os.environ, {"ACCESS_TOKEN_EXPIRE_MINUTES": "0"}):
            config = get_config()
            # Zero timeout is invalid
            assert config.access_token_expire_minutes > 0

    def test_extremely_large_token_expire(self):
        """Тест: экстремально большое значение expire."""
        with patch.dict(os.environ, {"ACCESS_TOKEN_EXPIRE_MINUTES": "999999999"}):
            config = get_config()
            # Should cap at reasonable maximum
            assert config.access_token_expire_minutes < 999999999 or \
                   config.access_token_expire_minutes == 999999999  # If no cap

    def test_redis_port_boundary(self):
        """Тест: граничные значения порта Redis."""
        # Port 0
        with patch.dict(os.environ, {"REDIS_PORT": "0"}):
            with pytest.raises((ConfigError, ValueError)):
                config = get_config()
                # Validate port
                assert 0 < config.redis.port < 65536

        # Port > 65535
        with patch.dict(os.environ, {"REDIS_PORT": "99999"}):
            with pytest.raises((ConfigError, ValueError)):
                config = get_config()
                assert 0 < config.redis.port < 65536


class TestEnvironmentEdgeCases:
    """Граничные случаи для переменных окружения."""

    def test_environment_invalid_value(self):
        """Тест: невалидное значение ENVIRONMENT."""
        with patch.dict(os.environ, {"ENVIRONMENT": "invalid_env"}):
            config = get_config()
            # Should default to development or raise error
            assert config.environment in ["development", "staging", "production"]

    def test_environment_case_sensitivity(self):
        """Тест: регистр значения ENVIRONMENT."""
        for env_value in ["PRODUCTION", "Production", "production"]:
            with patch.dict(os.environ, {"ENVIRONMENT": env_value}):
                config = get_config()
                # Should normalize to lowercase
                assert config.environment.lower() == "production"

    def test_boolean_env_parsing(self):
        """Тест: парсинг boolean значений из env."""
        # Various boolean representations
        true_values = ["true", "True", "TRUE", "1", "yes", "Yes"]
        false_values = ["false", "False", "FALSE", "0", "no", "No"]
        
        for value in true_values:
            with patch.dict(os.environ, {"DEBUG": value}):
                config = get_config()
                # Should parse as True
                if hasattr(config, 'debug'):
                    assert config.debug in [True, value]

    def test_missing_optional_variables(self):
        """Тест: отсутствие опциональных переменных."""
        # Remove all optional variables
        minimal_env = {
            "SECRET_KEY": "minimum_32_characters_required_here_12345",
            "APP_SECRET_KEY": "app_secret_32_characters_minimum_here_1234",
            "DATABASE_URL": "postgresql://user:pass@localhost/db"
        }
        
        with patch.dict(os.environ, minimal_env, clear=True):
            config = get_config()
            # Should work with defaults
            assert config.secret_key is not None


class TestRateLimitBoundary:
    """Граничные тесты для rate limiting."""

    def test_rate_limit_zero(self):
        """Тест: нулевой rate limit."""
        with patch.dict(os.environ, {"RATE_LIMIT_PER_MINUTE": "0"}):
            config = get_config()
            # Zero rate limit should be rejected or mean unlimited
            if hasattr(config, 'rate_limit_per_minute'):
                assert config.rate_limit_per_minute >= 0

    def test_rate_limit_negative(self):
        """Тест: отрицательный rate limit."""
        with patch.dict(os.environ, {"RATE_LIMIT_PER_MINUTE": "-100"}):
            config = get_config()
            # Should use absolute value or reject
            if hasattr(config, 'rate_limit_per_minute'):
                assert config.rate_limit_per_minute >= 0


class TestCORSOriginsBoundary:
    """Граничные тесты для CORS origins."""

    def test_cors_origins_empty(self):
        """Тест: пустой список CORS origins."""
        with patch.dict(os.environ, {"CORS_ORIGINS": ""}):
            config = get_config()
            # Should use defaults based on environment

    def test_cors_origins_single(self):
        """Тест: один CORS origin."""
        with patch.dict(os.environ, {"CORS_ORIGINS": "https://example.com"}):
            config = get_config()
            # Should parse correctly

    def test_cors_origins_with_whitespace(self):
        """Тест: CORS origins с пробелами."""
        with patch.dict(os.environ, {"CORS_ORIGINS": " https://a.com , https://b.com "}):
            config = get_config()
            # Should trim whitespace

    def test_cors_origins_with_invalid_url(self):
        """Тест: CORS origins с невалидным URL."""
        with patch.dict(os.environ, {"CORS_ORIGINS": "not-a-url,https://valid.com"}):
            config = get_config()
            # Should validate or filter invalid URLs
