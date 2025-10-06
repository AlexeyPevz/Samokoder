"""Tests for configuration validator."""
import pytest
from samokoder.core.config.validator import (
    validate_secret_key,
    generate_secret_key,
    DEFAULT_SECRETS,
)


class TestGenerateSecretKey:
    """Tests for secret key generation."""
    
    def test_generate_default_length(self):
        """Тест генерации ключа с длиной по умолчанию."""
        key = generate_secret_key()
        assert len(key) > 64  # URL-safe base64 даёт больше символов чем байт
        assert isinstance(key, str)
    
    def test_generate_custom_length(self):
        """Тест генерации ключа с кастомной длиной."""
        key = generate_secret_key(32)
        assert len(key) > 32
        assert isinstance(key, str)
    
    def test_generate_unique(self):
        """Тест что каждый ключ уникальный."""
        key1 = generate_secret_key()
        key2 = generate_secret_key()
        assert key1 != key2


class TestValidateSecretKey:
    """Tests for secret key validation."""
    
    def test_valid_key_development(self):
        """Тест валидного ключа в development."""
        key = generate_secret_key()
        assert validate_secret_key(key, "development") is True
    
    def test_valid_key_production(self):
        """Тест валидного ключа в production."""
        key = generate_secret_key()
        assert validate_secret_key(key, "production") is True
    
    def test_empty_key_development(self):
        """Тест пустого ключа в development."""
        assert validate_secret_key("", "development") is False
        assert validate_secret_key("   ", "development") is False
    
    def test_empty_key_production(self):
        """Тест пустого ключа в production (должен выбросить исключение)."""
        with pytest.raises(ValueError, match="cannot be empty"):
            validate_secret_key("", "production")
    
    def test_default_key_development(self):
        """Тест дефолтного ключа в development (warning, но не fail)."""
        for default_key in DEFAULT_SECRETS:
            assert validate_secret_key(default_key, "development") is False
    
    def test_default_key_production(self):
        """Тест дефолтного ключа в production (должен выбросить исключение)."""
        for default_key in DEFAULT_SECRETS:
            with pytest.raises(ValueError, match="default value"):
                validate_secret_key(default_key, "production")
    
    def test_short_key_development(self):
        """Тест короткого ключа в development."""
        assert validate_secret_key("short_key", "development") is False
    
    def test_short_key_production(self):
        """Тест короткого ключа в production."""
        with pytest.raises(ValueError, match="at least 32 characters"):
            validate_secret_key("short_key", "production")
    
    def test_minimum_length_key(self):
        """Тест ключа минимальной допустимой длины."""
        key = "a" * 32
        assert validate_secret_key(key, "development") is True
        assert validate_secret_key(key, "production") is True
