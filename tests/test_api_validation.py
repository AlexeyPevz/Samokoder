"""
Тесты для валидации API.

Проверяет:
- Pydantic модели
- Валидацию входных данных
- Обработку ошибок
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock
import json
from pydantic import ValidationError

from samokoder.core.api.models.projects import ProjectCreateRequest, ProjectUpdateRequest
from samokoder.core.api.models.auth import LoginRequest, RegisterRequest
from samokoder.core.api.models.keys import ApiKeyCreateRequest, ApiKeyProvider


class TestProjectValidation:
    """Тесты валидации проектов."""

    def test_project_create_valid_data(self):
        """Тест создания проекта с валидными данными."""
        data = {
            "name": "Test Project",
            "description": "Test description"
        }
        
        request = ProjectCreateRequest(**data)
        assert request.name == "Test Project"
        assert request.description == "Test description"

    def test_project_create_invalid_name(self):
        """Тест создания проекта с невалидным названием."""
        # Пустое название
        with pytest.raises(ValidationError, match="String should have at least 1 character"):
            ProjectCreateRequest(name="", description="Test")

        # Название с запрещенными символами
        with pytest.raises(ValidationError, match="Название содержит запрещенный символ"):
            ProjectCreateRequest(name="Test <script>", description="Test")

        # Название с SQL ключевыми словами
        with pytest.raises(ValidationError, match="содержит запрещенное слово"):
            ProjectCreateRequest(name="Test select Project", description="Test")

    def test_project_create_long_name(self):
        """Тест создания проекта со слишком длинным названием."""
        long_name = "a" * 101  # Больше максимума 100
        with pytest.raises(ValidationError):
            ProjectCreateRequest(name=long_name, description="Test")

    def test_project_update_optional_fields(self):
        """Тест обновления проекта с опциональными полями."""
        # Только название
        request = ProjectUpdateRequest(name="New Name")
        assert request.name == "New Name"
        assert request.description is None

        # Только описание
        request = ProjectUpdateRequest(description="New description")
        assert request.name is None
        assert request.description == "New description"

        # Оба поля
        request = ProjectUpdateRequest(name="New Name", description="New desc")
        assert request.name == "New Name"
        assert request.description == "New desc"


class TestAuthValidation:
    """Тесты валидации аутентификации."""

    def test_login_valid_data(self):
        """Тест входа с валидными данными."""
        data = {
            "email": "test@example.com",
            "password": "password123"
        }
        
        request = LoginRequest(**data)
        assert request.email == "test@example.com"
        assert request.password == "password123"

    def test_login_invalid_email(self):
        """Тест входа с невалидным email."""
        # Неверный формат email
        with pytest.raises(ValidationError):
            LoginRequest(email="invalid-email", password="password123")
        
        # Слишком длинный email
        long_email = "a" * 250 + "@example.com"
        with pytest.raises(ValidationError):
            LoginRequest(email=long_email, password="password123")

    def test_register_valid_data(self):
        """Тест регистрации с валидными данными."""
        data = {
            "email": "test@example.com",
            "password": "Password123",
            "confirm_password": "Password123"
        }
        
        request = RegisterRequest(**data)
        assert request.email == "test@example.com"
        assert request.password == "Password123"

    def test_register_password_mismatch(self):
        """Тест регистрации с несовпадающими паролями."""
        data = {
            "email": "test@example.com",
            "password": "Password123",
            "confirm_password": "DifferentPassword"
        }
        
        with pytest.raises(ValidationError, match="Пароли не совпадают"):
            RegisterRequest(**data)

    def test_register_weak_password(self):
        """Тест регистрации со слабым паролем."""
        # Слишком короткий пароль
        with pytest.raises(ValidationError, match="String should have at least 8 characters"):
            RegisterRequest(
                email="test@example.com",
                password="123",
                confirm_password="123"
            )
        
        # Только строчные буквы
        with pytest.raises(ValidationError, match="Пароль должен содержать буквы верхнего и нижнего регистра, а также цифры"):
            RegisterRequest(
                email="test@example.com",
                password="password123",
                confirm_password="password123"
            )
        
        # Только буквы
        with pytest.raises(ValidationError, match="Пароль должен содержать буквы верхнего и нижнего регистра, а также цифры"):
            RegisterRequest(
                email="test@example.com",
                password="PasswordOnly",
                confirm_password="PasswordOnly"
            )


class TestApiKeyValidation:
    """Тесты валидации API ключей."""

    def test_api_key_create_valid_openai(self):
        """Тест создания OpenAI ключа."""
        data = {
            "provider": ApiKeyProvider.OPENAI,
            "api_key": "sk-1234567890abcdef1234567890abcdef12345678",
            "model": "gpt-4"
        }
        
        request = ApiKeyCreateRequest(**data)
        assert request.provider == ApiKeyProvider.OPENAI
        assert request.api_key.startswith("sk-")
        assert request.model == "gpt-4"

    def test_api_key_create_valid_anthropic(self):
        """Тест создания Anthropic ключа."""
        data = {
            "provider": ApiKeyProvider.ANTHROPIC,
            "api_key": "sk-ant-api03-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            "model": "claude-3-sonnet-20240229"
        }
        
        request = ApiKeyCreateRequest(**data)
        assert request.provider == ApiKeyProvider.ANTHROPIC
        assert request.api_key.startswith("sk-ant-")

    def test_api_key_create_invalid_provider(self):
        """Тест создания ключа с невалидным провайдером."""
        data = {
            "provider": "invalid_provider",
            "api_key": "sk-1234567890abcdef1234567890abcdef12345678"
        }
        
        with pytest.raises(ValidationError):
            ApiKeyCreateRequest(**data)

    def test_api_key_create_empty_key(self):
        """Тест создания ключа с пустым API ключом."""
        data = {
            "provider": ApiKeyProvider.OPENAI,
            "api_key": ""
        }
        
        with pytest.raises(ValidationError, match="String should have at least 10 characters"):
            ApiKeyCreateRequest(**data)

    def test_api_key_create_short_key(self):
        """Тест создания ключа с коротким API ключом."""
        data = {
            "provider": ApiKeyProvider.OPENAI,
            "api_key": "sk-short"
        }
        
        with pytest.raises(ValidationError):
            ApiKeyCreateRequest(**data)


class TestModelSerialization:
    """Тесты сериализации моделей."""

    def test_project_model_to_dict(self):
        """Тест преобразования модели в dict."""
        request = ProjectCreateRequest(
            name="Test Project",
            description="Test description"
        )
        
        data = request.model_dump()
        assert data["name"] == "Test Project"
        assert data["description"] == "Test description"
        assert "model_config" not in data

    def test_project_model_json_serialization(self):
        """Тест JSON сериализации модели."""
        request = ProjectCreateRequest(
            name="Test Project",
            description="Test description"
        )
        
        json_data = request.model_dump_json()
        parsed = json.loads(json_data)
        
        assert parsed["name"] == "Test Project"
        assert parsed["description"] == "Test description"
