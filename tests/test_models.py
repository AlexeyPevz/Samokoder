"""
Unit тесты для Pydantic моделей валидации
"""

import pytest
from datetime import datetime
from pydantic import ValidationError

from backend.models.requests import (
    LoginRequest, RegisterRequest, ProjectCreateRequest, ProjectUpdateRequest,
    ChatRequest, APIKeyCreateRequest, UserSettingsUpdateRequest
)
from backend.models.responses import (
    UserResponse, ProjectResponse, AIResponse, ErrorResponse
)

class TestLoginRequest:
    """Тесты для модели LoginRequest"""
    
    def test_valid_login_request(self):
        """Тест валидного запроса на вход"""
        request = LoginRequest(
            email="test@example.com",
            password="ValidPass123"
        )
        assert request.email == "test@example.com"
        assert request.password == "ValidPass123"
    
    def test_invalid_email(self):
        """Тест невалидного email"""
        with pytest.raises(ValidationError) as exc_info:
            LoginRequest(
                email="invalid-email",
                password="ValidPass123"
            )
        assert "email" in str(exc_info.value)
    
    def test_password_too_short(self):
        """Тест слишком короткого пароля"""
        with pytest.raises(ValidationError) as exc_info:
            LoginRequest(
                email="test@example.com",
                password="short"
            )
        assert "at least 8 characters" in str(exc_info.value)
    
    def test_password_missing_uppercase(self):
        """Тест пароля без заглавных букв"""
        with pytest.raises(ValidationError) as exc_info:
            LoginRequest(
                email="test@example.com",
                password="lowercase123"
            )
        assert "заглавную букву" in str(exc_info.value)
    
    def test_password_missing_lowercase(self):
        """Тест пароля без строчных букв"""
        with pytest.raises(ValidationError) as exc_info:
            LoginRequest(
                email="test@example.com",
                password="UPPERCASE123"
            )
        assert "строчную букву" in str(exc_info.value)
    
    def test_password_missing_digit(self):
        """Тест пароля без цифр"""
        with pytest.raises(ValidationError) as exc_info:
            LoginRequest(
                email="test@example.com",
                password="NoDigitsHere"
            )
        assert "цифру" in str(exc_info.value)

class TestProjectCreateRequest:
    """Тесты для модели ProjectCreateRequest"""
    
    def test_valid_project_request(self):
        """Тест валидного запроса на создание проекта"""
        request = ProjectCreateRequest(
            name="Test Project",
            description="This is a test project description"
        )
        assert request.name == "Test Project"
        assert request.description == "This is a test project description"
    
    def test_empty_name(self):
        """Тест пустого названия проекта"""
        with pytest.raises(ValidationError) as exc_info:
            ProjectCreateRequest(
                name="",
                description="This is a test project description"
            )
        assert "at least 1 character" in str(exc_info.value)
    
    def test_whitespace_only_name(self):
        """Тест названия проекта только из пробелов"""
        with pytest.raises(ValidationError) as exc_info:
            ProjectCreateRequest(
                name="   ",
                description="This is a test project description"
            )
        assert "не может быть пустым" in str(exc_info.value)
    
    def test_description_too_short(self):
        """Тест слишком короткого описания"""
        with pytest.raises(ValidationError) as exc_info:
            ProjectCreateRequest(
                name="Test Project",
                description="Short"
            )
        assert "at least 10 characters" in str(exc_info.value)
    
    def test_name_too_long(self):
        """Тест слишком длинного названия"""
        with pytest.raises(ValidationError) as exc_info:
            ProjectCreateRequest(
                name="A" * 101,  # 101 символ
                description="This is a test project description"
            )
        assert "at most 100 characters" in str(exc_info.value)

class TestChatRequest:
    """Тесты для модели ChatRequest"""
    
    def test_valid_chat_request(self):
        """Тест валидного запроса на чат"""
        request = ChatRequest(
            message="Hello, AI!",
            context="chat",
            max_tokens=1000,
            temperature=0.7
        )
        assert request.message == "Hello, AI!"
        assert request.context == "chat"
        assert request.max_tokens == 1000
        assert request.temperature == 0.7
    
    def test_empty_message(self):
        """Тест пустого сообщения"""
        with pytest.raises(ValidationError) as exc_info:
            ChatRequest(
                message="",
                context="chat"
            )
        assert "не может быть пустым" in str(exc_info.value)
    
    def test_message_too_long(self):
        """Тест слишком длинного сообщения"""
        with pytest.raises(ValidationError) as exc_info:
            ChatRequest(
                message="A" * 4001,  # 4001 символ
                context="chat"
            )
        assert "слишком длинное" in str(exc_info.value)
    
    def test_invalid_temperature(self):
        """Тест невалидной температуры"""
        with pytest.raises(ValidationError) as exc_info:
            ChatRequest(
                message="Hello",
                temperature=3.0  # Слишком высокая
            )
        assert "меньше или равна 2.0" in str(exc_info.value)
    
    def test_negative_temperature(self):
        """Тест отрицательной температуры"""
        with pytest.raises(ValidationError) as exc_info:
            ChatRequest(
                message="Hello",
                temperature=-0.1
            )
        assert "больше или равна 0.0" in str(exc_info.value)

class TestAPIKeyCreateRequest:
    """Тесты для модели APIKeyCreateRequest"""
    
    def test_valid_openai_key(self):
        """Тест валидного OpenAI ключа"""
        request = APIKeyCreateRequest(
            provider="openai",
            key_name="My OpenAI Key",
            api_key="sk-1234567890abcdef1234567890abcdef"
        )
        assert request.provider == "openai"
        assert request.key_name == "My OpenAI Key"
        assert request.api_key == "sk-1234567890abcdef1234567890abcdef"
    
    def test_valid_anthropic_key(self):
        """Тест валидного Anthropic ключа"""
        request = APIKeyCreateRequest(
            provider="anthropic",
            key_name="My Anthropic Key",
            api_key="sk-ant-1234567890abcdef1234567890abcdef"
        )
        assert request.provider == "anthropic"
    
    def test_invalid_openai_key_format(self):
        """Тест невалидного формата OpenAI ключа"""
        with pytest.raises(ValidationError) as exc_info:
            APIKeyCreateRequest(
                provider="openai",
                key_name="My OpenAI Key",
                api_key="invalid-key-format"
            )
        assert "должен начинаться с" in str(exc_info.value)
    
    def test_invalid_anthropic_key_format(self):
        """Тест невалидного формата Anthropic ключа"""
        with pytest.raises(ValidationError) as exc_info:
            APIKeyCreateRequest(
                provider="anthropic",
                key_name="My Anthropic Key",
                api_key="sk-1234567890abcdef"
            )
        assert "должен начинаться с" in str(exc_info.value)
    
    def test_key_too_short(self):
        """Тест слишком короткого ключа"""
        with pytest.raises(ValidationError) as exc_info:
            APIKeyCreateRequest(
                provider="openai",
                key_name="My OpenAI Key",
                api_key="sk-short"
            )
        assert "at least 10 characters" in str(exc_info.value)

class TestUserSettingsUpdateRequest:
    """Тесты для модели UserSettingsUpdateRequest"""
    
    def test_valid_settings_update(self):
        """Тест валидного обновления настроек"""
        request = UserSettingsUpdateRequest(
            default_model="gpt-4o-mini",
            default_provider="openai",
            auto_export=True,
            theme="dark"
        )
        assert request.default_model == "gpt-4o-mini"
        assert request.default_provider == "openai"
        assert request.auto_export is True
        assert request.theme == "dark"
    
    def test_invalid_theme(self):
        """Тест невалидной темы"""
        with pytest.raises(ValidationError) as exc_info:
            UserSettingsUpdateRequest(
                theme="invalid-theme"
            )
        assert "должна быть light, dark или auto" in str(exc_info.value)
    
    def test_all_optional_fields(self):
        """Тест с всеми опциональными полями"""
        request = UserSettingsUpdateRequest()
        assert request.default_model is None
        assert request.default_provider is None
        assert request.auto_export is None
        assert request.theme is None

class TestResponseModels:
    """Тесты для моделей ответов"""
    
    def test_user_response(self):
        """Тест модели UserResponse"""
        user = UserResponse(
            id="user123",
            email="test@example.com",
            full_name="Test User",
            subscription_tier="free",
            subscription_status="active",
            api_credits_balance=10.5,
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        assert user.id == "user123"
        assert user.email == "test@example.com"
        assert user.subscription_tier == "free"
    
    def test_project_response(self):
        """Тест модели ProjectResponse"""
        project = ProjectResponse(
            id="project123",
            user_id="user123",
            name="Test Project",
            description="Test description",
            status="draft",
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        assert project.id == "project123"
        assert project.name == "Test Project"
        assert project.status == "draft"
    
    def test_ai_response(self):
        """Тест модели AIResponse"""
        ai_response = AIResponse(
            content="Hello, I'm an AI assistant!",
            provider="openai",
            model="gpt-4o-mini",
            tokens_used=25,
            cost_usd=0.001,
            response_time=1.5
        )
        assert ai_response.content == "Hello, I'm an AI assistant!"
        assert ai_response.provider == "openai"
        assert ai_response.tokens_used == 25
    
    def test_error_response(self):
        """Тест модели ErrorResponse"""
        error = ErrorResponse(
            error="validation_error",
            message="Ошибка валидации",
            details={"field": "email"}
        )
        assert error.success is False
        assert error.error == "validation_error"
        assert error.message == "Ошибка валидации"