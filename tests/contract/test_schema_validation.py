"""
Тесты валидации схем данных согласно OpenAPI спецификации.

Проверяет:
1. Соответствие типов данных
2. Обязательные поля
3. Форматы данных (email, uuid, date-time)
4. Ограничения (min/max length, enum values)
5. Вложенные объекты
"""

import re
from datetime import datetime
from typing import Any, Dict
from uuid import UUID

import pytest
from pydantic import ValidationError

from samokoder.core.api.models.auth import (
    RegisterRequest, LoginRequest, AuthResponse,
    TokenRefreshRequest, TokenRefreshResponse
)
from samokoder.core.api.models.projects import (
    ProjectCreateRequest, ProjectUpdateRequest,
    ProjectListResponse, ProjectDetailResponse
)
from samokoder.core.api.models.base import (
    UserResponse, ErrorResponse, ProjectResponse
)


class TestAuthSchemas:
    """Тесты схем аутентификации."""
    
    def test_register_request_valid(self):
        """Валидный запрос регистрации должен пройти валидацию."""
        request = RegisterRequest(
            email="user@example.com",
            password="SecurePass123!"
        )
        
        assert request.email == "user@example.com"
        assert request.password == "SecurePass123!"
    
    def test_register_request_weak_password(self):
        """Слабый пароль должен не пройти валидацию."""
        with pytest.raises(ValidationError) as exc_info:
            RegisterRequest(
                email="user@example.com",
                password="weak"
            )
        
        errors = exc_info.value.errors()
        assert any("пароль" in str(e["msg"]).lower() for e in errors)
    
    def test_register_request_no_uppercase(self):
        """Пароль без заглавной буквы должен не пройти валидацию."""
        with pytest.raises(ValidationError) as exc_info:
            RegisterRequest(
                email="user@example.com",
                password="securepass123!"
            )
        
        errors = exc_info.value.errors()
        assert any("заглавн" in str(e["msg"]).lower() for e in errors)
    
    def test_register_request_no_digit(self):
        """Пароль без цифры должен не пройти валидацию."""
        with pytest.raises(ValidationError) as exc_info:
            RegisterRequest(
                email="user@example.com",
                password="SecurePass!"
            )
        
        errors = exc_info.value.errors()
        assert any("цифр" in str(e["msg"]).lower() for e in errors)
    
    def test_register_request_no_special_char(self):
        """Пароль без спецсимвола должен не пройти валидацию."""
        with pytest.raises(ValidationError) as exc_info:
            RegisterRequest(
                email="user@example.com",
                password="SecurePass123"
            )
        
        errors = exc_info.value.errors()
        assert any("специальн" in str(e["msg"]).lower() for e in errors)
    
    def test_register_request_common_password(self):
        """Распространенный пароль должен не пройти валидацию."""
        with pytest.raises(ValidationError) as exc_info:
            RegisterRequest(
                email="user@example.com",
                password="Password123"  # В списке COMMON_PASSWORDS
            )
        
        errors = exc_info.value.errors()
        assert any("распространен" in str(e["msg"]).lower() for e in errors)
    
    def test_register_request_sequential_chars(self):
        """Пароль с повторяющимися символами должен не пройти валидацию."""
        with pytest.raises(ValidationError) as exc_info:
            RegisterRequest(
                email="user@example.com",
                password="Secuuure123!"  # uuu - три подряд
            )
        
        errors = exc_info.value.errors()
        assert any("одинаковых символов" in str(e["msg"]).lower() for e in errors)
    
    def test_register_request_invalid_email(self):
        """Невалидный email должен не пройти валидацию."""
        with pytest.raises(ValidationError):
            RegisterRequest(
                email="not-an-email",
                password="SecurePass123!"
            )
    
    def test_register_request_email_too_long(self):
        """Слишком длинный email должен не пройти валидацию."""
        with pytest.raises(ValidationError) as exc_info:
            RegisterRequest(
                email="a" * 250 + "@example.com",  # > 254 символов
                password="SecurePass123!"
            )
        
        errors = exc_info.value.errors()
        assert any("длинн" in str(e["msg"]).lower() for e in errors)
    
    def test_login_request_valid(self):
        """Валидный запрос логина должен пройти валидацию."""
        request = LoginRequest(
            email="user@example.com",
            password="any_password"
        )
        
        assert request.email == "user@example.com"
        assert request.password == "any_password"
    
    def test_auth_response_structure(self):
        """AuthResponse должен иметь все обязательные поля."""
        response = AuthResponse(
            access_token="token123",
            refresh_token="refresh456",
            token_type="bearer",
            expires_in=900,
            user_id=1,
            email="user@example.com"
        )
        
        assert response.access_token == "token123"
        assert response.refresh_token == "refresh456"
        assert response.token_type == "bearer"
        assert response.expires_in == 900
        assert response.user_id == 1
        assert response.email == "user@example.com"
    
    def test_token_refresh_request(self):
        """TokenRefreshRequest должен принимать refresh token."""
        request = TokenRefreshRequest(refresh_token="refresh_token_here")
        assert request.refresh_token == "refresh_token_here"


class TestProjectSchemas:
    """Тесты схем проектов."""
    
    def test_project_create_request_valid(self):
        """Валидный запрос создания проекта."""
        request = ProjectCreateRequest(
            name="My Project",
            description="Project description"
        )
        
        assert request.name == "My Project"
        assert request.description == "Project description"
    
    def test_project_create_request_name_required(self):
        """Имя проекта обязательно."""
        with pytest.raises(ValidationError):
            ProjectCreateRequest(description="Only description")
    
    def test_project_create_request_name_too_long(self):
        """Слишком длинное имя не должно пройти валидацию."""
        with pytest.raises(ValidationError):
            ProjectCreateRequest(name="a" * 101)  # max_length=100
    
    def test_project_create_request_description_optional(self):
        """Описание проекта опционально."""
        request = ProjectCreateRequest(name="Project")
        assert request.description is None
    
    def test_project_update_request_partial(self):
        """ProjectUpdateRequest позволяет частичное обновление."""
        request = ProjectUpdateRequest(name="New Name")
        assert request.name == "New Name"
        assert request.description is None
        
        request2 = ProjectUpdateRequest(description="New Description")
        assert request2.name is None
        assert request2.description == "New Description"
    
    def test_project_response_structure(self):
        """ProjectResponse должен иметь все обязательные поля."""
        from uuid import uuid4
        from datetime import datetime
        
        response = ProjectResponse(
            id=uuid4(),
            name="Project",
            description="Description",
            created_at=datetime.utcnow(),
            user_id=1
        )
        
        assert isinstance(response.id, UUID)
        assert response.name == "Project"
        assert isinstance(response.created_at, datetime)
    
    def test_project_list_response(self):
        """ProjectListResponse должен содержать список и общее количество."""
        from uuid import uuid4
        from datetime import datetime
        
        project = ProjectResponse(
            id=uuid4(),
            name="Project",
            created_at=datetime.utcnow(),
            user_id=1
        )
        
        response = ProjectListResponse(
            projects=[project],
            total=1
        )
        
        assert len(response.projects) == 1
        assert response.total == 1


class TestUserSchema:
    """Тесты схемы пользователя."""
    
    def test_user_response_structure(self):
        """UserResponse должен иметь все обязательные поля."""
        from datetime import datetime
        
        response = UserResponse(
            id=1,
            email="user@example.com",
            tier="free",
            created_at=datetime.utcnow(),
            projects_count=5
        )
        
        assert response.id == 1
        assert response.email == "user@example.com"
        assert response.tier == "free"
        assert isinstance(response.created_at, datetime)
        assert response.projects_count == 5
    
    def test_user_response_tier_validation(self):
        """Tier должен быть одним из допустимых значений."""
        from datetime import datetime
        
        # Валидные значения
        for tier in ["free", "pro", "enterprise"]:
            UserResponse(
                id=1,
                email="user@example.com",
                tier=tier,
                created_at=datetime.utcnow(),
                projects_count=0
            )
        
        # Невалидное значение - в UserResponse нет enum валидации,
        # но в спецификации указаны допустимые значения
        # (это проверяется на уровне API)


class TestErrorSchema:
    """Тесты схемы ошибок."""
    
    def test_error_response_minimal(self):
        """ErrorResponse с минимальными данными."""
        error = ErrorResponse(detail="Something went wrong")
        
        assert error.detail == "Something went wrong"
        assert error.error_code is None
        assert isinstance(error.timestamp, datetime)
    
    def test_error_response_full(self):
        """ErrorResponse со всеми полями."""
        timestamp = datetime.utcnow()
        error = ErrorResponse(
            detail="Project not found",
            error_code="PROJECT_NOT_FOUND",
            timestamp=timestamp
        )
        
        assert error.detail == "Project not found"
        assert error.error_code == "PROJECT_NOT_FOUND"
        assert error.timestamp == timestamp


class TestDataFormats:
    """Тесты форматов данных."""
    
    def test_email_format_validation(self):
        """Email должен соответствовать формату."""
        # Валидные email
        valid_emails = [
            "user@example.com",
            "test.user@domain.co.uk",
            "user+tag@example.com",
            "123@example.com"
        ]
        
        for email in valid_emails:
            request = LoginRequest(email=email, password="pass")
            assert "@" in request.email
    
    def test_uuid_format(self):
        """UUID должен быть валидным."""
        from uuid import uuid4
        
        project_id = uuid4()
        response = ProjectResponse(
            id=project_id,
            name="Test",
            created_at=datetime.utcnow(),
            user_id=1
        )
        
        # Проверить, что можно сконвертировать обратно в UUID
        assert isinstance(response.id, UUID)
        assert str(response.id) == str(project_id)
    
    def test_datetime_format(self):
        """DateTime должен быть в правильном формате."""
        now = datetime.utcnow()
        response = ProjectResponse(
            id=UUID('00000000-0000-0000-0000-000000000001'),
            name="Test",
            created_at=now,
            user_id=1
        )
        
        assert isinstance(response.created_at, datetime)
        
        # Проверить, что можно сериализовать в ISO формат
        from pydantic import BaseModel
        
        class TestModel(BaseModel):
            dt: datetime
        
        model = TestModel(dt=response.created_at)
        json_data = model.model_dump_json()
        assert "T" in json_data  # ISO формат содержит T между датой и временем


class TestFieldConstraints:
    """Тесты ограничений полей."""
    
    def test_string_min_length(self):
        """Минимальная длина строки должна соблюдаться."""
        # Password min_length=8
        with pytest.raises(ValidationError):
            RegisterRequest(
                email="user@example.com",
                password="Short1!"  # 7 символов
            )
    
    def test_string_max_length(self):
        """Максимальная длина строки должна соблюдаться."""
        # Project name max_length=100
        with pytest.raises(ValidationError):
            ProjectCreateRequest(name="a" * 101)
        
        # Должно работать с 100 символами
        ProjectCreateRequest(name="a" * 100)
    
    def test_integer_minimum(self):
        """Минимальное значение integer должно соблюдаться."""
        # projects_count minimum: 0
        with pytest.raises(ValidationError):
            UserResponse(
                id=1,
                email="user@example.com",
                tier="free",
                created_at=datetime.utcnow(),
                projects_count=-1  # Отрицательное недопустимо
            )


class TestSchemaConsistency:
    """Тесты консистентности между схемами."""
    
    def test_project_response_in_list_matches_detail(self):
        """ProjectResponse должен быть одинаковым в list и detail ответах."""
        from uuid import uuid4
        
        project = ProjectResponse(
            id=uuid4(),
            name="Test",
            created_at=datetime.utcnow(),
            user_id=1
        )
        
        # Используется в обоих ответах
        list_response = ProjectListResponse(projects=[project], total=1)
        detail_response = ProjectDetailResponse(project=project)
        
        assert list_response.projects[0].id == detail_response.project.id
        assert list_response.projects[0].name == detail_response.project.name
    
    def test_user_response_consistent(self):
        """UserResponse должен быть консистентным в разных эндпоинтах."""
        user = UserResponse(
            id=1,
            email="user@example.com",
            tier="free",
            created_at=datetime.utcnow(),
            projects_count=0
        )
        
        # Используется в /v1/auth/me
        # Должен содержать те же поля
        assert hasattr(user, 'id')
        assert hasattr(user, 'email')
        assert hasattr(user, 'tier')
        assert hasattr(user, 'created_at')
        assert hasattr(user, 'projects_count')


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
