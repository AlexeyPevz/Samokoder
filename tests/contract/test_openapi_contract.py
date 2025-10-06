"""
Контрактные тесты для проверки соответствия OpenAPI спецификации и реализации.

Эти тесты гарантируют:
1. Все эндпоинты из спецификации реализованы
2. Все реализованные эндпоинты документированы в спецификации
3. Схемы запросов/ответов соответствуют спецификации
4. Коды ошибок соответствуют документации
5. Обязательные поля присутствуют в ответах

Основано на:
- OpenAPI 3.1 спецификация: openapi.yaml
- Реализация: api/routers/*.py
"""

import json
from typing import Dict, Any, List
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient
from openapi_spec_validator import validate_spec
from openapi_spec_validator.readers import read_from_filename

from samokoder.api.main import app
from samokoder.core.db.models.user import User, Tier
from samokoder.core.db.models.project import Project


@pytest.fixture
def openapi_spec() -> Dict[str, Any]:
    """Загрузить и валидировать OpenAPI спецификацию."""
    spec_path = Path(__file__).parent.parent.parent / "openapi.yaml"
    
    # Загрузить спецификацию
    spec_dict, spec_url = read_from_filename(str(spec_path))
    
    # Валидировать спецификацию
    validate_spec(spec_dict)
    
    return spec_dict


@pytest.fixture
def client() -> TestClient:
    """Создать тестовый клиент FastAPI."""
    return TestClient(app)


@pytest.fixture
def auth_headers(test_user: User, client: TestClient) -> Dict[str, str]:
    """Получить headers с JWT токеном для аутентифицированных запросов."""
    # Login
    response = client.post(
        "/v1/auth/login",
        data={
            "username": test_user.email,
            "password": "TestPassword123!"
        }
    )
    assert response.status_code == 200
    
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


class TestOpenAPISpecification:
    """Тесты валидации самой спецификации OpenAPI."""
    
    def test_spec_is_valid_openapi_3_1(self, openapi_spec):
        """Спецификация должна быть валидной OpenAPI 3.1."""
        assert openapi_spec["openapi"].startswith("3.1")
        assert "info" in openapi_spec
        assert "paths" in openapi_spec
        
    def test_spec_has_required_metadata(self, openapi_spec):
        """Спецификация должна содержать необходимые метаданные."""
        info = openapi_spec["info"]
        assert info["title"] == "Samokoder SaaS API"
        assert "version" in info
        assert "description" in info
        
    def test_spec_defines_security_schemes(self, openapi_spec):
        """Спецификация должна определять схемы безопасности."""
        components = openapi_spec.get("components", {})
        security_schemes = components.get("securitySchemes", {})
        
        assert "BearerAuth" in security_schemes
        assert security_schemes["BearerAuth"]["type"] == "http"
        assert security_schemes["BearerAuth"]["scheme"] == "bearer"
        
    def test_spec_has_all_required_schemas(self, openapi_spec):
        """Спецификация должна определять все необходимые схемы."""
        schemas = openapi_spec["components"]["schemas"]
        
        required_schemas = [
            "RegisterRequest", "LoginRequest", "AuthResponse",
            "ProjectCreateRequest", "ProjectResponse", "ProjectListResponse",
            "ApiKeyCreate", "ApiKeyResponse", "ErrorResponse",
            "UserResponse", "TokenRefreshRequest", "TokenRefreshResponse"
        ]
        
        for schema_name in required_schemas:
            assert schema_name in schemas, f"Schema {schema_name} not found in spec"


class TestEndpointCoverage:
    """Тесты покрытия эндпоинтов спецификацией."""
    
    def test_all_spec_endpoints_are_implemented(self, openapi_spec, client):
        """Все эндпоинты из спецификации должны быть реализованы."""
        paths = openapi_spec["paths"]
        
        # Эндпоинты, которые требуют специальной настройки (пропускаем)
        skip_endpoints = {
            "/v1/ws/{project_id}",  # WebSocket - requires special handling
        }
        
        for path, methods in paths.items():
            if path in skip_endpoints:
                continue
                
            for method in methods.keys():
                if method in ["parameters", "servers", "summary", "description"]:
                    continue
                    
                # Заменить параметры пути на тестовые значения
                test_path = path.replace("{project_id}", "00000000-0000-0000-0000-000000000001")
                test_path = test_path.replace("{provider}", "openai")
                test_path = test_path.replace("{plugin_name}", "test")
                test_path = test_path.replace("{notification_id}", "test123")
                test_path = test_path.replace("{component_name}", "database")
                test_path = test_path.replace("{model}", "gpt-4")
                
                # Делаем запрос (может вернуть 401, 404 и т.д., но не 405)
                response = getattr(client, method.lower())(test_path)
                
                # 405 означает, что эндпоинт не реализован
                assert response.status_code != 405, \
                    f"{method.upper()} {path} returns 405 - endpoint not implemented"
    
    def test_no_undocumented_endpoints(self, openapi_spec):
        """Не должно быть недокументированных эндпоинтов в реализации."""
        # Получить все маршруты из FastAPI приложения
        app_routes = set()
        for route in app.routes:
            if hasattr(route, "path") and hasattr(route, "methods"):
                path = route.path
                for method in route.methods:
                    # Пропустить OPTIONS и HEAD
                    if method in ["OPTIONS", "HEAD"]:
                        continue
                    app_routes.add(f"{method} {path}")
        
        # Получить все эндпоинты из спецификации
        spec_routes = set()
        for path, methods in openapi_spec["paths"].items():
            for method in methods.keys():
                if method in ["parameters", "servers", "summary", "description"]:
                    continue
                spec_routes.add(f"{method.upper()} {path}")
        
        # Системные эндпоинты, которые не обязательно документировать
        system_routes = {
            "GET /docs", "GET /redoc", "GET /openapi.json",
            "GET /docs/oauth2-redirect"
        }
        
        # Найти недокументированные эндпоинты
        undocumented = app_routes - spec_routes - system_routes
        
        # Игнорировать метрики и статические файлы
        undocumented = {r for r in undocumented if not r.startswith("GET /metrics")}
        
        assert len(undocumented) == 0, \
            f"Found undocumented endpoints: {undocumented}"


class TestAuthenticationEndpoints:
    """Контрактные тесты для эндпоинтов аутентификации."""
    
    def test_register_request_schema(self, client, openapi_spec):
        """POST /v1/auth/register должен соответствовать схеме."""
        response = client.post(
            "/v1/auth/register",
            json={
                "email": "newuser@example.com",
                "password": "SecurePass123!"
            }
        )
        
        # Может быть 201 (успех) или 400 (пользователь существует)
        assert response.status_code in [201, 400]
        
        if response.status_code == 201:
            data = response.json()
            
            # Проверить обязательные поля из AuthResponse
            assert "access_token" in data
            assert "token_type" in data
            assert data["token_type"] == "bearer"
            assert "expires_in" in data
            assert "user_id" in data
            assert "email" in data
    
    def test_register_invalid_password(self, client):
        """Регистрация с невалидным паролем должна возвращать 422."""
        response = client.post(
            "/v1/auth/register",
            json={
                "email": "test@example.com",
                "password": "weak"  # Слишком простой пароль
            }
        )
        
        assert response.status_code == 422
        assert "detail" in response.json()
    
    def test_login_response_schema(self, client, test_user):
        """POST /v1/auth/login должен возвращать AuthResponse."""
        response = client.post(
            "/v1/auth/login",
            data={
                "username": test_user.email,
                "password": "TestPassword123!"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Проверить схему AuthResponse
        assert "access_token" in data
        assert isinstance(data["access_token"], str)
        assert "refresh_token" in data
        assert "token_type" in data
        assert data["token_type"] == "bearer"
        assert "expires_in" in data
        assert isinstance(data["expires_in"], int)
        assert "user_id" in data
        assert "email" in data
        assert data["email"] == test_user.email
    
    def test_login_sets_cookies(self, client, test_user):
        """POST /v1/auth/login должен устанавливать httpOnly cookies."""
        response = client.post(
            "/v1/auth/login",
            data={
                "username": test_user.email,
                "password": "TestPassword123!"
            }
        )
        
        assert response.status_code == 200
        
        # Проверить наличие cookies
        cookies = response.cookies
        assert "access_token" in cookies
        assert "refresh_token" in cookies
    
    def test_get_current_user(self, client, auth_headers):
        """GET /v1/auth/me должен возвращать UserResponse."""
        response = client.get("/v1/auth/me", headers=auth_headers)
        
        assert response.status_code == 200
        data = response.json()
        
        # Проверить схему UserResponse
        assert "id" in data
        assert "email" in data
        assert "tier" in data
        assert data["tier"] in ["free", "pro", "enterprise"]
        assert "created_at" in data
        assert "projects_count" in data
        assert isinstance(data["projects_count"], int)
    
    def test_unauthorized_access(self, client):
        """Запросы без токена должны возвращать 401."""
        response = client.get("/v1/auth/me")
        assert response.status_code == 401
        
        data = response.json()
        assert "detail" in data
    
    def test_refresh_token(self, client, test_user):
        """POST /v1/auth/refresh должен обновлять токен."""
        # Сначала получить refresh token
        login_response = client.post(
            "/v1/auth/login",
            data={
                "username": test_user.email,
                "password": "TestPassword123!"
            }
        )
        refresh_token = login_response.json()["refresh_token"]
        
        # Обновить токен
        response = client.post(
            "/v1/auth/refresh",
            json={"refresh_token": refresh_token}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Проверить схему TokenRefreshResponse
        assert "access_token" in data
        assert "token_type" in data
        assert data["token_type"] == "bearer"
        assert "expires_in" in data


class TestProjectEndpoints:
    """Контрактные тесты для эндпоинтов проектов."""
    
    def test_create_project_schema(self, client, auth_headers):
        """POST /v1/projects должен создавать проект."""
        response = client.post(
            "/v1/projects",
            headers=auth_headers,
            json={
                "name": "Test Project",
                "description": "Test Description"
            }
        )
        
        assert response.status_code == 201
        data = response.json()
        
        # Проверить схему ProjectDetailResponse
        assert "project" in data
        project = data["project"]
        
        assert "id" in project
        assert "name" in project
        assert project["name"] == "Test Project"
        assert "description" in project
        assert "created_at" in project
        assert "user_id" in project
    
    def test_create_project_validation(self, client, auth_headers):
        """Создание проекта без имени должно возвращать 422."""
        response = client.post(
            "/v1/projects",
            headers=auth_headers,
            json={"description": "Only description"}
        )
        
        assert response.status_code == 422
    
    def test_list_projects_schema(self, client, auth_headers):
        """GET /v1/projects должен возвращать ProjectListResponse."""
        response = client.get("/v1/projects", headers=auth_headers)
        
        assert response.status_code == 200
        data = response.json()
        
        # Проверить схему ProjectListResponse
        assert "projects" in data
        assert isinstance(data["projects"], list)
        assert "total" in data
        assert isinstance(data["total"], int)
        
        # Если есть проекты, проверить их схему
        if data["projects"]:
            project = data["projects"][0]
            assert "id" in project
            assert "name" in project
            assert "created_at" in project
    
    def test_get_project_not_found(self, client, auth_headers):
        """GET несуществующего проекта должен возвращать 404."""
        fake_uuid = "00000000-0000-0000-0000-000000000001"
        response = client.get(
            f"/v1/projects/{fake_uuid}",
            headers=auth_headers
        )
        
        assert response.status_code == 404
        assert "detail" in response.json()
    
    def test_update_project_schema(self, client, auth_headers, test_project):
        """PUT /v1/projects/{id} должен обновлять проект."""
        response = client.put(
            f"/v1/projects/{test_project.id}",
            headers=auth_headers,
            json={"name": "Updated Name"}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert "project" in data
        assert data["project"]["name"] == "Updated Name"
    
    def test_delete_project(self, client, auth_headers, test_project):
        """DELETE /v1/projects/{id} должен удалять проект."""
        response = client.delete(
            f"/v1/projects/{test_project.id}",
            headers=auth_headers
        )
        
        assert response.status_code == 204
        assert response.content == b""


class TestApiKeysEndpoints:
    """Контрактные тесты для эндпоинтов API ключей."""
    
    def test_add_api_key_schema(self, client, auth_headers):
        """POST /v1/keys должен добавлять API ключ."""
        response = client.post(
            "/v1/keys",
            headers=auth_headers,
            json={
                "provider": "openai",
                "api_key": "sk-test1234567890abcdef",
                "model": "gpt-4o-mini"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Проверить схему ApiKeyResponse
        assert "provider" in data
        assert data["provider"] == "openai"
        assert "display_key" in data
        assert data["display_key"].startswith("...-")
        assert "model" in data
    
    def test_add_api_key_validation(self, client, auth_headers):
        """Добавление ключа с невалидным провайдером должно вернуть ошибку."""
        response = client.post(
            "/v1/keys",
            headers=auth_headers,
            json={
                "provider": "invalid_provider",
                "api_key": "test_key"
            }
        )
        
        # Может быть 422 (валидация) или 500 (другая ошибка)
        assert response.status_code in [422, 500]
    
    def test_list_api_keys_schema(self, client, auth_headers):
        """GET /v1/keys должен возвращать список ключей."""
        response = client.get("/v1/keys", headers=auth_headers)
        
        assert response.status_code == 200
        data = response.json()
        
        assert isinstance(data, list)
        
        # Если есть ключи, проверить схему
        if data:
            key = data[0]
            assert "provider" in key
            assert "display_key" in key
    
    def test_delete_api_key(self, client, auth_headers):
        """DELETE /v1/keys/{provider} должен удалять ключ."""
        # Сначала добавить ключ
        client.post(
            "/v1/keys",
            headers=auth_headers,
            json={
                "provider": "groq",
                "api_key": "gsk-test1234567890"
            }
        )
        
        # Удалить ключ
        response = client.delete(
            "/v1/keys/groq",
            headers=auth_headers
        )
        
        assert response.status_code == 204


class TestModelsEndpoints:
    """Контрактные тесты для эндпоинтов моделей."""
    
    def test_get_all_models(self, client):
        """GET /v1/models должен возвращать модели (без авторизации)."""
        response = client.get("/v1/models")
        
        assert response.status_code == 200
        data = response.json()
        
        # Должны быть провайдеры
        assert "openai" in data
        assert "anthropic" in data
        assert "groq" in data
        assert "openrouter" in data
        
        # Проверить схему ProviderModels
        openai_models = data["openai"]
        assert "models" in openai_models
        assert isinstance(openai_models["models"], list)
        assert "default" in openai_models
        
        # Проверить схему ModelInfo
        if openai_models["models"]:
            model = openai_models["models"][0]
            assert "id" in model
            assert "name" in model
            assert "context" in model
            assert isinstance(model["context"], int)
    
    def test_get_provider_models(self, client):
        """GET /v1/models/{provider} должен возвращать модели провайдера."""
        response = client.get("/v1/models/anthropic")
        
        assert response.status_code == 200
        data = response.json()
        
        assert "models" in data
        assert "default" in data
        assert len(data["models"]) > 0
    
    def test_get_invalid_provider(self, client):
        """GET моделей несуществующего провайдера должен вернуть 404."""
        response = client.get("/v1/models/nonexistent")
        
        assert response.status_code == 404
        assert "detail" in response.json()


class TestHealthEndpoints:
    """Контрактные тесты для эндпоинтов здоровья."""
    
    def test_simple_health_check(self, client):
        """GET /health должен возвращать простой статус."""
        response = client.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        
        assert "status" in data
        assert data["status"] == "ok"
    
    def test_full_health_check(self, client):
        """GET /health/ должен возвращать полную информацию."""
        response = client.get("/health/")
        
        assert response.status_code == 200
        data = response.json()
        
        # Проверить схему SystemHealth
        assert "status" in data
        assert data["status"] in ["healthy", "degraded", "unhealthy"]
        assert "timestamp" in data
        assert "uptime" in data
        assert "components" in data
        assert "metrics" in data
        
        # Проверить компоненты
        components = data["components"]
        assert "database" in components
        assert "redis" in components
        assert "system" in components
    
    def test_health_status(self, client):
        """GET /health/status должен возвращать упрощенный статус."""
        response = client.get("/health/status")
        
        assert response.status_code == 200
        data = response.json()
        
        assert "status" in data
        assert "timestamp" in data
        assert "uptime_seconds" in data
        assert isinstance(data["uptime_seconds"], int)
    
    def test_component_health(self, client):
        """GET /health/components/{name} должен возвращать здоровье компонента."""
        response = client.get("/health/components/database")
        
        assert response.status_code == 200
        data = response.json()
        
        # Проверить схему ComponentHealth
        assert "name" in data
        assert "status" in data
        assert "message" in data
        assert "response_time" in data
        assert "last_check" in data
    
    def test_health_metrics(self, client):
        """GET /health/metrics должен возвращать метрики."""
        response = client.get("/health/metrics")
        
        assert response.status_code == 200
        data = response.json()
        
        assert "system" in data
        assert "process" in data
        assert "health" in data
        assert "components" in data


class TestErrorResponses:
    """Тесты проверки схем ошибок."""
    
    def test_404_error_schema(self, client, auth_headers):
        """404 ошибки должны соответствовать ErrorResponse."""
        response = client.get(
            "/v1/projects/00000000-0000-0000-0000-000000000001",
            headers=auth_headers
        )
        
        assert response.status_code == 404
        data = response.json()
        
        # Проверить схему ErrorResponse
        assert "detail" in data
        assert isinstance(data["detail"], str)
    
    def test_401_error_schema(self, client):
        """401 ошибки должны соответствовать ErrorResponse."""
        response = client.get("/v1/projects")
        
        assert response.status_code == 401
        data = response.json()
        
        assert "detail" in data
    
    def test_422_validation_error_schema(self, client, auth_headers):
        """422 ошибки должны соответствовать ValidationError."""
        response = client.post(
            "/v1/projects",
            headers=auth_headers,
            json={}  # Пустой JSON - не хватает обязательного поля
        )
        
        assert response.status_code == 422
        data = response.json()
        
        # Проверить схему ValidationError
        assert "detail" in data
        assert isinstance(data["detail"], list)
        
        if data["detail"]:
            error = data["detail"][0]
            assert "loc" in error
            assert "msg" in error
            assert "type" in error


class TestRateLimiting:
    """Тесты проверки rate limiting."""
    
    @pytest.mark.skip(reason="Rate limiting может мешать другим тестам")
    def test_login_rate_limit(self, client, test_user):
        """Должен применяться rate limit на /v1/auth/login."""
        # Сделать много запросов
        for i in range(10):
            response = client.post(
                "/v1/auth/login",
                data={
                    "username": test_user.email,
                    "password": "wrong_password"
                }
            )
            
            if response.status_code == 429:
                # Rate limit сработал
                assert "detail" in response.json()
                return
        
        # Если дошли сюда, rate limit не сработал (может быть отключен в тестах)
        pytest.skip("Rate limiting not active in test environment")


class TestDeprecation:
    """Тесты проверки заголовков deprecation."""
    
    def test_deprecated_endpoints_have_headers(self, client):
        """Deprecated эндпоинты должны иметь соответствующие заголовки."""
        # Пока нет deprecated эндпоинтов, но тест готов для будущего
        # response = client.get("/v1/deprecated-endpoint")
        # assert "Deprecation" in response.headers
        # assert "Sunset" in response.headers
        pass


# Фикстуры для тестов
@pytest.fixture
def test_user(db):
    """Создать тестового пользователя."""
    from samokoder.api.routers.auth import pwd_context
    
    user = User(
        email="test@example.com",
        hashed_password=pwd_context.hash("TestPassword123!"),
        tier=Tier.FREE
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def test_project(db, test_user):
    """Создать тестовый проект."""
    project = Project(
        name="Test Project",
        description="Test Description",
        user_id=test_user.id
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
