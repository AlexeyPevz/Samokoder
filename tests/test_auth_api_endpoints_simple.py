"""
Тесты для Auth API endpoints - простые тесты для увеличения покрытия
"""
import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from fastapi import HTTPException, status, Request

# Импорт модулей для тестирования
from backend.api.auth import router, login, register, logout, get_current_user_info, check_rate_limit, STRICT_RATE_LIMITS
from backend.models.requests import LoginRequest, RegisterRequest
from backend.models.responses import LoginResponse, RegisterResponse


class TestAuthApiEndpoints:
    """Тесты для Auth API endpoints"""

    @pytest.fixture
    def mock_login_request(self):
        """Мок запроса входа"""
        return LoginRequest(
            email="test@example.com",
            password="SecurePassword123!"
        )

    @pytest.fixture
    def mock_register_request(self):
        """Мок запроса регистрации"""
        return RegisterRequest(
            email="test@example.com",
            password="SecurePassword123!",
            full_name="Test User"
        )

    @pytest.fixture
    def mock_user(self):
        """Мок пользователя"""
        return {
            "id": "test-user-id",
            "email": "test@example.com",
            "role": "user"
        }

    @pytest.fixture
    def mock_request(self):
        """Мок HTTP запроса"""
        request = Mock(spec=Request)
        request.client = Mock()
        request.client.host = "127.0.0.1"
        return request

    @pytest.mark.asyncio
    async def test_check_rate_limit(self):
        """Тест функции проверки rate limit"""
        # Тест всегда возвращает True (демо-реализация)
        result = check_rate_limit("127.0.0.1", "login")
        assert result is True
        
        result = check_rate_limit("192.168.1.1", "register")
        assert result is True

    def test_strict_rate_limits_config(self):
        """Тест конфигурации строгих rate limits"""
        assert "login" in STRICT_RATE_LIMITS
        assert "register" in STRICT_RATE_LIMITS
        assert STRICT_RATE_LIMITS["login"]["attempts"] == 3
        assert STRICT_RATE_LIMITS["login"]["window"] == 900
        assert STRICT_RATE_LIMITS["register"]["attempts"] == 5
        assert STRICT_RATE_LIMITS["register"]["window"] == 3600

    @pytest.mark.asyncio
    async def test_login_success(self, mock_login_request, mock_request):
        """Тест успешного входа"""
        with patch('backend.api.auth.connection_pool_manager') as mock_pool, \
             patch('backend.api.auth.secure_password_validation') as mock_validation, \
             patch('backend.api.auth.execute_supabase_operation') as mock_supabase:
            
            # Настройка моков
            mock_validation.return_value = True
            
            mock_supabase_client = Mock()
            mock_auth_response = Mock()
            mock_auth_response.user = Mock()
            mock_auth_response.user.id = "test-user-id"
            mock_auth_response.session = Mock()
            mock_auth_response.session.access_token = "test-token"
            
            mock_supabase_client.auth.sign_in_with_password.return_value = mock_auth_response
            mock_pool.get_supabase_client.return_value = mock_supabase_client
            
            mock_profile = {
                "id": "test-user-id",
                "email": "test@example.com",
                "full_name": "Test User"
            }
            mock_supabase.return_value = Mock(data=[mock_profile])
            
            # Вызов функции
            result = await login(
                credentials=mock_login_request,
                request=mock_request,
                rate_limit={}
            )
            
            # Проверки
            assert isinstance(result, LoginResponse)
            assert result.success is True
            assert result.access_token == "test-token"
            assert result.token_type == "bearer"
            assert result.expires_in == 3600
            assert result.user.id == "test-user-id"
            assert result.user.email == "test@example.com"
            assert result.message == "Успешный вход"

    @pytest.mark.asyncio
    async def test_login_invalid_password(self, mock_login_request, mock_request):
        """Тест входа с невалидным паролем"""
        with patch('backend.api.auth.secure_password_validation') as mock_validation:
            
            # Настройка моков
            mock_validation.return_value = False
            
            # Проверка исключения
            with pytest.raises(HTTPException) as exc_info:
                await login(
                    credentials=mock_login_request,
                    request=mock_request,
                    rate_limit={}
                )
            
            assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
            assert exc_info.value.detail == "Invalid credentials"

    @pytest.mark.asyncio
    async def test_login_no_user(self, mock_login_request, mock_request):
        """Тест входа с несуществующим пользователем"""
        with patch('backend.api.auth.connection_pool_manager') as mock_pool, \
             patch('backend.api.auth.secure_password_validation') as mock_validation:
            
            # Настройка моков
            mock_validation.return_value = True
            
            mock_supabase_client = Mock()
            mock_auth_response = Mock()
            mock_auth_response.user = None  # Пользователь не найден
            
            mock_supabase_client.auth.sign_in_with_password.return_value = mock_auth_response
            mock_pool.get_supabase_client.return_value = mock_supabase_client
            
            # Проверка исключения
            with pytest.raises(HTTPException) as exc_info:
                await login(
                    credentials=mock_login_request,
                    request=mock_request,
                    rate_limit={}
                )
            
            assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
            assert exc_info.value.detail == "Invalid credentials"

    @pytest.mark.asyncio
    async def test_login_no_profile(self, mock_login_request, mock_request):
        """Тест входа без профиля пользователя"""
        with patch('backend.api.auth.connection_pool_manager') as mock_pool, \
             patch('backend.api.auth.secure_password_validation') as mock_validation, \
             patch('backend.api.auth.execute_supabase_operation') as mock_supabase:
            
            # Настройка моков
            mock_validation.return_value = True
            
            mock_supabase_client = Mock()
            mock_auth_response = Mock()
            mock_auth_response.user = Mock()
            mock_auth_response.user.id = "test-user-id"
            mock_auth_response.session = Mock()
            mock_auth_response.session.access_token = "test-token"
            
            mock_supabase_client.auth.sign_in_with_password.return_value = mock_auth_response
            mock_pool.get_supabase_client.return_value = mock_supabase_client
            
            mock_supabase.return_value = Mock(data=[])  # Пустой профиль
            
            # Проверка исключения
            with pytest.raises(HTTPException) as exc_info:
                await login(
                    credentials=mock_login_request,
                    request=mock_request,
                    rate_limit={}
                )
            
            assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND
            assert exc_info.value.detail == "User profile not found"

    @pytest.mark.asyncio
    async def test_login_exception(self, mock_login_request, mock_request):
        """Тест исключения при входе"""
        with patch('backend.api.auth.secure_password_validation') as mock_validation:
            
            # Настройка моков для исключения
            mock_validation.side_effect = Exception("Validation error")
            
            # Проверка исключения
            with pytest.raises(HTTPException) as exc_info:
                await login(
                    credentials=mock_login_request,
                    request=mock_request,
                    rate_limit={}
                )
            
            assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
            assert exc_info.value.detail == "Login failed"

    @pytest.mark.asyncio
    async def test_register_success(self, mock_register_request, mock_request):
        """Тест успешной регистрации"""
        with patch('backend.api.auth.connection_pool_manager') as mock_pool, \
             patch('backend.api.auth.secure_password_validation') as mock_validation, \
             patch('backend.api.auth.execute_supabase_operation') as mock_supabase:
            
            # Настройка моков
            mock_validation.return_value = True
            
            mock_supabase_client = Mock()
            mock_auth_response = Mock()
            mock_auth_response.user = Mock()
            mock_auth_response.user.id = "test-user-id"
            
            mock_supabase_client.auth.sign_up.return_value = mock_auth_response
            mock_pool.get_supabase_client.return_value = mock_supabase_client
            
            mock_supabase.return_value = Mock(data=[{"id": "test-user-id"}])
            
            # Вызов функции
            result = await register(
                user_data=mock_register_request,
                request=mock_request,
                rate_limit={}
            )
            
            # Проверки
            assert isinstance(result, RegisterResponse)
            assert result.success is True
            assert result.user_id == "test-user-id"
            assert result.email == "test@example.com"
            assert result.message == "Пользователь успешно зарегистрирован"

    @pytest.mark.asyncio
    async def test_register_invalid_password(self, mock_register_request, mock_request):
        """Тест регистрации с невалидным паролем"""
        with patch('backend.api.auth.secure_password_validation') as mock_validation:
            
            # Настройка моков
            mock_validation.return_value = False
            
            # Проверка исключения
            with pytest.raises(HTTPException) as exc_info:
                await register(
                    user_data=mock_register_request,
                    request=mock_request,
                    rate_limit={}
                )
            
            assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
            assert exc_info.value.detail == "Password does not meet security requirements"

    @pytest.mark.asyncio
    async def test_register_no_user(self, mock_register_request, mock_request):
        """Тест регистрации без пользователя"""
        with patch('backend.api.auth.connection_pool_manager') as mock_pool, \
             patch('backend.api.auth.secure_password_validation') as mock_validation:
            
            # Настройка моков
            mock_validation.return_value = True
            
            mock_supabase_client = Mock()
            mock_auth_response = Mock()
            mock_auth_response.user = None  # Пользователь не создан
            
            mock_supabase_client.auth.sign_up.return_value = mock_auth_response
            mock_pool.get_supabase_client.return_value = mock_supabase_client
            
            # Проверка исключения
            with pytest.raises(HTTPException) as exc_info:
                await register(
                    user_data=mock_register_request,
                    request=mock_request,
                    rate_limit={}
                )
            
            assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
            assert exc_info.value.detail == "Registration failed"

    @pytest.mark.asyncio
    async def test_register_no_profile(self, mock_register_request, mock_request):
        """Тест регистрации без создания профиля"""
        with patch('backend.api.auth.connection_pool_manager') as mock_pool, \
             patch('backend.api.auth.secure_password_validation') as mock_validation, \
             patch('backend.api.auth.execute_supabase_operation') as mock_supabase:
            
            # Настройка моков
            mock_validation.return_value = True
            
            mock_supabase_client = Mock()
            mock_auth_response = Mock()
            mock_auth_response.user = Mock()
            mock_auth_response.user.id = "test-user-id"
            
            mock_supabase_client.auth.sign_up.return_value = mock_auth_response
            mock_pool.get_supabase_client.return_value = mock_supabase_client
            
            mock_supabase.return_value = Mock(data=[])  # Пустой профиль
            
            # Проверка исключения
            with pytest.raises(HTTPException) as exc_info:
                await register(
                    user_data=mock_register_request,
                    request=mock_request,
                    rate_limit={}
                )
            
            assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
            assert exc_info.value.detail == "Failed to create user profile"

    @pytest.mark.asyncio
    async def test_register_exception(self, mock_register_request, mock_request):
        """Тест исключения при регистрации"""
        with patch('backend.api.auth.secure_password_validation') as mock_validation:
            
            # Настройка моков для исключения
            mock_validation.side_effect = Exception("Validation error")
            
            # Проверка исключения
            with pytest.raises(HTTPException) as exc_info:
                await register(
                    user_data=mock_register_request,
                    request=mock_request,
                    rate_limit={}
                )
            
            assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
            assert exc_info.value.detail == "Registration failed"

    @pytest.mark.asyncio
    async def test_logout_success(self, mock_user):
        """Тест успешного выхода"""
        with patch('backend.api.auth.connection_pool_manager') as mock_pool:
            
            # Настройка моков
            mock_supabase_client = Mock()
            mock_supabase_client.auth.sign_out.return_value = None
            mock_pool.get_supabase_client.return_value = mock_supabase_client
            
            # Вызов функции
            result = await logout(current_user=mock_user)
            
            # Проверки
            assert result == {"message": "Успешный выход"}

    @pytest.mark.asyncio
    async def test_logout_exception(self, mock_user):
        """Тест исключения при выходе"""
        with patch('backend.api.auth.connection_pool_manager') as mock_pool:
            
            # Настройка моков для исключения
            mock_supabase_client = Mock()
            mock_supabase_client.auth.sign_out.side_effect = Exception("Sign out error")
            mock_pool.get_supabase_client.return_value = mock_supabase_client
            
            # Проверка исключения
            with pytest.raises(HTTPException) as exc_info:
                await logout(current_user=mock_user)
            
            assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
            assert exc_info.value.detail == "Logout failed"

    @pytest.mark.asyncio
    async def test_get_current_user_info(self, mock_user):
        """Тест получения информации о текущем пользователе"""
        # Вызов функции
        result = await get_current_user_info(current_user=mock_user)
        
        # Проверки
        assert result == mock_user
        assert result["id"] == "test-user-id"
        assert result["email"] == "test@example.com"

    def test_router_initialization(self):
        """Тест инициализации роутера"""
        assert router is not None
        assert hasattr(router, 'routes')
        assert len(router.routes) > 0

    def test_auth_endpoints_import(self):
        """Тест импорта Auth endpoints"""
        from backend.api.auth import router
        assert router is not None
        
        # Проверка наличия основных функций
        from backend.api.auth import (
            login,
            register,
            logout,
            get_current_user_info,
            check_rate_limit
        )
        assert login is not None
        assert register is not None
        assert logout is not None
        assert get_current_user_info is not None
        assert check_rate_limit is not None

    @pytest.mark.asyncio
    async def test_login_request_model_validation(self):
        """Тест валидации модели LoginRequest"""
        # Валидный запрос
        valid_request = LoginRequest(
            email="test@example.com",
            password="SecurePassword123!"
        )
        assert valid_request.email == "test@example.com"
        assert valid_request.password == "SecurePassword123!"

    @pytest.mark.asyncio
    async def test_register_request_model_validation(self):
        """Тест валидации модели RegisterRequest"""
        # Валидный запрос
        valid_request = RegisterRequest(
            email="test@example.com",
            password="SecurePassword123!",
            full_name="Test User"
        )
        assert valid_request.email == "test@example.com"
        assert valid_request.password == "SecurePassword123!"
        assert valid_request.full_name == "Test User"

    @pytest.mark.asyncio
    async def test_login_response_model_validation(self):
        """Тест валидации модели LoginResponse"""
        from backend.models.responses import UserResponse
        from datetime import datetime
        
        user = UserResponse(
            id="test-user-id",
            email="test@example.com",
            full_name="Test User",
            subscription_tier="free",
            subscription_status="active",
            api_credits_balance=0.0,
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        
        response = LoginResponse(
            success=True,
            message="Успешный вход",
            user=user,
            access_token="test-token",
            token_type="bearer",
            expires_in=3600
        )
        
        assert response.success is True
        assert response.message == "Успешный вход"
        assert response.access_token == "test-token"
        assert response.token_type == "bearer"
        assert response.expires_in == 3600
        assert response.user.id == "test-user-id"
        assert response.user.email == "test@example.com"

    @pytest.mark.asyncio
    async def test_register_response_model_validation(self):
        """Тест валидации модели RegisterResponse"""
        response = RegisterResponse(
            success=True,
            message="Пользователь успешно зарегистрирован",
            user_id="test-user-id",
            email="test@example.com"
        )
        
        assert response.success is True
        assert response.message == "Пользователь успешно зарегистрирован"
        assert response.user_id == "test-user-id"
        assert response.email == "test@example.com"

    @pytest.mark.asyncio
    async def test_request_client_handling(self, mock_login_request):
        """Тест обработки клиента запроса"""
        # Тест с клиентом
        request_with_client = Mock(spec=Request)
        request_with_client.client = Mock()
        request_with_client.client.host = "192.168.1.1"
        
        with patch('backend.api.auth.secure_password_validation') as mock_validation:
            mock_validation.return_value = False
            
            with pytest.raises(HTTPException):
                await login(
                    credentials=mock_login_request,
                    request=request_with_client,
                    rate_limit={}
                )
        
        # Тест без клиента
        request_without_client = Mock(spec=Request)
        request_without_client.client = None
        
        with patch('backend.api.auth.secure_password_validation') as mock_validation:
            mock_validation.return_value = False
            
            with pytest.raises(HTTPException):
                await login(
                    credentials=mock_login_request,
                    request=request_without_client,
                    rate_limit={}
                )

    @pytest.mark.asyncio
    async def test_logout_with_unknown_user(self):
        """Тест выхода с неизвестным пользователем"""
        unknown_user = {"id": None}
        
        with patch('backend.api.auth.connection_pool_manager') as mock_pool:
            mock_supabase_client = Mock()
            mock_supabase_client.auth.sign_out.return_value = None
            mock_pool.get_supabase_client.return_value = mock_supabase_client
            
            result = await logout(current_user=unknown_user)
            assert result == {"message": "Успешный выход"}