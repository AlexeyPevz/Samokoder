"""
Комплексные тесты для API ключей
Покрытие всех эндпоинтов и сценариев ошибок
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from fastapi import HTTPException
from fastapi.testclient import TestClient
from datetime import datetime
import uuid

from backend.api.api_keys import router
from backend.models.requests import APIKeyCreateRequest
from backend.models.responses import APIKeyResponse, APIKeyListResponse
from backend.core.exceptions import DatabaseError, ValidationError, EncryptionError


class TestAPIKeysEndpoints:
    """Тесты для всех эндпоинтов API ключей"""
    
    @pytest.fixture
    def mock_current_user(self):
        return {"id": str(uuid.uuid4()), "email": "test@example.com"}
    
    @pytest.fixture
    def mock_api_key_request(self):
        return APIKeyCreateRequest(
            provider="openrouter",
            key_name="Test Key",
            api_key="sk-or-test123456789"
        )
    
    @pytest.fixture
    def mock_encryption_service(self):
        mock_service = Mock()
        mock_service.encrypt_api_key.return_value = "encrypted_key_data"
        mock_service.get_key_last_4.return_value = "789"
        return mock_service
    
    @pytest.fixture
    def mock_supabase_response(self):
        return Mock(
            data=[{
                "id": str(uuid.uuid4()),
                "user_id": str(uuid.uuid4()),
                "provider_name": "openrouter",
                "key_name": "Test Key",
                "api_key_last_4": "789",
                "is_active": True,
                "created_at": datetime.now()
            }]
        )
    
    @pytest.fixture
    def mock_supabase_single_response(self):
        return Mock(
            data={
                "id": str(uuid.uuid4()),
                "user_id": str(uuid.uuid4()),
                "provider_name": "openrouter",
                "key_name": "Test Key",
                "api_key_last_4": "789",
                "is_active": True,
                "created_at": datetime.now()
            }
        )
    
    @pytest.fixture
    def mock_connection_manager(self):
        mock_manager = Mock()
        mock_supabase = Mock()
        mock_manager.get_pool.return_value = mock_supabase
        return mock_manager
    
    # === CREATE API KEY TESTS ===
    
    @pytest.mark.asyncio
    async def test_create_api_key_success(self, mock_current_user, mock_api_key_request, 
                                         mock_encryption_service, mock_supabase_response, 
                                         mock_connection_manager):
        """Тест успешного создания API ключа"""
        with patch('backend.api.api_keys.connection_manager', mock_connection_manager), \
             patch('backend.api.api_keys.get_encryption_service', return_value=mock_encryption_service), \
             patch('backend.api.api_keys.execute_supabase_operation', return_value=mock_supabase_response), \
             patch('backend.api.api_keys.generate_unique_uuid', return_value=str(uuid.uuid4())):
            
            from backend.api.api_keys import create_api_key
            
            result = await create_api_key(mock_api_key_request, mock_current_user)
            
            assert isinstance(result, APIKeyResponse)
            assert result.provider == "openrouter"
            assert result.key_name == "Test Key"
            assert result.key_last_4 == "789"
            assert result.is_active is True
    
    @pytest.mark.asyncio
    async def test_create_api_key_supabase_unavailable(self, mock_current_user, mock_api_key_request):
        """Тест создания API ключа когда Supabase недоступен"""
        mock_connection_manager = Mock()
        mock_connection_manager.get_pool.return_value = None
        
        with patch('backend.api.api_keys.connection_manager', mock_connection_manager):
            from backend.api.api_keys import create_api_key
            
            with pytest.raises(HTTPException) as exc_info:
                await create_api_key(mock_api_key_request, mock_current_user)
            
            assert exc_info.value.status_code == 503
            assert "Supabase недоступен" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_create_api_key_database_error(self, mock_current_user, mock_api_key_request,
                                                mock_encryption_service, mock_connection_manager):
        """Тест создания API ключа с ошибкой базы данных"""
        with patch('backend.api.api_keys.connection_manager', mock_connection_manager), \
             patch('backend.api.api_keys.get_encryption_service', return_value=mock_encryption_service), \
             patch('backend.api.api_keys.execute_supabase_operation', side_effect=DatabaseError("DB Error")):
            
            from backend.api.api_keys import create_api_key
            
            with pytest.raises(HTTPException) as exc_info:
                await create_api_key(mock_api_key_request, mock_current_user)
            
            assert exc_info.value.status_code == 503
            assert "Database service unavailable" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_create_api_key_encryption_error(self, mock_current_user, mock_api_key_request,
                                                  mock_connection_manager):
        """Тест создания API ключа с ошибкой шифрования"""
        mock_encryption_service = Mock()
        mock_encryption_service.encrypt_api_key.side_effect = EncryptionError("Encryption failed")
        
        with patch('backend.api.api_keys.connection_manager', mock_connection_manager), \
             patch('backend.api.api_keys.get_encryption_service', return_value=mock_encryption_service):
            
            from backend.api.api_keys import create_api_key
            
            with pytest.raises(HTTPException) as exc_info:
                await create_api_key(mock_api_key_request, mock_current_user)
            
            assert exc_info.value.status_code == 500
            assert "Encryption service error" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_create_api_key_validation_error(self, mock_current_user, mock_api_key_request,
                                                  mock_encryption_service, mock_connection_manager):
        """Тест создания API ключа с ошибкой валидации"""
        with patch('backend.api.api_keys.connection_manager', mock_connection_manager), \
             patch('backend.api.api_keys.get_encryption_service', return_value=mock_encryption_service), \
             patch('backend.api.api_keys.execute_supabase_operation', side_effect=ValidationError("Validation failed")):
            
            from backend.api.api_keys import create_api_key
            
            with pytest.raises(HTTPException) as exc_info:
                await create_api_key(mock_api_key_request, mock_current_user)
            
            assert exc_info.value.status_code == 400
            assert "Validation failed" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_create_api_key_no_response_data(self, mock_current_user, mock_api_key_request,
                                                  mock_encryption_service, mock_connection_manager):
        """Тест создания API ключа без данных ответа"""
        mock_supabase_response = Mock(data=None)
        
        with patch('backend.api.api_keys.connection_manager', mock_connection_manager), \
             patch('backend.api.api_keys.get_encryption_service', return_value=mock_encryption_service), \
             patch('backend.api.api_keys.execute_supabase_operation', return_value=mock_supabase_response):
            
            from backend.api.api_keys import create_api_key
            
            with pytest.raises(HTTPException) as exc_info:
                await create_api_key(mock_api_key_request, mock_current_user)
            
            assert exc_info.value.status_code == 500
            assert "Ошибка сохранения API ключа" in exc_info.value.detail
    
    # === GET API KEYS TESTS ===
    
    @pytest.mark.asyncio
    async def test_get_api_keys_success(self, mock_current_user, mock_supabase_response, mock_connection_manager):
        """Тест успешного получения списка API ключей"""
        with patch('backend.api.api_keys.connection_manager', mock_connection_manager), \
             patch('backend.api.api_keys.execute_supabase_operation', return_value=mock_supabase_response):
            
            from backend.api.api_keys import get_api_keys
            
            result = await get_api_keys(mock_current_user)
            
            assert isinstance(result, APIKeyListResponse)
            assert result.total_count == 1
            assert len(result.keys) == 1
            assert result.keys[0].provider == "openrouter"
    
    @pytest.mark.asyncio
    async def test_get_api_keys_supabase_unavailable(self, mock_current_user):
        """Тест получения API ключей когда Supabase недоступен"""
        mock_connection_manager = Mock()
        mock_connection_manager.get_pool.return_value = None
        
        with patch('backend.api.api_keys.connection_manager', mock_connection_manager):
            from backend.api.api_keys import get_api_keys
            
            result = await get_api_keys(mock_current_user)
            
            assert isinstance(result, APIKeyListResponse)
            assert result.keys == []
            assert result.total_count == 0
    
    @pytest.mark.asyncio
    async def test_get_api_keys_no_data(self, mock_current_user, mock_connection_manager):
        """Тест получения API ключей без данных"""
        mock_supabase_response = Mock(data=None)
        
        with patch('backend.api.api_keys.connection_manager', mock_connection_manager), \
             patch('backend.api.api_keys.execute_supabase_operation', return_value=mock_supabase_response):
            
            from backend.api.api_keys import get_api_keys
            
            result = await get_api_keys(mock_current_user)
            
            assert isinstance(result, APIKeyListResponse)
            assert result.keys == []
            assert result.total_count == 0
    
    @pytest.mark.asyncio
    async def test_get_api_keys_database_error(self, mock_current_user, mock_connection_manager):
        """Тест получения API ключей с ошибкой базы данных"""
        with patch('backend.api.api_keys.connection_manager', mock_connection_manager), \
             patch('backend.api.api_keys.execute_supabase_operation', side_effect=DatabaseError("DB Error")):
            
            from backend.api.api_keys import get_api_keys
            
            with pytest.raises(HTTPException) as exc_info:
                await get_api_keys(mock_current_user)
            
            assert exc_info.value.status_code == 503
            assert "Database service unavailable" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_get_api_keys_encryption_error(self, mock_current_user, mock_connection_manager):
        """Тест получения API ключей с ошибкой шифрования"""
        with patch('backend.api.api_keys.connection_manager', mock_connection_manager), \
             patch('backend.api.api_keys.execute_supabase_operation', side_effect=EncryptionError("Encryption Error")):
            
            from backend.api.api_keys import get_api_keys
            
            with pytest.raises(HTTPException) as exc_info:
                await get_api_keys(mock_current_user)
            
            assert exc_info.value.status_code == 500
            assert "Encryption service error" in exc_info.value.detail
    
    # === GET SINGLE API KEY TESTS ===
    
    @pytest.mark.asyncio
    async def test_get_api_key_success(self, mock_current_user, mock_supabase_single_response, mock_connection_manager):
        """Тест успешного получения конкретного API ключа"""
        key_id = str(uuid.uuid4())
        
        with patch('backend.api.api_keys.connection_manager', mock_connection_manager), \
             patch('backend.api.api_keys.execute_supabase_operation', return_value=mock_supabase_single_response):
            
            from backend.api.api_keys import get_api_key
            
            result = await get_api_key(key_id, mock_current_user)
            
            assert isinstance(result, APIKeyResponse)
            assert result.provider == "openrouter"
            assert result.key_name == "Test Key"
    
    @pytest.mark.asyncio
    async def test_get_api_key_supabase_unavailable(self, mock_current_user):
        """Тест получения API ключа когда Supabase недоступен"""
        key_id = str(uuid.uuid4())
        mock_connection_manager = Mock()
        mock_connection_manager.get_pool.return_value = None
        
        with patch('backend.api.api_keys.connection_manager', mock_connection_manager):
            from backend.api.api_keys import get_api_key
            
            with pytest.raises(HTTPException) as exc_info:
                await get_api_key(key_id, mock_current_user)
            
            assert exc_info.value.status_code == 503
            assert "Supabase недоступен" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_get_api_key_not_found(self, mock_current_user, mock_connection_manager):
        """Тест получения несуществующего API ключа"""
        key_id = str(uuid.uuid4())
        mock_supabase_response = Mock(data=None)
        
        with patch('backend.api.api_keys.connection_manager', mock_connection_manager), \
             patch('backend.api.api_keys.execute_supabase_operation', return_value=mock_supabase_response):
            
            from backend.api.api_keys import get_api_key
            
            with pytest.raises(HTTPException) as exc_info:
                await get_api_key(key_id, mock_current_user)
            
            assert exc_info.value.status_code == 404
            assert "API ключ не найден" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_get_api_key_database_error(self, mock_current_user, mock_connection_manager):
        """Тест получения API ключа с ошибкой базы данных"""
        key_id = str(uuid.uuid4())
        
        with patch('backend.api.api_keys.connection_manager', mock_connection_manager), \
             patch('backend.api.api_keys.execute_supabase_operation', side_effect=DatabaseError("DB Error")):
            
            from backend.api.api_keys import get_api_key
            
            with pytest.raises(HTTPException) as exc_info:
                await get_api_key(key_id, mock_current_user)
            
            assert exc_info.value.status_code == 503
            assert "Database service unavailable" in exc_info.value.detail
    
    # === TOGGLE API KEY TESTS ===
    
    @pytest.mark.asyncio
    async def test_toggle_api_key_success(self, mock_current_user, mock_connection_manager):
        """Тест успешного переключения API ключа"""
        key_id = str(uuid.uuid4())
        
        # Мок для получения текущего состояния
        get_response = Mock(data={"is_active": True})
        # Мок для обновления состояния
        update_response = Mock()
        
        with patch('backend.api.api_keys.connection_manager', mock_connection_manager), \
             patch('backend.api.api_keys.execute_supabase_operation') as mock_execute:
            
            # Настраиваем разные ответы для разных вызовов
            mock_execute.side_effect = [get_response, update_response]
            
            from backend.api.api_keys import toggle_api_key
            
            result = await toggle_api_key(key_id, mock_current_user)
            
            assert result["is_active"] is False
            assert "выключен" in result["message"]
    
    @pytest.mark.asyncio
    async def test_toggle_api_key_not_found(self, mock_current_user, mock_connection_manager):
        """Тест переключения несуществующего API ключа"""
        key_id = str(uuid.uuid4())
        mock_supabase_response = Mock(data=None)
        
        with patch('backend.api.api_keys.connection_manager', mock_connection_manager), \
             patch('backend.api.api_keys.execute_supabase_operation', return_value=mock_supabase_response):
            
            from backend.api.api_keys import toggle_api_key
            
            with pytest.raises(HTTPException) as exc_info:
                await toggle_api_key(key_id, mock_current_user)
            
            assert exc_info.value.status_code == 404
            assert "API ключ не найден" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_toggle_api_key_database_error(self, mock_current_user, mock_connection_manager):
        """Тест переключения API ключа с ошибкой базы данных"""
        key_id = str(uuid.uuid4())
        
        with patch('backend.api.api_keys.connection_manager', mock_connection_manager), \
             patch('backend.api.api_keys.execute_supabase_operation', side_effect=DatabaseError("DB Error")):
            
            from backend.api.api_keys import toggle_api_key
            
            with pytest.raises(HTTPException) as exc_info:
                await toggle_api_key(key_id, mock_current_user)
            
            assert exc_info.value.status_code == 503
            assert "Database service unavailable" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_toggle_api_key_validation_error(self, mock_current_user, mock_connection_manager):
        """Тест переключения API ключа с ошибкой валидации"""
        key_id = str(uuid.uuid4())
        
        with patch('backend.api.api_keys.connection_manager', mock_connection_manager), \
             patch('backend.api.api_keys.execute_supabase_operation', side_effect=ValidationError("Validation Error")):
            
            from backend.api.api_keys import toggle_api_key
            
            with pytest.raises(HTTPException) as exc_info:
                await toggle_api_key(key_id, mock_current_user)
            
            assert exc_info.value.status_code == 400
            assert "Validation Error" in exc_info.value.detail
    
    # === DELETE API KEY TESTS ===
    
    @pytest.mark.asyncio
    async def test_delete_api_key_success(self, mock_current_user, mock_connection_manager):
        """Тест успешного удаления API ключа"""
        key_id = str(uuid.uuid4())
        
        # Мок для проверки существования ключа
        check_response = Mock(data={"id": key_id})
        # Мок для удаления ключа
        delete_response = Mock()
        
        with patch('backend.api.api_keys.connection_manager', mock_connection_manager), \
             patch('backend.api.api_keys.execute_supabase_operation') as mock_execute:
            
            # Настраиваем разные ответы для разных вызовов
            mock_execute.side_effect = [check_response, delete_response]
            
            from backend.api.api_keys import delete_api_key
            
            result = await delete_api_key(key_id, mock_current_user)
            
            assert result["message"] == "API ключ удален"
    
    @pytest.mark.asyncio
    async def test_delete_api_key_not_found(self, mock_current_user, mock_connection_manager):
        """Тест удаления несуществующего API ключа"""
        key_id = str(uuid.uuid4())
        mock_supabase_response = Mock(data=None)
        
        with patch('backend.api.api_keys.connection_manager', mock_connection_manager), \
             patch('backend.api.api_keys.execute_supabase_operation', return_value=mock_supabase_response):
            
            from backend.api.api_keys import delete_api_key
            
            with pytest.raises(HTTPException) as exc_info:
                await delete_api_key(key_id, mock_current_user)
            
            assert exc_info.value.status_code == 404
            assert "API ключ не найден" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_delete_api_key_database_error(self, mock_current_user, mock_connection_manager):
        """Тест удаления API ключа с ошибкой базы данных"""
        key_id = str(uuid.uuid4())
        
        with patch('backend.api.api_keys.connection_manager', mock_connection_manager), \
             patch('backend.api.api_keys.execute_supabase_operation', side_effect=DatabaseError("DB Error")):
            
            from backend.api.api_keys import delete_api_key
            
            with pytest.raises(HTTPException) as exc_info:
                await delete_api_key(key_id, mock_current_user)
            
            assert exc_info.value.status_code == 503
            assert "Database service unavailable" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_delete_api_key_validation_error(self, mock_current_user, mock_connection_manager):
        """Тест удаления API ключа с ошибкой валидации"""
        key_id = str(uuid.uuid4())
        
        with patch('backend.api.api_keys.connection_manager', mock_connection_manager), \
             patch('backend.api.api_keys.execute_supabase_operation', side_effect=ValidationError("Validation Error")):
            
            from backend.api.api_keys import delete_api_key
            
            with pytest.raises(HTTPException) as exc_info:
                await delete_api_key(key_id, mock_current_user)
            
            assert exc_info.value.status_code == 400
            assert "Validation Error" in exc_info.value.detail
    
    # === GENERAL ERROR HANDLING TESTS ===
    
    @pytest.mark.asyncio
    async def test_create_api_key_general_exception(self, mock_current_user, mock_api_key_request,
                                                   mock_encryption_service, mock_connection_manager):
        """Тест создания API ключа с общим исключением"""
        with patch('backend.api.api_keys.connection_manager', mock_connection_manager), \
             patch('backend.api.api_keys.get_encryption_service', return_value=mock_encryption_service), \
             patch('backend.api.api_keys.execute_supabase_operation', side_effect=Exception("Unexpected error")):
            
            from backend.api.api_keys import create_api_key
            
            with pytest.raises(HTTPException) as exc_info:
                await create_api_key(mock_api_key_request, mock_current_user)
            
            assert exc_info.value.status_code == 500
            assert "Ошибка создания API ключа" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_get_api_keys_general_exception(self, mock_current_user, mock_connection_manager):
        """Тест получения API ключей с общим исключением"""
        with patch('backend.api.api_keys.connection_manager', mock_connection_manager), \
             patch('backend.api.api_keys.execute_supabase_operation', side_effect=Exception("Unexpected error")):
            
            from backend.api.api_keys import get_api_keys
            
            with pytest.raises(HTTPException) as exc_info:
                await get_api_keys(mock_current_user)
            
            assert exc_info.value.status_code == 500
            assert "Ошибка получения API ключей" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_get_api_key_general_exception(self, mock_current_user, mock_connection_manager):
        """Тест получения API ключа с общим исключением"""
        key_id = str(uuid.uuid4())
        
        with patch('backend.api.api_keys.connection_manager', mock_connection_manager), \
             patch('backend.api.api_keys.execute_supabase_operation', side_effect=Exception("Unexpected error")):
            
            from backend.api.api_keys import get_api_key
            
            with pytest.raises(HTTPException) as exc_info:
                await get_api_key(key_id, mock_current_user)
            
            assert exc_info.value.status_code == 500
            assert "Ошибка получения API ключа" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_toggle_api_key_general_exception(self, mock_current_user, mock_connection_manager):
        """Тест переключения API ключа с общим исключением"""
        key_id = str(uuid.uuid4())
        
        with patch('backend.api.api_keys.connection_manager', mock_connection_manager), \
             patch('backend.api.api_keys.execute_supabase_operation', side_effect=Exception("Unexpected error")):
            
            from backend.api.api_keys import toggle_api_key
            
            with pytest.raises(HTTPException) as exc_info:
                await toggle_api_key(key_id, mock_current_user)
            
            assert exc_info.value.status_code == 500
            assert "Ошибка переключения API ключа" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_delete_api_key_general_exception(self, mock_current_user, mock_connection_manager):
        """Тест удаления API ключа с общим исключением"""
        key_id = str(uuid.uuid4())
        
        with patch('backend.api.api_keys.connection_manager', mock_connection_manager), \
             patch('backend.api.api_keys.execute_supabase_operation', side_effect=Exception("Unexpected error")):
            
            from backend.api.api_keys import delete_api_key
            
            with pytest.raises(HTTPException) as exc_info:
                await delete_api_key(key_id, mock_current_user)
            
            assert exc_info.value.status_code == 500
            assert "Ошибка удаления API ключа" in exc_info.value.detail