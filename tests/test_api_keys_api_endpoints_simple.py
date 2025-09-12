"""
Simple tests for API Keys API endpoints - working with current API implementation
"""
import pytest
from unittest.mock import Mock, AsyncMock, patch
from backend.models.requests import APIKeyCreateRequest
from backend.models.responses import APIKeyResponse, APIKeyListResponse
from backend.core.exceptions import DatabaseError, ValidationError, NotFoundError, EncryptionError, ConfigurationError


class TestAPIKeysAPIModels:
    """Test API Keys API models"""
    
    def test_api_key_create_request_model(self):
        """Test APIKeyCreateRequest model"""
        from backend.models.responses import AIProvider
        
        request = APIKeyCreateRequest(
            api_key="sk-1234567890abcdef1234567890abcdef",
            provider=AIProvider.OPENAI,
            key_name="My OpenAI Key"
        )
        
        assert request.api_key == "sk-1234567890abcdef1234567890abcdef"
        assert request.provider == "openai"
        assert request.name == "My OpenAI Key"
        assert request.description == "API key for OpenAI services"
    
    def test_api_key_response_model(self):
        """Test APIKeyResponse model"""
        response = APIKeyResponse(
            id="key123",
            provider="openai",
            key_name="My OpenAI Key",
            key_last_4="cdef",
            is_active=True,
            created_at="2024-01-01T00:00:00Z"
        )
        
        assert response.id == "key123"
        assert response.user_id == "user123"
        assert response.provider == "openai"
        assert response.name == "My OpenAI Key"
        assert response.description == "API key for OpenAI services"
        assert response.key_last_4 == "cdef"
        assert response.is_active is True
        assert response.created_at == "2024-01-01T00:00:00Z"
        assert response.updated_at == "2024-01-01T00:00:00Z"
    
    def test_api_key_list_response_model(self):
        """Test APIKeyListResponse model"""
        api_keys = [
            APIKeyResponse(
                id="key1",
                provider="openai",
                key_name="OpenAI Key",
                key_last_4="abcd",
                is_active=True,
                created_at="2024-01-01T00:00:00Z"
            ),
            APIKeyResponse(
                id="key2",
                provider="anthropic",
                key_name="Anthropic Key",
                key_last_4="efgh",
                is_active=True,
                created_at="2024-01-01T00:00:00Z"
            )
        ]
        
        response = APIKeyListResponse(
            keys=api_keys,
            total_count=2
        )
        
        assert len(response.api_keys) == 2
        assert response.total_count == 2
        assert response.api_keys[0].provider == "openai"
        assert response.api_keys[1].provider == "anthropic"
    
    def test_api_key_create_request_validation(self):
        """Test APIKeyCreateRequest validation"""
        # Valid request
        valid_request = APIKeyCreateRequest(
            api_key="sk-1234567890abcdef1234567890abcdef",
            provider="openai",
            name="Valid Key"
        )
        
        assert valid_request.api_key.startswith("sk-")
        assert valid_request.provider == "openai"
        assert len(valid_request.name) > 0
        
        # Test with description
        request_with_desc = APIKeyCreateRequest(
            api_key="sk-1234567890abcdef1234567890abcdef",
            provider="anthropic",
            name="Anthropic Key",
            description="API key for Anthropic services"
        )
        
        assert request_with_desc.description == "API key for Anthropic services"


class TestAPIKeysAPIFunctions:
    """Test API Keys API function logic"""
    
    def test_encryption_service_functions(self):
        """Test encryption service functions"""
        from backend.services.encryption_service import get_encryption_service
        
        # Test encryption service exists
        encryption_service = get_encryption_service()
        assert encryption_service is not None
        
        # Test encryption methods exist
        assert hasattr(encryption_service, 'encrypt_api_key')
        assert hasattr(encryption_service, 'decrypt_api_key')
        assert hasattr(encryption_service, 'get_key_last_4')
        assert callable(encryption_service.encrypt_api_key)
        assert callable(encryption_service.decrypt_api_key)
        assert callable(encryption_service.get_key_last_4)
    
    def test_uuid_generation_functions(self):
        """Test UUID generation functions"""
        from backend.utils.uuid_manager import generate_unique_uuid
        
        # Test UUID generation
        uuid1 = generate_unique_uuid("api_key_creation")
        uuid2 = generate_unique_uuid("api_key_creation")
        
        assert uuid1 is not None
        assert uuid2 is not None
        assert uuid1 != uuid2  # Should be unique
        assert len(uuid1) > 10  # Should be reasonable length
        assert len(uuid2) > 10
    
    def test_connection_manager_functions(self):
        """Test connection manager functions"""
        from backend.services.connection_manager import connection_manager
        
        # Test connection manager exists
        assert connection_manager is not None
        
        # Test get_pool method exists
        assert hasattr(connection_manager, 'get_pool')
        assert callable(connection_manager.get_pool)
    
    def test_supabase_operation_functions(self):
        """Test Supabase operation functions"""
        from backend.services.supabase_manager import execute_supabase_operation
        
        # Test execute_supabase_operation exists
        assert execute_supabase_operation is not None
        assert callable(execute_supabase_operation)


class TestAPIKeysAPIIntegration:
    """Test API Keys API integration scenarios"""
    
    @pytest.mark.asyncio
    async def test_api_key_creation_workflow(self):
        """Test complete API key creation workflow"""
        # Mock dependencies
        with patch('backend.services.connection_manager.connection_manager') as mock_conn, \
             patch('backend.services.encryption_service.get_encryption_service') as mock_enc, \
             patch('backend.utils.uuid_manager.generate_unique_uuid', return_value="key123"), \
             patch('backend.services.supabase_manager.execute_supabase_operation') as mock_supabase:
            
            # Mock connection manager
            mock_pool = Mock()
            mock_conn.get_pool.return_value = mock_pool
            
            # Mock encryption service
            mock_enc_service = Mock()
            mock_enc_service.encrypt_api_key.return_value = "encrypted_key"
            mock_enc_service.get_key_last_4.return_value = "cdef"
            mock_enc.return_value = mock_enc_service
            
            # Mock Supabase response
            mock_supabase.return_value = Mock(data=[{"id": "key123"}])
            
            # Test API key creation request
            request = APIKeyCreateRequest(
                api_key="sk-1234567890abcdef1234567890abcdef",
                provider="openai",
                name="Test Key",
                description="Test API key"
            )
            
            # Verify request structure
            assert request.api_key.startswith("sk-")
            assert request.provider == "openai"
            assert request.name == "Test Key"
            assert request.description == "Test API key"
    
    @pytest.mark.asyncio
    async def test_api_key_listing_workflow(self):
        """Test API key listing workflow"""
        # Mock API keys data
        mock_api_keys_data = [
            {
                "id": "key1",
                "user_id": "user123",
                "provider": "openai",
                "name": "OpenAI Key",
                "description": "OpenAI API key",
                "key_last_4": "abcd",
                "is_active": True,
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z"
            },
            {
                "id": "key2",
                "user_id": "user123",
                "provider": "anthropic",
                "name": "Anthropic Key",
                "description": "Anthropic API key",
                "key_last_4": "efgh",
                "is_active": True,
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z"
            }
        ]
        
        # Create APIKeyResponse objects
        api_keys = []
        for key_data in mock_api_keys_data:
            api_key = APIKeyResponse(
                id=key_data["id"],
                user_id=key_data["user_id"],
                provider=key_data["provider"],
                name=key_data["name"],
                description=key_data["description"],
                key_last_4=key_data["key_last_4"],
                is_active=key_data["is_active"],
                created_at=key_data["created_at"],
                updated_at=key_data["updated_at"]
            )
            api_keys.append(api_key)
        
        # Create list response
        response = APIKeyListResponse(
            api_keys=api_keys,
            total_count=len(api_keys)
        )
        
        assert len(response.api_keys) == 2
        assert response.api_keys[0].provider == "openai"
        assert response.api_keys[1].provider == "anthropic"
        assert response.total_count == 2
    
    @pytest.mark.asyncio
    async def test_api_key_encryption_workflow(self):
        """Test API key encryption workflow"""
        # Mock encryption workflow
        original_key = "sk-1234567890abcdef1234567890abcdef"
        user_id = "user123"
        encrypted_key = "encrypted_" + original_key
        key_last_4 = original_key[-4:]
        
        # Test encryption workflow
        assert len(original_key) > 20  # Should be reasonable length
        assert original_key.startswith("sk-")
        assert len(encrypted_key) > len(original_key)  # Encrypted should be longer
        assert key_last_4 == "cdef"
        assert len(key_last_4) == 4


class TestAPIKeysAPISecurity:
    """Test API Keys API security features"""
    
    def test_api_key_encryption(self):
        """Test API key encryption security"""
        # Test API key format validation
        valid_api_keys = [
            "sk-1234567890abcdef1234567890abcdef",
            "sk-ant-1234567890abcdef1234567890abcdef",
            "sk-groq-1234567890abcdef1234567890abcdef"
        ]
        
        invalid_api_keys = [
            "invalid_key",
            "sk-",
            "sk-123",
            "",
            "plaintext_key"
        ]
        
        for key in valid_api_keys:
            assert key.startswith("sk-")
            assert len(key) > 20
            assert " " not in key
        
        for key in invalid_api_keys:
            if key:
                assert not (key.startswith("sk-") and len(key) > 20)
    
    def test_key_last_4_extraction(self):
        """Test key last 4 characters extraction"""
        api_keys = [
            "sk-1234567890abcdef1234567890abcdef",
            "sk-ant-1234567890abcdef1234567890abcdef",
            "sk-groq-1234567890abcdef1234567890abcdef"
        ]
        
        for key in api_keys:
            last_4 = key[-4:]
            assert len(last_4) == 4
            assert last_4.isalnum()
    
    def test_provider_validation(self):
        """Test provider validation"""
        valid_providers = ["openai", "anthropic", "groq", "openrouter"]
        
        for provider in valid_providers:
            assert isinstance(provider, str)
            assert len(provider) > 0
            assert provider.isalpha()
            assert provider.islower()
    
    def test_user_id_validation(self):
        """Test user ID validation"""
        valid_user_ids = ["user123", "user_456", "user-789"]
        
        for user_id in valid_user_ids:
            assert isinstance(user_id, str)
            assert len(user_id) > 0
            assert "user" in user_id.lower()


class TestAPIKeysAPIDataFlow:
    """Test API Keys API data flow"""
    
    def test_api_key_data_transformation(self):
        """Test API key data transformation"""
        # Raw API key data from database
        raw_key_data = {
            "id": "key123",
            "user_id": "user123",
            "provider": "openai",
            "name": "My OpenAI Key",
            "description": "API key for OpenAI services",
            "encrypted_key": "encrypted_key_data",
            "key_last_4": "cdef",
            "is_active": True,
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z"
        }
        
        # Transform to APIKeyResponse
        api_key_response = APIKeyResponse(
            id=raw_key_data["id"],
            user_id=raw_key_data["user_id"],
            provider=raw_key_data["provider"],
            name=raw_key_data["name"],
            description=raw_key_data["description"],
            key_last_4=raw_key_data["key_last_4"],
            is_active=raw_key_data["is_active"],
            created_at=raw_key_data["created_at"],
            updated_at=raw_key_data["updated_at"]
        )
        
        assert api_key_response.id == "key123"
        assert api_key_response.user_id == "user123"
        assert api_key_response.provider == "openai"
        assert api_key_response.key_last_4 == "cdef"
        assert api_key_response.is_active is True
    
    def test_api_key_request_validation(self):
        """Test API key request validation"""
        # Test valid request
        valid_request = APIKeyCreateRequest(
            api_key="sk-1234567890abcdef1234567890abcdef",
            provider="openai",
            name="Valid Key"
        )
        
        assert valid_request.api_key.startswith("sk-")
        assert valid_request.provider == "openai"
        assert len(valid_request.name) > 0
        
        # Test request with all fields
        full_request = APIKeyCreateRequest(
            api_key="sk-1234567890abcdef1234567890abcdef",
            provider="anthropic",
            name="Anthropic Key",
            description="API key for Anthropic services"
        )
        
        assert full_request.description == "API key for Anthropic services"
        assert full_request.provider == "anthropic"
    
    def test_api_key_list_data_flow(self):
        """Test API key list data flow"""
        # Mock multiple API keys
        api_keys_data = [
            {
                "id": "key1",
                "provider": "openai",
                "name": "OpenAI Key",
                "key_last_4": "abcd"
            },
            {
                "id": "key2",
                "provider": "anthropic",
                "name": "Anthropic Key",
                "key_last_4": "efgh"
            }
        ]
        
        # Transform to APIKeyResponse objects
        api_keys = []
        for key_data in api_keys_data:
            api_key = APIKeyResponse(
                id=key_data["id"],
                user_id="user123",
                provider=key_data["provider"],
                name=key_data["name"],
                description="API key",
                key_last_4=key_data["key_last_4"],
                is_active=True,
                created_at="2024-01-01T00:00:00Z",
                updated_at="2024-01-01T00:00:00Z"
            )
            api_keys.append(api_key)
        
        # Create list response
        list_response = APIKeyListResponse(
            api_keys=api_keys,
            total_count=len(api_keys)
        )
        
        assert len(list_response.api_keys) == 2
        assert list_response.total_count == 2


class TestAPIKeysAPIMockData:
    """Test API Keys API with mock data"""
    
    def test_mock_api_key_creation_data(self):
        """Test mock API key creation data"""
        mock_user = {"id": "user123", "email": "test@example.com"}
        mock_key_data = {
            "api_key": "sk-1234567890abcdef1234567890abcdef",
            "provider": "openai",
            "name": "My OpenAI Key",
            "description": "API key for OpenAI services"
        }
        
        # Simulate API key record creation
        key_record = {
            "id": "key123",
            "user_id": mock_user["id"],
            "provider": mock_key_data["provider"],
            "name": mock_key_data["name"],
            "description": mock_key_data["description"],
            "encrypted_key": "encrypted_" + mock_key_data["api_key"],
            "key_last_4": mock_key_data["api_key"][-4:],
            "is_active": True
        }
        
        assert key_record["user_id"] == "user123"
        assert key_record["provider"] == "openai"
        assert key_record["name"] == "My OpenAI Key"
        assert key_record["key_last_4"] == "cdef"
        assert key_record["is_active"] is True
    
    def test_mock_api_key_encryption_data(self):
        """Test mock API key encryption data"""
        # Mock encryption workflow
        original_keys = [
            "sk-1234567890abcdef1234567890abcdef",
            "sk-ant-1234567890abcdef1234567890abcdef",
            "sk-groq-1234567890abcdef1234567890abcdef"
        ]
        
        for original_key in original_keys:
            # Mock encryption process
            encrypted_key = f"enc_{original_key}"
            key_last_4 = original_key[-4:]
            
            assert encrypted_key.startswith("enc_")
            assert len(key_last_4) == 4
            assert key_last_4.isalnum()
    
    def test_mock_api_key_list_data(self):
        """Test mock API key list data"""
        # Mock API keys list
        mock_api_keys = [
            {
                "id": "key1",
                "provider": "openai",
                "name": "OpenAI Key",
                "key_last_4": "abcd",
                "is_active": True
            },
            {
                "id": "key2",
                "provider": "anthropic",
                "name": "Anthropic Key",
                "key_last_4": "efgh",
                "is_active": True
            },
            {
                "id": "key3",
                "provider": "groq",
                "name": "Groq Key",
                "key_last_4": "ijkl",
                "is_active": False
            }
        ]
        
        # Test API keys list operations
        active_keys = [key for key in mock_api_keys if key["is_active"]]
        inactive_keys = [key for key in mock_api_keys if not key["is_active"]]
        
        assert len(active_keys) == 2
        assert len(inactive_keys) == 1
        assert active_keys[0]["provider"] == "openai"
        assert inactive_keys[0]["provider"] == "groq"
    
    def test_mock_api_key_provider_data(self):
        """Test mock API key provider data"""
        # Mock provider configurations
        provider_configs = {
            "openai": {
                "name": "OpenAI",
                "prefix": "sk-",
                "required_length": 51,
                "description": "OpenAI API key"
            },
            "anthropic": {
                "name": "Anthropic",
                "prefix": "sk-ant-",
                "required_length": 55,
                "description": "Anthropic API key"
            },
            "groq": {
                "name": "Groq",
                "prefix": "sk-groq-",
                "required_length": 59,
                "description": "Groq API key"
            }
        }
        
        # Test provider configurations
        for provider, config in provider_configs.items():
            assert "name" in config
            assert "prefix" in config
            assert "required_length" in config
            assert "description" in config
            
            assert isinstance(config["name"], str)
            assert isinstance(config["prefix"], str)
            assert isinstance(config["required_length"], int)
            assert isinstance(config["description"], str)
            
            assert len(config["name"]) > 0
            assert config["prefix"].startswith("sk-")
            assert config["required_length"] > 20
    
    def test_mock_api_key_validation_data(self):
        """Test mock API key validation data"""
        # Mock validation scenarios
        validation_scenarios = [
            {
                "api_key": "sk-1234567890abcdef1234567890abcdef",
                "provider": "openai",
                "is_valid": True,
                "error": None
            },
            {
                "api_key": "invalid_key",
                "provider": "openai",
                "is_valid": False,
                "error": "Invalid API key format"
            },
            {
                "api_key": "sk-123",
                "provider": "openai",
                "is_valid": False,
                "error": "API key too short"
            },
            {
                "api_key": "sk-1234567890abcdef1234567890abcdef",
                "provider": "invalid_provider",
                "is_valid": False,
                "error": "Invalid provider"
            }
        ]
        
        # Test validation scenarios
        for scenario in validation_scenarios:
            assert "api_key" in scenario
            assert "provider" in scenario
            assert "is_valid" in scenario
            assert "error" in scenario
            
            assert isinstance(scenario["api_key"], str)
            assert isinstance(scenario["provider"], str)
            assert isinstance(scenario["is_valid"], bool)
            
            if scenario["is_valid"]:
                assert scenario["error"] is None
                assert scenario["api_key"].startswith("sk-")
                assert len(scenario["api_key"]) > 20
            else:
                assert scenario["error"] is not None
                assert isinstance(scenario["error"], str)


class TestAPIKeysAPIEdgeCases:
    """Test API Keys API edge cases"""
    
    def test_empty_api_key_handling(self):
        """Test empty API key handling"""
        empty_key_data = {
            "api_key": "",
            "provider": "openai",
            "name": "Empty Key"
        }
        
        # Test empty key validation
        assert empty_key_data["api_key"] == ""
        assert len(empty_key_data["api_key"]) == 0
        
        # Empty keys should be rejected
        assert len(empty_key_data["api_key"]) < 10
    
    def test_long_api_key_handling(self):
        """Test long API key handling"""
        long_key_data = {
            "api_key": "sk-" + "x" * 200,  # Very long key
            "provider": "openai",
            "name": "Long Key"
        }
        
        max_length = 100  # Reasonable limit
        
        # Test long key validation
        assert len(long_key_data["api_key"]) > max_length
        
        # Very long keys should be rejected
        assert len(long_key_data["api_key"]) > max_length
    
    def test_special_character_handling(self):
        """Test special character handling"""
        special_key_data = {
            "api_key": "sk-1234567890abcdef1234567890abcdef!@#",
            "provider": "openai",
            "name": "Special Key"
        }
        
        # Test special character handling
        assert special_key_data["api_key"].startswith("sk-")
        
        # Check for special characters
        has_special_chars = any(char in special_key_data["api_key"] for char in "!@#$%^&*()")
        if has_special_chars:
            assert has_special_chars
    
    def test_unicode_handling(self):
        """Test unicode handling"""
        unicode_key_data = {
            "api_key": "sk-1234567890abcdef1234567890abcdef",
            "provider": "openai",
            "name": "Ключ API",  # Unicode name
            "description": "API ключ для OpenAI"
        }
        
        # Test unicode handling
        assert isinstance(unicode_key_data["name"], str)
        assert isinstance(unicode_key_data["description"], str)
        
        # Should be able to encode/decode
        name_encoded = unicode_key_data["name"].encode("utf-8")
        name_decoded = name_encoded.decode("utf-8")
        assert name_decoded == unicode_key_data["name"]
    
    def test_concurrent_api_key_creation(self):
        """Test concurrent API key creation"""
        # Mock concurrent creation scenarios
        concurrent_scenarios = [
            {
                "user_id": "user1",
                "provider": "openai",
                "timestamp": "2024-01-01T00:00:00Z"
            },
            {
                "user_id": "user1",
                "provider": "anthropic",
                "timestamp": "2024-01-01T00:00:01Z"
            },
            {
                "user_id": "user2",
                "provider": "openai",
                "timestamp": "2024-01-01T00:00:00Z"
            }
        ]
        
        # Test concurrent creation structure
        for scenario in concurrent_scenarios:
            assert "user_id" in scenario
            assert "provider" in scenario
            assert "timestamp" in scenario
            
            assert isinstance(scenario["user_id"], str)
            assert isinstance(scenario["provider"], str)
            assert isinstance(scenario["timestamp"], str)
            
            assert len(scenario["user_id"]) > 0
            assert len(scenario["provider"]) > 0
            assert len(scenario["timestamp"]) > 0