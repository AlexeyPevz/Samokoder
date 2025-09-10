"""
Integration tests for Security components
"""
import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from backend.security.secrets_manager import SecretsManager, EnvironmentSecretsProvider, FileSecretsProvider
from backend.security.key_rotation import KeyRotationManager

class TestSecretsManagerIntegration:
    """Integration tests for Secrets Manager"""
    
    @pytest.fixture
    def secrets_manager(self):
        """Create secrets manager instance"""
        return SecretsManager()
    
    @pytest.mark.asyncio
    async def test_environment_provider_success(self):
        """Test successful environment provider operations"""
        provider = EnvironmentSecretsProvider(prefix="TEST_")
        
        # Test get secret
        with patch.dict('os.environ', {'TEST_API_KEY': 'test_value'}):
            result = await provider.get_secret("api_key")
            assert result == "test_value"
        
        # Test set secret
        await provider.set_secret("new_key", "new_value")
        assert provider.get_secret("new_key") == "new_value"
        
        # Test delete secret
        result = await provider.delete_secret("new_key")
        assert result is True
    
    @pytest.mark.asyncio
    async def test_file_provider_success(self, tmp_path):
        """Test successful file provider operations"""
        secrets_file = tmp_path / "secrets.json"
        provider = FileSecretsProvider(str(secrets_file))
        
        # Test set secret
        result = await provider.set_secret("test_key", "test_value")
        assert result is True
        
        # Test get secret
        result = await provider.get_secret("test_key")
        assert result == "test_value"
        
        # Test delete secret
        result = await provider.delete_secret("test_key")
        assert result is True
        
        # Test get deleted secret
        result = await provider.get_secret("test_key")
        assert result is None
    
    @pytest.mark.asyncio
    async def test_secrets_manager_with_environment_provider(self, secrets_manager):
        """Test secrets manager with environment provider"""
        provider = EnvironmentSecretsProvider(prefix="TEST_")
        secrets_manager.add_provider("env", provider)
        
        with patch.dict('os.environ', {'TEST_API_KEY': 'test_value'}):
            # Test get secret
            result = await secrets_manager.get_secret("api_key", provider_name="env")
            assert result == "test_value"
            
            # Test set secret
            result = await secrets_manager.set_secret("new_key", "new_value", provider_name="env")
            assert result is True
            
            # Test delete secret
            result = await secrets_manager.delete_secret("new_key", provider_name="env")
            assert result is True
    
    @pytest.mark.asyncio
    async def test_secrets_manager_caching(self, secrets_manager):
        """Test secrets manager caching functionality"""
        provider = EnvironmentSecretsProvider(prefix="TEST_")
        secrets_manager.add_provider("env", provider)
        
        with patch.dict('os.environ', {'TEST_CACHE_KEY': 'cached_value'}):
            # First call - should cache
            result1 = await secrets_manager.get_secret("cache_key", provider_name="env")
            assert result1 == "cached_value"
            
            # Second call - should use cache
            result2 = await secrets_manager.get_secret("cache_key", provider_name="env")
            assert result2 == "cached_value"
            
            # Verify cache hit
            assert secrets_manager._cache.get("env:cache_key") == "cached_value"
    
    @pytest.mark.asyncio
    async def test_secrets_manager_fallback(self, secrets_manager):
        """Test secrets manager fallback functionality"""
        # Add primary provider that fails
        primary_provider = Mock()
        primary_provider.get_secret = AsyncMock(return_value=None)
        secrets_manager.add_provider("primary", primary_provider)
        
        # Add fallback provider
        fallback_provider = Mock()
        fallback_provider.get_secret = AsyncMock(return_value="fallback_value")
        secrets_manager.add_provider("fallback", fallback_provider)
        
        # Test fallback
        result = await secrets_manager.get_secret("test_key")
        assert result == "fallback_value"
        
        # Verify both providers were called
        primary_provider.get_secret.assert_called_once_with("test_key")
        fallback_provider.get_secret.assert_called_once_with("test_key")
    
    @pytest.mark.asyncio
    async def test_secrets_manager_audit_logging(self, secrets_manager):
        """Test secrets manager audit logging"""
        provider = EnvironmentSecretsProvider(prefix="TEST_")
        secrets_manager.add_provider("env", provider)
        
        with patch.dict('os.environ', {'TEST_AUDIT_KEY': 'audit_value'}):
            # Test get secret with audit logging
            with patch.object(secrets_manager, '_log_audit') as mock_log:
                await secrets_manager.get_secret("audit_key", provider_name="env")
                mock_log.assert_called_once()
            
            # Test set secret with audit logging
            with patch.object(secrets_manager, '_log_audit') as mock_log:
                await secrets_manager.set_secret("audit_key", "new_value", provider_name="env")
                mock_log.assert_called_once()
            
            # Test delete secret with audit logging
            with patch.object(secrets_manager, '_log_audit') as mock_log:
                await secrets_manager.delete_secret("audit_key", provider_name="env")
                mock_log.assert_called_once()

class TestKeyRotationManagerIntegration:
    """Integration tests for Key Rotation Manager"""
    
    @pytest.fixture
    def key_rotation_manager(self):
        """Create key rotation manager instance"""
        return KeyRotationManager()
    
    def test_generate_secure_key_encryption(self, key_rotation_manager):
        """Test secure key generation for encryption keys"""
        key = key_rotation_manager.generate_secure_key("api_encryption_key", 32)
        
        # Should be base64 encoded
        assert isinstance(key, str)
        assert len(key) > 0
        
        # Should be valid base64
        import base64
        try:
            base64.urlsafe_b64decode(key + "==")  # Add padding for validation
            assert True
        except Exception:
            assert False, "Generated key is not valid base64"
    
    def test_generate_secure_key_api(self, key_rotation_manager):
        """Test secure key generation for API keys"""
        key = key_rotation_manager.generate_secure_key("openai_api_key", 32)
        
        # Should be hex encoded
        assert isinstance(key, str)
        assert len(key) == 64  # 32 bytes * 2 (hex)
        
        # Should be valid hex
        try:
            bytes.fromhex(key)
            assert True
        except ValueError:
            assert False, "Generated key is not valid hex"
    
    @pytest.mark.asyncio
    async def test_check_rotation_needed_no_history(self, key_rotation_manager):
        """Test rotation check with no history"""
        with patch.object(key_rotation_manager, 'get_last_rotation_date', return_value=None):
            keys_to_rotate = await key_rotation_manager.check_rotation_needed()
            
            # All keys should need rotation
            assert len(keys_to_rotate) == len(key_rotation_manager.rotation_schedule)
            assert "api_encryption_key" in keys_to_rotate
            assert "jwt_secret" in keys_to_rotate
    
    @pytest.mark.asyncio
    async def test_check_rotation_needed_with_history(self, key_rotation_manager):
        """Test rotation check with history"""
        from datetime import datetime, timedelta
        
        # Mock recent rotation
        recent_date = datetime.now() - timedelta(days=1)
        
        with patch.object(key_rotation_manager, 'get_last_rotation_date', return_value=recent_date):
            keys_to_rotate = await key_rotation_manager.check_rotation_needed()
            
            # No keys should need rotation
            assert len(keys_to_rotate) == 0
    
    @pytest.mark.asyncio
    async def test_check_rotation_needed_expired(self, key_rotation_manager):
        """Test rotation check with expired keys"""
        from datetime import datetime, timedelta
        
        # Mock expired rotation
        expired_date = datetime.now() - timedelta(days=100)
        
        with patch.object(key_rotation_manager, 'get_last_rotation_date', return_value=expired_date):
            keys_to_rotate = await key_rotation_manager.check_rotation_needed()
            
            # All keys should need rotation
            assert len(keys_to_rotate) == len(key_rotation_manager.rotation_schedule)
    
    @pytest.mark.asyncio
    async def test_rotate_key_success(self, key_rotation_manager):
        """Test successful key rotation"""
        with patch.object(key_rotation_manager, 'generate_secure_key', return_value="new_key"):
            with patch.object(key_rotation_manager, 'secrets_manager') as mock_secrets:
                mock_secrets.set_secret = AsyncMock(return_value=True)
                mock_secrets.get_secret = AsyncMock(return_value="old_key")
                
                result = await key_rotation_manager.rotate_key("test_key")
                
                assert result is True
                mock_secrets.set_secret.assert_called_once_with("test_key", "new_key")
    
    @pytest.mark.asyncio
    async def test_rotate_key_failure(self, key_rotation_manager):
        """Test key rotation failure"""
        with patch.object(key_rotation_manager, 'generate_secure_key', return_value="new_key"):
            with patch.object(key_rotation_manager, 'secrets_manager') as mock_secrets:
                mock_secrets.set_secret = AsyncMock(return_value=False)
                mock_secrets.get_secret = AsyncMock(return_value="old_key")
                
                result = await key_rotation_manager.rotate_key("test_key")
                
                assert result is False
    
    @pytest.mark.asyncio
    async def test_rotate_all_keys_success(self, key_rotation_manager):
        """Test successful rotation of all keys"""
        with patch.object(key_rotation_manager, 'check_rotation_needed', return_value=["key1", "key2"]):
            with patch.object(key_rotation_manager, 'rotate_key', return_value=True):
                result = await key_rotation_manager.rotate_all_keys()
                
                assert result == {"key1": True, "key2": True}
    
    @pytest.mark.asyncio
    async def test_rotate_all_keys_partial_failure(self, key_rotation_manager):
        """Test partial failure in key rotation"""
        with patch.object(key_rotation_manager, 'check_rotation_needed', return_value=["key1", "key2"]):
            with patch.object(key_rotation_manager, 'rotate_key', side_effect=[True, False]):
                result = await key_rotation_manager.rotate_all_keys()
                
                assert result == {"key1": True, "key2": False}
    
    @pytest.mark.asyncio
    async def test_get_rotation_status(self, key_rotation_manager):
        """Test rotation status retrieval"""
        from datetime import datetime, timedelta
        
        # Mock rotation history
        rotation_history = {
            "key1": datetime.now() - timedelta(days=30),
            "key2": datetime.now() - timedelta(days=100)
        }
        
        with patch.object(key_rotation_manager, 'rotation_history', rotation_history):
            status = await key_rotation_manager.get_rotation_status()
            
            assert "key1" in status
            assert "key2" in status
            assert status["key1"]["days_since_rotation"] == 30
            assert status["key2"]["days_since_rotation"] == 100
            assert status["key1"]["needs_rotation"] is False
            assert status["key2"]["needs_rotation"] is True
    
    @pytest.mark.asyncio
    async def test_schedule_rotation_success(self, key_rotation_manager):
        """Test successful rotation scheduling"""
        with patch.object(key_rotation_manager, 'rotate_all_keys', return_value={"key1": True}):
            with patch('asyncio.create_task') as mock_task:
                result = await key_rotation_manager.schedule_rotation()
                
                assert result is True
                mock_task.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_schedule_rotation_failure(self, key_rotation_manager):
        """Test rotation scheduling failure"""
        with patch.object(key_rotation_manager, 'rotate_all_keys', side_effect=Exception("Rotation failed")):
            result = await key_rotation_manager.schedule_rotation()
            
            assert result is False