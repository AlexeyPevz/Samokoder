"""
Комплексные тесты для MFA endpoints
Покрытие: 38% → 90%+
"""

import pytest
import uuid
import base64
import io
from unittest.mock import Mock, patch, MagicMock
from fastapi import HTTPException, status
from datetime import datetime

from backend.api.mfa import (
    router,
    setup_mfa,
    verify_mfa,
    disable_mfa,
    store_mfa_secret,
    get_mfa_secret,
    delete_mfa_secret,
    mfa_secrets
)
from backend.models.requests import MFAVerifyRequest
from backend.models.responses import MFASetupResponse, MFAVerifyResponse

def mock_pyotp_import(name, *args, **kwargs):
    """Mock для импорта pyotp"""
    if name == 'pyotp':
        mock_pyotp = Mock()
        mock_totp = Mock()
        mock_pyotp.TOTP.return_value = mock_totp
        mock_totp.verify.return_value = True
        return mock_pyotp
    elif name == 'time':
        mock_time = Mock()
        mock_time.time.return_value = 1640995200
        return mock_time
    else:
        return __import__(name, *args, **kwargs)

def mock_pyotp_import_false(name, *args, **kwargs):
    """Mock для импорта pyotp с verify=False"""
    if name == 'pyotp':
        mock_pyotp = Mock()
        mock_totp = Mock()
        mock_pyotp.TOTP.return_value = mock_totp
        mock_totp.verify.return_value = False
        return mock_pyotp
    elif name == 'time':
        mock_time = Mock()
        mock_time.time.return_value = 1640995200
        return mock_time
    else:
        return __import__(name, *args, **kwargs)

def mock_pyotp_import_error(name, *args, **kwargs):
    """Mock для импорта pyotp с ImportError"""
    if name == 'pyotp':
        raise ImportError("pyotp not available")
    elif name == 'time':
        mock_time = Mock()
        mock_time.time.return_value = 1640995200
        return mock_time
    else:
        return __import__(name, *args, **kwargs)

def mock_pyotp_import_exception(name, *args, **kwargs):
    """Mock для импорта pyotp с Exception"""
    if name == 'pyotp':
        raise Exception("pyotp error")
    elif name == 'time':
        mock_time = Mock()
        mock_time.time.return_value = 1640995200
        return mock_time
    else:
        return __import__(name, *args, **kwargs)


class TestMFAEndpoints:
    """Тесты для MFA endpoints"""
    
    @pytest.fixture(autouse=True)
    def setup_method(self):
        """Настройка для каждого теста"""
        # Очищаем fallback хранилище
        global mfa_secrets
        mfa_secrets.clear()
    
    @pytest.fixture
    def mock_current_user(self):
        return {
            "id": str(uuid.uuid4()),
            "email": "test@example.com",
            "is_active": True
        }
    
    @pytest.fixture
    def mock_redis_client(self):
        return Mock()
    
    # === SETUP MFA ===
    
    @pytest.mark.asyncio
    async def test_setup_mfa_success(self, mock_current_user):
        """Тест успешной настройки MFA"""
        with patch('backend.api.mfa.redis_client', None):  # Используем fallback
            result = await setup_mfa(mock_current_user)
            
            assert isinstance(result, MFASetupResponse)
            assert len(result.secret) > 0
            assert result.qr_code.startswith("data:image/png;base64,")
            assert len(result.backup_codes) == 10
            assert all(len(code) == 8 for code in result.backup_codes)
            
            # Проверяем, что секрет сохранен
            assert mock_current_user["id"] in mfa_secrets
    
    @pytest.mark.asyncio
    async def test_setup_mfa_with_redis(self, mock_current_user, mock_redis_client):
        """Тест настройки MFA с Redis"""
        with patch('backend.api.mfa.redis_client', mock_redis_client):
            result = await setup_mfa(mock_current_user)
            
            assert isinstance(result, MFASetupResponse)
            assert len(result.secret) > 0
            assert result.qr_code.startswith("data:image/png;base64,")
            assert len(result.backup_codes) == 10
            
            # Проверяем, что секрет сохранен в Redis
            mock_redis_client.setex.assert_called_once()
            call_args = mock_redis_client.setex.call_args
            assert call_args[0][0] == f"mfa_secret:{mock_current_user['id']}"
            assert call_args[0][2] == result.secret
            assert call_args[0][1] == 3600  # TTL
    
    @pytest.mark.asyncio
    async def test_setup_mfa_exception(self, mock_current_user):
        """Тест обработки исключения при настройке MFA"""
        with patch('backend.api.mfa.secrets.token_urlsafe', side_effect=Exception("Token generation failed")):
            with pytest.raises(HTTPException) as exc_info:
                await setup_mfa(mock_current_user)
            
            assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
            assert "Ошибка настройки MFA" in str(exc_info.value.detail)
    
    # === VERIFY MFA ===
    
    @pytest.mark.asyncio
    async def test_verify_mfa_success_with_pyotp(self, mock_current_user):
        """Тест успешной проверки MFA с pyotp"""
        # Сохраняем секрет
        test_secret = "test_secret_key"
        mfa_secrets[mock_current_user["id"]] = test_secret
        
        with patch('backend.api.mfa.redis_client', None), \
             patch('builtins.__import__', side_effect=mock_pyotp_import):
            
            request = MFAVerifyRequest(code="123456")
            result = await verify_mfa(request, mock_current_user)
            
            assert isinstance(result, MFAVerifyResponse)
            assert result.verified is True
            assert "MFA код подтвержден" in result.message
    
    @pytest.mark.asyncio
    async def test_verify_mfa_success_dev_mode(self, mock_current_user):
        """Тест успешной проверки MFA в dev режиме (без pyotp)"""
        # Сохраняем секрет
        test_secret = "test_secret_key"
        mfa_secrets[mock_current_user["id"]] = test_secret
        
        with patch('backend.api.mfa.redis_client', None), \
             patch('builtins.__import__', side_effect=mock_pyotp_import_error):
            
            request = MFAVerifyRequest(code="123456")
            result = await verify_mfa(request, mock_current_user)
            
            assert isinstance(result, MFAVerifyResponse)
            assert result.verified is True
            assert "MFA код подтвержден (dev mode)" in result.message
    
    @pytest.mark.asyncio
    async def test_verify_mfa_invalid_code_dev_mode(self, mock_current_user):
        """Тест проверки неверного MFA кода в dev режиме"""
        # Сохраняем секрет
        test_secret = "test_secret_key"
        mfa_secrets[mock_current_user["id"]] = test_secret
        
        with patch('backend.api.mfa.redis_client', None), \
             patch('builtins.__import__', side_effect=mock_pyotp_import_error):
            
            request = MFAVerifyRequest(code="123456")  # В dev режиме любой 6-значный код принимается
            result = await verify_mfa(request, mock_current_user)
            
            assert isinstance(result, MFAVerifyResponse)
            assert result.verified is True  # В dev режиме принимается
            assert "MFA код подтвержден (dev mode)" in result.message
    
    @pytest.mark.asyncio
    async def test_verify_mfa_invalid_code_pyotp(self, mock_current_user):
        """Тест проверки неверного MFA кода с pyotp"""
        # Сохраняем секрет
        test_secret = "test_secret_key"
        mfa_secrets[mock_current_user["id"]] = test_secret
        
        with patch('backend.api.mfa.redis_client', None), \
             patch('builtins.__import__', side_effect=mock_pyotp_import_false):
            
            request = MFAVerifyRequest(code="123456")
            result = await verify_mfa(request, mock_current_user)
            
            assert isinstance(result, MFAVerifyResponse)
            assert result.verified is False
            assert "Неверный MFA код" in result.message
    
    @pytest.mark.asyncio
    async def test_verify_mfa_no_secret(self, mock_current_user):
        """Тест проверки MFA когда секрет не настроен"""
        with patch('backend.api.mfa.redis_client', None):
            request = MFAVerifyRequest(code="123456")
            
            with pytest.raises(HTTPException) as exc_info:
                await verify_mfa(request, mock_current_user)
            
            assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
            assert "MFA не настроен для пользователя" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_verify_mfa_with_redis(self, mock_current_user, mock_redis_client):
        """Тест проверки MFA с Redis"""
        test_secret = "test_secret_key"
        mock_redis_client.get.return_value = test_secret.encode()
        
        with patch('backend.api.mfa.redis_client', mock_redis_client), \
             patch('builtins.__import__', side_effect=mock_pyotp_import):
            
            request = MFAVerifyRequest(code="123456")
            result = await verify_mfa(request, mock_current_user)
            
            assert isinstance(result, MFAVerifyResponse)
            assert result.verified is True
            
            # Проверяем, что секрет получен из Redis
            mock_redis_client.get.assert_called_once_with(f"mfa_secret:{mock_current_user['id']}")
    
    @pytest.mark.asyncio
    async def test_verify_mfa_exception(self, mock_current_user):
        """Тест обработки исключения при проверке MFA"""
        # Сохраняем секрет
        test_secret = "test_secret_key"
        mfa_secrets[mock_current_user["id"]] = test_secret
        
        with patch('backend.api.mfa.redis_client', None), \
             patch('builtins.__import__', side_effect=mock_pyotp_import_exception):
            
            request = MFAVerifyRequest(code="123456")
            
            with pytest.raises(HTTPException) as exc_info:
                await verify_mfa(request, mock_current_user)
            
            assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
            assert "Ошибка проверки MFA" in str(exc_info.value.detail)
    
    # === DISABLE MFA ===
    
    @pytest.mark.asyncio
    async def test_disable_mfa_success_fallback(self, mock_current_user):
        """Тест успешного отключения MFA (fallback)"""
        # Сохраняем секрет
        test_secret = "test_secret_key"
        mfa_secrets[mock_current_user["id"]] = test_secret
        
        with patch('backend.api.mfa.redis_client', None):
            result = await disable_mfa(mock_current_user)
            
            assert result["message"] == "MFA отключен"
            assert mock_current_user["id"] not in mfa_secrets
    
    @pytest.mark.asyncio
    async def test_disable_mfa_success_redis(self, mock_current_user, mock_redis_client):
        """Тест успешного отключения MFA (Redis)"""
        with patch('backend.api.mfa.redis_client', mock_redis_client):
            result = await disable_mfa(mock_current_user)
            
            assert result["message"] == "MFA отключен"
            mock_redis_client.delete.assert_called_once_with(f"mfa_secret:{mock_current_user['id']}")
    
    @pytest.mark.asyncio
    async def test_disable_mfa_exception(self, mock_current_user, mock_redis_client):
        """Тест обработки исключения при отключении MFA"""
        mock_redis_client.delete.side_effect = Exception("Redis error")
        
        with patch('backend.api.mfa.redis_client', mock_redis_client):
            with pytest.raises(HTTPException) as exc_info:
                await disable_mfa(mock_current_user)
            
            assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
            assert "Ошибка отключения MFA" in str(exc_info.value.detail)
    
    # === HELPER FUNCTIONS ===
    
    def test_store_mfa_secret_fallback(self):
        """Тест сохранения MFA секрета (fallback)"""
        global mfa_secrets
        mfa_secrets.clear()
        
        user_id = "test_user"
        secret = "test_secret"
        
        with patch('backend.api.mfa.redis_client', None):
            store_mfa_secret(user_id, secret)
            
            assert mfa_secrets[user_id] == secret
    
    def test_store_mfa_secret_redis(self, mock_redis_client):
        """Тест сохранения MFA секрета (Redis)"""
        user_id = "test_user"
        secret = "test_secret"
        
        with patch('backend.api.mfa.redis_client', mock_redis_client):
            store_mfa_secret(user_id, secret)
            
            mock_redis_client.setex.assert_called_once_with(f"mfa_secret:{user_id}", 3600, secret)
    
    def test_get_mfa_secret_fallback(self):
        """Тест получения MFA секрета (fallback)"""
        global mfa_secrets
        mfa_secrets.clear()
        
        user_id = "test_user"
        secret = "test_secret"
        mfa_secrets[user_id] = secret
        
        with patch('backend.api.mfa.redis_client', None):
            result = get_mfa_secret(user_id)
            
            assert result == secret
    
    def test_get_mfa_secret_redis(self, mock_redis_client):
        """Тест получения MFA секрета (Redis)"""
        user_id = "test_user"
        secret = "test_secret"
        mock_redis_client.get.return_value = secret.encode()
        
        with patch('backend.api.mfa.redis_client', mock_redis_client):
            result = get_mfa_secret(user_id)
            
            assert result == secret.encode()
            mock_redis_client.get.assert_called_once_with(f"mfa_secret:{user_id}")
    
    def test_get_mfa_secret_not_found_fallback(self):
        """Тест получения несуществующего MFA секрета (fallback)"""
        global mfa_secrets
        mfa_secrets.clear()
        
        user_id = "nonexistent_user"
        
        with patch('backend.api.mfa.redis_client', None):
            result = get_mfa_secret(user_id)
            
            assert result is None
    
    def test_get_mfa_secret_not_found_redis(self, mock_redis_client):
        """Тест получения несуществующего MFA секрета (Redis)"""
        user_id = "nonexistent_user"
        mock_redis_client.get.return_value = None
        
        with patch('backend.api.mfa.redis_client', mock_redis_client):
            result = get_mfa_secret(user_id)
            
            assert result is None
    
    def test_delete_mfa_secret_fallback(self):
        """Тест удаления MFA секрета (fallback)"""
        global mfa_secrets
        mfa_secrets.clear()
        
        user_id = "test_user"
        secret = "test_secret"
        mfa_secrets[user_id] = secret
        
        with patch('backend.api.mfa.redis_client', None):
            delete_mfa_secret(user_id)
            
            assert user_id not in mfa_secrets
    
    def test_delete_mfa_secret_redis(self, mock_redis_client):
        """Тест удаления MFA секрета (Redis)"""
        user_id = "test_user"
        
        with patch('backend.api.mfa.redis_client', mock_redis_client):
            delete_mfa_secret(user_id)
            
            mock_redis_client.delete.assert_called_once_with(f"mfa_secret:{user_id}")
    
    def test_delete_mfa_secret_nonexistent_fallback(self):
        """Тест удаления несуществующего MFA секрета (fallback)"""
        global mfa_secrets
        mfa_secrets.clear()
        
        user_id = "nonexistent_user"
        
        with patch('backend.api.mfa.redis_client', None):
            # Не должно вызывать исключение
            delete_mfa_secret(user_id)
            
            assert user_id not in mfa_secrets
    
    # === INTEGRATION TESTS ===
    
    @pytest.mark.asyncio
    async def test_mfa_full_workflow(self, mock_current_user):
        """Интеграционный тест полного workflow MFA"""
        with patch('backend.api.mfa.redis_client', None):
            # 1. Настраиваем MFA
            setup_result = await setup_mfa(mock_current_user)
            assert setup_result.secret is not None
            
            # 2. Проверяем, что секрет сохранен
            secret = get_mfa_secret(mock_current_user["id"])
            assert secret == setup_result.secret
            
            # 3. Проверяем MFA код (dev режим)
            with patch('builtins.__import__', side_effect=mock_pyotp_import_error):
                verify_request = MFAVerifyRequest(code="123456")
                verify_result = await verify_mfa(verify_request, mock_current_user)
                assert verify_result.verified is True
            
            # 4. Отключаем MFA
            disable_result = await disable_mfa(mock_current_user)
            assert disable_result["message"] == "MFA отключен"
            
            # 5. Проверяем, что секрет удален
            secret_after_disable = get_mfa_secret(mock_current_user["id"])
            assert secret_after_disable is None
    
    @pytest.mark.asyncio
    async def test_mfa_qr_code_generation(self, mock_current_user):
        """Тест генерации QR кода"""
        with patch('backend.api.mfa.redis_client', None):
            result = await setup_mfa(mock_current_user)
            
            # Проверяем, что QR код в правильном формате
            assert result.qr_code.startswith("data:image/png;base64,")
            
            # Декодируем base64 и проверяем, что это валидный PNG
            qr_data = result.qr_code.split(",")[1]
            qr_bytes = base64.b64decode(qr_data)
            assert qr_bytes.startswith(b'\x89PNG')  # PNG signature
    
    @pytest.mark.asyncio
    async def test_mfa_backup_codes_generation(self, mock_current_user):
        """Тест генерации backup кодов"""
        with patch('backend.api.mfa.redis_client', None):
            result = await setup_mfa(mock_current_user)
            
            # Проверяем backup коды
            assert len(result.backup_codes) == 10
            assert all(len(code) == 8 for code in result.backup_codes)
            assert all(code.isalnum() and code.isupper() and all(c in '0123456789ABCDEF' for c in code) for code in result.backup_codes)
            
            # Проверяем, что все коды уникальны
            assert len(set(result.backup_codes)) == 10