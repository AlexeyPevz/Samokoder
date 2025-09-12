#!/usr/bin/env python3
"""
Комплексные тесты для User Repository
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from uuid import uuid4, UUID
from backend.repositories.user_repository import UserRepository
from backend.core.exceptions import DatabaseError, NotFoundError, ValidationError, ConnectionError, TimeoutError


class TestUserRepository:
    """Тесты для UserRepository"""
    
    def setup_method(self):
        """Настройка для каждого теста"""
        self.repository = UserRepository()
        self.mock_supabase = Mock()
        self.mock_response = Mock()
        self.mock_response.data = [{"id": "test_id", "email": "test@example.com"}]
        
    def test_init(self):
        """Тест инициализации UserRepository"""
        assert self.repository._supabase is None
    
    @patch('backend.repositories.user_repository.connection_pool_manager')
    def test_get_supabase(self, mock_connection_manager):
        """Тест получения Supabase клиента"""
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        
        result = self.repository._get_supabase()
        
        assert result == self.mock_supabase
        assert self.repository._supabase == self.mock_supabase
        mock_connection_manager.get_supabase_client.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    async def test_find_by_id_success(self, mock_connection_manager, mock_execute_operation):
        """Тест успешного поиска пользователя по ID"""
        user_id = uuid4()
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_execute_operation.return_value = self.mock_response
        
        result = await self.repository.find_by_id(user_id)
        
        assert result == {"id": "test_id", "email": "test@example.com"}
        mock_execute_operation.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    async def test_find_by_id_not_found(self, mock_connection_manager, mock_execute_operation):
        """Тест поиска несуществующего пользователя по ID"""
        user_id = uuid4()
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_response = Mock()
        mock_response.data = []
        mock_execute_operation.return_value = mock_response
        
        result = await self.repository.find_by_id(user_id)
        
        assert result is None
        mock_execute_operation.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    async def test_find_by_id_connection_error(self, mock_connection_manager, mock_execute_operation):
        """Тест ошибки подключения при поиске пользователя по ID"""
        user_id = uuid4()
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_execute_operation.side_effect = ConnectionError("Connection failed")
        
        with pytest.raises(DatabaseError, match="Database connection failed"):
            await self.repository.find_by_id(user_id)
    
    @pytest.mark.asyncio
    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    async def test_find_by_id_timeout_error(self, mock_connection_manager, mock_execute_operation):
        """Тест ошибки таймаута при поиске пользователя по ID"""
        user_id = uuid4()
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_execute_operation.side_effect = TimeoutError("Operation timed out")
        
        with pytest.raises(DatabaseError, match="Database operation timed out"):
            await self.repository.find_by_id(user_id)
    
    @pytest.mark.asyncio
    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    async def test_find_by_id_generic_error(self, mock_connection_manager, mock_execute_operation):
        """Тест общей ошибки при поиске пользователя по ID"""
        user_id = uuid4()
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_execute_operation.side_effect = Exception("Generic error")
        
        with pytest.raises(DatabaseError, match="Database operation failed"):
            await self.repository.find_by_id(user_id)
    
    @pytest.mark.asyncio
    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    async def test_find_by_email_success(self, mock_connection_manager, mock_execute_operation):
        """Тест успешного поиска пользователя по email"""
        email = "test@example.com"
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_execute_operation.return_value = self.mock_response
        
        result = await self.repository.find_by_email(email)
        
        assert result == {"id": "test_id", "email": "test@example.com"}
        mock_execute_operation.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    async def test_find_by_email_not_found(self, mock_connection_manager, mock_execute_operation):
        """Тест поиска несуществующего пользователя по email"""
        email = "nonexistent@example.com"
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_response = Mock()
        mock_response.data = []
        mock_execute_operation.return_value = mock_response
        
        result = await self.repository.find_by_email(email)
        
        assert result is None
        mock_execute_operation.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    async def test_find_by_email_error(self, mock_connection_manager, mock_execute_operation):
        """Тест ошибки при поиске пользователя по email"""
        email = "test@example.com"
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_execute_operation.side_effect = Exception("Search failed")
        
        with pytest.raises(DatabaseError, match="Database operation failed"):
            await self.repository.find_by_email(email)
    
    @pytest.mark.asyncio
    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    async def test_save_success(self, mock_connection_manager, mock_execute_operation):
        """Тест успешного сохранения пользователя"""
        user_data = {"email": "newuser@example.com", "name": "New User"}
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_response = Mock()
        mock_response.data = [{"id": "new_user_id", **user_data}]
        mock_execute_operation.return_value = mock_response
        
        result = await self.repository.save(user_data)
        
        assert result["id"] == "new_user_id"
        assert result["email"] == "newuser@example.com"
        assert result["name"] == "New User"
        mock_execute_operation.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    async def test_save_error(self, mock_connection_manager, mock_execute_operation):
        """Тест ошибки при сохранении пользователя"""
        user_data = {"email": "newuser@example.com"}
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_execute_operation.side_effect = Exception("Save failed")
        
        with pytest.raises(DatabaseError, match="Database operation failed"):
            await self.repository.save(user_data)
    
    @pytest.mark.asyncio
    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    async def test_update_success(self, mock_connection_manager, mock_execute_operation):
        """Тест успешного обновления пользователя"""
        user_id = uuid4()
        user_data = {"name": "Updated User"}
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_response = Mock()
        mock_response.data = [{"id": str(user_id), **user_data}]
        mock_execute_operation.return_value = mock_response
        
        result = await self.repository.update(user_id, user_data)
        
        assert result["id"] == str(user_id)
        assert result["name"] == "Updated User"
        mock_execute_operation.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    async def test_update_error(self, mock_connection_manager, mock_execute_operation):
        """Тест ошибки при обновлении пользователя"""
        user_id = uuid4()
        user_data = {"name": "Updated User"}
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_execute_operation.side_effect = Exception("Update failed")
        
        with pytest.raises(DatabaseError, match="Database operation failed"):
            await self.repository.update(user_id, user_data)
    
    @pytest.mark.asyncio
    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    async def test_delete_success(self, mock_connection_manager, mock_execute_operation):
        """Тест успешного удаления пользователя"""
        user_id = uuid4()
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_response = Mock()
        mock_response.data = [{"id": str(user_id)}]
        mock_execute_operation.return_value = mock_response
        
        result = await self.repository.delete(user_id)
        
        assert result is True
        mock_execute_operation.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    async def test_delete_not_found(self, mock_connection_manager, mock_execute_operation):
        """Тест удаления несуществующего пользователя"""
        user_id = uuid4()
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_response = Mock()
        mock_response.data = []
        mock_execute_operation.return_value = mock_response
        
        result = await self.repository.delete(user_id)
        
        assert result is False
        mock_execute_operation.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    async def test_delete_error(self, mock_connection_manager, mock_execute_operation):
        """Тест ошибки при удалении пользователя"""
        user_id = uuid4()
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_execute_operation.side_effect = Exception("Delete failed")
        
        with pytest.raises(DatabaseError, match="Database operation failed"):
            await self.repository.delete(user_id)
    
    @pytest.mark.asyncio
    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    async def test_find_by_subscription_tier_success(self, mock_connection_manager, mock_execute_operation):
        """Тест успешного поиска пользователей по уровню подписки"""
        tier = "professional"
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_response = Mock()
        mock_response.data = [{"id": "user1"}, {"id": "user2"}]
        mock_execute_operation.return_value = mock_response
        
        result = await self.repository.find_by_subscription_tier(tier)
        
        assert len(result) == 2
        assert result[0]["id"] == "user1"
        assert result[1]["id"] == "user2"
        mock_execute_operation.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    async def test_find_by_subscription_tier_error(self, mock_connection_manager, mock_execute_operation):
        """Тест ошибки при поиске пользователей по уровню подписки"""
        tier = "professional"
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_execute_operation.side_effect = Exception("Search failed")
        
        with pytest.raises(DatabaseError, match="Database operation failed"):
            await self.repository.find_by_subscription_tier(tier)
    
    @pytest.mark.asyncio
    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    async def test_find_active_users_success(self, mock_connection_manager, mock_execute_operation):
        """Тест успешного поиска активных пользователей"""
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_response = Mock()
        mock_response.data = [{"id": "active1"}, {"id": "active2"}]
        mock_execute_operation.return_value = mock_response
        
        result = await self.repository.find_active_users(limit=50, offset=10)
        
        assert len(result) == 2
        mock_execute_operation.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    async def test_find_active_users_default_params(self, mock_connection_manager, mock_execute_operation):
        """Тест поиска активных пользователей с параметрами по умолчанию"""
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_response = Mock()
        mock_response.data = []
        mock_execute_operation.return_value = mock_response
        
        result = await self.repository.find_active_users()
        
        assert result == []
        mock_execute_operation.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    async def test_find_active_users_error(self, mock_connection_manager, mock_execute_operation):
        """Тест ошибки при поиске активных пользователей"""
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_execute_operation.side_effect = Exception("Search failed")
        
        with pytest.raises(DatabaseError, match="Database operation failed"):
            await self.repository.find_active_users()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    async def test_update_subscription_success(self, mock_connection_manager, mock_execute_operation):
        """Тест успешного обновления подписки пользователя"""
        user_id = uuid4()
        tier = "professional"
        status = "active"
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_response = Mock()
        mock_response.data = [{"id": str(user_id), "subscription_tier": tier, "subscription_status": status}]
        mock_execute_operation.return_value = mock_response
        
        result = await self.repository.update_subscription(user_id, tier, status)
        
        assert result is True
        mock_execute_operation.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    async def test_update_subscription_not_found(self, mock_connection_manager, mock_execute_operation):
        """Тест обновления подписки несуществующего пользователя"""
        user_id = uuid4()
        tier = "professional"
        status = "active"
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_response = Mock()
        mock_response.data = []
        mock_execute_operation.return_value = mock_response
        
        result = await self.repository.update_subscription(user_id, tier, status)
        
        assert result is False
        mock_execute_operation.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    async def test_update_subscription_error(self, mock_connection_manager, mock_execute_operation):
        """Тест ошибки при обновлении подписки пользователя"""
        user_id = uuid4()
        tier = "professional"
        status = "active"
        mock_connection_manager.get_supabase_client.return_value = self.mock_supabase
        mock_execute_operation.side_effect = Exception("Update failed")
        
        with pytest.raises(DatabaseError, match="Database operation failed"):
            await self.repository.update_subscription(user_id, tier, status)