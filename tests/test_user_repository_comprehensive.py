"""
Комплексные тесты для UserRepository (15% покрытие)
"""
import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from uuid import uuid4, UUID
from datetime import datetime, timezone

from backend.repositories.user_repository import UserRepository
from backend.core.exceptions import DatabaseError, NotFoundError, ValidationError, ConnectionError, TimeoutError


class TestUserRepository:
    """Тесты для UserRepository"""

    def setup_method(self):
        """Настройка перед каждым тестом"""
        self.repository = UserRepository()
        self.mock_supabase = AsyncMock()
        self.mock_response = Mock()
        self.mock_response.data = [{"id": "123", "email": "test@example.com"}]

    @patch('backend.repositories.user_repository.connection_pool_manager')
    def test_init(self, mock_pool_manager):
        """Тест инициализации UserRepository"""
        repository = UserRepository()
        assert repository._supabase is None
        assert hasattr(repository, '_get_supabase')

    @patch('backend.repositories.user_repository.connection_pool_manager')
    def test_get_supabase_initial(self, mock_pool_manager):
        """Тест получения Supabase клиента при первом вызове"""
        mock_client = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_client
        
        repository = UserRepository()
        result = repository._get_supabase()
        
        assert result == mock_client
        assert repository._supabase == mock_client
        mock_pool_manager.get_supabase_client.assert_called_once()

    @patch('backend.repositories.user_repository.connection_pool_manager')
    def test_get_supabase_cached(self, mock_pool_manager):
        """Тест получения кэшированного Supabase клиента"""
        mock_client = Mock()
        repository = UserRepository()
        repository._supabase = mock_client
        
        result = repository._get_supabase()
        
        assert result == mock_client
        mock_pool_manager.get_supabase_client.assert_not_called()

    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    @patch('backend.repositories.user_repository.db_config')
    async def test_find_by_id_success(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест успешного поиска пользователя по ID"""
        # Arrange
        user_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_execute.return_value = self.mock_response
        mock_db_config.TABLES = {"profiles": "profiles"}
        mock_db_config.QUERIES = {"select_all": "*"}
        mock_db_config.COLUMNS = {"id": "id"}
        
        # Act
        result = await self.repository.find_by_id(user_id)
        
        # Assert
        assert result == self.mock_response.data[0]
        mock_execute.assert_called_once()

    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    @patch('backend.repositories.user_repository.db_config')
    async def test_find_by_id_not_found(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест поиска несуществующего пользователя"""
        # Arrange
        user_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.data = []
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"profiles": "profiles"}
        mock_db_config.QUERIES = {"select_all": "*"}
        mock_db_config.COLUMNS = {"id": "id"}
        
        # Act
        result = await self.repository.find_by_id(user_id)
        
        # Assert
        assert result is None

    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    @patch('backend.repositories.user_repository.db_config')
    async def test_find_by_id_connection_error(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест обработки ConnectionError при поиске пользователя"""
        # Arrange
        user_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_execute.side_effect = ConnectionError("Connection failed")
        mock_db_config.TABLES = {"profiles": "profiles"}
        mock_db_config.QUERIES = {"select_all": "*"}
        mock_db_config.COLUMNS = {"id": "id"}
        
        # Act & Assert
        with pytest.raises(DatabaseError) as exc_info:
            await self.repository.find_by_id(user_id)
        assert "Database connection failed" in str(exc_info.value)

    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    @patch('backend.repositories.user_repository.db_config')
    async def test_find_by_id_timeout_error(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест обработки TimeoutError при поиске пользователя"""
        # Arrange
        user_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_execute.side_effect = TimeoutError("Timeout")
        mock_db_config.TABLES = {"profiles": "profiles"}
        mock_db_config.QUERIES = {"select_all": "*"}
        mock_db_config.COLUMNS = {"id": "id"}
        
        # Act & Assert
        with pytest.raises(DatabaseError) as exc_info:
            await self.repository.find_by_id(user_id)
        assert "Database operation timed out" in str(exc_info.value)

    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    @patch('backend.repositories.user_repository.db_config')
    async def test_find_by_id_general_error(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест обработки общего исключения при поиске пользователя"""
        # Arrange
        user_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_execute.side_effect = Exception("General error")
        mock_db_config.TABLES = {"profiles": "profiles"}
        mock_db_config.QUERIES = {"select_all": "*"}
        mock_db_config.COLUMNS = {"id": "id"}
        
        # Act & Assert
        with pytest.raises(DatabaseError) as exc_info:
            await self.repository.find_by_id(user_id)
        assert "Database operation failed" in str(exc_info.value)

    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    @patch('backend.repositories.user_repository.db_config')
    async def test_find_by_email_success(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест успешного поиска пользователя по email"""
        # Arrange
        email = "test@example.com"
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_execute.return_value = self.mock_response
        mock_db_config.TABLES = {"profiles": "profiles"}
        mock_db_config.QUERIES = {"select_all": "*"}
        mock_db_config.COLUMNS = {"email": "email"}
        
        # Act
        result = await self.repository.find_by_email(email)
        
        # Assert
        assert result == self.mock_response.data[0]
        mock_execute.assert_called_once()

    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    @patch('backend.repositories.user_repository.db_config')
    async def test_find_by_email_not_found(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест поиска несуществующего пользователя по email"""
        # Arrange
        email = "nonexistent@example.com"
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.data = []
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"profiles": "profiles"}
        mock_db_config.QUERIES = {"select_all": "*"}
        mock_db_config.COLUMNS = {"email": "email"}
        
        # Act
        result = await self.repository.find_by_email(email)
        
        # Assert
        assert result is None

    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    @patch('backend.repositories.user_repository.db_config')
    async def test_find_by_email_error(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест обработки ошибки при поиске пользователя по email"""
        # Arrange
        email = "test@example.com"
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_execute.side_effect = Exception("Database error")
        mock_db_config.TABLES = {"profiles": "profiles"}
        mock_db_config.QUERIES = {"select_all": "*"}
        mock_db_config.COLUMNS = {"email": "email"}
        
        # Act & Assert
        with pytest.raises(DatabaseError):
            await self.repository.find_by_email(email)

    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    @patch('backend.repositories.user_repository.db_config')
    async def test_create_success(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест успешного создания пользователя"""
        # Arrange
        user_data = {
            "id": str(uuid4()),
            "email": "newuser@example.com",
            "full_name": "New User"
        }
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.data = [user_data]
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"profiles": "profiles"}
        
        # Act
        result = await self.repository.create(user_data)
        
        # Assert
        assert result == user_data
        mock_execute.assert_called_once()

    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    @patch('backend.repositories.user_repository.db_config')
    async def test_create_validation_error(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест обработки ValidationError при создании пользователя"""
        # Arrange
        user_data = {"email": "newuser@example.com"}  # Неполные данные
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_execute.side_effect = ValidationError("Validation failed")
        mock_db_config.TABLES = {"profiles": "profiles"}
        
        # Act & Assert
        with pytest.raises(DatabaseError) as exc_info:
            await self.repository.create(user_data)
        assert "Database operation failed" in str(exc_info.value)

    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    @patch('backend.repositories.user_repository.db_config')
    async def test_update_success(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест успешного обновления пользователя"""
        # Arrange
        user_id = uuid4()
        update_data = {"full_name": "Updated Name"}
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.data = [{"id": str(user_id), "full_name": "Updated Name"}]
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"profiles": "profiles"}
        mock_db_config.COLUMNS = {"id": "id"}
        
        # Act
        result = await self.repository.update(user_id, update_data)
        
        # Assert
        assert result == mock_response.data[0]
        mock_execute.assert_called_once()

    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    @patch('backend.repositories.user_repository.db_config')
    async def test_update_not_found(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест обновления несуществующего пользователя"""
        # Arrange
        user_id = uuid4()
        update_data = {"full_name": "Updated Name"}
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.data = []
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"profiles": "profiles"}
        mock_db_config.COLUMNS = {"id": "id"}
        
        # Act & Assert
        with pytest.raises(NotFoundError):
            await self.repository.update(user_id, update_data)

    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    @patch('backend.repositories.user_repository.db_config')
    async def test_delete_success(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест успешного удаления пользователя"""
        # Arrange
        user_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.data = [{"id": str(user_id)}]
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"profiles": "profiles"}
        mock_db_config.COLUMNS = {"id": "id"}
        
        # Act
        result = await self.repository.delete(user_id)
        
        # Assert
        assert result is True
        mock_execute.assert_called_once()

    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    @patch('backend.repositories.user_repository.db_config')
    async def test_delete_not_found(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест удаления несуществующего пользователя"""
        # Arrange
        user_id = uuid4()
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.data = []
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"profiles": "profiles"}
        mock_db_config.COLUMNS = {"id": "id"}
        
        # Act & Assert
        with pytest.raises(NotFoundError):
            await self.repository.delete(user_id)

    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    @patch('backend.repositories.user_repository.db_config')
    async def test_exists_by_email_true(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест проверки существования пользователя по email - существует"""
        # Arrange
        email = "test@example.com"
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.data = [{"id": "123", "email": "test@example.com"}]
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"profiles": "profiles"}
        mock_db_config.QUERIES = {"select_all": "*"}
        mock_db_config.COLUMNS = {"email": "email"}
        
        # Act
        result = await self.repository.exists_by_email(email)
        
        # Assert
        assert result is True
        mock_execute.assert_called_once()

    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    @patch('backend.repositories.user_repository.db_config')
    async def test_exists_by_email_false(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест проверки существования пользователя по email - не существует"""
        # Arrange
        email = "nonexistent@example.com"
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.data = []
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"profiles": "profiles"}
        mock_db_config.QUERIES = {"select_all": "*"}
        mock_db_config.COLUMNS = {"email": "email"}
        
        # Act
        result = await self.repository.exists_by_email(email)
        
        # Assert
        assert result is False
        mock_execute.assert_called_once()

    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    @patch('backend.repositories.user_repository.db_config')
    async def test_exists_by_email_error(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест обработки ошибки при проверке существования пользователя по email"""
        # Arrange
        email = "test@example.com"
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_execute.side_effect = ConnectionError("Connection failed")
        mock_db_config.TABLES = {"profiles": "profiles"}
        mock_db_config.QUERIES = {"select_all": "*"}
        mock_db_config.COLUMNS = {"email": "email"}
        
        # Act & Assert
        with pytest.raises(DatabaseError) as exc_info:
            await self.repository.exists_by_email(email)
        assert "Database connection failed" in str(exc_info.value)

    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    @patch('backend.repositories.user_repository.db_config')
    async def test_update_subscription_success(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест успешного обновления подписки пользователя"""
        # Arrange
        user_id = uuid4()
        subscription_data = {
            "subscription_tier": "professional",
            "subscription_status": "active"
        }
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.data = [{"id": str(user_id), **subscription_data}]
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"profiles": "profiles"}
        mock_db_config.COLUMNS = {"id": "id"}
        
        # Act
        result = await self.repository.update_subscription(user_id, subscription_data)
        
        # Assert
        assert result == mock_response.data[0]
        mock_execute.assert_called_once()

    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    @patch('backend.repositories.user_repository.db_config')
    async def test_update_subscription_not_found(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест обновления подписки несуществующего пользователя"""
        # Arrange
        user_id = uuid4()
        subscription_data = {
            "subscription_tier": "professional",
            "subscription_status": "active"
        }
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.data = []
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"profiles": "profiles"}
        mock_db_config.COLUMNS = {"id": "id"}
        
        # Act & Assert
        with pytest.raises(NotFoundError):
            await self.repository.update_subscription(user_id, subscription_data)

    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    @patch('backend.repositories.user_repository.db_config')
    async def test_update_subscription_error(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест обработки ошибки при обновлении подписки пользователя"""
        # Arrange
        user_id = uuid4()
        subscription_data = {
            "subscription_tier": "professional",
            "subscription_status": "active"
        }
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_execute.side_effect = TimeoutError("Timeout")
        mock_db_config.TABLES = {"profiles": "profiles"}
        mock_db_config.COLUMNS = {"id": "id"}
        
        # Act & Assert
        with pytest.raises(DatabaseError) as exc_info:
            await self.repository.update_subscription(user_id, subscription_data)
        assert "Database operation timed out" in str(exc_info.value)

    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    @patch('backend.repositories.user_repository.db_config')
    async def test_update_credits_success(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест успешного обновления кредитов пользователя"""
        # Arrange
        user_id = uuid4()
        credits = 100.50
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.data = [{"id": str(user_id), "api_credits_balance": credits}]
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"profiles": "profiles"}
        mock_db_config.COLUMNS = {"id": "id"}
        
        # Act
        result = await self.repository.update_credits(user_id, credits)
        
        # Assert
        assert result == mock_response.data[0]
        mock_execute.assert_called_once()

    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    @patch('backend.repositories.user_repository.db_config')
    async def test_update_credits_not_found(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест обновления кредитов несуществующего пользователя"""
        # Arrange
        user_id = uuid4()
        credits = 100.50
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_response = Mock()
        mock_response.data = []
        mock_execute.return_value = mock_response
        mock_db_config.TABLES = {"profiles": "profiles"}
        mock_db_config.COLUMNS = {"id": "id"}
        
        # Act & Assert
        with pytest.raises(NotFoundError):
            await self.repository.update_credits(user_id, credits)

    @patch('backend.repositories.user_repository.execute_supabase_operation')
    @patch('backend.repositories.user_repository.connection_pool_manager')
    @patch('backend.repositories.user_repository.db_config')
    async def test_update_credits_error(self, mock_db_config, mock_pool_manager, mock_execute):
        """Тест обработки ошибки при обновлении кредитов пользователя"""
        # Arrange
        user_id = uuid4()
        credits = 100.50
        mock_supabase = Mock()
        mock_pool_manager.get_supabase_client.return_value = mock_supabase
        mock_execute.side_effect = Exception("Database error")
        mock_db_config.TABLES = {"profiles": "profiles"}
        mock_db_config.COLUMNS = {"id": "id"}
        
        # Act & Assert
        with pytest.raises(DatabaseError):
            await self.repository.update_credits(user_id, credits)