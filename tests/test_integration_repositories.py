"""
Integration tests for Repositories
"""
import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
from uuid import uuid4
from backend.repositories.user_repository import UserRepository
from backend.repositories.project_repository import ProjectRepository
from backend.repositories.chat_repository import ChatRepository
from backend.core.database_config import db_config

class TestUserRepositoryIntegration:
    """Integration tests for User Repository"""
    
    @pytest.fixture
    def user_repo(self):
        """Create user repository instance"""
        return UserRepository()
    
    @pytest.fixture
    def mock_supabase(self):
        """Mock Supabase client"""
        mock_client = Mock()
        mock_table = Mock()
        mock_client.table.return_value = mock_table
        return mock_client, mock_table
    
    @pytest.mark.asyncio
    async def test_find_by_id_success(self, user_repo, mock_supabase):
        """Test successful user find by ID"""
        mock_client, mock_table = mock_supabase
        
        # Mock response
        user_data = {"id": str(uuid4()), "email": "test@example.com", "full_name": "Test User"}
        mock_response = Mock()
        mock_response.data = [user_data]
        mock_table.select.return_value.eq.return_value.execute.return_value = mock_response
        
        # Mock connection pool
        with patch('backend.repositories.user_repository.connection_pool_manager') as mock_pool:
            mock_pool.get_supabase_client.return_value = mock_client
            
            user_id = uuid4()
            result = await user_repo.find_by_id(user_id)
            
            assert result == user_data
            mock_table.select.assert_called_with(db_config.QUERIES["select_all"])
            mock_table.select.return_value.eq.assert_called_with(db_config.COLUMNS["id"], str(user_id))
    
    @pytest.mark.asyncio
    async def test_find_by_id_not_found(self, user_repo, mock_supabase):
        """Test user find by ID when not found"""
        mock_client, mock_table = mock_supabase
        
        # Mock empty response
        mock_response = Mock()
        mock_response.data = []
        mock_table.select.return_value.eq.return_value.execute.return_value = mock_response
        
        # Mock connection pool
        with patch('backend.repositories.user_repository.connection_pool_manager') as mock_pool:
            mock_pool.get_supabase_client.return_value = mock_client
            
            user_id = uuid4()
            result = await user_repo.find_by_id(user_id)
            
            assert result is None
    
    @pytest.mark.asyncio
    async def test_find_by_email_success(self, user_repo, mock_supabase):
        """Test successful user find by email"""
        mock_client, mock_table = mock_supabase
        
        # Mock response
        user_data = {"id": str(uuid4()), "email": "test@example.com", "full_name": "Test User"}
        mock_response = Mock()
        mock_response.data = [user_data]
        mock_table.select.return_value.eq.return_value.execute.return_value = mock_response
        
        # Mock connection pool
        with patch('backend.repositories.user_repository.connection_pool_manager') as mock_pool:
            mock_pool.get_supabase_client.return_value = mock_client
            
            result = await user_repo.find_by_email("test@example.com")
            
            assert result == user_data
            mock_table.select.return_value.eq.assert_called_with(db_config.COLUMNS["email"], "test@example.com")
    
    @pytest.mark.asyncio
    async def test_save_user_success(self, user_repo, mock_supabase):
        """Test successful user save"""
        mock_client, mock_table = mock_supabase
        
        # Mock response
        user_data = {"id": str(uuid4()), "email": "test@example.com", "full_name": "Test User"}
        mock_response = Mock()
        mock_response.data = [user_data]
        mock_table.insert.return_value.execute.return_value = mock_response
        
        # Mock connection pool
        with patch('backend.repositories.user_repository.connection_pool_manager') as mock_pool:
            mock_pool.get_supabase_client.return_value = mock_client
            
            result = await user_repo.save(user_data)
            
            assert result == user_data
            mock_table.insert.assert_called_with(user_data)
    
    @pytest.mark.asyncio
    async def test_update_user_success(self, user_repo, mock_supabase):
        """Test successful user update"""
        mock_client, mock_table = mock_supabase
        
        # Mock response
        user_data = {"id": str(uuid4()), "email": "test@example.com", "full_name": "Updated User"}
        mock_response = Mock()
        mock_response.data = [user_data]
        mock_table.update.return_value.eq.return_value.execute.return_value = mock_response
        
        # Mock connection pool
        with patch('backend.repositories.user_repository.connection_pool_manager') as mock_pool:
            mock_pool.get_supabase_client.return_value = mock_client
            
            user_id = uuid4()
            result = await user_repo.update(user_id, user_data)
            
            assert result == user_data
            mock_table.update.assert_called_with(user_data)
            mock_table.update.return_value.eq.assert_called_with(db_config.COLUMNS["id"], str(user_id))
    
    @pytest.mark.asyncio
    async def test_delete_user_success(self, user_repo, mock_supabase):
        """Test successful user delete"""
        mock_client, mock_table = mock_supabase
        
        # Mock response
        mock_response = Mock()
        mock_response.data = [{"id": str(uuid4())}]
        mock_table.delete.return_value.eq.return_value.execute.return_value = mock_response
        
        # Mock connection pool
        with patch('backend.repositories.user_repository.connection_pool_manager') as mock_pool:
            mock_pool.get_supabase_client.return_value = mock_client
            
            user_id = uuid4()
            result = await user_repo.delete(user_id)
            
            assert result is True
            mock_table.delete.assert_called_once()
            mock_table.delete.return_value.eq.assert_called_with(db_config.COLUMNS["id"], str(user_id))
    
    @pytest.mark.asyncio
    async def test_find_active_users_success(self, user_repo, mock_supabase):
        """Test successful active users find"""
        mock_client, mock_table = mock_supabase
        
        # Mock response
        users_data = [
            {"id": str(uuid4()), "email": "user1@example.com", "subscription_status": "active"},
            {"id": str(uuid4()), "email": "user2@example.com", "subscription_status": "active"}
        ]
        mock_response = Mock()
        mock_response.data = users_data
        mock_table.select.return_value.eq.return_value.range.return_value.execute.return_value = mock_response
        
        # Mock connection pool
        with patch('backend.repositories.user_repository.connection_pool_manager') as mock_pool:
            mock_pool.get_supabase_client.return_value = mock_client
            
            result = await user_repo.find_active_users(limit=10, offset=0)
            
            assert result == users_data
            mock_table.select.return_value.eq.assert_called_with("subscription_status", db_config.STATUS["active"])
            mock_table.select.return_value.eq.return_value.range.assert_called_with(0, 9)
    
    @pytest.mark.asyncio
    async def test_repository_error_handling(self, user_repo, mock_supabase):
        """Test repository error handling"""
        mock_client, mock_table = mock_supabase
        
        # Mock exception
        mock_table.select.return_value.eq.return_value.execute.side_effect = Exception("Database error")
        
        # Mock connection pool
        with patch('backend.repositories.user_repository.connection_pool_manager') as mock_pool:
            mock_pool.get_supabase_client.return_value = mock_client
            
            user_id = uuid4()
            result = await user_repo.find_by_id(user_id)
            
            assert result is None

class TestProjectRepositoryIntegration:
    """Integration tests for Project Repository"""
    
    @pytest.fixture
    def project_repo(self):
        """Create project repository instance"""
        return ProjectRepository()
    
    @pytest.fixture
    def mock_supabase(self):
        """Mock Supabase client"""
        mock_client = Mock()
        mock_table = Mock()
        mock_client.table.return_value = mock_table
        return mock_client, mock_table
    
    @pytest.mark.asyncio
    async def test_find_by_user_id_success(self, project_repo, mock_supabase):
        """Test successful projects find by user ID"""
        mock_client, mock_table = mock_supabase
        
        # Mock response
        projects_data = [
            {"id": str(uuid4()), "user_id": str(uuid4()), "name": "Project 1", "is_active": True},
            {"id": str(uuid4()), "user_id": str(uuid4()), "name": "Project 2", "is_active": True}
        ]
        mock_response = Mock()
        mock_response.data = projects_data
        mock_table.select.return_value.eq.return_value.eq.return_value.range.return_value.order.return_value.execute.return_value = mock_response
        
        # Mock connection pool
        with patch('backend.repositories.project_repository.connection_pool_manager') as mock_pool:
            mock_pool.get_supabase_client.return_value = mock_client
            
            user_id = uuid4()
            result = await project_repo.find_by_user_id(user_id, limit=10, offset=0)
            
            assert result == projects_data
            mock_table.select.return_value.eq.assert_any_call(db_config.COLUMNS["user_id"], str(user_id))
            mock_table.select.return_value.eq.return_value.eq.assert_called_with(db_config.COLUMNS["is_active"], True)
    
    @pytest.mark.asyncio
    async def test_save_project_success(self, project_repo, mock_supabase):
        """Test successful project save"""
        mock_client, mock_table = mock_supabase
        
        # Mock response
        project_data = {"id": str(uuid4()), "user_id": str(uuid4()), "name": "Test Project"}
        mock_response = Mock()
        mock_response.data = [project_data]
        mock_table.insert.return_value.execute.return_value = mock_response
        
        # Mock connection pool
        with patch('backend.repositories.project_repository.connection_pool_manager') as mock_pool:
            mock_pool.get_supabase_client.return_value = mock_client
            
            result = await project_repo.save(project_data)
            
            assert result == project_data
            mock_table.insert.assert_called_with(project_data)
    
    @pytest.mark.asyncio
    async def test_search_projects_success(self, project_repo, mock_supabase):
        """Test successful project search"""
        mock_client, mock_table = mock_supabase
        
        # Mock response
        projects_data = [
            {"id": str(uuid4()), "user_id": str(uuid4()), "name": "Test Project", "description": "Test description"}
        ]
        mock_response = Mock()
        mock_response.data = projects_data
        mock_table.select.return_value.eq.return_value.eq.return_value.or_.return_value.range.return_value.order.return_value.execute.return_value = mock_response
        
        # Mock connection pool
        with patch('backend.repositories.project_repository.connection_pool_manager') as mock_pool:
            mock_pool.get_supabase_client.return_value = mock_client
            
            user_id = uuid4()
            result = await project_repo.search(user_id, "test", limit=10, offset=0)
            
            assert result == projects_data
            mock_table.select.return_value.eq.assert_any_call(db_config.COLUMNS["user_id"], str(user_id))
            mock_table.select.return_value.eq.return_value.eq.assert_called_with(db_config.COLUMNS["is_active"], True)

class TestChatRepositoryIntegration:
    """Integration tests for Chat Repository"""
    
    @pytest.fixture
    def chat_repo(self):
        """Create chat repository instance"""
        return ChatRepository()
    
    @pytest.fixture
    def mock_supabase(self):
        """Mock Supabase client"""
        mock_client = Mock()
        mock_table = Mock()
        mock_client.table.return_value = mock_table
        return mock_client, mock_table
    
    @pytest.mark.asyncio
    async def test_find_session_by_id_success(self, chat_repo, mock_supabase):
        """Test successful chat session find by ID"""
        mock_client, mock_table = mock_supabase
        
        # Mock response
        session_data = {"id": str(uuid4()), "project_id": str(uuid4()), "title": "Test Session"}
        mock_response = Mock()
        mock_response.data = [session_data]
        mock_table.select.return_value.eq.return_value.execute.return_value = mock_response
        
        # Mock connection pool
        with patch('backend.repositories.chat_repository.connection_pool_manager') as mock_pool:
            mock_pool.get_supabase_client.return_value = mock_client
            
            session_id = uuid4()
            result = await chat_repo.find_session_by_id(session_id)
            
            assert result == session_data
            mock_table.select.assert_called_with(db_config.QUERIES["select_all"])
            mock_table.select.return_value.eq.assert_called_with(db_config.COLUMNS["id"], str(session_id))
    
    @pytest.mark.asyncio
    async def test_save_session_success(self, chat_repo, mock_supabase):
        """Test successful chat session save"""
        mock_client, mock_table = mock_supabase
        
        # Mock response
        session_data = {"id": str(uuid4()), "project_id": str(uuid4()), "title": "Test Session"}
        mock_response = Mock()
        mock_response.data = [session_data]
        mock_table.insert.return_value.execute.return_value = mock_response
        
        # Mock connection pool
        with patch('backend.repositories.chat_repository.connection_pool_manager') as mock_pool:
            mock_pool.get_supabase_client.return_value = mock_client
            
            result = await chat_repo.save_session(session_data)
            
            assert result == session_data
            mock_table.insert.assert_called_with(session_data)
    
    @pytest.mark.asyncio
    async def test_find_messages_by_session_success(self, chat_repo, mock_supabase):
        """Test successful messages find by session ID"""
        mock_client, mock_table = mock_supabase
        
        # Mock response
        messages_data = [
            {"id": str(uuid4()), "session_id": str(uuid4()), "role": "user", "content": "Hello"},
            {"id": str(uuid4()), "session_id": str(uuid4()), "role": "assistant", "content": "Hi there"}
        ]
        mock_response = Mock()
        mock_response.data = messages_data
        mock_table.select.return_value.eq.return_value.range.return_value.order.return_value.execute.return_value = mock_response
        
        # Mock connection pool
        with patch('backend.repositories.chat_repository.connection_pool_manager') as mock_pool:
            mock_pool.get_supabase_client.return_value = mock_client
            
            session_id = uuid4()
            result = await chat_repo.find_messages_by_session(session_id, limit=50, offset=0)
            
            assert result == messages_data
            mock_table.select.return_value.eq.assert_called_with(db_config.COLUMNS["session_id"], str(session_id))
    
    @pytest.mark.asyncio
    async def test_save_message_success(self, chat_repo, mock_supabase):
        """Test successful chat message save"""
        mock_client, mock_table = mock_supabase
        
        # Mock response
        message_data = {"id": str(uuid4()), "session_id": str(uuid4()), "role": "user", "content": "Hello"}
        mock_response = Mock()
        mock_response.data = [message_data]
        mock_table.insert.return_value.execute.return_value = mock_response
        
        # Mock connection pool
        with patch('backend.repositories.chat_repository.connection_pool_manager') as mock_pool:
            mock_pool.get_supabase_client.return_value = mock_client
            
            result = await chat_repo.save_message(message_data)
            
            assert result == message_data
            mock_table.insert.assert_called_with(message_data)
    
    @pytest.mark.asyncio
    async def test_count_messages_by_session_success(self, chat_repo, mock_supabase):
        """Test successful message count by session"""
        mock_client, mock_table = mock_supabase
        
        # Mock response
        mock_response = Mock()
        mock_response.count = 5
        mock_table.select.return_value.eq.return_value.execute.return_value = mock_response
        
        # Mock connection pool
        with patch('backend.repositories.chat_repository.connection_pool_manager') as mock_pool:
            mock_pool.get_supabase_client.return_value = mock_client
            
            session_id = uuid4()
            result = await chat_repo.count_messages_by_session(session_id)
            
            assert result == 5
            mock_table.select.assert_called_with(db_config.QUERIES["count_exact"], count="exact")
            mock_table.select.return_value.eq.assert_called_with(db_config.COLUMNS["session_id"], str(session_id))