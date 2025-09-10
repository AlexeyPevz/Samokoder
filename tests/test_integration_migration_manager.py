"""
Integration tests for Migration Manager
"""
import pytest
import asyncio
import os
import tempfile
from unittest.mock import Mock, patch, AsyncMock
from backend.services.migration_manager import MigrationManager

class TestMigrationManagerIntegration:
    """Integration tests for Migration Manager"""
    
    def test_migration_manager_initialization(self):
        """Test migration manager initialization"""
        # Test with custom database URL
        db_url = "postgresql://user:pass@localhost:5432/testdb"
        manager = MigrationManager(db_url)
        
        assert manager.database_url == db_url
        assert manager.alembic_config == "alembic.ini"
    
    def test_migration_manager_initialization_with_env(self):
        """Test migration manager initialization with environment variable"""
        # Set environment variable
        test_url = "postgresql://env_user:env_pass@localhost:5432/env_db"
        with patch.dict(os.environ, {"DATABASE_URL": test_url}):
            manager = MigrationManager()
            assert manager.database_url == test_url
    
    def test_migration_manager_initialization_with_settings(self):
        """Test migration manager initialization with settings fallback"""
        # Mock settings
        with patch('backend.services.migration_manager.settings') as mock_settings:
            mock_settings.database_user = "test_user"
            mock_settings.database_password = "test_pass"
            mock_settings.database_host = "test_host"
            mock_settings.database_port = "5432"
            mock_settings.database_name = "test_db"
            
            manager = MigrationManager()
            expected_url = "postgresql://test_user:test_pass@test_host:5432/test_db"
            assert manager.database_url == expected_url
    
    @pytest.mark.asyncio
    async def test_migration_upgrade_success(self):
        """Test successful migration upgrade"""
        manager = MigrationManager("postgresql://test:test@localhost:5432/test")
        
        # Mock subprocess
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate.return_value = (b"Migration successful", b"")
            mock_subprocess.return_value = mock_process
            
            result = await manager.upgrade("head")
            
            assert result is True
            mock_subprocess.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_migration_upgrade_failure(self):
        """Test migration upgrade failure"""
        manager = MigrationManager("postgresql://test:test@localhost:5432/test")
        
        # Mock subprocess
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 1
            mock_process.communicate.return_value = (b"", b"Migration failed")
            mock_subprocess.return_value = mock_process
            
            result = await manager.upgrade("head")
            
            assert result is False
            mock_subprocess.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_migration_downgrade_success(self):
        """Test successful migration downgrade"""
        manager = MigrationManager("postgresql://test:test@localhost:5432/test")
        
        # Mock subprocess
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate.return_value = (b"Downgrade successful", b"")
            mock_subprocess.return_value = mock_process
            
            result = await manager.downgrade("-1")
            
            assert result is True
            mock_subprocess.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_migration_downgrade_failure(self):
        """Test migration downgrade failure"""
        manager = MigrationManager("postgresql://test:test@localhost:5432/test")
        
        # Mock subprocess
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 1
            mock_process.communicate.return_value = (b"", b"Downgrade failed")
            mock_subprocess.return_value = mock_process
            
            result = await manager.downgrade("-1")
            
            assert result is False
            mock_subprocess.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_current_revision_success(self):
        """Test successful current revision retrieval"""
        manager = MigrationManager("postgresql://test:test@localhost:5432/test")
        
        # Mock subprocess
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate.return_value = (b"abc123 (head)", b"")
            mock_subprocess.return_value = mock_process
            
            revision = await manager.current_revision()
            
            assert revision == "abc123"
            mock_subprocess.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_current_revision_failure(self):
        """Test current revision retrieval failure"""
        manager = MigrationManager("postgresql://test:test@localhost:5432/test")
        
        # Mock subprocess
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 1
            mock_process.communicate.return_value = (b"", b"Error getting revision")
            mock_subprocess.return_value = mock_process
            
            revision = await manager.current_revision()
            
            assert revision is None
            mock_subprocess.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_migration_success(self):
        """Test successful migration creation"""
        manager = MigrationManager("postgresql://test:test@localhost:5432/test")
        
        # Mock subprocess
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate.return_value = (b"Migration created", b"")
            mock_subprocess.return_value = mock_process
            
            result = await manager.create_migration("test migration")
            
            assert result is True
            mock_subprocess.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_migration_failure(self):
        """Test migration creation failure"""
        manager = MigrationManager("postgresql://test:test@localhost:5432/test")
        
        # Mock subprocess
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 1
            mock_process.communicate.return_value = (b"", b"Error creating migration")
            mock_subprocess.return_value = mock_process
            
            result = await manager.create_migration("test migration")
            
            assert result is False
            mock_subprocess.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_migration_history_success(self):
        """Test successful migration history retrieval"""
        manager = MigrationManager("postgresql://test:test@localhost:5432/test")
        
        # Mock subprocess
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate.return_value = (b"abc123 - Initial migration\nxyz789 - Add users table", b"")
            mock_subprocess.return_value = mock_process
            
            history = await manager.history()
            
            assert len(history) == 2
            assert "abc123 - Initial migration" in history
            assert "xyz789 - Add users table" in history
            mock_subprocess.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_migration_history_failure(self):
        """Test migration history retrieval failure"""
        manager = MigrationManager("postgresql://test:test@localhost:5432/test")
        
        # Mock subprocess
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 1
            mock_process.communicate.return_value = (b"", b"Error getting history")
            mock_subprocess.return_value = mock_process
            
            history = await manager.history()
            
            assert history == []
            mock_subprocess.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_migration_status_check(self):
        """Test migration status check"""
        manager = MigrationManager("postgresql://test:test@localhost:5432/test")
        
        # Mock subprocess calls
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            # Mock current revision call
            mock_process_current = AsyncMock()
            mock_process_current.returncode = 0
            mock_process_current.communicate.return_value = (b"abc123 (head)", b"")
            
            # Mock history call
            mock_process_history = AsyncMock()
            mock_process_history.returncode = 0
            mock_process_history.communicate.return_value = (b"abc123 - Initial migration", b"")
            
            mock_subprocess.side_effect = [mock_process_current, mock_process_history]
            
            status = await manager.check_migration_status()
            
            assert "current_revision" in status
            assert "history" in status
            assert status["current_revision"] == "abc123"
            assert len(status["history"]) == 1
    
    @pytest.mark.asyncio
    async def test_migration_exception_handling(self):
        """Test migration exception handling"""
        manager = MigrationManager("postgresql://test:test@localhost:5432/test")
        
        # Mock subprocess to raise exception
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_subprocess.side_effect = Exception("Subprocess error")
            
            result = await manager.upgrade("head")
            
            assert result is False
    
    @pytest.mark.asyncio
    async def test_migration_environment_variables(self):
        """Test migration with environment variables"""
        manager = MigrationManager("postgresql://test:test@localhost:5432/test")
        
        # Mock subprocess
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate.return_value = (b"Success", b"")
            mock_subprocess.return_value = mock_process
            
            await manager.upgrade("head")
            
            # Check that environment variables were passed
            call_args = mock_subprocess.call_args
            env = call_args[1]["env"]
            assert "DATABASE_URL" in env
            assert env["DATABASE_URL"] == "postgresql://test:test@localhost:5432/test"