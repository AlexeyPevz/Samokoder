"""
Упрощенные тесты для Health endpoints (18% покрытие)
"""
import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient
from fastapi import FastAPI
from datetime import datetime

from backend.api.health import router, check_external_services_health, get_memory_usage, get_disk_usage
from backend.services.health_checker import HealthChecker


class TestHealthEndpoints:
    """Тесты для Health endpoints"""

    def setup_method(self):
        """Настройка перед каждым тестом"""
        self.app = FastAPI()
        self.app.include_router(router)
        self.client = TestClient(self.app)

    @patch('backend.api.health.monitoring')
    def test_basic_health_check_success(self, mock_monitoring):
        """Тест базовой проверки здоровья - успех"""
        # Arrange
        mock_monitoring.get_health_status.return_value = {
            "status": "healthy",
            "uptime": 3600,
            "services": {"database": "healthy", "redis": "healthy"}
        }
        
        # Act
        response = self.client.get("/")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["version"] == "1.0.0"
        assert "timestamp" in data
        assert data["uptime"] == 3600
        assert "services" in data

    @patch('backend.api.health.monitoring')
    def test_basic_health_check_monitoring_error(self, mock_monitoring):
        """Тест базовой проверки здоровья - ошибка мониторинга"""
        # Arrange
        mock_monitoring.get_health_status.side_effect = Exception("Monitoring error")
        
        # Act
        response = self.client.get("/")
        
        # Assert
        assert response.status_code == 500
        assert "Health check failed" in response.json()["detail"]

    @patch('backend.api.health.monitoring')
    @patch('backend.api.health.check_external_services_health')
    @patch('backend.api.health.get_memory_usage')
    @patch('backend.api.health.get_disk_usage')
    def test_detailed_health_check_success(self, mock_disk, mock_memory, mock_external, mock_monitoring):
        """Тест детальной проверки здоровья - успех"""
        # Arrange
        mock_monitoring.get_health_status.return_value = {
            "status": "healthy",
            "uptime": 3600,
            "services": {"database": "healthy"}
        }
        mock_monitoring.active_projects = {"project1": {}, "project2": {}}
        mock_external.return_value = {"supabase": "healthy", "redis": "healthy"}
        mock_memory.return_value = {"total_bytes": 1000000, "used_percent": 50}
        mock_disk.return_value = {"total_bytes": 2000000, "used_percent": 30}
        
        # Act
        response = self.client.get("/detailed")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["version"] == "1.0.0"
        assert data["active_projects"] == 2
        assert "external_services" in data
        assert "memory_usage" in data
        assert "disk_usage" in data

    @patch('backend.api.health.connection_manager')
    @patch('backend.api.health.execute_supabase_operation')
    def test_database_health_check_success(self, mock_execute, mock_connection_manager):
        """Тест проверки здоровья базы данных - успех"""
        # Arrange
        mock_supabase = Mock()
        mock_connection_manager.get_pool.return_value = mock_supabase
        mock_execute.return_value = [{"id": "test"}]
        
        # Act
        response = self.client.get("/database")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "response_time_ms" in data
        assert "timestamp" in data

    @patch('backend.api.health.connection_manager')
    def test_database_health_check_mock_mode(self, mock_connection_manager):
        """Тест проверки здоровья базы данных - режим mock"""
        # Arrange
        mock_connection_manager.get_pool.side_effect = Exception("No connection")
        
        # Act
        response = self.client.get("/database")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "mock"
        assert "Database in mock mode" in data["message"]

    @patch('backend.api.health.get_ai_service')
    def test_ai_health_check_success(self, mock_get_ai_service):
        """Тест проверки здоровья AI сервисов - успех"""
        # Arrange
        mock_ai_service = Mock()
        mock_get_ai_service.return_value = mock_ai_service
        
        # Act
        response = self.client.get("/ai")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "providers" in data
        assert "timestamp" in data

    @patch('backend.api.health.psutil')
    def test_system_health_check_success(self, mock_psutil):
        """Тест проверки системных ресурсов - успех"""
        # Arrange
        mock_psutil.cpu_percent.return_value = 25.5
        mock_memory = Mock()
        mock_memory.total = 8 * 1024**3  # 8 GB
        mock_memory.available = 4 * 1024**3  # 4 GB
        mock_memory.percent = 50.0
        mock_psutil.virtual_memory.return_value = mock_memory
        
        mock_disk = Mock()
        mock_disk.total = 100 * 1024**3  # 100 GB
        mock_disk.free = 70 * 1024**3  # 70 GB
        mock_disk.used = 30 * 1024**3  # 30 GB
        mock_psutil.disk_usage.return_value = mock_disk
        mock_psutil.pids.return_value = [1, 2, 3, 4, 5]
        
        # Act
        response = self.client.get("/system")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["cpu_usage_percent"] == 25.5
        assert "memory" in data
        assert "disk" in data
        assert data["processes_count"] == 5

    @pytest.mark.asyncio
    @patch('backend.api.health.settings')
    @patch('backend.api.health.connection_manager')
    @patch('backend.api.health.execute_supabase_operation')
    async def test_check_external_services_health_success(self, mock_execute, mock_connection_manager, mock_settings):
        """Тест проверки внешних сервисов - успех"""
        # Arrange
        mock_settings.supabase_url = "https://real.supabase.co"
        mock_supabase = Mock()
        mock_connection_manager.get_pool.return_value = mock_supabase
        mock_execute.return_value = [{"id": "test"}]
        
        # Act
        result = await check_external_services_health()
        
        # Assert
        assert "supabase" in result
        assert result["supabase"] == "healthy"

    @patch('backend.api.health.psutil')
    def test_get_memory_usage_success(self, mock_psutil):
        """Тест получения информации о памяти - успех"""
        # Arrange
        mock_memory = Mock()
        mock_memory.total = 8 * 1024**3
        mock_memory.available = 4 * 1024**3
        mock_memory.used = 4 * 1024**3
        mock_memory.percent = 50.0
        mock_psutil.virtual_memory.return_value = mock_memory
        
        # Act
        result = get_memory_usage()
        
        # Assert
        assert result["total_bytes"] == 8 * 1024**3
        assert result["available_bytes"] == 4 * 1024**3
        assert result["used_bytes"] == 4 * 1024**3
        assert result["used_percent"] == 50.0

    @patch('backend.api.health.psutil')
    def test_get_disk_usage_success(self, mock_psutil):
        """Тест получения информации о диске - успех"""
        # Arrange
        mock_disk = Mock()
        mock_disk.total = 100 * 1024**3
        mock_disk.free = 70 * 1024**3
        mock_disk.used = 30 * 1024**3
        mock_psutil.disk_usage.return_value = mock_disk
        
        # Act
        result = get_disk_usage()
        
        # Assert
        assert result["total_bytes"] == 100 * 1024**3
        assert result["free_bytes"] == 70 * 1024**3
        assert result["used_bytes"] == 30 * 1024**3
        assert result["used_percent"] == 30.0


class TestHealthChecker:
    """Тесты для HealthChecker"""

    def setup_method(self):
        """Настройка перед каждым тестом"""
        self.checker = HealthChecker()

    def test_init(self):
        """Тест инициализации"""
        assert hasattr(self.checker, 'redis_client')

    @pytest.mark.asyncio
    async def test_check_redis_success(self):
        """Тест проверки Redis - успех"""
        # Arrange
        mock_redis = AsyncMock()
        mock_redis.ping.return_value = True
        mock_redis.set.return_value = True
        mock_redis.get.return_value = b"test"
        mock_redis.delete.return_value = True
        self.checker.redis_client = mock_redis
        
        # Act
        result = await self.checker.check_redis()
        
        # Assert
        assert result["status"] == "healthy"
        assert "timestamp" in result

    @pytest.mark.asyncio
    async def test_check_redis_no_client(self):
        """Тест проверки Redis - нет клиента"""
        # Arrange
        self.checker.redis_client = None
        
        # Act
        result = await self.checker.check_redis()
        
        # Assert
        assert result["status"] == "unavailable"
        assert "Redis client not initialized" in result["error"]

    @pytest.mark.asyncio
    async def test_check_ai_provider_mock_key(self):
        """Тест проверки AI провайдера - mock ключ"""
        # Act
        result = await self.checker.check_ai_provider("openai", "mock_key")
        
        # Assert
        assert result["status"] == "mock"
        assert result["provider"] == "openai"

    @pytest.mark.asyncio
    async def test_check_ai_provider_unknown(self):
        """Тест проверки AI провайдера - неизвестный провайдер"""
        # Act
        result = await self.checker.check_ai_provider("unknown", "test_key")
        
        # Assert
        assert result["status"] == "unknown"
        assert result["provider"] == "unknown"

    @pytest.mark.asyncio
    async def test_close(self):
        """Тест закрытия соединений"""
        # Arrange
        mock_redis = AsyncMock()
        self.checker.redis_client = mock_redis
        
        # Act
        await self.checker.close()
        
        # Assert
        mock_redis.close.assert_called_once()