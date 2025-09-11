"""
Комплексные тесты для Health endpoints
Покрывают все основные функции и сценарии
"""

import pytest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
from datetime import datetime
from typing import Dict, Any

from backend.api.health import (
    basic_health_check, detailed_health_check, database_health_check,
    ai_health_check, system_health_check
)
from backend.models.responses import HealthCheckResponse
from backend.core.exceptions import DatabaseError, NetworkError


class TestHealthEndpoints:
    """Тесты для Health endpoints"""
    
    def test_basic_health_check_endpoint_exists(self):
        """Проверяем, что endpoint basic_health_check существует"""
        assert callable(basic_health_check)
    
    def test_detailed_health_check_endpoint_exists(self):
        """Проверяем, что endpoint detailed_health_check существует"""
        assert callable(detailed_health_check)
    
    def test_database_health_check_endpoint_exists(self):
        """Проверяем, что endpoint database_health_check существует"""
        assert callable(database_health_check)
    
    def test_ai_health_check_endpoint_exists(self):
        """Проверяем, что endpoint ai_health_check существует"""
        assert callable(ai_health_check)
    
    def test_system_health_check_endpoint_exists(self):
        """Проверяем, что endpoint system_health_check существует"""
        assert callable(system_health_check)


class TestHealthCheckResponse:
    """Тесты для HealthCheckResponse модели"""
    
    def test_health_check_response_creation(self):
        """Проверяем создание HealthCheckResponse"""
        response = HealthCheckResponse(
            status="healthy",
            timestamp="2025-01-11T10:00:00Z",
            version="1.0.0",
            uptime=3600,
            services={
                "database": "healthy",
                "redis": "healthy",
                "ai": "healthy"
            }
        )
        
        assert response.status == "healthy"
        assert response.timestamp == "2025-01-11T10:00:00Z"
        assert response.version == "1.0.0"
        assert response.uptime == 3600
        assert response.services["database"] == "healthy"
        assert response.services["redis"] == "healthy"
        assert response.services["ai"] == "healthy"
    
    def test_health_check_response_unhealthy(self):
        """Проверяем создание HealthCheckResponse для нездоровой системы"""
        response = HealthCheckResponse(
            status="unhealthy",
            timestamp="2025-01-11T10:00:00Z",
            version="1.0.0",
            uptime=3600,
            services={
                "database": "unhealthy",
                "redis": "healthy",
                "ai": "healthy"
            }
        )
        
        assert response.status == "unhealthy"
        assert response.services["database"] == "unhealthy"


class TestBasicHealthCheck:
    """Тесты для basic_health_check"""
    
    @pytest.mark.asyncio
    async def test_basic_health_check_success(self):
        """Тест успешной базовой проверки здоровья"""
        response = await basic_health_check()
        
        assert response["status"] == "healthy"
        assert "timestamp" in response
        assert "version" in response
        assert "uptime" in response
    
    @pytest.mark.asyncio
    async def test_basic_health_check_structure(self):
        """Тест структуры ответа базовой проверки"""
        response = await basic_health_check()
        
        # Проверяем обязательные поля
        required_fields = ["status", "timestamp", "version", "uptime"]
        for field in required_fields:
            assert field in response
        
        # Проверяем типы данных
        assert isinstance(response["status"], str)
        assert isinstance(response["timestamp"], str)
        assert isinstance(response["version"], str)
        assert isinstance(response["uptime"], (int, float))


class TestDetailedHealthCheck:
    """Тесты для detailed_health_check"""
    
    @pytest.mark.asyncio
    async def test_detailed_health_check_success(self):
        """Тест успешной детальной проверки здоровья"""
        response = await detailed_health_check()
        
        assert response["status"] in ["healthy", "unhealthy", "degraded"]
        assert "timestamp" in response
        assert "version" in response
        assert "uptime" in response
        assert "services" in response
    
    @pytest.mark.asyncio
    async def test_detailed_health_check_services(self):
        """Тест проверки сервисов в детальной проверке"""
        response = await detailed_health_check()
        
        services = response["services"]
        assert isinstance(services, dict)
        
        # Проверяем основные сервисы
        expected_services = ["database", "redis", "ai", "storage"]
        for service in expected_services:
            if service in services:
                assert services[service] in ["healthy", "unhealthy", "degraded", "unknown"]
    
    @pytest.mark.asyncio
    async def test_detailed_health_check_metrics(self):
        """Тест метрик в детальной проверке"""
        response = await detailed_health_check()
        
        # Проверяем наличие метрик
        if "metrics" in response:
            metrics = response["metrics"]
            assert isinstance(metrics, dict)
            
            # Проверяем основные метрики
            if "cpu_usage" in metrics:
                assert isinstance(metrics["cpu_usage"], (int, float))
                assert 0 <= metrics["cpu_usage"] <= 100
            
            if "memory_usage" in metrics:
                assert isinstance(metrics["memory_usage"], (int, float))
                assert 0 <= metrics["memory_usage"] <= 100
            
            if "disk_usage" in metrics:
                assert isinstance(metrics["disk_usage"], (int, float))
                assert 0 <= metrics["disk_usage"] <= 100


class TestDatabaseHealthCheck:
    """Тесты для database_health_check"""
    
    @pytest.mark.asyncio
    async def test_database_health_check_success(self):
        """Тест успешной проверки базы данных"""
        with patch('backend.services.connection_manager.connection_manager') as mock_manager:
            mock_manager.health_check_all.return_value = {
                "database": {"status": "healthy", "response_time": 0.1}
            }
            
            response = await database_health_check()
            
            assert response["status"] == "healthy"
            assert "database" in response
            assert response["database"]["status"] == "healthy"
            assert "response_time" in response["database"]
    
    @pytest.mark.asyncio
    async def test_database_health_check_failure(self):
        """Тест проверки базы данных при ошибке"""
        with patch('backend.services.connection_manager.connection_manager') as mock_manager:
            mock_manager.health_check_all.side_effect = DatabaseError("Connection failed")
            
            response = await database_health_check()
            
            assert response["status"] == "unhealthy"
            assert "error" in response
            assert "Connection failed" in response["error"]
    
    @pytest.mark.asyncio
    async def test_database_health_check_timeout(self):
        """Тест проверки базы данных при таймауте"""
        with patch('backend.services.connection_manager.connection_manager') as mock_manager:
            mock_manager.health_check_all.side_effect = asyncio.TimeoutError("Request timeout")
            
            response = await database_health_check()
            
            assert response["status"] == "unhealthy"
            assert "error" in response
            assert "timeout" in response["error"].lower()


class TestAIHealthCheck:
    """Тесты для ai_health_check"""
    
    @pytest.mark.asyncio
    async def test_ai_health_check_success(self):
        """Тест успешной проверки AI сервисов"""
        with patch('backend.services.ai_service.get_ai_service') as mock_get_service:
            mock_service = MagicMock()
            mock_service.health_check.return_value = {
                "openai": {"status": "healthy", "response_time": 0.2},
                "anthropic": {"status": "healthy", "response_time": 0.3}
            }
            mock_get_service.return_value = mock_service
            
            response = await ai_health_check()
            
            assert response["status"] == "healthy"
            assert "ai_providers" in response
            assert "openai" in response["ai_providers"]
            assert "anthropic" in response["ai_providers"]
    
    @pytest.mark.asyncio
    async def test_ai_health_check_partial_failure(self):
        """Тест проверки AI сервисов при частичном сбое"""
        with patch('backend.services.ai_service.get_ai_service') as mock_get_service:
            mock_service = MagicMock()
            mock_service.health_check.return_value = {
                "openai": {"status": "healthy", "response_time": 0.2},
                "anthropic": {"status": "unhealthy", "error": "API key invalid"}
            }
            mock_get_service.return_value = mock_service
            
            response = await ai_health_check()
            
            assert response["status"] == "degraded"
            assert "ai_providers" in response
            assert response["ai_providers"]["openai"]["status"] == "healthy"
            assert response["ai_providers"]["anthropic"]["status"] == "unhealthy"
    
    @pytest.mark.asyncio
    async def test_ai_health_check_all_fail(self):
        """Тест проверки AI сервисов при полном сбое"""
        with patch('backend.services.ai_service.get_ai_service') as mock_get_service:
            mock_service = MagicMock()
            mock_service.health_check.side_effect = NetworkError("All AI services down")
            mock_get_service.return_value = mock_service
            
            response = await ai_health_check()
            
            assert response["status"] == "unhealthy"
            assert "error" in response
            assert "All AI services down" in response["error"]


class TestSystemHealthCheck:
    """Тесты для system_health_check"""
    
    @pytest.mark.asyncio
    async def test_system_health_check_success(self):
        """Тест успешной проверки системы"""
        with patch('psutil.cpu_percent') as mock_cpu, \
             patch('psutil.virtual_memory') as mock_memory, \
             patch('psutil.disk_usage') as mock_disk:
            
            mock_cpu.return_value = 25.5
            mock_memory.return_value = MagicMock(percent=60.0)
            mock_disk.return_value = MagicMock(percent=45.0)
            
            response = await system_health_check()
            
            assert response["status"] == "healthy"
            assert "system" in response
            assert "cpu_usage" in response["system"]
            assert "memory_usage" in response["system"]
            assert "disk_usage" in response["system"]
            assert response["system"]["cpu_usage"] == 25.5
            assert response["system"]["memory_usage"] == 60.0
            assert response["system"]["disk_usage"] == 45.0
    
    @pytest.mark.asyncio
    async def test_system_health_check_high_usage(self):
        """Тест проверки системы при высокой нагрузке"""
        with patch('psutil.cpu_percent') as mock_cpu, \
             patch('psutil.virtual_memory') as mock_memory, \
             patch('psutil.disk_usage') as mock_disk:
            
            mock_cpu.return_value = 95.0
            mock_memory.return_value = MagicMock(percent=90.0)
            mock_disk.return_value = MagicMock(percent=85.0)
            
            response = await system_health_check()
            
            assert response["status"] == "degraded"
            assert response["system"]["cpu_usage"] == 95.0
            assert response["system"]["memory_usage"] == 90.0
            assert response["system"]["disk_usage"] == 85.0
    
    @pytest.mark.asyncio
    async def test_system_health_check_critical_usage(self):
        """Тест проверки системы при критической нагрузке"""
        with patch('psutil.cpu_percent') as mock_cpu, \
             patch('psutil.virtual_memory') as mock_memory, \
             patch('psutil.disk_usage') as mock_disk:
            
            mock_cpu.return_value = 100.0
            mock_memory.return_value = MagicMock(percent=100.0)
            mock_disk.return_value = MagicMock(percent=100.0)
            
            response = await system_health_check()
            
            assert response["status"] == "unhealthy"
            assert response["system"]["cpu_usage"] == 100.0
            assert response["system"]["memory_usage"] == 100.0
            assert response["system"]["disk_usage"] == 100.0
    
    @pytest.mark.asyncio
    async def test_system_health_check_error(self):
        """Тест проверки системы при ошибке"""
        with patch('psutil.cpu_percent') as mock_cpu:
            mock_cpu.side_effect = Exception("System error")
            
            response = await system_health_check()
            
            assert response["status"] == "unhealthy"
            assert "error" in response
            assert "System error" in response["error"]


class TestHealthCheckIntegration:
    """Интеграционные тесты для проверки здоровья"""
    
    @pytest.mark.asyncio
    async def test_health_check_full_system_healthy(self):
        """Тест полной проверки здоровой системы"""
        with patch('backend.services.connection_manager.connection_manager') as mock_db_manager, \
             patch('backend.services.ai_service.get_ai_service') as mock_ai_service, \
             patch('psutil.cpu_percent') as mock_cpu, \
             patch('psutil.virtual_memory') as mock_memory, \
             patch('psutil.disk_usage') as mock_disk:
            
            # Настраиваем моки для здоровой системы
            mock_db_manager.health_check_all.return_value = {
                "database": {"status": "healthy", "response_time": 0.1},
                "redis": {"status": "healthy", "response_time": 0.05}
            }
            
            mock_ai_service_instance = MagicMock()
            mock_ai_service_instance.health_check.return_value = {
                "openai": {"status": "healthy", "response_time": 0.2}
            }
            mock_ai_service.return_value = mock_ai_service_instance
            
            mock_cpu.return_value = 30.0
            mock_memory.return_value = MagicMock(percent=50.0)
            mock_disk.return_value = MagicMock(percent=40.0)
            
            # Выполняем детальную проверку
            response = await detailed_health_check()
            
            assert response["status"] == "healthy"
            assert "services" in response
            assert "metrics" in response
            
            # Проверяем сервисы
            services = response["services"]
            assert services["database"] == "healthy"
            assert services["redis"] == "healthy"
            assert services["ai"] == "healthy"
            
            # Проверяем метрики
            metrics = response["metrics"]
            assert metrics["cpu_usage"] == 30.0
            assert metrics["memory_usage"] == 50.0
            assert metrics["disk_usage"] == 40.0
    
    @pytest.mark.asyncio
    async def test_health_check_full_system_unhealthy(self):
        """Тест полной проверки нездоровой системы"""
        with patch('backend.services.connection_manager.connection_manager') as mock_db_manager, \
             patch('backend.services.ai_service.get_ai_service') as mock_ai_service, \
             patch('psutil.cpu_percent') as mock_cpu, \
             patch('psutil.virtual_memory') as mock_memory, \
             patch('psutil.disk_usage') as mock_disk:
            
            # Настраиваем моки для нездоровой системы
            mock_db_manager.health_check_all.side_effect = DatabaseError("Database down")
            
            mock_ai_service_instance = MagicMock()
            mock_ai_service_instance.health_check.side_effect = NetworkError("AI services down")
            mock_ai_service.return_value = mock_ai_service_instance
            
            mock_cpu.return_value = 100.0
            mock_memory.return_value = MagicMock(percent=100.0)
            mock_disk.return_value = MagicMock(percent=100.0)
            
            # Выполняем детальную проверку
            response = await detailed_health_check()
            
            assert response["status"] == "unhealthy"
            assert "services" in response
            assert "metrics" in response
            
            # Проверяем сервисы
            services = response["services"]
            assert services["database"] == "unhealthy"
            assert services["ai"] == "unhealthy"
            
            # Проверяем метрики
            metrics = response["metrics"]
            assert metrics["cpu_usage"] == 100.0
            assert metrics["memory_usage"] == 100.0
            assert metrics["disk_usage"] == 100.0


class TestHealthCheckErrorHandling:
    """Тесты для обработки ошибок в проверке здоровья"""
    
    @pytest.mark.asyncio
    async def test_health_check_network_error(self):
        """Тест обработки NetworkError"""
        with patch('backend.services.connection_manager.connection_manager') as mock_manager:
            mock_manager.health_check_all.side_effect = NetworkError("Network unreachable")
            
            response = await database_health_check()
            
            assert response["status"] == "unhealthy"
            assert "error" in response
            assert "Network unreachable" in response["error"]
    
    @pytest.mark.asyncio
    async def test_health_check_timeout_error(self):
        """Тест обработки TimeoutError"""
        with patch('backend.services.connection_manager.connection_manager') as mock_manager:
            mock_manager.health_check_all.side_effect = asyncio.TimeoutError("Request timeout")
            
            response = await database_health_check()
            
            assert response["status"] == "unhealthy"
            assert "error" in response
            assert "timeout" in response["error"].lower()
    
    @pytest.mark.asyncio
    async def test_health_check_generic_error(self):
        """Тест обработки общих ошибок"""
        with patch('backend.services.connection_manager.connection_manager') as mock_manager:
            mock_manager.health_check_all.side_effect = Exception("Unexpected error")
            
            response = await database_health_check()
            
            assert response["status"] == "unhealthy"
            assert "error" in response
            assert "Unexpected error" in response["error"]


class TestHealthCheckPerformance:
    """Тесты производительности для проверки здоровья"""
    
    @pytest.mark.asyncio
    async def test_health_check_response_time(self):
        """Тест времени ответа проверки здоровья"""
        import time
        
        start_time = time.time()
        response = await basic_health_check()
        end_time = time.time()
        
        response_time = end_time - start_time
        
        # Проверка должна выполняться быстро (менее 1 секунды)
        assert response_time < 1.0
        assert response["status"] == "healthy"
    
    @pytest.mark.asyncio
    async def test_health_check_concurrent_requests(self):
        """Тест одновременных запросов проверки здоровья"""
        # Создаем несколько одновременных запросов
        tasks = [basic_health_check() for _ in range(5)]
        responses = await asyncio.gather(*tasks)
        
        # Все запросы должны быть успешными
        for response in responses:
            assert response["status"] == "healthy"
            assert "timestamp" in response
            assert "version" in response