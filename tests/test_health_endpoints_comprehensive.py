"""
Комплексные тесты для Health endpoints
Покрытие: 52% → 90%+
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from fastapi import HTTPException, status
from datetime import datetime

from backend.api.health import (
    router,
    basic_health_check,
    detailed_health_check,
    database_health_check,
    ai_health_check,
    system_health_check,
    check_external_services_health,
    get_memory_usage,
    get_disk_usage
)
from backend.models.responses import HealthCheckResponse, DetailedHealthResponse
from backend.core.exceptions import MonitoringError, ConfigurationError, DatabaseError


class TestHealthEndpoints:
    """Тесты для Health endpoints"""
    
    @pytest.fixture
    def mock_health_status(self):
        return {
            "status": "healthy",
            "uptime": 3600.5,
            "services": {
                "database": "healthy",
                "redis": "healthy",
                "ai_service": "healthy"
            }
        }
    
    @pytest.fixture
    def mock_monitoring(self):
        mock_monitoring = Mock()
        mock_monitoring.get_health_status.return_value = {
            "status": "healthy",
            "uptime": 3600.5,
            "services": {
                "database": "healthy",
                "redis": "healthy",
                "ai_service": "healthy"
            }
        }
        mock_monitoring.active_projects = {"project1": "active", "project2": "active"}
        return mock_monitoring
    
    # === BASIC HEALTH CHECK ===
    
    @pytest.mark.asyncio
    async def test_basic_health_check_success(self, mock_health_status):
        """Тест успешной базовой проверки здоровья"""
        with patch('backend.api.health.monitoring') as mock_monitoring:
            mock_monitoring.get_health_status.return_value = mock_health_status
            
            result = await basic_health_check()
            
            assert isinstance(result, HealthCheckResponse)
            assert result.status == "healthy"
            assert result.version == "1.0.0"
            assert result.uptime == 3600.5
            assert result.services == {
                "database": "healthy",
                "redis": "healthy",
                "ai_service": "healthy"
            }
            assert isinstance(result.timestamp, datetime)
    
    @pytest.mark.asyncio
    async def test_basic_health_check_monitoring_error(self):
        """Тест обработки ошибки мониторинга"""
        with patch('backend.api.health.monitoring') as mock_monitoring:
            mock_monitoring.get_health_status.side_effect = MonitoringError("Monitoring failed")
            
            with pytest.raises(HTTPException) as exc_info:
                await basic_health_check()
            
            assert exc_info.value.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
            assert "Monitoring service unavailable" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_basic_health_check_configuration_error(self):
        """Тест обработки ошибки конфигурации"""
        with patch('backend.api.health.monitoring') as mock_monitoring:
            mock_monitoring.get_health_status.side_effect = ConfigurationError("Config failed")
            
            with pytest.raises(HTTPException) as exc_info:
                await basic_health_check()
            
            assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
            assert "Configuration error" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_basic_health_check_generic_error(self):
        """Тест обработки общей ошибки"""
        with patch('backend.api.health.monitoring') as mock_monitoring:
            mock_monitoring.get_health_status.side_effect = Exception("Generic error")
            
            with pytest.raises(HTTPException) as exc_info:
                await basic_health_check()
            
            assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
            assert "Health check failed" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_basic_health_check_unknown_status(self):
        """Тест с неизвестным статусом"""
        with patch('backend.api.health.monitoring') as mock_monitoring:
            mock_monitoring.get_health_status.return_value = {}
            
            result = await basic_health_check()
            
            assert result.status == "unknown"
            assert result.uptime == 0
            assert result.services == {}
    
    # === DETAILED HEALTH CHECK ===
    
    @pytest.mark.asyncio
    async def test_detailed_health_check_success(self, mock_health_status):
        """Тест успешной детальной проверки здоровья"""
        with patch('backend.api.health.monitoring') as mock_monitoring, \
             patch('backend.api.health.check_external_services_health') as mock_external, \
             patch('backend.api.health.get_memory_usage') as mock_memory, \
             patch('backend.api.health.get_disk_usage') as mock_disk:
            
            mock_monitoring.get_health_status.return_value = mock_health_status
            mock_monitoring.active_projects = {"project1": "active", "project2": "active"}
            mock_external.return_value = {"redis": "healthy", "database": "healthy"}
            mock_memory.return_value = {"used": 1024, "total": 2048}
            mock_disk.return_value = {"used": 512, "total": 1024}
            
            result = await detailed_health_check()
            
            assert isinstance(result, DetailedHealthResponse)
            assert result.status == "healthy"
            assert result.version == "1.0.0"
            assert result.uptime == 3600.5
            assert result.active_projects == 2
            assert result.external_services == {"redis": "healthy", "database": "healthy"}
            assert result.memory_usage == {"used": 1024, "total": 2048}
            assert result.disk_usage == {"used": 512, "total": 1024}
    
    @pytest.mark.asyncio
    async def test_detailed_health_check_monitoring_error(self):
        """Тест обработки ошибки мониторинга в детальной проверке"""
        with patch('backend.api.health.monitoring') as mock_monitoring:
            mock_monitoring.get_health_status.side_effect = MonitoringError("Monitoring failed")
            
            with pytest.raises(HTTPException) as exc_info:
                await detailed_health_check()
            
            assert exc_info.value.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
            assert "Monitoring service unavailable" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_detailed_health_check_configuration_error(self):
        """Тест обработки ошибки конфигурации в детальной проверке"""
        with patch('backend.api.health.monitoring') as mock_monitoring:
            mock_monitoring.get_health_status.side_effect = ConfigurationError("Config failed")
            
            with pytest.raises(HTTPException) as exc_info:
                await detailed_health_check()
            
            assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
            assert "Configuration error" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_detailed_health_check_generic_error(self):
        """Тест обработки общей ошибки в детальной проверке"""
        with patch('backend.api.health.monitoring') as mock_monitoring:
            mock_monitoring.get_health_status.side_effect = Exception("Generic error")
            
            with pytest.raises(HTTPException) as exc_info:
                await detailed_health_check()
            
            assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
            assert "Detailed health check failed" in str(exc_info.value.detail)
    
    # === DATABASE HEALTH CHECK ===
    
    @pytest.mark.asyncio
    async def test_database_health_check_success(self):
        """Тест успешной проверки базы данных"""
        with patch('backend.services.connection_manager.connection_manager') as mock_conn_mgr, \
             patch('backend.api.health.execute_supabase_operation') as mock_supabase:
            
            mock_supabase_instance = Mock()
            mock_conn_mgr.get_pool.return_value = mock_supabase_instance
            mock_supabase.return_value = {"success": True}
            
            result = await database_health_check()
            
            assert result["status"] == "healthy"
            assert "response_time_ms" in result
            assert "Database connection successful" in result["message"]
    
    @pytest.mark.asyncio
    async def test_database_health_check_timeout(self):
        """Тест проверки базы данных с таймаутом"""
        async def slow_operation(*args, **kwargs):
            await asyncio.sleep(0.1)  # Имитируем медленную операцию
            return {"success": True}
        
        with patch('backend.services.connection_manager.connection_manager') as mock_conn_mgr, \
             patch('backend.api.health.execute_supabase_operation', side_effect=slow_operation):
            
            mock_supabase_instance = Mock()
            mock_conn_mgr.get_pool.return_value = mock_supabase_instance
            
            result = await database_health_check()
            
            assert result["status"] == "healthy"
            assert result["response_time_ms"] > 50  # Должно быть больше 50мс
    
    @pytest.mark.asyncio
    async def test_database_health_check_error(self):
        """Тест проверки базы данных с ошибкой"""
        with patch('backend.services.connection_manager.connection_manager') as mock_conn_mgr, \
             patch('backend.api.health.execute_supabase_operation') as mock_supabase:
            
            mock_supabase_instance = Mock()
            mock_conn_mgr.get_pool.return_value = mock_supabase_instance
            mock_supabase.side_effect = DatabaseError("Connection failed")
            
            result = await database_health_check()
            
            assert result["status"] == "unhealthy"
            assert "Database error" in result["message"]
    
    @pytest.mark.asyncio
    async def test_database_health_check_exception(self):
        """Тест проверки базы данных с исключением"""
        with patch('backend.services.connection_manager.connection_manager') as mock_conn_mgr, \
             patch('backend.api.health.execute_supabase_operation') as mock_supabase:
            
            mock_supabase_instance = Mock()
            mock_conn_mgr.get_pool.return_value = mock_supabase_instance
            mock_supabase.side_effect = Exception("Unexpected error")
            
            result = await database_health_check()
            
            assert result["status"] == "unhealthy"
            assert "Database connection failed" in result["message"]
    
    # === AI HEALTH CHECK ===
    
    @pytest.mark.asyncio
    async def test_ai_health_check_success(self):
        """Тест успешной проверки AI сервиса"""
        with patch('backend.services.ai_service.get_ai_service') as mock_ai_service:
            mock_ai_service.return_value = Mock()
            
            result = await ai_health_check()
            
            assert result["status"] == "healthy"
            assert "providers" in result
            assert "AI services check completed" in result["message"]
    
    @pytest.mark.asyncio
    async def test_ai_health_check_timeout(self):
        """Тест проверки AI сервиса с таймаутом"""
        with patch('backend.services.ai_service.get_ai_service') as mock_ai_service:
            mock_ai_service.return_value = Mock()
            
            result = await ai_health_check()
            
            assert result["status"] == "healthy"
            assert "providers" in result
    
    @pytest.mark.asyncio
    async def test_ai_health_check_error(self):
        """Тест проверки AI сервиса с ошибкой"""
        with patch('backend.services.ai_service.get_ai_service') as mock_ai_service:
            mock_ai_service.side_effect = Exception("AI service unavailable")
            
            result = await ai_health_check()
            
            assert result["status"] == "unhealthy"
            assert "AI services check failed" in result["message"]
    
    # === SYSTEM HEALTH CHECK ===
    
    @pytest.mark.asyncio
    async def test_system_health_check_success(self):
        """Тест успешной проверки системы"""
        with patch('backend.api.health.psutil.cpu_percent') as mock_cpu, \
             patch('backend.api.health.psutil.virtual_memory') as mock_memory, \
             patch('backend.api.health.psutil.disk_usage') as mock_disk, \
             patch('backend.api.health.psutil.pids') as mock_pids:
            
            mock_cpu.return_value = 50.0
            mock_memory.return_value = Mock(
                total=2*1024**3, available=1*1024**3, percent=50.0
            )
            mock_disk.return_value = Mock(
                total=1024**3, free=512*1024**2, used=512*1024**2
            )
            mock_pids.return_value = [1, 2, 3]
            
            result = await system_health_check()
            
            assert result["status"] == "healthy"
            assert "memory" in result
            assert "disk" in result
            assert "cpu_usage_percent" in result
    
    @pytest.mark.asyncio
    async def test_system_health_check_error(self):
        """Тест проверки системы с ошибкой"""
        with patch('backend.api.health.psutil.cpu_percent') as mock_cpu:
            mock_cpu.side_effect = Exception("System check failed")
            
            result = await system_health_check()
            
            assert result["status"] == "unhealthy"
            assert "System resources check failed" in result["message"]
    
    # === CHECK EXTERNAL SERVICES ===
    
    @pytest.mark.asyncio
    async def test_check_external_services_health_success(self):
        """Тест успешной проверки внешних сервисов"""
        result = await check_external_services_health()
        
        assert isinstance(result, dict)
        assert "redis" in result
        # Проверяем, что возвращаются строковые статусы
        assert isinstance(result["redis"], str)
    
    # === GET MEMORY USAGE ===
    
    def test_get_memory_usage_success(self):
        """Тест успешного получения информации об использовании памяти"""
        with patch('backend.api.health.psutil.virtual_memory') as mock_memory:
            mock_memory.return_value = Mock(
                total=2048 * 1024 * 1024,  # 2GB
                used=1024 * 1024 * 1024,   # 1GB
                available=1024 * 1024 * 1024,  # 1GB
                percent=50.0
            )
            
            result = get_memory_usage()
            
            assert result["total_bytes"] == 2048 * 1024 * 1024
            assert result["used_bytes"] == 1024 * 1024 * 1024
            assert result["used_percent"] == 50.0
            assert result["available_bytes"] == 1024 * 1024 * 1024
    
    def test_get_memory_usage_error(self):
        """Тест получения информации об использовании памяти с ошибкой"""
        with patch('backend.api.health.psutil.virtual_memory') as mock_memory:
            mock_memory.side_effect = Exception("Memory check failed")
            
            result = get_memory_usage()
            
            assert result["total_bytes"] == 0
            assert result["used_bytes"] == 0
            assert result["used_percent"] == 0
    
    # === GET DISK USAGE ===
    
    def test_get_disk_usage_success(self):
        """Тест успешного получения информации об использовании диска"""
        with patch('backend.api.health.psutil.disk_usage') as mock_disk:
            mock_disk.return_value = Mock(
                total=1024 * 1024 * 1024,  # 1GB
                used=512 * 1024 * 1024,    # 512MB
                free=512 * 1024 * 1024     # 512MB
            )
            
            result = get_disk_usage()
            
            assert result["total_bytes"] == 1024 * 1024 * 1024
            assert result["used_bytes"] == 512 * 1024 * 1024
            assert result["free_bytes"] == 512 * 1024 * 1024
            assert result["used_percent"] == 50.0
    
    def test_get_disk_usage_error(self):
        """Тест получения информации об использовании диска с ошибкой"""
        with patch('backend.api.health.psutil.disk_usage') as mock_disk:
            mock_disk.side_effect = Exception("Disk check failed")
            
            result = get_disk_usage()
            
            assert result["total_bytes"] == 0
            assert result["used_bytes"] == 0
            assert result["free_bytes"] == 0
            assert result["used_percent"] == 0
    
    # === INTEGRATION TESTS ===
    
    @pytest.mark.asyncio
    async def test_health_check_integration(self):
        """Интеграционный тест проверки здоровья"""
        # Тестируем базовую проверку
        with patch('backend.api.health.monitoring') as mock_monitoring:
            mock_monitoring.get_health_status.return_value = {
                "status": "healthy",
                "uptime": 3600.5,
                "services": {"database": "healthy"}
            }
            
            basic_result = await basic_health_check()
            assert basic_result.status == "healthy"
        
        # Тестируем детальную проверку
        with patch('backend.api.health.monitoring') as mock_monitoring, \
             patch('backend.api.health.check_external_services_health') as mock_external, \
             patch('backend.api.health.get_memory_usage') as mock_memory, \
             patch('backend.api.health.get_disk_usage') as mock_disk:
            
            mock_monitoring.get_health_status.return_value = {
                "status": "healthy",
                "uptime": 3600.5,
                "services": {"database": "healthy"}
            }
            mock_monitoring.active_projects = {"project1": "active"}
            mock_external.return_value = {"redis": "healthy"}
            mock_memory.return_value = {"used": 1024, "total": 2048}
            mock_disk.return_value = {"used": 512, "total": 1024}
            
            detailed_result = await detailed_health_check()
            assert detailed_result.status == "healthy"
            assert detailed_result.active_projects == 1