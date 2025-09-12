"""
Системные метрики
"""

import asyncio
import logging
import psutil
import os
from datetime import datetime, timedelta
from typing import Dict, Any, List
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

@dataclass
class SystemMetrics:
    """Метрики системы"""
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    memory_used_mb: float = 0.0
    memory_available_mb: float = 0.0
    disk_usage_percent: float = 0.0
    disk_free_gb: float = 0.0
    load_average: List[float] = field(default_factory=list)
    uptime_seconds: float = 0.0
    process_count: int = 0
    network_connections: int = 0

class SystemMetricsCollector:
    """Сборщик системных метрик"""
    
    def __init__(self):
        self._last_collection = None
        self._boot_time = psutil.boot_time()
    
    async def collect_metrics(self) -> SystemMetrics:
        """Собрать системные метрики"""
        try:
            # CPU
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Memory
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            memory_used_mb = memory.used / (1024 * 1024)
            memory_available_mb = memory.available / (1024 * 1024)
            
            # Disk
            disk = psutil.disk_usage('/')
            disk_usage_percent = (disk.used / disk.total) * 100
            disk_free_gb = disk.free / (1024 * 1024 * 1024)
            
            # Load average
            load_average = list(psutil.getloadavg()) if hasattr(psutil, 'getloadavg') else []
            
            # Uptime
            uptime_seconds = time.time() - self._boot_time
            
            # Process count
            process_count = len(psutil.pids())
            
            # Network connections
            network_connections = len(psutil.net_connections())
            
            metrics = SystemMetrics(
                cpu_percent=cpu_percent,
                memory_percent=memory_percent,
                memory_used_mb=memory_used_mb,
                memory_available_mb=memory_available_mb,
                disk_usage_percent=disk_usage_percent,
                disk_free_gb=disk_free_gb,
                load_average=load_average,
                uptime_seconds=uptime_seconds,
                process_count=process_count,
                network_connections=network_connections
            )
            
            self._last_collection = datetime.now()
            return metrics
            
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")
            return SystemMetrics()
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Получить сводку метрик"""
        if not self._last_collection:
            return {"error": "No metrics collected yet"}
        
        return {
            "last_collection": self._last_collection.isoformat(),
            "boot_time": datetime.fromtimestamp(self._boot_time).isoformat(),
            "uptime_hours": (time.time() - self._boot_time) / 3600
        }