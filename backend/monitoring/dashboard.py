"""
Дашборд и визуализация метрик
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import json

logger = logging.getLogger(__name__)

@dataclass
class DashboardWidget:
    """Виджет дашборда"""
    id: str
    title: str
    widget_type: str  # chart, gauge, table, alert
    data: Dict[str, Any]
    position: Dict[str, int]  # x, y, width, height
    refresh_interval: int = 30  # секунды

@dataclass
class DashboardConfig:
    """Конфигурация дашборда"""
    name: str
    widgets: List[DashboardWidget]
    auto_refresh: bool = True
    refresh_interval: int = 30

class DashboardManager:
    """Менеджер дашбордов"""
    
    def __init__(self):
        self.dashboards: Dict[str, DashboardConfig] = {}
        self._setup_default_dashboards()
    
    def _setup_default_dashboards(self):
        """Настройка дашбордов по умолчанию"""
        # Основной дашборд
        main_dashboard = DashboardConfig(
            name="main",
            widgets=[
                DashboardWidget(
                    id="cpu_usage",
                    title="CPU Usage",
                    widget_type="gauge",
                    data={"metric": "cpu_usage_percent", "max": 100},
                    position={"x": 0, "y": 0, "width": 6, "height": 4}
                ),
                DashboardWidget(
                    id="memory_usage",
                    title="Memory Usage",
                    widget_type="gauge",
                    data={"metric": "memory_usage_percent", "max": 100},
                    position={"x": 6, "y": 0, "width": 6, "height": 4}
                ),
                DashboardWidget(
                    id="request_rate",
                    title="Request Rate",
                    widget_type="chart",
                    data={"metric": "http_requests_total", "type": "line"},
                    position={"x": 0, "y": 4, "width": 12, "height": 4}
                ),
                DashboardWidget(
                    id="error_rate",
                    title="Error Rate",
                    widget_type="chart",
                    data={"metric": "error_rate", "type": "line"},
                    position={"x": 0, "y": 8, "width": 6, "height": 4}
                ),
                DashboardWidget(
                    id="active_alerts",
                    title="Active Alerts",
                    widget_type="alert",
                    data={"severity": "critical"},
                    position={"x": 6, "y": 8, "width": 6, "height": 4}
                )
            ]
        )
        
        self.dashboards["main"] = main_dashboard
        
        # Дашборд производительности
        perf_dashboard = DashboardConfig(
            name="performance",
            widgets=[
                DashboardWidget(
                    id="response_time",
                    title="Response Time",
                    widget_type="chart",
                    data={"metric": "http_request_duration_seconds", "type": "histogram"},
                    position={"x": 0, "y": 0, "width": 12, "height": 6}
                ),
                DashboardWidget(
                    id="throughput",
                    title="Throughput",
                    widget_type="chart",
                    data={"metric": "requests_per_second", "type": "line"},
                    position={"x": 0, "y": 6, "width": 12, "height": 4}
                )
            ]
        )
        
        self.dashboards["performance"] = perf_dashboard
    
    def create_dashboard(self, config: DashboardConfig):
        """Создать дашборд"""
        self.dashboards[config.name] = config
        logger.info(f"Created dashboard: {config.name}")
    
    def get_dashboard(self, name: str) -> Optional[DashboardConfig]:
        """Получить дашборд"""
        return self.dashboards.get(name)
    
    def list_dashboards(self) -> List[str]:
        """Получить список дашбордов"""
        return list(self.dashboards.keys())
    
    async def get_dashboard_data(self, name: str, metrics_data: Dict[str, Any]) -> Dict[str, Any]:
        """Получить данные дашборда"""
        dashboard = self.get_dashboard(name)
        if not dashboard:
            return {}
        
        dashboard_data = {
            "name": dashboard.name,
            "widgets": [],
            "timestamp": datetime.now().isoformat()
        }
        
        for widget in dashboard.widgets:
            widget_data = await self._get_widget_data(widget, metrics_data)
            dashboard_data["widgets"].append({
                "id": widget.id,
                "title": widget.title,
                "type": widget.widget_type,
                "data": widget_data,
                "position": widget.position
            })
        
        return dashboard_data
    
    async def _get_widget_data(self, widget: DashboardWidget, metrics_data: Dict[str, Any]) -> Dict[str, Any]:
        """Получить данные виджета"""
        metric_name = widget.data.get("metric")
        if not metric_name:
            return {"error": "No metric specified"}
        
        metric_value = metrics_data.get(metric_name)
        if metric_value is None:
            return {"error": f"Metric {metric_name} not found"}
        
        if widget.widget_type == "gauge":
            return {
                "value": metric_value,
                "max": widget.data.get("max", 100),
                "unit": widget.data.get("unit", "%")
            }
        elif widget.widget_type == "chart":
            return {
                "data": metric_value,
                "type": widget.data.get("type", "line"),
                "x_axis": "time",
                "y_axis": "value"
            }
        elif widget.widget_type == "alert":
            severity = widget.data.get("severity", "all")
            return {
                "alerts": self._filter_alerts_by_severity(metric_value, severity)
            }
        else:
            return {"value": metric_value}
    
    def _filter_alerts_by_severity(self, alerts_data: Any, severity: str) -> List[Dict[str, Any]]:
        """Фильтровать алерты по критичности"""
        if not isinstance(alerts_data, list):
            return []
        
        if severity == "all":
            return alerts_data
        
        return [alert for alert in alerts_data if alert.get("severity") == severity]
    
    def export_dashboard_config(self, name: str) -> Dict[str, Any]:
        """Экспортировать конфигурацию дашборда"""
        dashboard = self.get_dashboard(name)
        if not dashboard:
            return {}
        
        return asdict(dashboard)
    
    def import_dashboard_config(self, config_data: Dict[str, Any]):
        """Импортировать конфигурацию дашборда"""
        try:
            dashboard = DashboardConfig(**config_data)
            self.dashboards[dashboard.name] = dashboard
            logger.info(f"Imported dashboard: {dashboard.name}")
        except Exception as e:
            logger.error(f"Error importing dashboard config: {e}")
    
    def delete_dashboard(self, name: str):
        """Удалить дашборд"""
        if name in self.dashboards:
            del self.dashboards[name]
            logger.info(f"Deleted dashboard: {name}")
    
    def get_dashboard_summary(self) -> Dict[str, Any]:
        """Получить сводку дашбордов"""
        return {
            "total_dashboards": len(self.dashboards),
            "dashboard_names": list(self.dashboards.keys()),
            "default_dashboards": ["main", "performance"]
        }