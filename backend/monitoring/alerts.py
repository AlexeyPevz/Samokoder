"""
Система алертов и уведомлений
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass
from collections import defaultdict

logger = logging.getLogger(__name__)

@dataclass
class AlertRule:
    """Правило для алертов"""
    name: str
    condition: Callable[[Dict[str, Any]], bool]
    severity: str  # critical, warning, info
    message: str
    cooldown: int = 300  # секунды

@dataclass
class Alert:
    """Алерт"""
    rule_name: str
    severity: str
    message: str
    timestamp: datetime
    resolved: bool = False
    resolved_at: Optional[datetime] = None

class AlertManager:
    """Менеджер алертов"""
    
    def __init__(self):
        self.rules: Dict[str, AlertRule] = {}
        self.active_alerts: Dict[str, Alert] = {}
        self.alert_history: List[Alert] = []
        self.last_alert_time: Dict[str, datetime] = {}
        self._setup_default_rules()
    
    def _setup_default_rules(self):
        """Настройка правил по умолчанию"""
        self.add_rule(AlertRule(
            name="high_cpu_usage",
            condition=lambda metrics: metrics.get('cpu_usage_percent', 0) > 80,
            severity="warning",
            message="High CPU usage detected: {cpu_usage_percent}%",
            cooldown=300
        ))
        
        self.add_rule(AlertRule(
            name="high_memory_usage",
            condition=lambda metrics: metrics.get('memory_usage_percent', 0) > 85,
            severity="critical",
            message="High memory usage detected: {memory_usage_percent}%",
            cooldown=180
        ))
        
        self.add_rule(AlertRule(
            name="high_error_rate",
            condition=lambda metrics: metrics.get('error_rate', 0) > 5,
            severity="critical",
            message="High error rate detected: {error_rate}%",
            cooldown=60
        ))
        
        self.add_rule(AlertRule(
            name="low_disk_space",
            condition=lambda metrics: metrics.get('disk_usage_percent', 0) > 90,
            severity="warning",
            message="Low disk space: {disk_usage_percent}% used",
            cooldown=600
        ))
    
    def add_rule(self, rule: AlertRule):
        """Добавить правило алерта"""
        self.rules[rule.name] = rule
        logger.info(f"Added alert rule: {rule.name}")
    
    def remove_rule(self, rule_name: str):
        """Удалить правило алерта"""
        if rule_name in self.rules:
            del self.rules[rule_name]
            logger.info(f"Removed alert rule: {rule_name}")
    
    async def check_alerts(self, metrics: Dict[str, Any]):
        """Проверить алерты на основе метрик"""
        current_time = datetime.now()
        
        for rule_name, rule in self.rules.items():
            try:
                # Проверяем cooldown
                if rule_name in self.last_alert_time:
                    time_since_last = (current_time - self.last_alert_time[rule_name]).total_seconds()
                    if time_since_last < rule.cooldown:
                        continue
                
                # Проверяем условие
                if rule.condition(metrics):
                    await self._trigger_alert(rule, metrics, current_time)
                else:
                    # Если условие не выполняется, разрешаем алерт
                    await self._resolve_alert(rule_name, current_time)
                    
            except Exception as e:
                logger.error(f"Error checking alert rule {rule_name}: {e}")
    
    async def _trigger_alert(self, rule: AlertRule, metrics: Dict[str, Any], timestamp: datetime):
        """Срабатывание алерта"""
        # Форматируем сообщение
        message = rule.message.format(**metrics)
        
        alert = Alert(
            rule_name=rule.name,
            severity=rule.severity,
            message=message,
            timestamp=timestamp
        )
        
        # Добавляем в активные алерты
        self.active_alerts[rule.name] = alert
        self.alert_history.append(alert)
        self.last_alert_time[rule.name] = timestamp
        
        # Логируем алерт
        log_level = logging.CRITICAL if rule.severity == "critical" else logging.WARNING
        logger.log(log_level, f"ALERT [{rule.severity.upper()}] {rule.name}: {message}")
        
        # Отправляем уведомление (здесь можно добавить интеграции)
        await self._send_notification(alert)
    
    async def _resolve_alert(self, rule_name: str, timestamp: datetime):
        """Разрешение алерта"""
        if rule_name in self.active_alerts:
            alert = self.active_alerts[rule_name]
            alert.resolved = True
            alert.resolved_at = timestamp
            
            logger.info(f"Alert resolved: {rule_name}")
            del self.active_alerts[rule_name]
    
    async def _send_notification(self, alert: Alert):
        """Отправка уведомления (заглушка)"""
        # Здесь можно добавить интеграции с Slack, Email, PagerDuty и т.д.
        logger.info(f"Notification sent for alert: {alert.rule_name}")
    
    def get_active_alerts(self) -> List[Alert]:
        """Получить активные алерты"""
        return list(self.active_alerts.values())
    
    def get_alert_history(self, limit: int = 100) -> List[Alert]:
        """Получить историю алертов"""
        return self.alert_history[-limit:]
    
    def get_alerts_by_severity(self, severity: str) -> List[Alert]:
        """Получить алерты по уровню критичности"""
        return [alert for alert in self.alert_history if alert.severity == severity]
    
    def clear_resolved_alerts(self, older_than_hours: int = 24):
        """Очистить разрешенные алерты старше указанного времени"""
        cutoff_time = datetime.now() - timedelta(hours=older_than_hours)
        self.alert_history = [
            alert for alert in self.alert_history 
            if not alert.resolved or alert.resolved_at > cutoff_time
        ]
        logger.info(f"Cleared resolved alerts older than {older_than_hours} hours")