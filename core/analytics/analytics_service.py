import asyncio
import json
import time
from typing import Dict, Any, List
from samokoder.core.db.models.user import User
from samokoder.core.db.models.project import Project
from sqlalchemy.orm import Session


class AnalyticsService:
    """Service for collecting and analyzing usage metrics"""
    
    def __init__(self):
        self.metrics = {}
        self.action_logs = []
    
    async def record_user_action(
        self, 
        user_id: int, 
        action: str, 
        details: Dict[str, Any] = None,
        project_id: str = None
    ) -> None:
        """
        Record a user action for analytics
        
        :param user_id: User ID
        :param action: Action name
        :param details: Additional details about the action
        :param project_id: Project ID (optional)
        """
        timestamp = time.time()
        log_entry = {
            "user_id": user_id,
            "action": action,
            "details": details or {},
            "project_id": project_id,
            "timestamp": timestamp
        }
        
        self.action_logs.append(log_entry)
        
        # Update metrics
        await self._update_metrics(user_id, action, project_id)
    
    async def _update_metrics(self, user_id: int, action: str, project_id: str = None) -> None:
        """
        Update usage metrics based on user actions
        
        :param user_id: User ID
        :param action: Action name
        :param project_id: Project ID (optional)
        """
        # Initialize user metrics if not exists
        if user_id not in self.metrics:
            self.metrics[user_id] = {
                "total_actions": 0,
                "actions_by_type": {},
                "projects_created": 0,
                "projects_used": set(),
                "last_active": time.time()
            }
        
        user_metrics = self.metrics[user_id]
        
        # Update total actions
        user_metrics["total_actions"] += 1
        
        # Update actions by type
        if action not in user_metrics["actions_by_type"]:
            user_metrics["actions_by_type"][action] = 0
        user_metrics["actions_by_type"][action] += 1
        
        # Update project-specific metrics
        if action == "project_create" and project_id:
            user_metrics["projects_created"] += 1
            user_metrics["projects_used"].add(project_id)
        elif project_id:
            user_metrics["projects_used"].add(project_id)
        
        # Update last active time
        user_metrics["last_active"] = time.time()
    
    async def get_user_metrics(self, user_id: int) -> Dict[str, Any]:
        """
        Get analytics metrics for a user
        
        :param user_id: User ID
        :return: User metrics
        """
        if user_id not in self.metrics:
            return {
                "total_actions": 0,
                "actions_by_type": {},
                "projects_created": 0,
                "projects_used_count": 0,
                "last_active": None
            }
        
        user_metrics = self.metrics[user_id]
        return {
            "total_actions": user_metrics["total_actions"],
            "actions_by_type": user_metrics["actions_by_type"],
            "projects_created": user_metrics["projects_created"],
            "projects_used_count": len(user_metrics["projects_used"]),
            "last_active": user_metrics["last_active"]
        }
    
    async def get_system_metrics(self) -> Dict[str, Any]:
        """
        Get overall system metrics
        
        :return: System metrics
        """
        total_users = len(self.metrics)
        total_actions = sum(user_metrics["total_actions"] for user_metrics in self.metrics.values())
        total_projects_created = sum(user_metrics["projects_created"] for user_metrics in self.metrics.values())
        
        # Get most common actions
        action_counts = {}
        for user_metrics in self.metrics.values():
            for action, count in user_metrics["actions_by_type"].items():
                if action not in action_counts:
                    action_counts[action] = 0
                action_counts[action] += count
        
        most_common_actions = sorted(action_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return {
            "total_users": total_users,
            "total_actions": total_actions,
            "total_projects_created": total_projects_created,
            "most_common_actions": most_common_actions,
            "active_users_24h": await self._get_active_users_count(24 * 3600),
            "active_users_7d": await self._get_active_users_count(7 * 24 * 3600)
        }
    
    async def _get_active_users_count(self, time_window: int) -> int:
        """
        Get count of active users within a time window
        
        :param time_window: Time window in seconds
        :return: Count of active users
        """
        current_time = time.time()
        active_users = 0
        
        for user_metrics in self.metrics.values():
            if current_time - user_metrics["last_active"] <= time_window:
                active_users += 1
                
        return active_users
    
    async def get_user_action_logs(self, user_id: int, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get action logs for a user
        
        :param user_id: User ID
        :param limit: Maximum number of logs to return
        :return: List of action logs
        """
        user_logs = [log for log in self.action_logs if log["user_id"] == user_id]
        return sorted(user_logs, key=lambda x: x["timestamp"], reverse=True)[:limit]
    
    async def export_metrics(self) -> Dict[str, Any]:
        """
        Export all metrics for analysis
        
        :return: All metrics data
        """
        # Convert sets to lists for JSON serialization
        exportable_metrics = {}
        for user_id, user_metrics in self.metrics.items():
            exportable_metrics[user_id] = {
                "total_actions": user_metrics["total_actions"],
                "actions_by_type": user_metrics["actions_by_type"],
                "projects_created": user_metrics["projects_created"],
                "projects_used": list(user_metrics["projects_used"]),
                "last_active": user_metrics["last_active"]
            }
        
        return {
            "metrics": exportable_metrics,
            "action_logs": self.action_logs,
            "exported_at": time.time()
        }


# Global instance
analytics_service = AnalyticsService()


# Example usage functions
async def record_project_creation(user_id: int, project_id: str) -> None:
    """Record project creation event"""
    await analytics_service.record_user_action(
        user_id, 
        "project_create", 
        {"project_id": project_id},
        project_id
    )


async def record_chat_message(user_id: int, project_id: str, message_length: int) -> None:
    """Record chat message event"""
    await analytics_service.record_user_action(
        user_id, 
        "chat_message", 
        {"message_length": message_length},
        project_id
    )


async def record_preview_view(user_id: int, project_id: str) -> None:
    """Record preview view event"""
    await analytics_service.record_user_action(
        user_id, 
        "preview_view", 
        {},
        project_id
    )


async def record_error_fix(user_id: int, project_id: str, error_type: str) -> None:
    """Record error fix event"""
    await analytics_service.record_user_action(
        user_id, 
        "error_fix", 
        {"error_type": error_type},
        project_id
    )