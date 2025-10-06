from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from samokoder.core.db.session import get_db
from samokoder.core.db.models.user import User
from samokoder.core.analytics.analytics_service import analytics_service
from samokoder.api.routers.auth import get_current_user, require_admin
from typing import Dict, Any, List
import json

router = APIRouter()

@router.get("/analytics/user")
async def get_user_analytics(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get analytics metrics for the current user
    
    :param user: Current user
    :param db: Database session
    :return: User analytics metrics
    """
    try:
        metrics = await analytics_service.get_user_metrics(user.id)
        return {
            "user_id": user.id,
            "metrics": metrics
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting user analytics: {str(e)}")


@router.get("/analytics/system")
async def get_system_analytics(
    admin: User = Depends(require_admin),  # P0-1: FIXED - Require admin privileges
    db: Session = Depends(get_db)
):
    """
    Get overall system analytics metrics (ADMIN ONLY).
    
    :param admin: Current admin user
    :param db: Database session
    :return: System analytics metrics
    """
    try:
        
        metrics = await analytics_service.get_system_metrics()
        return {
            "metrics": metrics
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting system analytics: {str(e)}")


@router.get("/analytics/user/actions")
async def get_user_action_logs(
    limit: int = 100,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get action logs for the current user
    
    :param limit: Maximum number of logs to return
    :param user: Current user
    :param db: Database session
    :return: User action logs
    """
    try:
        logs = await analytics_service.get_user_action_logs(user.id, limit)
        return {
            "user_id": user.id,
            "logs": logs
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting user action logs: {str(e)}")


@router.post("/analytics/record")
async def record_user_action(
    action: str,
    details: Dict[str, Any] = None,
    project_id: str = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Record a user action for analytics
    
    :param action: Action name
    :param details: Additional details about the action
    :param project_id: Project ID (optional)
    :param user: Current user
    :param db: Database session
    :return: Result
    """
    try:
        await analytics_service.record_user_action(user.id, action, details, project_id)
        return {
            "success": True,
            "message": f"Action {action} recorded"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error recording action: {str(e)}")


@router.get("/analytics/export")
async def export_analytics(
    admin: User = Depends(require_admin),  # P0-1: FIXED - Require admin privileges
    db: Session = Depends(get_db)
):
    """
    Export all analytics data (ADMIN ONLY).
    
    :param admin: Current admin user
    :param db: Database session
    :return: Exported analytics data
    """
    try:
        
        data = await analytics_service.export_metrics()
        return data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error exporting analytics: {str(e)}")