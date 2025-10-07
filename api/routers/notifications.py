from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession  # FIX: Async session
from samokoder.core.db.session import get_async_db  # FIX: Async DB
from samokoder.core.db.models.user import User
from samokoder.core.services.notification_service import notification_service
from samokoder.api.routers.auth import get_current_user
from typing import List, Optional
import json

router = APIRouter()

@router.post("/notifications/subscribe")
async def subscribe_to_notifications(
    notification_types: List[str],
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db)  # FIX: AsyncSession
):
    """
    Subscribe user to notification types
    
    :param notification_types: List of notification types to subscribe to
    :param user: Current user
    :param db: Database session
    :return: Subscription result
    """
    try:
        await notification_service.subscribe_user(user.id, notification_types)
        return {
            "success": True,
            "message": f"Subscribed to notification types: {', '.join(notification_types)}"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error subscribing to notifications: {str(e)}")


@router.post("/notifications/unsubscribe")
async def unsubscribe_from_notifications(
    notification_types: List[str],
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db)  # FIX: AsyncSession
):
    """
    Unsubscribe user from notification types
    
    :param notification_types: List of notification types to unsubscribe from
    :param user: Current user
    :param db: Database session
    :return: Unsubscription result
    """
    try:
        await notification_service.unsubscribe_user(user.id, notification_types)
        return {
            "success": True,
            "message": f"Unsubscribed from notification types: {', '.join(notification_types)}"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error unsubscribing from notifications: {str(e)}")


@router.get("/notifications")
async def get_user_notifications(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db)  # FIX: AsyncSession
):
    """
    Get user's notifications
    
    :param user: Current user
    :param db: Database session
    :return: User's notifications
    """
    try:
        notifications = await notification_service.get_user_notifications(user.id)
        return {
            "notifications": notifications
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting notifications: {str(e)}")


@router.post("/notifications/{notification_id}/read")
async def mark_notification_as_read(
    notification_id: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db)  # FIX: AsyncSession
):
    """
    Mark a notification as read
    
    :param notification_id: Notification ID
    :param user: Current user
    :param db: Database session
    :return: Result
    """
    try:
        success = await notification_service.mark_notification_as_read(user.id, notification_id)
        return {
            "success": success,
            "message": "Notification marked as read" if success else "Failed to mark notification as read"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error marking notification as read: {str(e)}")


@router.post("/notifications/test")
async def send_test_notification(
    notification_type: str,
    title: str,
    message: str,
    data: Optional[dict] = None,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db)  # FIX: AsyncSession
):
    """
    Send a test notification to the user
    
    :param notification_type: Type of notification
    :param title: Notification title
    :param message: Notification message
    :param data: Additional data
    :param user: Current user
    :param db: Database session
    :return: Result
    """
    try:
        await notification_service.send_notification(
            user.id, 
            notification_type, 
            title, 
            message, 
            data
        )
        return {
            "success": True,
            "message": f"Test notification sent: {title}"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error sending test notification: {str(e)}")