import asyncio
from typing import Dict, List, Optional
from samokoder.core.db.models.user import User
from samokoder.core.db.session import get_db
from sqlalchemy.orm import Session


class NotificationService:
    """Service for managing user notifications"""
    
    def __init__(self):
        self.user_subscriptions: Dict[int, List[str]] = {}  # user_id -> list of notification types
        self.notification_handlers: Dict[str, List[callable]] = {}  # notification_type -> list of handlers
    
    async def subscribe_user(self, user_id: int, notification_types: List[str]):
        """
        Subscribe a user to specific notification types
        
        :param user_id: User ID
        :param notification_types: List of notification types to subscribe to
        """
        if user_id not in self.user_subscriptions:
            self.user_subscriptions[user_id] = []
        
        for notification_type in notification_types:
            if notification_type not in self.user_subscriptions[user_id]:
                self.user_subscriptions[user_id].append(notification_type)
    
    async def unsubscribe_user(self, user_id: int, notification_types: List[str]):
        """
        Unsubscribe a user from specific notification types
        
        :param user_id: User ID
        :param notification_types: List of notification types to unsubscribe from
        """
        if user_id in self.user_subscriptions:
            for notification_type in notification_types:
                if notification_type in self.user_subscriptions[user_id]:
                    self.user_subscriptions[user_id].remove(notification_type)
    
    async def send_notification(
        self, 
        user_id: int, 
        notification_type: str, 
        title: str, 
        message: str, 
        data: Optional[Dict] = None
    ):
        """
        Send a notification to a user
        
        :param user_id: User ID
        :param notification_type: Type of notification
        :param title: Notification title
        :param message: Notification message
        :param data: Additional data
        """
        # Check if user is subscribed to this notification type
        if user_id in self.user_subscriptions and notification_type in self.user_subscriptions[user_id]:
            # Send notification through all registered handlers
            if notification_type in self.notification_handlers:
                for handler in self.notification_handlers[notification_type]:
                    try:
                        await handler(user_id, title, message, data)
                    except Exception as e:
                        log.error(f"Error sending notification: {e}", exc_info=True)
    
    async def send_broadcast_notification(
        self, 
        notification_type: str, 
        title: str, 
        message: str, 
        data: Optional[Dict] = None
    ):
        """
        Send a notification to all subscribed users
        
        :param notification_type: Type of notification
        :param title: Notification title
        :param message: Notification message
        :param data: Additional data
        """
        # Get all users subscribed to this notification type
        subscribed_users = []
        for user_id, subscriptions in self.user_subscriptions.items():
            if notification_type in subscriptions:
                subscribed_users.append(user_id)
        
        # Send notification to each subscribed user
        for user_id in subscribed_users:
            await self.send_notification(user_id, notification_type, title, message, data)
    
    def register_handler(self, notification_type: str, handler: callable):
        """
        Register a handler for a specific notification type
        
        :param notification_type: Type of notification
        :param handler: Handler function
        """
        if notification_type not in self.notification_handlers:
            self.notification_handlers[notification_type] = []
        
        self.notification_handlers[notification_type].append(handler)
    
    async def get_user_notifications(self, user_id: int) -> List[Dict]:
        """
        Get notifications for a user from database
        
        :param user_id: User ID
        :return: List of notifications
        """
        # In a real implementation, we would fetch notifications from database
        # For now, we return an empty list
        return []
    
    async def mark_notification_as_read(self, user_id: int, notification_id: str) -> bool:
        """
        Mark a notification as read
        
        :param user_id: User ID
        :param notification_id: Notification ID
        :return: True if successful
        """
        # In a real implementation, we would update notification in database
        # For now, we return True
        return True


# Global instance
notification_service = NotificationService()


# Example handlers
async def email_notification_handler(user_id: int, title: str, message: str, data: Optional[Dict] = None):
    """Handler for sending email notifications"""
    # Get user from database using async session
    from samokoder.core.db.session import SessionManager
    async with SessionManager().get_session() as db:
        from sqlalchemy import select
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalars().first()
        if user and user.email:
            # In a real implementation, we would send an email
            log.info(f"Sending email to {user.email}: {title} - {message}")


async def push_notification_handler(user_id: int, title: str, message: str, data: Optional[Dict] = None):
    """Handler for sending push notifications"""
    # In a real implementation, we would send a push notification
    log.info(f"Sending push notification to user {user_id}: {title} - {message}")


# Register handlers
notification_service.register_handler("email", email_notification_handler)
notification_service.register_handler("push", push_notification_handler)