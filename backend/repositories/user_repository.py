"""
User Repository Implementation
"""
import logging
from typing import Optional, Dict, Any
from uuid import UUID
from backend.contracts.database import UserRepositoryProtocol
from backend.services.connection_pool import connection_pool_manager

logger = logging.getLogger(__name__)

class UserRepository(UserRepositoryProtocol):
    """User Repository Implementation"""
    
    def __init__(self):
        self._supabase = None
    
    def _get_supabase(self):
        """Get Supabase client"""
        if self._supabase is None:
            self._supabase = connection_pool_manager.get_supabase_client()
        return self._supabase
    
    async def find_by_id(self, user_id: UUID) -> Optional[Dict[str, Any]]:
        """Find user by ID"""
        try:
            supabase = self._get_supabase()
            response = supabase.table("profiles").select("*").eq("id", str(user_id)).execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error(f"Failed to find user by ID {user_id}: {e}")
            return None
    
    async def find_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Find user by email"""
        try:
            supabase = self._get_supabase()
            response = supabase.table("profiles").select("*").eq("email", email).execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error(f"Failed to find user by email {email}: {e}")
            return None
    
    async def save(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Save user"""
        try:
            supabase = self._get_supabase()
            response = supabase.table("profiles").insert(user_data).execute()
            return response.data[0] if response.data else {}
        except Exception as e:
            logger.error(f"Failed to save user: {e}")
            raise
    
    async def update(self, user_id: UUID, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update user"""
        try:
            supabase = self._get_supabase()
            response = supabase.table("profiles").update(user_data).eq("id", str(user_id)).execute()
            return response.data[0] if response.data else {}
        except Exception as e:
            logger.error(f"Failed to update user {user_id}: {e}")
            raise
    
    async def delete(self, user_id: UUID) -> bool:
        """Delete user"""
        try:
            supabase = self._get_supabase()
            response = supabase.table("profiles").delete().eq("id", str(user_id)).execute()
            return len(response.data) > 0
        except Exception as e:
            logger.error(f"Failed to delete user {user_id}: {e}")
            return False
    
    async def find_by_subscription_tier(self, tier: str) -> list[Dict[str, Any]]:
        """Find users by subscription tier"""
        try:
            supabase = self._get_supabase()
            response = supabase.table("profiles").select("*").eq("subscription_tier", tier).execute()
            return response.data or []
        except Exception as e:
            logger.error(f"Failed to find users by subscription tier {tier}: {e}")
            return []
    
    async def find_active_users(self, limit: int = 100, offset: int = 0) -> list[Dict[str, Any]]:
        """Find active users"""
        try:
            supabase = self._get_supabase()
            response = supabase.table("profiles").select("*").eq("subscription_status", "active").range(offset, offset + limit - 1).execute()
            return response.data or []
        except Exception as e:
            logger.error(f"Failed to find active users: {e}")
            return []
    
    async def update_subscription(self, user_id: UUID, tier: str, status: str) -> bool:
        """Update user subscription"""
        try:
            supabase = self._get_supabase()
            response = supabase.table("profiles").update({
                "subscription_tier": tier,
                "subscription_status": status
            }).eq("id", str(user_id)).execute()
            return len(response.data) > 0
        except Exception as e:
            logger.error(f"Failed to update subscription for user {user_id}: {e}")
            return False