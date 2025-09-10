"""
Chat Repository Implementation
"""
import logging
from typing import Optional, List, Dict, Any
from uuid import UUID
from backend.contracts.database import ChatRepositoryProtocol
from backend.services.connection_pool import connection_pool_manager

logger = logging.getLogger(__name__)

class ChatRepository(ChatRepositoryProtocol):
    """Chat Repository Implementation"""
    
    def __init__(self):
        self._supabase = None
    
    def _get_supabase(self):
        """Get Supabase client"""
        if self._supabase is None:
            self._supabase = connection_pool_manager.get_supabase_client()
        return self._supabase
    
    async def find_session_by_id(self, session_id: UUID) -> Optional[Dict[str, Any]]:
        """Find chat session by ID"""
        try:
            supabase = self._get_supabase()
            response = supabase.table("chat_sessions").select("*").eq("id", str(session_id)).execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error(f"Failed to find chat session by ID {session_id}: {e}")
            return None
    
    async def find_sessions_by_project(self, project_id: UUID, limit: int = 10, offset: int = 0) -> List[Dict[str, Any]]:
        """Find chat sessions by project ID"""
        try:
            supabase = self._get_supabase()
            response = supabase.table("chat_sessions").select("*").eq("project_id", str(project_id)).eq("is_active", True).range(offset, offset + limit - 1).order("created_at", desc=True).execute()
            return response.data or []
        except Exception as e:
            logger.error(f"Failed to find chat sessions by project ID {project_id}: {e}")
            return []
    
    async def save_session(self, session_data: Dict[str, Any]) -> Dict[str, Any]:
        """Save chat session"""
        try:
            supabase = self._get_supabase()
            response = supabase.table("chat_sessions").insert(session_data).execute()
            return response.data[0] if response.data else {}
        except Exception as e:
            logger.error(f"Failed to save chat session: {e}")
            raise
    
    async def find_messages_by_session(self, session_id: UUID, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """Find messages by session ID"""
        try:
            supabase = self._get_supabase()
            response = supabase.table("chat_messages").select("*").eq("session_id", str(session_id)).range(offset, offset + limit - 1).order("created_at", desc=False).execute()
            return response.data or []
        except Exception as e:
            logger.error(f"Failed to find messages by session ID {session_id}: {e}")
            return []
    
    async def save_message(self, message_data: Dict[str, Any]) -> Dict[str, Any]:
        """Save chat message"""
        try:
            supabase = self._get_supabase()
            response = supabase.table("chat_messages").insert(message_data).execute()
            return response.data[0] if response.data else {}
        except Exception as e:
            logger.error(f"Failed to save chat message: {e}")
            raise
    
    async def find_sessions_by_user(self, user_id: UUID, limit: int = 20, offset: int = 0) -> List[Dict[str, Any]]:
        """Find chat sessions by user ID"""
        try:
            supabase = self._get_supabase()
            response = supabase.table("chat_sessions").select("*").eq("user_id", str(user_id)).eq("is_active", True).range(offset, offset + limit - 1).order("updated_at", desc=True).execute()
            return response.data or []
        except Exception as e:
            logger.error(f"Failed to find chat sessions by user ID {user_id}: {e}")
            return []
    
    async def find_recent_sessions(self, user_id: UUID, limit: int = 5) -> List[Dict[str, Any]]:
        """Find recent chat sessions for user"""
        try:
            supabase = self._get_supabase()
            response = supabase.table("chat_sessions").select("*").eq("user_id", str(user_id)).eq("is_active", True).order("updated_at", desc=True).limit(limit).execute()
            return response.data or []
        except Exception as e:
            logger.error(f"Failed to find recent chat sessions for user {user_id}: {e}")
            return []
    
    async def update_session(self, session_id: UUID, session_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update chat session"""
        try:
            supabase = self._get_supabase()
            response = supabase.table("chat_sessions").update(session_data).eq("id", str(session_id)).execute()
            return response.data[0] if response.data else {}
        except Exception as e:
            logger.error(f"Failed to update chat session {session_id}: {e}")
            raise
    
    async def delete_session(self, session_id: UUID) -> bool:
        """Delete chat session (soft delete)"""
        try:
            supabase = self._get_supabase()
            response = supabase.table("chat_sessions").update({"is_active": False}).eq("id", str(session_id)).execute()
            return len(response.data) > 0
        except Exception as e:
            logger.error(f"Failed to delete chat session {session_id}: {e}")
            return False
    
    async def count_messages_by_session(self, session_id: UUID) -> int:
        """Count messages in session"""
        try:
            supabase = self._get_supabase()
            response = supabase.table("chat_messages").select("id", count="exact").eq("session_id", str(session_id)).execute()
            return response.count or 0
        except Exception as e:
            logger.error(f"Failed to count messages for session {session_id}: {e}")
            return 0