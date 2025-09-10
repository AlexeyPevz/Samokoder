"""
Database Service Implementation
"""
import logging
from typing import Optional, List, Dict, Any
from uuid import UUID
from backend.contracts.database import DatabaseServiceProtocol
from backend.services.connection_pool import connection_pool_manager

logger = logging.getLogger(__name__)

class DatabaseServiceImpl(DatabaseServiceProtocol):
    """Implementation of Database Service Protocol"""
    
    def __init__(self):
        self._supabase = None
    
    def _get_supabase(self):
        """Get Supabase client"""
        if self._supabase is None:
            self._supabase = connection_pool_manager.get_supabase_client()
        return self._supabase
    
    async def get_user(self, user_id: UUID) -> Optional[Dict[str, Any]]:
        """Get user by ID"""
        try:
            supabase = self._get_supabase()
            response = supabase.table("profiles").select("*").eq("id", str(user_id)).execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error(f"Failed to get user {user_id}: {e}")
            return None
    
    async def create_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new user"""
        try:
            supabase = self._get_supabase()
            response = supabase.table("profiles").insert(user_data).execute()
            return response.data[0] if response.data else {}
        except Exception as e:
            logger.error(f"Failed to create user: {e}")
            raise
    
    async def update_user(self, user_id: UUID, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update user"""
        try:
            supabase = self._get_supabase()
            response = supabase.table("profiles").update(user_data).eq("id", str(user_id)).execute()
            return response.data[0] if response.data else {}
        except Exception as e:
            logger.error(f"Failed to update user {user_id}: {e}")
            raise
    
    async def delete_user(self, user_id: UUID) -> bool:
        """Delete user"""
        try:
            supabase = self._get_supabase()
            response = supabase.table("profiles").delete().eq("id", str(user_id)).execute()
            return len(response.data) > 0
        except Exception as e:
            logger.error(f"Failed to delete user {user_id}: {e}")
            return False
    
    async def get_project(self, project_id: UUID, user_id: UUID) -> Optional[Dict[str, Any]]:
        """Get project by ID for user"""
        try:
            supabase = self._get_supabase()
            response = supabase.table("projects").select("*").eq("id", str(project_id)).eq("user_id", str(user_id)).execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error(f"Failed to get project {project_id}: {e}")
            return None
    
    async def create_project(self, project_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new project"""
        try:
            supabase = self._get_supabase()
            response = supabase.table("projects").insert(project_data).execute()
            return response.data[0] if response.data else {}
        except Exception as e:
            logger.error(f"Failed to create project: {e}")
            raise
    
    async def update_project(self, project_id: UUID, project_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update project"""
        try:
            supabase = self._get_supabase()
            response = supabase.table("projects").update(project_data).eq("id", str(project_id)).execute()
            return response.data[0] if response.data else {}
        except Exception as e:
            logger.error(f"Failed to update project {project_id}: {e}")
            raise
    
    async def delete_project(self, project_id: UUID, user_id: UUID) -> bool:
        """Delete project"""
        try:
            supabase = self._get_supabase()
            response = supabase.table("projects").update({"is_active": False}).eq("id", str(project_id)).eq("user_id", str(user_id)).execute()
            return len(response.data) > 0
        except Exception as e:
            logger.error(f"Failed to delete project {project_id}: {e}")
            return False
    
    async def list_projects(self, user_id: UUID, limit: int = 10, offset: int = 0) -> List[Dict[str, Any]]:
        """List user projects"""
        try:
            supabase = self._get_supabase()
            response = supabase.table("projects").select("*").eq("user_id", str(user_id)).eq("is_active", True).range(offset, offset + limit - 1).execute()
            return response.data or []
        except Exception as e:
            logger.error(f"Failed to list projects for user {user_id}: {e}")
            return []
    
    async def get_chat_session(self, session_id: UUID, user_id: UUID) -> Optional[Dict[str, Any]]:
        """Get chat session by ID for user"""
        try:
            supabase = self._get_supabase()
            response = supabase.table("chat_sessions").select("*").eq("id", str(session_id)).eq("user_id", str(user_id)).execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error(f"Failed to get chat session {session_id}: {e}")
            return None
    
    async def create_chat_session(self, session_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new chat session"""
        try:
            supabase = self._get_supabase()
            response = supabase.table("chat_sessions").insert(session_data).execute()
            return response.data[0] if response.data else {}
        except Exception as e:
            logger.error(f"Failed to create chat session: {e}")
            raise
    
    async def get_chat_messages(self, session_id: UUID, user_id: UUID, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """Get chat messages for session"""
        try:
            supabase = self._get_supabase()
            response = supabase.table("chat_messages").select("*").eq("session_id", str(session_id)).range(offset, offset + limit - 1).order("created_at", desc=False).execute()
            return response.data or []
        except Exception as e:
            logger.error(f"Failed to get chat messages for session {session_id}: {e}")
            return []
    
    async def create_chat_message(self, message_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new chat message"""
        try:
            supabase = self._get_supabase()
            response = supabase.table("chat_messages").insert(message_data).execute()
            return response.data[0] if response.data else {}
        except Exception as e:
            logger.error(f"Failed to create chat message: {e}")
            raise
    
    async def get_api_key(self, key_id: UUID, user_id: UUID) -> Optional[Dict[str, Any]]:
        """Get API key by ID for user"""
        try:
            supabase = self._get_supabase()
            response = supabase.table("api_keys").select("*").eq("id", str(key_id)).eq("user_id", str(user_id)).execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error(f"Failed to get API key {key_id}: {e}")
            return None
    
    async def create_api_key(self, key_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new API key"""
        try:
            supabase = self._get_supabase()
            response = supabase.table("api_keys").insert(key_data).execute()
            return response.data[0] if response.data else {}
        except Exception as e:
            logger.error(f"Failed to create API key: {e}")
            raise
    
    async def update_api_key(self, key_id: UUID, key_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update API key"""
        try:
            supabase = self._get_supabase()
            response = supabase.table("api_keys").update(key_data).eq("id", str(key_id)).execute()
            return response.data[0] if response.data else {}
        except Exception as e:
            logger.error(f"Failed to update API key {key_id}: {e}")
            raise
    
    async def delete_api_key(self, key_id: UUID, user_id: UUID) -> bool:
        """Delete API key"""
        try:
            supabase = self._get_supabase()
            response = supabase.table("api_keys").delete().eq("id", str(key_id)).eq("user_id", str(user_id)).execute()
            return len(response.data) > 0
        except Exception as e:
            logger.error(f"Failed to delete API key {key_id}: {e}")
            return False
    
    async def list_api_keys(self, user_id: UUID) -> List[Dict[str, Any]]:
        """List user API keys"""
        try:
            supabase = self._get_supabase()
            response = supabase.table("api_keys").select("*").eq("user_id", str(user_id)).eq("is_active", True).execute()
            return response.data or []
        except Exception as e:
            logger.error(f"Failed to list API keys for user {user_id}: {e}")
            return []
    
    async def get_ai_usage(self, user_id: UUID, days: int = 30) -> List[Dict[str, Any]]:
        """Get AI usage statistics for user"""
        try:
            from datetime import datetime, timedelta
            start_date = datetime.now() - timedelta(days=days)
            
            supabase = self._get_supabase()
            response = supabase.table("ai_usage").select("*").eq("user_id", str(user_id)).gte("created_at", start_date.isoformat()).execute()
            return response.data or []
        except Exception as e:
            logger.error(f"Failed to get AI usage for user {user_id}: {e}")
            return []
    
    async def create_ai_usage(self, usage_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create AI usage record"""
        try:
            supabase = self._get_supabase()
            response = supabase.table("ai_usage").insert(usage_data).execute()
            return response.data[0] if response.data else {}
        except Exception as e:
            logger.error(f"Failed to create AI usage record: {e}")
            raise