"""
Supabase Service Implementation
"""
import logging
from typing import Optional, List, Dict, Any
from backend.contracts.supabase_service import SupabaseServiceProtocol
from backend.services.connection_manager import connection_manager

logger = logging.getLogger(__name__)

class SupabaseServiceImpl(SupabaseServiceProtocol):
    """Implementation of Supabase Service Protocol"""
    
    def __init__(self):
        self.client = None
    
    def _get_client(self):
        """Get Supabase client from connection manager"""
        if self.client is None:
            try:
                self.client = connection_manager.get_pool('supabase')
            except Exception as e:
                logger.error(f"Failed to get Supabase client: {e}")
                return None
        return self.client
    
    async def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user by ID"""
        client = self._get_client()
        if not client:
            return None
        
        try:
            response = client.table("profiles").select("*").eq("id", user_id).single().execute()
            return response.data if response.data else None
        except Exception as e:
            logger.error(f"Error getting user {user_id}: {e}")
            return None
    
    async def create_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new user"""
        client = self._get_client()
        if not client:
            raise RuntimeError("Supabase not available")
        
        try:
            response = client.table("profiles").insert(user_data).execute()
            return response.data[0] if response.data else {}
        except Exception as e:
            logger.error(f"Error creating user: {e}")
            raise
    
    async def update_user(self, user_id: str, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update user"""
        client = self._get_client()
        if not client:
            raise RuntimeError("Supabase not available")
        
        try:
            response = client.table("profiles").update(user_data).eq("id", user_id).execute()
            return response.data[0] if response.data else {}
        except Exception as e:
            logger.error(f"Error updating user {user_id}: {e}")
            raise
    
    async def delete_user(self, user_id: str) -> bool:
        """Delete user"""
        client = self._get_client()
        if not client:
            return False
        
        try:
            client.table("profiles").delete().eq("id", user_id).execute()
            return True
        except Exception as e:
            logger.error(f"Error deleting user {user_id}: {e}")
            return False
    
    async def get_project(self, project_id: str, user_id: str) -> Optional[Dict[str, Any]]:
        """Get project by ID for user"""
        client = self._get_client()
        if not client:
            return None
        
        try:
            response = client.table("projects").select("*").eq("id", project_id).eq("user_id", user_id).single().execute()
            return response.data if response.data else None
        except Exception as e:
            logger.error(f"Error getting project {project_id}: {e}")
            return None
    
    async def create_project(self, project_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new project"""
        client = self._get_client()
        if not client:
            raise RuntimeError("Supabase not available")
        
        try:
            response = client.table("projects").insert(project_data).execute()
            return response.data[0] if response.data else {}
        except Exception as e:
            logger.error(f"Error creating project: {e}")
            raise
    
    async def update_project(self, project_id: str, project_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update project"""
        client = self._get_client()
        if not client:
            raise RuntimeError("Supabase not available")
        
        try:
            response = client.table("projects").update(project_data).eq("id", project_id).execute()
            return response.data[0] if response.data else {}
        except Exception as e:
            logger.error(f"Error updating project {project_id}: {e}")
            raise
    
    async def delete_project(self, project_id: str, user_id: str) -> bool:
        """Delete project"""
        client = self._get_client()
        if not client:
            return False
        
        try:
            client.table("projects").delete().eq("id", project_id).eq("user_id", user_id).execute()
            return True
        except Exception as e:
            logger.error(f"Error deleting project {project_id}: {e}")
            return False
    
    async def list_projects(self, user_id: str, limit: int = 10, offset: int = 0) -> List[Dict[str, Any]]:
        """List user projects"""
        client = self._get_client()
        if not client:
            return []
        
        try:
            response = client.table("projects").select("*").eq("user_id", user_id).order("created_at", desc=True).range(offset, offset + limit - 1).execute()
            return response.data if response.data else []
        except Exception as e:
            logger.error(f"Error listing projects for user {user_id}: {e}")
            return []
    
    async def get_chat_session(self, session_id: str, user_id: str) -> Optional[Dict[str, Any]]:
        """Get chat session by ID for user"""
        client = self._get_client()
        if not client:
            return None
        
        try:
            response = client.table("chat_sessions").select("*").eq("id", session_id).eq("user_id", user_id).single().execute()
            return response.data if response.data else None
        except Exception as e:
            logger.error(f"Error getting chat session {session_id}: {e}")
            return None
    
    async def create_chat_session(self, session_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new chat session"""
        client = self._get_client()
        if not client:
            raise RuntimeError("Supabase not available")
        
        try:
            response = client.table("chat_sessions").insert(session_data).execute()
            return response.data[0] if response.data else {}
        except Exception as e:
            logger.error(f"Error creating chat session: {e}")
            raise
    
    async def get_chat_messages(self, session_id: str, user_id: str, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """Get chat messages for session"""
        client = self._get_client()
        if not client:
            return []
        
        try:
            response = client.table("chat_messages").select("*").eq("session_id", session_id).order("created_at", desc=False).range(offset, offset + limit - 1).execute()
            return response.data if response.data else []
        except Exception as e:
            logger.error(f"Error getting chat messages for session {session_id}: {e}")
            return []
    
    async def create_chat_message(self, message_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new chat message"""
        client = self._get_client()
        if not client:
            raise RuntimeError("Supabase not available")
        
        try:
            response = client.table("chat_messages").insert(message_data).execute()
            return response.data[0] if response.data else {}
        except Exception as e:
            logger.error(f"Error creating chat message: {e}")
            raise
    
    async def get_api_key(self, key_id: str, user_id: str) -> Optional[Dict[str, Any]]:
        """Get API key by ID for user"""
        client = self._get_client()
        if not client:
            return None
        
        try:
            response = client.table("api_keys").select("*").eq("id", key_id).eq("user_id", user_id).single().execute()
            return response.data if response.data else None
        except Exception as e:
            logger.error(f"Error getting API key {key_id}: {e}")
            return None
    
    async def create_api_key(self, key_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new API key"""
        client = self._get_client()
        if not client:
            raise RuntimeError("Supabase not available")
        
        try:
            response = client.table("api_keys").insert(key_data).execute()
            return response.data[0] if response.data else {}
        except Exception as e:
            logger.error(f"Error creating API key: {e}")
            raise
    
    async def update_api_key(self, key_id: str, key_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update API key"""
        client = self._get_client()
        if not client:
            raise RuntimeError("Supabase not available")
        
        try:
            response = client.table("api_keys").update(key_data).eq("id", key_id).execute()
            return response.data[0] if response.data else {}
        except Exception as e:
            logger.error(f"Error updating API key {key_id}: {e}")
            raise
    
    async def delete_api_key(self, key_id: str, user_id: str) -> bool:
        """Delete API key"""
        client = self._get_client()
        if not client:
            return False
        
        try:
            client.table("api_keys").delete().eq("id", key_id).eq("user_id", user_id).execute()
            return True
        except Exception as e:
            logger.error(f"Error deleting API key {key_id}: {e}")
            return False
    
    async def list_api_keys(self, user_id: str) -> List[Dict[str, Any]]:
        """List user API keys"""
        client = self._get_client()
        if not client:
            return []
        
        try:
            response = client.table("api_keys").select("*").eq("user_id", user_id).eq("is_active", True).execute()
            return response.data if response.data else []
        except Exception as e:
            logger.error(f"Error listing API keys for user {user_id}: {e}")
            return []
    
    async def get_ai_usage(self, user_id: str, days: int = 30) -> List[Dict[str, Any]]:
        """Get AI usage statistics for user"""
        client = self._get_client()
        if not client:
            return []
        
        try:
            response = client.table("ai_usage").select("*").eq("user_id", user_id).order("created_at", desc=True).execute()
            return response.data if response.data else []
        except Exception as e:
            logger.error(f"Error getting AI usage for user {user_id}: {e}")
            return []
    
    async def create_ai_usage(self, usage_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create AI usage record"""
        client = self._get_client()
        if not client:
            raise RuntimeError("Supabase not available")
        
        try:
            response = client.table("ai_usage").insert(usage_data).execute()
            return response.data[0] if response.data else {}
        except Exception as e:
            logger.error(f"Error creating AI usage record: {e}")
            raise
    
    async def health_check(self) -> Dict[str, Any]:
        """Check Supabase health"""
        client = self._get_client()
        if not client:
            return {
                "status": "unhealthy",
                "error": "Supabase not configured"
            }
        
        try:
            # Simple query to test connection
            client.table("profiles").select("id").limit(1).execute()
            return {
                "status": "healthy",
                "response_time": 0.001
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e)
            }