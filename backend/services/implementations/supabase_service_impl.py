"""
Supabase Service Implementation
"""
import logging
from typing import Optional, List, Dict, Any
from supabase import create_client, Client
from backend.contracts.supabase_service import SupabaseServiceProtocol
from config.settings import settings

logger = logging.getLogger(__name__)

class SupabaseServiceImpl(SupabaseServiceProtocol):
    """Implementation of Supabase Service Protocol"""
    
    def __init__(self):
        self.client: Optional[Client] = None
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize Supabase client"""
        try:
            if (settings.supabase_url and 
                settings.supabase_anon_key and 
                not settings.supabase_url.endswith("example.supabase.co") and
                not settings.supabase_anon_key.endswith("example")):
                self.client = create_client(
                    settings.supabase_url, 
                    settings.supabase_anon_key
                )
                logger.info("Supabase client initialized successfully")
            else:
                logger.warning("Supabase not configured - working without database")
                self.client = None
        except Exception as e:
            logger.warning(f"Supabase client creation failed: {e}")
            self.client = None
    
    async def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user by ID"""
        if not self.client:
            return None
        
        try:
            response = self.client.table("profiles").select("*").eq("id", user_id).single().execute()
            return response.data if response.data else None
        except Exception as e:
            logger.error(f"Error getting user {user_id}: {e}")
            return None
    
    async def create_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new user"""
        if not self.client:
            raise RuntimeError("Supabase not available")
        
        try:
            response = self.client.table("profiles").insert(user_data).execute()
            return response.data[0] if response.data else {}
        except Exception as e:
            logger.error(f"Error creating user: {e}")
            raise
    
    async def update_user(self, user_id: str, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update user"""
        if not self.client:
            raise RuntimeError("Supabase not available")
        
        try:
            response = self.client.table("profiles").update(user_data).eq("id", user_id).execute()
            return response.data[0] if response.data else {}
        except Exception as e:
            logger.error(f"Error updating user {user_id}: {e}")
            raise
    
    async def delete_user(self, user_id: str) -> bool:
        """Delete user"""
        if not self.client:
            return False
        
        try:
            self.client.table("profiles").delete().eq("id", user_id).execute()
            return True
        except Exception as e:
            logger.error(f"Error deleting user {user_id}: {e}")
            return False
    
    async def get_project(self, project_id: str, user_id: str) -> Optional[Dict[str, Any]]:
        """Get project by ID for user"""
        if not self.client:
            return None
        
        try:
            response = self.client.table("projects").select("*").eq("id", project_id).eq("user_id", user_id).single().execute()
            return response.data if response.data else None
        except Exception as e:
            logger.error(f"Error getting project {project_id}: {e}")
            return None
    
    async def create_project(self, project_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new project"""
        if not self.client:
            raise RuntimeError("Supabase not available")
        
        try:
            response = self.client.table("projects").insert(project_data).execute()
            return response.data[0] if response.data else {}
        except Exception as e:
            logger.error(f"Error creating project: {e}")
            raise
    
    async def update_project(self, project_id: str, project_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update project"""
        if not self.client:
            raise RuntimeError("Supabase not available")
        
        try:
            response = self.client.table("projects").update(project_data).eq("id", project_id).execute()
            return response.data[0] if response.data else {}
        except Exception as e:
            logger.error(f"Error updating project {project_id}: {e}")
            raise
    
    async def delete_project(self, project_id: str, user_id: str) -> bool:
        """Delete project"""
        if not self.client:
            return False
        
        try:
            self.client.table("projects").delete().eq("id", project_id).eq("user_id", user_id).execute()
            return True
        except Exception as e:
            logger.error(f"Error deleting project {project_id}: {e}")
            return False
    
    async def list_projects(self, user_id: str, limit: int = 10, offset: int = 0) -> List[Dict[str, Any]]:
        """List user projects"""
        if not self.client:
            return []
        
        try:
            response = self.client.table("projects").select("*").eq("user_id", user_id).order("created_at", desc=True).range(offset, offset + limit - 1).execute()
            return response.data if response.data else []
        except Exception as e:
            logger.error(f"Error listing projects for user {user_id}: {e}")
            return []
    
    async def get_chat_session(self, session_id: str, user_id: str) -> Optional[Dict[str, Any]]:
        """Get chat session by ID for user"""
        if not self.client:
            return None
        
        try:
            response = self.client.table("chat_sessions").select("*").eq("id", session_id).eq("user_id", user_id).single().execute()
            return response.data if response.data else None
        except Exception as e:
            logger.error(f"Error getting chat session {session_id}: {e}")
            return None
    
    async def create_chat_session(self, session_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new chat session"""
        if not self.client:
            raise RuntimeError("Supabase not available")
        
        try:
            response = self.client.table("chat_sessions").insert(session_data).execute()
            return response.data[0] if response.data else {}
        except Exception as e:
            logger.error(f"Error creating chat session: {e}")
            raise
    
    async def get_chat_messages(self, session_id: str, user_id: str, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """Get chat messages for session"""
        if not self.client:
            return []
        
        try:
            response = self.client.table("chat_messages").select("*").eq("session_id", session_id).order("created_at", desc=False).range(offset, offset + limit - 1).execute()
            return response.data if response.data else []
        except Exception as e:
            logger.error(f"Error getting chat messages for session {session_id}: {e}")
            return []
    
    async def create_chat_message(self, message_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new chat message"""
        if not self.client:
            raise RuntimeError("Supabase not available")
        
        try:
            response = self.client.table("chat_messages").insert(message_data).execute()
            return response.data[0] if response.data else {}
        except Exception as e:
            logger.error(f"Error creating chat message: {e}")
            raise
    
    async def get_api_key(self, key_id: str, user_id: str) -> Optional[Dict[str, Any]]:
        """Get API key by ID for user"""
        if not self.client:
            return None
        
        try:
            response = self.client.table("api_keys").select("*").eq("id", key_id).eq("user_id", user_id).single().execute()
            return response.data if response.data else None
        except Exception as e:
            logger.error(f"Error getting API key {key_id}: {e}")
            return None
    
    async def create_api_key(self, key_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new API key"""
        if not self.client:
            raise RuntimeError("Supabase not available")
        
        try:
            response = self.client.table("api_keys").insert(key_data).execute()
            return response.data[0] if response.data else {}
        except Exception as e:
            logger.error(f"Error creating API key: {e}")
            raise
    
    async def update_api_key(self, key_id: str, key_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update API key"""
        if not self.client:
            raise RuntimeError("Supabase not available")
        
        try:
            response = self.client.table("api_keys").update(key_data).eq("id", key_id).execute()
            return response.data[0] if response.data else {}
        except Exception as e:
            logger.error(f"Error updating API key {key_id}: {e}")
            raise
    
    async def delete_api_key(self, key_id: str, user_id: str) -> bool:
        """Delete API key"""
        if not self.client:
            return False
        
        try:
            self.client.table("api_keys").delete().eq("id", key_id).eq("user_id", user_id).execute()
            return True
        except Exception as e:
            logger.error(f"Error deleting API key {key_id}: {e}")
            return False
    
    async def list_api_keys(self, user_id: str) -> List[Dict[str, Any]]:
        """List user API keys"""
        if not self.client:
            return []
        
        try:
            response = self.client.table("api_keys").select("*").eq("user_id", user_id).eq("is_active", True).execute()
            return response.data if response.data else []
        except Exception as e:
            logger.error(f"Error listing API keys for user {user_id}: {e}")
            return []
    
    async def get_ai_usage(self, user_id: str, days: int = 30) -> List[Dict[str, Any]]:
        """Get AI usage statistics for user"""
        if not self.client:
            return []
        
        try:
            response = self.client.table("ai_usage").select("*").eq("user_id", user_id).order("created_at", desc=True).execute()
            return response.data if response.data else []
        except Exception as e:
            logger.error(f"Error getting AI usage for user {user_id}: {e}")
            return []
    
    async def create_ai_usage(self, usage_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create AI usage record"""
        if not self.client:
            raise RuntimeError("Supabase not available")
        
        try:
            response = self.client.table("ai_usage").insert(usage_data).execute()
            return response.data[0] if response.data else {}
        except Exception as e:
            logger.error(f"Error creating AI usage record: {e}")
            raise
    
    async def health_check(self) -> Dict[str, Any]:
        """Check Supabase health"""
        if not self.client:
            return {
                "status": "unhealthy",
                "error": "Supabase not configured"
            }
        
        try:
            # Simple query to test connection
            self.client.table("profiles").select("id").limit(1).execute()
            return {
                "status": "healthy",
                "response_time": 0.001
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e)
            }