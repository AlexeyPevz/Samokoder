"""
Supabase Service Contract
"""
from typing import Protocol, Optional, List, Dict, Any
from uuid import UUID

class SupabaseServiceProtocol(Protocol):
    """Protocol for Supabase service implementations"""
    
    async def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user by ID"""
        ...
    
    async def create_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new user"""
        ...
    
    async def update_user(self, user_id: str, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update user"""
        ...
    
    async def delete_user(self, user_id: str) -> bool:
        """Delete user"""
        ...
    
    async def get_project(self, project_id: str, user_id: str) -> Optional[Dict[str, Any]]:
        """Get project by ID for user"""
        ...
    
    async def create_project(self, project_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new project"""
        ...
    
    async def update_project(self, project_id: str, project_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update project"""
        ...
    
    async def delete_project(self, project_id: str, user_id: str) -> bool:
        """Delete project"""
        ...
    
    async def list_projects(self, user_id: str, limit: int = 10, offset: int = 0) -> List[Dict[str, Any]]:
        """List user projects"""
        ...
    
    async def get_chat_session(self, session_id: str, user_id: str) -> Optional[Dict[str, Any]]:
        """Get chat session by ID for user"""
        ...
    
    async def create_chat_session(self, session_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new chat session"""
        ...
    
    async def get_chat_messages(self, session_id: str, user_id: str, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """Get chat messages for session"""
        ...
    
    async def create_chat_message(self, message_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new chat message"""
        ...
    
    async def get_api_key(self, key_id: str, user_id: str) -> Optional[Dict[str, Any]]:
        """Get API key by ID for user"""
        ...
    
    async def create_api_key(self, key_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new API key"""
        ...
    
    async def update_api_key(self, key_id: str, key_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update API key"""
        ...
    
    async def delete_api_key(self, key_id: str, user_id: str) -> bool:
        """Delete API key"""
        ...
    
    async def list_api_keys(self, user_id: str) -> List[Dict[str, Any]]:
        """List user API keys"""
        ...
    
    async def get_ai_usage(self, user_id: str, days: int = 30) -> List[Dict[str, Any]]:
        """Get AI usage statistics for user"""
        ...
    
    async def create_ai_usage(self, usage_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create AI usage record"""
        ...
    
    async def health_check(self) -> Dict[str, Any]:
        """Check Supabase health"""
        ...