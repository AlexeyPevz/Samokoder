"""
Database service contracts
"""
from typing import Protocol, Optional, List, Dict, Any
from uuid import UUID

class DatabaseServiceProtocol(Protocol):
    """Protocol for database service implementations"""
    
    async def get_user(self, user_id: UUID) -> Optional[Dict[str, Any]]:
        """Get user by ID"""
        ...
    
    async def create_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new user"""
        ...
    
    async def update_user(self, user_id: UUID, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update user"""
        ...
    
    async def delete_user(self, user_id: UUID) -> bool:
        """Delete user"""
        ...
    
    async def get_project(self, project_id: UUID, user_id: UUID) -> Optional[Dict[str, Any]]:
        """Get project by ID for user"""
        ...
    
    async def create_project(self, project_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new project"""
        ...
    
    async def update_project(self, project_id: UUID, project_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update project"""
        ...
    
    async def delete_project(self, project_id: UUID, user_id: UUID) -> bool:
        """Delete project"""
        ...
    
    async def list_projects(self, user_id: UUID, limit: int = 10, offset: int = 0) -> List[Dict[str, Any]]:
        """List user projects"""
        ...
    
    async def get_chat_session(self, session_id: UUID, user_id: UUID) -> Optional[Dict[str, Any]]:
        """Get chat session by ID for user"""
        ...
    
    async def create_chat_session(self, session_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new chat session"""
        ...
    
    async def get_chat_messages(self, session_id: UUID, user_id: UUID, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """Get chat messages for session"""
        ...
    
    async def create_chat_message(self, message_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new chat message"""
        ...
    
    async def get_api_key(self, key_id: UUID, user_id: UUID) -> Optional[Dict[str, Any]]:
        """Get API key by ID for user"""
        ...
    
    async def create_api_key(self, key_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create new API key"""
        ...
    
    async def update_api_key(self, key_id: UUID, key_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update API key"""
        ...
    
    async def delete_api_key(self, key_id: UUID, user_id: UUID) -> bool:
        """Delete API key"""
        ...
    
    async def list_api_keys(self, user_id: UUID) -> List[Dict[str, Any]]:
        """List user API keys"""
        ...
    
    async def get_ai_usage(self, user_id: UUID, days: int = 30) -> List[Dict[str, Any]]:
        """Get AI usage statistics for user"""
        ...
    
    async def create_ai_usage(self, usage_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create AI usage record"""
        ...

class UserRepositoryProtocol(Protocol):
    """Protocol for user repository implementations"""
    
    async def find_by_id(self, user_id: UUID) -> Optional[Dict[str, Any]]:
        """Find user by ID"""
        ...
    
    async def find_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Find user by email"""
        ...
    
    async def save(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Save user"""
        ...
    
    async def update(self, user_id: UUID, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update user"""
        ...
    
    async def delete(self, user_id: UUID) -> bool:
        """Delete user"""
        ...

class ProjectRepositoryProtocol(Protocol):
    """Protocol for project repository implementations"""
    
    async def find_by_id(self, project_id: UUID) -> Optional[Dict[str, Any]]:
        """Find project by ID"""
        ...
    
    async def find_by_user_id(self, user_id: UUID, limit: int = 10, offset: int = 0) -> List[Dict[str, Any]]:
        """Find projects by user ID"""
        ...
    
    async def save(self, project_data: Dict[str, Any]) -> Dict[str, Any]:
        """Save project"""
        ...
    
    async def update(self, project_id: UUID, project_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update project"""
        ...
    
    async def delete(self, project_id: UUID) -> bool:
        """Delete project"""
        ...

class ChatRepositoryProtocol(Protocol):
    """Protocol for chat repository implementations"""
    
    async def find_session_by_id(self, session_id: UUID) -> Optional[Dict[str, Any]]:
        """Find chat session by ID"""
        ...
    
    async def find_sessions_by_project(self, project_id: UUID, limit: int = 10, offset: int = 0) -> List[Dict[str, Any]]:
        """Find chat sessions by project ID"""
        ...
    
    async def save_session(self, session_data: Dict[str, Any]) -> Dict[str, Any]:
        """Save chat session"""
        ...
    
    async def find_messages_by_session(self, session_id: UUID, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """Find messages by session ID"""
        ...
    
    async def save_message(self, message_data: Dict[str, Any]) -> Dict[str, Any]:
        """Save chat message"""
        ...