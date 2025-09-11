"""
Chat Repository Implementation
"""
import logging
from typing import Optional, List, Dict, Any
from uuid import UUID
from backend.contracts.database import ChatRepositoryProtocol
from backend.services.connection_pool import connection_pool_manager
from backend.core.database_config import db_config
from backend.core.exceptions import (
    DatabaseError, NotFoundError, ValidationError, 
    ConnectionError, TimeoutError
)

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
            response = supabase.table(db_config.TABLES["chat_sessions"]).select(db_config.QUERIES["select_all"]).eq(db_config.COLUMNS["id"], str(session_id)).execute()
            return response.data[0] if response.data else None
        except ConnectionError as e:
            logger.error(f"Connection error finding chat session by ID {session_id}: {e}")
            raise DatabaseError(f"Database connection failed: {e}")
        except TimeoutError as e:
            logger.error(f"Timeout error finding chat session by ID {session_id}: {e}")
            raise DatabaseError(f"Database operation timed out: {e}")
        except Exception as e:
            logger.error(f"Failed to find chat session by ID {session_id}: {e}")
            raise DatabaseError(f"Database operation failed: {e}")
    
    async def find_sessions_by_project(self, project_id: UUID, limit: int = 10, offset: int = 0) -> List[Dict[str, Any]]:
        """Find chat sessions by project ID"""
        try:
            supabase = self._get_supabase()
            response = supabase.table(db_config.TABLES["chat_sessions"]).select(db_config.QUERIES["select_all"]).eq(db_config.COLUMNS["project_id"], str(project_id)).eq(db_config.COLUMNS["is_active"], True).range(offset, offset + limit - 1).order(db_config.QUERIES["order_created_desc"], desc=True).execute()
            return response.data or []
        except ConnectionError as e:
            logger.error(f"Connection error finding chat sessions by project ID {project_id}: {e}")
            raise DatabaseError(f"Database connection failed: {e}")
        except TimeoutError as e:
            logger.error(f"Timeout error finding chat sessions by project ID {project_id}: {e}")
            raise DatabaseError(f"Database operation timed out: {e}")
        except Exception as e:
            logger.error(f"Failed to find chat sessions by project ID {project_id}: {e}")
            raise DatabaseError(f"Database operation failed: {e}")
    
    async def save_session(self, session_data: Dict[str, Any]) -> Dict[str, Any]:
        """Save chat session"""
        try:
            supabase = self._get_supabase()
            response = supabase.table(db_config.TABLES["chat_sessions"]).insert(session_data).execute()
            return response.data[0] if response.data else {}
        except ValidationError as e:
            logger.error(f"Validation error saving chat session: {e}")
            raise
        except ConnectionError as e:
            logger.error(f"Connection error saving chat session: {e}")
            raise DatabaseError(f"Database connection failed: {e}")
        except TimeoutError as e:
            logger.error(f"Timeout error saving chat session: {e}")
            raise DatabaseError(f"Database operation timed out: {e}")
        except Exception as e:
            logger.error(f"Failed to save chat session: {e}")
            raise DatabaseError(f"Database operation failed: {e}")
    
    async def find_messages_by_session(self, session_id: UUID, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """Find messages by session ID"""
        try:
            supabase = self._get_supabase()
            response = supabase.table(db_config.TABLES["chat_messages"]).select(db_config.QUERIES["select_all"]).eq(db_config.COLUMNS["session_id"], str(session_id)).range(offset, offset + limit - 1).order(db_config.QUERIES["order_created_desc"], desc=False).execute()
            return response.data or []
        except ConnectionError as e:
            logger.error(f"Connection error finding messages by session ID {session_id}: {e}")
            raise DatabaseError(f"Database connection failed: {e}")
        except TimeoutError as e:
            logger.error(f"Timeout error finding messages by session ID {session_id}: {e}")
            raise DatabaseError(f"Database operation timed out: {e}")
        except Exception as e:
            logger.error(f"Failed to find messages by session ID {session_id}: {e}")
            raise DatabaseError(f"Database operation failed: {e}")
    
    async def save_message(self, message_data: Dict[str, Any]) -> Dict[str, Any]:
        """Save chat message"""
        try:
            supabase = self._get_supabase()
            response = supabase.table(db_config.TABLES["chat_messages"]).insert(message_data).execute()
            return response.data[0] if response.data else {}
        except ValidationError as e:
            logger.error(f"Validation error saving chat message: {e}")
            raise
        except ConnectionError as e:
            logger.error(f"Connection error saving chat message: {e}")
            raise DatabaseError(f"Database connection failed: {e}")
        except TimeoutError as e:
            logger.error(f"Timeout error saving chat message: {e}")
            raise DatabaseError(f"Database operation timed out: {e}")
        except Exception as e:
            logger.error(f"Failed to save chat message: {e}")
            raise DatabaseError(f"Database operation failed: {e}")
    
    async def find_sessions_by_user(self, user_id: UUID, limit: int = 20, offset: int = 0) -> List[Dict[str, Any]]:
        """Find chat sessions by user ID"""
        try:
            supabase = self._get_supabase()
            response = supabase.table(db_config.TABLES["chat_sessions"]).select(db_config.QUERIES["select_all"]).eq(db_config.COLUMNS["user_id"], str(user_id)).eq(db_config.COLUMNS["is_active"], True).range(offset, offset + limit - 1).order(db_config.QUERIES["order_updated_desc"], desc=True).execute()
            return response.data or []
        except ConnectionError as e:
            logger.error(f"Connection error finding chat sessions by user ID {user_id}: {e}")
            raise DatabaseError(f"Database connection failed: {e}")
        except TimeoutError as e:
            logger.error(f"Timeout error finding chat sessions by user ID {user_id}: {e}")
            raise DatabaseError(f"Database operation timed out: {e}")
        except Exception as e:
            logger.error(f"Failed to find chat sessions by user ID {user_id}: {e}")
            raise DatabaseError(f"Database operation failed: {e}")
    
    async def find_recent_sessions(self, user_id: UUID, limit: int = 5) -> List[Dict[str, Any]]:
        """Find recent chat sessions for user"""
        try:
            supabase = self._get_supabase()
            response = supabase.table(db_config.TABLES["chat_sessions"]).select(db_config.QUERIES["select_all"]).eq(db_config.COLUMNS["user_id"], str(user_id)).eq(db_config.COLUMNS["is_active"], True).order(db_config.QUERIES["order_updated_desc"], desc=True).limit(limit).execute()
            return response.data or []
        except ConnectionError as e:
            logger.error(f"Connection error finding recent chat sessions for user {user_id}: {e}")
            raise DatabaseError(f"Database connection failed: {e}")
        except TimeoutError as e:
            logger.error(f"Timeout error finding recent chat sessions for user {user_id}: {e}")
            raise DatabaseError(f"Database operation timed out: {e}")
        except Exception as e:
            logger.error(f"Failed to find recent chat sessions for user {user_id}: {e}")
            raise DatabaseError(f"Database operation failed: {e}")
    
    async def update_session(self, session_id: UUID, session_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update chat session"""
        try:
            supabase = self._get_supabase()
            response = supabase.table(db_config.TABLES["chat_sessions"]).update(session_data).eq(db_config.COLUMNS["id"], str(session_id)).execute()
            return response.data[0] if response.data else {}
        except ValidationError as e:
            logger.error(f"Validation error updating chat session {session_id}: {e}")
            raise
        except ConnectionError as e:
            logger.error(f"Connection error updating chat session {session_id}: {e}")
            raise DatabaseError(f"Database connection failed: {e}")
        except TimeoutError as e:
            logger.error(f"Timeout error updating chat session {session_id}: {e}")
            raise DatabaseError(f"Database operation timed out: {e}")
        except Exception as e:
            logger.error(f"Failed to update chat session {session_id}: {e}")
            raise DatabaseError(f"Database operation failed: {e}")
    
    async def delete_session(self, session_id: UUID) -> bool:
        """Delete chat session (soft delete)"""
        try:
            supabase = self._get_supabase()
            response = supabase.table(db_config.TABLES["chat_sessions"]).update({db_config.COLUMNS["is_active"]: False}).eq(db_config.COLUMNS["id"], str(session_id)).execute()
            return len(response.data) > 0
        except ConnectionError as e:
            logger.error(f"Connection error deleting chat session {session_id}: {e}")
            raise DatabaseError(f"Database connection failed: {e}")
        except TimeoutError as e:
            logger.error(f"Timeout error deleting chat session {session_id}: {e}")
            raise DatabaseError(f"Database operation timed out: {e}")
        except Exception as e:
            logger.error(f"Failed to delete chat session {session_id}: {e}")
            raise DatabaseError(f"Database operation failed: {e}")
    
    async def count_messages_by_session(self, session_id: UUID) -> int:
        """Count messages in session"""
        try:
            supabase = self._get_supabase()
            response = supabase.table(db_config.TABLES["chat_messages"]).select(db_config.QUERIES["count_exact"], count="exact").eq(db_config.COLUMNS["session_id"], str(session_id)).execute()
            return response.count or 0
        except ConnectionError as e:
            logger.error(f"Connection error counting messages for session {session_id}: {e}")
            raise DatabaseError(f"Database connection failed: {e}")
        except TimeoutError as e:
            logger.error(f"Timeout error counting messages for session {session_id}: {e}")
            raise DatabaseError(f"Database operation timed out: {e}")
        except Exception as e:
            logger.error(f"Failed to count messages for session {session_id}: {e}")
            raise DatabaseError(f"Database operation failed: {e}")