"""
Project Repository Implementation
"""
import logging
from typing import Optional, List, Dict, Any
from uuid import UUID
from backend.contracts.database import ProjectRepositoryProtocol
from backend.services.connection_pool import connection_pool_manager
from backend.core.database_config import db_config

logger = logging.getLogger(__name__)

class ProjectRepository(ProjectRepositoryProtocol):
    """Project Repository Implementation"""
    
    def __init__(self):
        self._supabase = None
    
    def _get_supabase(self):
        """Get Supabase client"""
        if self._supabase is None:
            self._supabase = connection_pool_manager.get_supabase_client()
        return self._supabase
    
    async def find_by_id(self, project_id: UUID) -> Optional[Dict[str, Any]]:
        """Find project by ID"""
        try:
            supabase = self._get_supabase()
            response = supabase.table(db_config.TABLES["projects"]).select(db_config.QUERIES["select_all"]).eq(db_config.COLUMNS["id"], str(project_id)).execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error(f"Failed to find project by ID {project_id}: {e}")
            return None
    
    async def find_by_user_id(self, user_id: UUID, limit: int = 10, offset: int = 0) -> List[Dict[str, Any]]:
        """Find projects by user ID"""
        try:
            supabase = self._get_supabase()
            response = supabase.table(db_config.TABLES["projects"]).select(db_config.QUERIES["select_all"]).eq(db_config.COLUMNS["user_id"], str(user_id)).eq(db_config.COLUMNS["is_active"], True).range(offset, offset + limit - 1).order(db_config.QUERIES["order_created_desc"], desc=True).execute()
            return response.data or []
        except Exception as e:
            logger.error(f"Failed to find projects by user ID {user_id}: {e}")
            return []
    
    async def save(self, project_data: Dict[str, Any]) -> Dict[str, Any]:
        """Save project"""
        try:
            supabase = self._get_supabase()
            response = supabase.table(db_config.TABLES["projects"]).insert(project_data).execute()
            return response.data[0] if response.data else {}
        except Exception as e:
            logger.error(f"Failed to save project: {e}")
            raise
    
    async def update(self, project_id: UUID, project_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update project"""
        try:
            supabase = self._get_supabase()
            response = supabase.table(db_config.TABLES["projects"]).update(project_data).eq(db_config.COLUMNS["id"], str(project_id)).execute()
            return response.data[0] if response.data else {}
        except Exception as e:
            logger.error(f"Failed to update project {project_id}: {e}")
            raise
    
    async def delete(self, project_id: UUID) -> bool:
        """Delete project (soft delete)"""
        try:
            supabase = self._get_supabase()
            response = supabase.table(db_config.TABLES["projects"]).update({db_config.COLUMNS["is_active"]: False}).eq(db_config.COLUMNS["id"], str(project_id)).execute()
            return len(response.data) > 0
        except Exception as e:
            logger.error(f"Failed to delete project {project_id}: {e}")
            return False
    
    async def find_by_name(self, user_id: UUID, name: str) -> Optional[Dict[str, Any]]:
        """Find project by name for user"""
        try:
            supabase = self._get_supabase()
            response = supabase.table(db_config.TABLES["projects"]).select(db_config.QUERIES["select_all"]).eq(db_config.COLUMNS["user_id"], str(user_id)).eq("name", name).eq(db_config.COLUMNS["is_active"], True).execute()
            return response.data[0] if response.data else None
        except Exception as e:
            logger.error(f"Failed to find project by name {name} for user {user_id}: {e}")
            return None
    
    async def find_recent(self, user_id: UUID, limit: int = 5) -> List[Dict[str, Any]]:
        """Find recent projects for user"""
        try:
            supabase = self._get_supabase()
            response = supabase.table(db_config.TABLES["projects"]).select(db_config.QUERIES["select_all"]).eq(db_config.COLUMNS["user_id"], str(user_id)).eq(db_config.COLUMNS["is_active"], True).order(db_config.QUERIES["order_updated_desc"], desc=True).limit(limit).execute()
            return response.data or []
        except Exception as e:
            logger.error(f"Failed to find recent projects for user {user_id}: {e}")
            return []
    
    async def search(self, user_id: UUID, query: str, limit: int = 10, offset: int = 0) -> List[Dict[str, Any]]:
        """Search projects by name or description"""
        try:
            supabase = self._get_supabase()
            response = supabase.table(db_config.TABLES["projects"]).select(db_config.QUERIES["select_all"]).eq(db_config.COLUMNS["user_id"], str(user_id)).eq(db_config.COLUMNS["is_active"], True).or_(f"name.ilike.%{query}%,description.ilike.%{query}%").range(offset, offset + limit - 1).execute()
            return response.data or []
        except Exception as e:
            logger.error(f"Failed to search projects for user {user_id} with query {query}: {e}")
            return []
    
    async def count_by_user(self, user_id: UUID) -> int:
        """Count projects for user"""
        try:
            supabase = self._get_supabase()
            response = supabase.table(db_config.TABLES["projects"]).select(db_config.QUERIES["count_exact"], count="exact").eq(db_config.COLUMNS["user_id"], str(user_id)).eq(db_config.COLUMNS["is_active"], True).execute()
            return response.count or 0
        except Exception as e:
            logger.error(f"Failed to count projects for user {user_id}: {e}")
            return 0