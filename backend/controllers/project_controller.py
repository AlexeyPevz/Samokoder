"""
Project Controller
Контроллер для управления проектами
"""

import logging
from typing import Dict, List, Optional, Any
from uuid import UUID

from backend.services.supabase_manager import execute_supabase_operation
from backend.services.project_state_manager import ProjectStateManager
from backend.services.gpt_pilot_wrapper_v2 import SamokoderGPTPilot
from backend.models.requests import ProjectCreateRequest, ProjectUpdateRequest
from backend.models.responses import ProjectResponse, ProjectListResponse, ProjectCreateResponse

logger = logging.getLogger(__name__)

class ProjectController:
    """Контроллер для управления проектами"""
    
    def __init__(self):
        self.state_manager = ProjectStateManager()
    
    async def create_project(self, user_id: str, request: ProjectCreateRequest) -> ProjectCreateResponse:
        """Создать новый проект"""
        try:
            # Создаем проект в базе данных
            project_data = {
                "name": request.name,
                "description": request.description,
                "user_id": user_id,
                "status": "active",
                "is_active": True
            }
            
            def create_project_db(client):
                return client.table("projects").insert(project_data).execute()
            
            result = await execute_supabase_operation(create_project_db, "anon")
            
            if not result.data:
                raise Exception("Failed to create project in database")
            
            project_id = result.data[0]["id"]
            
            # Создаем рабочую директорию
            workspace_path = f"workspaces/{user_id}/{project_id}"
            
            # Инициализируем состояние проекта
            await self.state_manager.initialize_project(project_id, user_id, workspace_path)
            
            logger.info(f"Project {project_id} created for user {user_id}")
            
            return ProjectCreateResponse(
                success=True,
                message="Проект создан, готов к работе",
                project_id=project_id,
                workspace_path=workspace_path
            )
            
        except Exception as e:
            logger.error(f"Error creating project: {e}")
            return ProjectCreateResponse(
                success=False,
                message=f"Ошибка создания проекта: {str(e)}",
                project_id="",
                workspace_path=""
            )
    
    async def get_project(self, project_id: str, user_id: str) -> Optional[ProjectResponse]:
        """Получить проект по ID"""
        try:
            def get_project_db(client):
                return client.table("projects").select("*").eq("id", project_id).eq("user_id", user_id).eq("is_active", True).execute()
            
            result = await execute_supabase_operation(get_project_db, "anon")
            
            if not result.data:
                return None
            
            project_data = result.data[0]
            return ProjectResponse(**project_data)
            
        except Exception as e:
            logger.error(f"Error getting project {project_id}: {e}")
            return None
    
    async def list_projects(self, user_id: str, limit: int = 10, offset: int = 0, 
                          project_status: Optional[str] = None, search: Optional[str] = None) -> ProjectListResponse:
        """Получить список проектов пользователя"""
        try:
            def build_query(client):
                query = client.table("projects").select("*").eq("user_id", user_id).eq("is_active", True)
                
                if project_status:
                    query = query.eq("status", project_status)
                
                if search:
                    # Безопасный поиск с параметризованными запросами
                    search_pattern = f"%{search}%"
                    query = query.or_("name.ilike.{search_pattern},description.ilike.{search_pattern}".format(search_pattern=search_pattern))
                
                return query.range(offset, offset + limit - 1)
            
            result = await execute_supabase_operation(build_query, "anon")
            
            projects = [ProjectResponse(**project) for project in result.data]
            
            return ProjectListResponse(
                projects=projects,
                total=len(projects),
                limit=limit,
                offset=offset
            )
            
        except Exception as e:
            logger.error(f"Error listing projects: {e}")
            return ProjectListResponse(projects=[], total=0, limit=limit, offset=offset)
    
    async def update_project(self, project_id: str, user_id: str, request: ProjectUpdateRequest) -> bool:
        """Обновить проект"""
        try:
            update_data = {}
            if request.name is not None:
                update_data["name"] = request.name
            if request.description is not None:
                update_data["description"] = request.description
            if request.status is not None:
                update_data["status"] = request.status
            
            if not update_data:
                return True
            
            def update_project_db(client):
                return client.table("projects").update(update_data).eq("id", project_id).eq("user_id", user_id).execute()
            
            result = await execute_supabase_operation(update_project_db, "anon")
            
            logger.info(f"Project {project_id} updated")
            return True
            
        except Exception as e:
            logger.error(f"Error updating project {project_id}: {e}")
            return False
    
    async def delete_project(self, project_id: str, user_id: str) -> bool:
        """Удалить проект (мягкое удаление)"""
        try:
            def delete_project_db(client):
                return client.table("projects").update({"is_active": False}).eq("id", project_id).eq("user_id", user_id).execute()
            
            await execute_supabase_operation(delete_project_db, "anon")
            
            # Очищаем состояние проекта
            await self.state_manager.cleanup_project(project_id)
            
            logger.info(f"Project {project_id} deleted")
            return True
            
        except Exception as e:
            logger.error(f"Error deleting project {project_id}: {e}")
            return False
    
    async def get_project_state(self, project_id: str) -> Dict[str, Any]:
        """Получить состояние проекта"""
        try:
            return await self.state_manager.get_project_state(project_id)
        except Exception as e:
            logger.error(f"Error getting project state {project_id}: {e}")
            return {}

# Глобальный экземпляр контроллера
_project_controller: Optional[ProjectController] = None

def get_project_controller() -> ProjectController:
    """Получить экземпляр контроллера проектов"""
    global _project_controller
    if _project_controller is None:
        _project_controller = ProjectController()
    return _project_controller