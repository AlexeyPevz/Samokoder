"""
Project management endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, status, Query
from backend.models.requests import ProjectCreateRequest, ProjectUpdateRequest
from backend.models.responses import ProjectResponse, ProjectListResponse, ProjectCreateResponse
from backend.auth.dependencies import get_current_user
from backend.middleware.secure_rate_limiter import api_rate_limit
# from backend.services.connection_pool import connection_pool_manager
from backend.services.supabase_manager import execute_supabase_operation
import logging
from datetime import datetime
import uuid

logger = logging.getLogger(__name__)

router = APIRouter()

@router.post("/", response_model=ProjectCreateResponse)
async def create_project(
    project_data: ProjectCreateRequest,
    current_user: dict = Depends(get_current_user),
    rate_limit: dict = Depends(api_rate_limit)
):
    """Create a new project"""
    try:
        
        project_id = str(uuid.uuid4())
        workspace_path = f"workspaces/{current_user['id']}/{project_id}"
        
        # Create project record
        project_record = {
            "id": project_id,
            "user_id": current_user["id"],
            "name": project_data.name,
            "description": project_data.description,
            "ai_config": project_data.ai_config or {},
            "workspace_path": workspace_path,
            "is_active": True
        }
        
        response = await execute_supabase_operation(
            lambda client: client.table("projects").insert(project_record),
            "anon"
        )
        
        if not response.data:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create project"
            )
        
        # Create workspace directory
        os.makedirs(workspace_path, exist_ok=True)
        
        return ProjectCreateResponse(
            project_id=project_id,
            message="Проект создан, готов к работе"
        )
        
    except Exception as e:
        logger.error(f"Failed to create project: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create project"
        )

@router.get("/", response_model=ProjectListResponse)
async def list_projects(
    current_user: dict = Depends(get_current_user),
    limit: int = Query(10, ge=1, le=100),
    offset: int = Query(0, ge=0),
    rate_limit: dict = Depends(api_rate_limit)
):
    """List user projects"""
    try:
        
        response = await execute_supabase_operation(
            lambda client: client.table("projects").select("*").eq("user_id", current_user["id"]).eq("is_active", True).range(offset, offset + limit - 1),
            "anon"
        )
        
        projects = []
        for project in response.data:
            projects.append(ProjectResponse(
                id=project["id"],
                name=project["name"],
                description=project["description"],
                ai_config=project["ai_config"],
                workspace_path=project["workspace_path"],
                created_at=project["created_at"],
                updated_at=project["updated_at"]
            ))
        
        return ProjectListResponse(
            projects=projects,
            total=len(projects),
            limit=limit,
            offset=offset
        )
        
    except Exception as e:
        logger.error(f"Failed to list projects: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list projects"
        )

@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(
    project_id: str,
    current_user: dict = Depends(get_current_user),
    rate_limit: dict = Depends(api_rate_limit)
):
    """Get project by ID"""
    try:
        
        response = await execute_supabase_operation(
            lambda client: client.table("projects").select("*").eq("id", project_id).eq("user_id", current_user["id"])
        )
        
        if not response.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found"
            )
        
        project = response.data[0]
        
        return ProjectResponse(
            id=project["id"],
            name=project["name"],
            description=project["description"],
            ai_config=project["ai_config"],
            workspace_path=project["workspace_path"],
            created_at=project["created_at"],
            updated_at=project["updated_at"]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get project {project_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get project"
        )

@router.put("/{project_id}", response_model=ProjectResponse)
async def update_project(
    project_id: str,
    project_data: ProjectUpdateRequest,
    current_user: dict = Depends(get_current_user),
    rate_limit: dict = Depends(api_rate_limit)
):
    """Update project"""
    try:
        
        # Check if project exists and belongs to user
        existing_response = await execute_supabase_operation(
            lambda client: client.table("projects").select("*").eq("id", project_id).eq("user_id", current_user["id"])
        )
        
        if not existing_response.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found"
            )
        
        # Update project
        update_data = project_data.dict(exclude_unset=True)
        update_data["updated_at"] = datetime.now().isoformat()
        
        response = await execute_supabase_operation(
            lambda client: client.table("projects").update(update_data).eq("id", project_id)
        )
        
        if not response.data:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update project"
            )
        
        project = response.data[0]
        
        return ProjectResponse(
            id=project["id"],
            name=project["name"],
            description=project["description"],
            ai_config=project["ai_config"],
            workspace_path=project["workspace_path"],
            created_at=project["created_at"],
            updated_at=project["updated_at"]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update project {project_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update project"
        )

@router.delete("/{project_id}")
async def delete_project(
    project_id: str,
    current_user: dict = Depends(get_current_user),
    rate_limit: dict = Depends(api_rate_limit)
):
    """Delete project (soft delete)"""
    try:
        
        # Check if project exists and belongs to user
        existing_response = await execute_supabase_operation(
            lambda client: client.table("projects").select("*").eq("id", project_id).eq("user_id", current_user["id"])
        )
        
        if not existing_response.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found"
            )
        
        # Soft delete project
        response = await execute_supabase_operation(
            lambda client: client.table("projects").update({"is_active": False}).eq("id", project_id)
        )
        
        if not response.data:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to delete project"
            )
        
        return {"message": "Проект удален"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete project {project_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete project"
        )

@router.get("/{project_id}/files")
async def get_project_files(
    project_id: str,
    current_user: dict = Depends(get_current_user),
    rate_limit: dict = Depends(api_rate_limit)
):
    """Get project files list"""
    try:
        
        # Check if project exists and belongs to user
        project_response = await execute_supabase_operation(
            lambda client: client.table("projects").select("*").eq("id", project_id).eq("user_id", current_user["id"])
        )
        
        if not project_response.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found"
            )
        
        # Mock implementation - in real app would read from filesystem
        files = [
            {
                "name": "main.py",
                "path": "main.py",
                "size": 1024,
                "type": "file",
                "modified_at": "2024-12-19T10:00:00Z"
            },
            {
                "name": "requirements.txt",
                "path": "requirements.txt", 
                "size": 512,
                "type": "file",
                "modified_at": "2024-12-19T10:00:00Z"
            }
        ]
        
        return {
            "files": files,
            "total_count": len(files),
            "project_id": project_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get project files {project_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get project files"
        )

@router.get("/{project_id}/files/{file_path:path}")
async def get_file_content(
    project_id: str,
    file_path: str,
    current_user: dict = Depends(get_current_user),
    rate_limit: dict = Depends(api_rate_limit)
):
    """Get file content"""
    try:
        
        # Check if project exists and belongs to user
        project_response = await execute_supabase_operation(
            lambda client: client.table("projects").select("*").eq("id", project_id).eq("user_id", current_user["id"])
        )
        
        if not project_response.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found"
            )
        
        # Mock implementation - in real app would read from filesystem
        content = f"# Mock content for {file_path}\n# This is a placeholder implementation"
        
        return {
            "file_path": file_path,
            "content": content,
            "project_id": project_id,
            "size": len(content)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get file content {project_id}/{file_path}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get file content"
        )

@router.post("/{project_id}/chat")
async def chat_with_project(
    project_id: str,
    chat_data: dict,
    current_user: dict = Depends(get_current_user),
    rate_limit: dict = Depends(api_rate_limit)
):
    """Chat with project AI assistant"""
    try:
        
        # Check if project exists and belongs to user
        project_response = await execute_supabase_operation(
            lambda client: client.table("projects").select("*").eq("id", project_id).eq("user_id", current_user["id"])
        )
        
        if not project_response.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found"
            )
        
        # Mock implementation - in real app would use AI service
        message = chat_data.get("message", "")
        response = f"AI Assistant for project {project_id}: I received your message: '{message}'. This is a mock response."
        
        return {
            "message": response,
            "project_id": project_id,
            "timestamp": "2024-12-19T10:00:00Z",
            "agent": "project_ai"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to chat with project {project_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to chat with project"
        )

@router.post("/{project_id}/generate")
async def generate_project_code(
    project_id: str,
    generation_data: dict,
    current_user: dict = Depends(get_current_user),
    rate_limit: dict = Depends(api_rate_limit)
):
    """Generate code for project"""
    try:
        
        # Check if project exists and belongs to user
        project_response = await execute_supabase_operation(
            lambda client: client.table("projects").select("*").eq("id", project_id).eq("user_id", current_user["id"])
        )
        
        if not project_response.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found"
            )
        
        # Mock implementation - in real app would use AI service
        prompt = generation_data.get("prompt", "")
        generated_files = [
            {
                "path": "generated_file.py",
                "content": f"# Generated code for: {prompt}\nprint('Hello from generated code!')",
                "size": 100
            }
        ]
        
        return {
            "generated_files": generated_files,
            "message": "Code generation completed",
            "project_id": project_id,
            "timestamp": "2024-12-19T10:00:00Z"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to generate code for project {project_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate code"
        )

@router.post("/{project_id}/export")
async def export_project(
    project_id: str,
    current_user: dict = Depends(get_current_user),
    rate_limit: dict = Depends(api_rate_limit)
):
    """Export project as ZIP"""
    try:
        
        # Check if project exists and belongs to user
        project_response = await execute_supabase_operation(
            lambda client: client.table("projects").select("*").eq("id", project_id).eq("user_id", current_user["id"])
        )
        
        if not project_response.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found"
            )
        
        # Mock implementation - in real app would create ZIP
        return {
            "message": "Project export initiated",
            "project_id": project_id,
            "download_url": f"/api/projects/{project_id}/download/export.zip",
            "status": "processing"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to export project {project_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to export project"
        )