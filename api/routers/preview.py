from samokoder.core.proc.process_manager import ProcessManager
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from uuid import UUID
import asyncio

from samokoder.core.db.session import get_async_db
from samokoder.core.db.models.project import Project
from samokoder.core.db.models.user import User
from samokoder.api.routers.auth import get_current_user

router = APIRouter()

# In-memory storage for preview processes (P1-1: TODO - move to Redis for production)
preview_processes = {}

@router.post("/projects/{project_id}/preview/start")
async def start_preview(
    project_id: UUID, 
    user: User = Depends(get_current_user), 
    db: AsyncSession = Depends(get_async_db)  # P2-1: FIXED - async session
):
    """Start preview server for a project (P1-1: IMPROVED)."""
    result = await db.execute(
        select(Project).where(Project.id == project_id, Project.user_id == user.id)
    )
    project = result.scalars().first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    project_root = f"/workspace/projects/{project.id}"
    process_manager = ProcessManager(project_root)
    
    # Start the preview server in background
    process = await process_manager.run_command("npm run dev", background=True)
    
    # Store process info
    port = 3001  # TODO: Dynamic port allocation
    preview_processes[str(project_id)] = {
        "process": process,
        "port": port,
        "status": "running",
        "started_at": asyncio.get_event_loop().time()
    }
    
    return {"url": f"http://localhost:{port}", "status": "running", "process_id": str(project_id)}

@router.post("/projects/{project_id}/preview/stop")
async def stop_preview(
    project_id: UUID, 
    user: User = Depends(get_current_user), 
    db: AsyncSession = Depends(get_async_db)  # P2-1: FIXED - async session
):
    """Stop preview server for a project (P1-1: IMPLEMENTED)."""
    result = await db.execute(
        select(Project).where(Project.id == project_id, Project.user_id == user.id)
    )
    project = result.scalars().first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Stop the preview process
    project_key = str(project_id)
    if project_key in preview_processes:
        process_info = preview_processes[project_key]
        process = process_info.get("process")
        
        if process:
            try:
                process.terminate()
                await asyncio.sleep(1)  # Give it time to terminate gracefully
                if process.poll() is None:  # Still running
                    process.kill()  # Force kill
                
                process_info["status"] = "stopped"
                del preview_processes[project_key]
                
                return {
                    "success": True, 
                    "message": "Preview stopped successfully",
                    "stopped_at": asyncio.get_event_loop().time()
                }
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Failed to stop preview: {str(e)}")
    
    return {"success": True, "message": "Preview was not running"}

@router.get("/projects/{project_id}/preview/status")
async def get_preview_status(
    project_id: UUID, 
    user: User = Depends(get_current_user), 
    db: AsyncSession = Depends(get_async_db)  # P2-1: FIXED - async session
):
    """Get preview server status for a project (P1-1: IMPLEMENTED)."""
    result = await db.execute(
        select(Project).where(Project.id == project_id, Project.user_id == user.id)
    )
    project = result.scalars().first()
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Check if preview is running
    project_key = str(project_id)
    if project_key in preview_processes:
        process_info = preview_processes[project_key]
        process = process_info.get("process")
        
        # Check if process is still alive
        if process and process.poll() is None:
            return {
                "status": {
                    "url": f"http://localhost:{process_info['port']}", 
                    "status": "running",
                    "started_at": process_info.get("started_at"),
                    "uptime_seconds": asyncio.get_event_loop().time() - process_info.get("started_at", 0)
                }
            }
        else:
            # Process died
            del preview_processes[project_key]
    
    return {"status": {"status": "stopped", "url": None}}
