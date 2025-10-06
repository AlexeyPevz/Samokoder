from samokoder.core.proc.process_manager import ProcessManager
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from uuid import UUID

from samokoder.core.db.session import get_db
from samokoder.core.db.models.project import Project
from samokoder.core.db.models.user import User
from samokoder.api.routers.auth import get_current_user

router = APIRouter()

@router.post("/projects/{project_id}/preview/start")
async def start_preview(project_id: UUID, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id, Project.user_id == user.id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    project_root = f"/workspace/projects/{project.id}"
    process_manager = ProcessManager(project_root)
    
    await process_manager.run_command("npm run dev", background=True)
    
    port = 3001 # Assuming a fixed port for now
    return {"url": f"http://localhost:{port}", "status": "running"}

@router.post("/projects/{project_id}/preview/stop")
async def stop_preview(project_id: UUID, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id, Project.user_id == user.id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # TODO: Implement the logic to stop the preview

    return {"success": True, "message": "Preview stopped successfully"}

@router.get("/projects/{project_id}/preview/status")
async def get_preview_status(project_id: UUID, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id, Project.user_id == user.id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # TODO: Implement the logic to get the preview status

    return {"status": {"url": f"http://localhost:3001", "status": "running"}}
