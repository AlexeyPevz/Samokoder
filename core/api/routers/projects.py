from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from samokoder.core.db.session import get_db
from samokoder.core.api.dependencies import get_current_user
from samokoder.core.db.models.user import User
from samokoder.core.db.models.project import Project
from samokoder.core.api.middleware.limits import project_limits

router = APIRouter(prefix="/projects", tags=["projects"])

@router.get("/")
async def get_projects(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    projects = db.query(Project).filter(Project.user_id == current_user.id).all()
    return [{"id": p.id, "name": p.name, "description": p.description} for p in projects]

@router.post("/")
async def create_project(project_data: dict, current_user: User = Depends(get_current_user), db: Session = Depends(get_db), limits_check = Depends(project_limits)):
    project = Project(name=project_data["name"], description=project_data.get("description"), user_id=current_user.id)
    db.add(project)
    db.commit()
    db.refresh(project)
    return {"id": project.id, "name": project.name}

@router.get("/{project_id}")
async def get_project(project_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id, Project.user_id == current_user.id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return {"id": project.id, "name": project.name, "description": project.description}
