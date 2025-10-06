from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
import zipfile
from io import BytesIO
import os
from samokoder.core.api.dependencies import get_current_user
from samokoder.core.db.models.user import User
from samokoder.core.state.state_manager import StateManager

router = APIRouter(prefix="/projects", tags=["export"])

@router.get("/{project_id}/export")
async def export_project(project_id: str, current_user: User = Depends(get_current_user)):
    sm = StateManager.from_project_id(project_id, current_user.id)
    if not sm.project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    project_root = sm.get_full_project_root()
    if not project_root or not os.path.exists(project_root):
        raise HTTPException(status_code=404, detail="Project root not found")
    
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        for root, dirs, files in os.walk(project_root):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, project_root)
                zip_file.write(file_path, arcname)
    
    zip_buffer.seek(0)
    return StreamingResponse(
        iter([zip_buffer.getvalue()]),
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename=project-{project_id}.zip"}
    )
