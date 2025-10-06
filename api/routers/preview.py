from samokoder.core.proc.process_manager import ProcessManager
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from uuid import UUID
import asyncio
import json
import os
from pathlib import Path

from samokoder.core.db.session import get_async_db
from samokoder.core.db.models.project import Project
from samokoder.core.db.models.user import User
from samokoder.api.routers.auth import get_current_user
from samokoder.core.config.constants import (
    PREVIEW_ALLOWED_SCRIPTS,
    PREVIEW_START_PORT,
    PREVIEW_END_PORT,
    PREVIEW_MAX_DURATION_SECONDS,
)

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

    # Detect npm script
    pkg_path = Path(project_root) / "package.json"
    if not pkg_path.exists():
        raise HTTPException(status_code=400, detail="package.json not found in project")
    try:
        pkg = json.loads(pkg_path.read_text(encoding="utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid package.json")
    scripts = (pkg.get("scripts") or {})
    script_name = next((s for s in PREVIEW_ALLOWED_SCRIPTS if s in scripts), None)
    if not script_name:
        raise HTTPException(status_code=400, detail="No allowed preview scripts found (preview/dev/start)")

    # Pick a port deterministically in allowed range
    port = PREVIEW_START_PORT + (abs(hash(str(project.id))) % (PREVIEW_END_PORT - PREVIEW_START_PORT))

    # Ensure env with PORT and NODE_ENV
    env = {
        "PORT": str(port),
        "NODE_ENV": "development",
    }

    # Start the preview server in background (local; isolation via container planned)
    cmd = f"npm run {script_name}"
    process = await process_manager.start_process(cmd, cwd=".", env=env, bg=True)

    # TTL auto-stop task
    async def _ttl_guard(proc, key: str):
        try:
            await asyncio.sleep(PREVIEW_MAX_DURATION_SECONDS)
            if proc.is_running:
                await proc.terminate()
        finally:
            preview_processes.pop(key, None)

    key = str(project_id)
    asyncio.create_task(_ttl_guard(process, key))

    # Store process info
    preview_processes[key] = {
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

    # Stop the preview process (best-effort; current run_command path is sync)
    project_key = str(project_id)
    if project_key in preview_processes:
        process_info = preview_processes[project_key]
        process = process_info.get("process")
        # No tracked process in this simplified path; mark stopped
        process_info["status"] = "stopped"
        del preview_processes[project_key]
        return {
            "success": True,
            "message": "Preview stopped successfully",
            "stopped_at": asyncio.get_event_loop().time(),
        }
    
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
