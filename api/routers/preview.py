from samokoder.core.proc.process_manager import ProcessManager
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from uuid import UUID
from datetime import datetime
import asyncio
import json
import os
from pathlib import Path
import docker

from samokoder.core.log import get_logger
from samokoder.core.db.session import get_async_db

log = get_logger(__name__)
from samokoder.core.db.models.project import Project
from samokoder.core.db.models.user import User
from samokoder.api.routers.auth import get_current_user
from samokoder.core.config.constants import (
    PREVIEW_ALLOWED_SCRIPTS,
    PREVIEW_START_PORT,
    PREVIEW_END_PORT,
    PREVIEW_MAX_DURATION_SECONDS,
)
from samokoder.core.api.middleware.tier_limits import require_deploy_access

router = APIRouter()

# In-memory storage for preview processes (P1-1: TODO - move to Redis for production)
preview_processes = {}

# Track active TTL guard tasks to prevent resource leaks
_active_ttl_tasks = set()

@router.post("/projects/{project_id}/preview/start")
async def start_preview(
    project_id: UUID, 
    user: User = Depends(get_current_user), 
    db: AsyncSession = Depends(get_async_db),  # P2-1: FIXED - async session
    _deploy_check = Depends(require_deploy_access)  # Tier-based deploy/preview access
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
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise HTTPException(status_code=400, detail=f"Invalid package.json: {str(e)}")
    except (OSError, IOError) as e:
        raise HTTPException(status_code=400, detail=f"Cannot read package.json: {str(e)}")
    scripts = (pkg.get("scripts") or {})
    script_name = next((s for s in PREVIEW_ALLOWED_SCRIPTS if s in scripts), None)
    if not script_name:
        raise HTTPException(status_code=400, detail="No allowed preview scripts found (preview/dev/start)")

    # Pick a port deterministically in allowed range (stable across restarts)
    # FIX: Use uuid.int instead of hash() for stable port assignment
    port = PREVIEW_START_PORT + (int(project.id.int) % (PREVIEW_END_PORT - PREVIEW_START_PORT))

    # Ensure env with PORT and NODE_ENV
    env = {
        "PORT": str(port),
        "NODE_ENV": "development",
    }

    use_container = os.getenv("ENABLE_PREVIEW_CONTAINER", "1") == "1"
    key = str(project_id)
    if use_container:
        try:
            client = docker.from_env()
            
            # SECURITY: Limit preview containers per user
            user_containers = client.containers.list(
                all=True,
                filters={
                    "label": [
                        "managed-by=samokoder",
                        "preview=true",
                        f"user_id={user.id}"
                    ]
                }
            )
            MAX_PREVIEW_CONTAINERS_PER_USER = int(os.getenv("MAX_PREVIEW_CONTAINERS_PER_USER", "5"))
            if len(user_containers) >= MAX_PREVIEW_CONTAINERS_PER_USER:
                raise HTTPException(
                    status_code=429,
                    detail=f"Maximum number of preview containers ({MAX_PREVIEW_CONTAINERS_PER_USER}) reached. Please stop some preview servers first."
                )
            
            container_name = f"samokoder-preview-{project.id}"
            vol_name = f"samokoder_preview_nm_{project.id}"
            
            # Check if container already exists
            try:
                existing_container = client.containers.get(container_name)
                # Container exists - stop and remove it first
                try:
                    existing_container.stop(timeout=5)
                except (docker.errors.APIError, docker.errors.NotFound):
                    pass  # Already stopped or doesn't exist
                existing_container.remove(force=True)
            except docker.errors.NotFound:
                pass  # Container doesn't exist, that's fine
            
            # Create or get named volume with labels
            try:
                volume = client.volumes.get(vol_name)
            except docker.errors.NotFound:
                volume = client.volumes.create(
                    name=vol_name,
                    labels={
                        "managed-by": "samokoder",
                        "project_id": str(project.id),
                        "creation_timestamp": datetime.utcnow().isoformat(),
                    }
                )
            
            # Compose the command: install deps if needed, then run script
            cmd = f"sh -lc \"[ -d node_modules ] || npm ci; npm run {script_name}\""
            container = client.containers.run(
                image="node:20-alpine",
                command=cmd,
                working_dir="/workspace",
                environment=env,
                volumes={
                    project_root: {"bind": "/workspace", "mode": "ro"},
                    vol_name: {"bind": "/workspace/node_modules", "mode": "rw"},
                },
                name=container_name,
                detach=True,
                labels={
                    "managed-by": "samokoder",
                    "preview": "true",
                    "project_id": str(project.id),
                    "user_id": str(user.id),
                    "creation_timestamp": datetime.utcnow().isoformat(),
                    "max_lifetime_hours": "1",
                },
                mem_limit="1g",
                nano_cpus=1_000_000_000,  # ~1 CPU
                ports={f"{port}/tcp": port},
                network_mode="bridge",
                tty=False,
            )

            async def _ttl_guard_container(cid: str, k: str):
                try:
                    await asyncio.sleep(PREVIEW_MAX_DURATION_SECONDS)
                    try:
                        c = client.containers.get(cid)
                        c.stop(timeout=5)
                        c.remove(v=True, force=True)
                    except (docker.errors.APIError, docker.errors.NotFound) as e:
                        log.debug(f"TTL guard cleanup failed (container may be already removed): {e}")
                    finally:
                        preview_processes.pop(k, None)
                finally:
                    # Remove task from tracking set when done
                    _active_ttl_tasks.discard(asyncio.current_task())

            task = asyncio.create_task(_ttl_guard_container(container.id, key))
            _active_ttl_tasks.add(task)
            preview_processes[key] = {
                "container_id": container.id,
                "port": port,
                "status": "running",
                "started_at": asyncio.get_event_loop().time(),
            }
        except Exception as e:
            # Fallback to local process if containerization fails
            cmd = f"npm run {script_name}"
            process = await process_manager.start_process(cmd, cwd=".", env=env, bg=True)
            async def _ttl_guard(proc, k: str):
                try:
                    await asyncio.sleep(PREVIEW_MAX_DURATION_SECONDS)
                    if proc.is_running:
                        await proc.terminate()
                finally:
                    preview_processes.pop(k, None)
                    # Remove task from tracking set when done
                    _active_ttl_tasks.discard(asyncio.current_task())
            task = asyncio.create_task(_ttl_guard(process, key))
            _active_ttl_tasks.add(task)
            preview_processes[key] = {
                "process": process,
                "port": port,
                "status": "running",
                "started_at": asyncio.get_event_loop().time(),
                "warning": f"container_fallback:{str(e)}",
            }
    else:
        # Local process mode
        cmd = f"npm run {script_name}"
        process = await process_manager.start_process(cmd, cwd=".", env=env, bg=True)
        async def _ttl_guard(proc, k: str):
            try:
                await asyncio.sleep(PREVIEW_MAX_DURATION_SECONDS)
                if proc.is_running:
                    await proc.terminate()
            finally:
                preview_processes.pop(k, None)
                # Remove task from tracking set when done
                _active_ttl_tasks.discard(asyncio.current_task())
        task = asyncio.create_task(_ttl_guard(process, key))
        _active_ttl_tasks.add(task)
        preview_processes[key] = {
            "process": process,
            "port": port,
            "status": "running",
            "started_at": asyncio.get_event_loop().time(),
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
        try:
            if cid := process_info.get("container_id"):
                client = docker.from_env()
                try:
                    c = client.containers.get(cid)
                    c.stop(timeout=5)
                    c.remove(v=True, force=True)
                except (docker.errors.APIError, docker.errors.NotFound) as e:
                    log.debug(f"Container cleanup failed: {e}")
            elif proc := process_info.get("process"):
                try:
                    await proc.terminate()
                except (AttributeError, RuntimeError) as e:
                    log.debug(f"Process termination failed: {e}")
        finally:
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
        
        # Check if container or process is still alive
        if "container_id" in process_info:
            # Container-based preview - assume running if in dict
            # (container cleanup happens in TTL guard)
            return {
                "status": {
                    "url": f"http://localhost:{process_info['port']}", 
                    "status": "running",
                    "started_at": process_info.get("started_at"),
                    "uptime_seconds": asyncio.get_event_loop().time() - process_info.get("started_at", 0)
                }
            }
        elif "process" in process_info:
            # Process-based preview
            process = process_info["process"]
            if process and process.is_running:
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
