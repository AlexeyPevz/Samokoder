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
import psutil

from redis.asyncio import Redis as AsyncRedis

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

# Redis-backed storage for preview processes (P1-1: moved from in-memory)
_redis_client: AsyncRedis | None = None
REDIS_PREVIEW_PREFIX = "preview:process:"


async def _get_redis() -> AsyncRedis:
    global _redis_client
    if _redis_client is None:
        # Prefer REDIS_URL; fallback to REDIS_HOST/PORT
        redis_url = os.getenv("REDIS_URL") or f"redis://{os.getenv('REDIS_HOST', 'localhost')}:{os.getenv('REDIS_PORT', '6379')}"
        _redis_client = AsyncRedis.from_url(redis_url, encoding="utf-8", decode_responses=True)
    return _redis_client


async def _save_preview_state(project_id: UUID, state: dict, ttl_seconds: int) -> None:
    r = await _get_redis()
    key = f"{REDIS_PREVIEW_PREFIX}{project_id}"
    await r.set(key, json.dumps(state), ex=int(ttl_seconds) + 300)


async def _load_preview_state(project_id: UUID) -> dict | None:
    r = await _get_redis()
    key = f"{REDIS_PREVIEW_PREFIX}{project_id}"
    raw = await r.get(key)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


async def _delete_preview_state(project_id: UUID) -> None:
    r = await _get_redis()
    key = f"{REDIS_PREVIEW_PREFIX}{project_id}"
    await r.delete(key)

# Track active TTL guard tasks to prevent resource leaks (per-instance)
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
                read_only=True,
                cap_drop=["ALL"],
                security_opt=["no-new-privileges:true"],
                pids_limit=256,
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
                        await _delete_preview_state(project_id)
                finally:
                    # Remove task from tracking set when done
                    _active_ttl_tasks.discard(asyncio.current_task())

            task = asyncio.create_task(_ttl_guard_container(container.id, key))
            _active_ttl_tasks.add(task)
            await _save_preview_state(
                project_id,
                {
                    "mode": "container",
                    "container_id": container.id,
                    "port": port,
                    "status": "running",
                    "started_at": asyncio.get_event_loop().time(),
                    "user_id": str(user.id),
                },
                PREVIEW_MAX_DURATION_SECONDS,
            )
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
                    await _delete_preview_state(project_id)
                    # Remove task from tracking set when done
                    _active_ttl_tasks.discard(asyncio.current_task())
            task = asyncio.create_task(_ttl_guard(process, key))
            _active_ttl_tasks.add(task)
            await _save_preview_state(
                project_id,
                {
                    "mode": "process",
                    "pid": process.pid,
                    "port": port,
                    "status": "running",
                    "started_at": asyncio.get_event_loop().time(),
                    "warning": f"container_fallback:{str(e)}",
                },
                PREVIEW_MAX_DURATION_SECONDS,
            )
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
                await _delete_preview_state(project_id)
                # Remove task from tracking set when done
                _active_ttl_tasks.discard(asyncio.current_task())
        task = asyncio.create_task(_ttl_guard(process, key))
        _active_ttl_tasks.add(task)
        await _save_preview_state(
            project_id,
            {
                "mode": "process",
                "pid": process.pid,
                "port": port,
                "status": "running",
                "started_at": asyncio.get_event_loop().time(),
            },
            PREVIEW_MAX_DURATION_SECONDS,
        )
    
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

    # Stop the preview process (best-effort)
    process_info = await _load_preview_state(project_id)
    if process_info:
        try:
            if process_info.get("mode") == "container" and (cid := process_info.get("container_id")):
                client = docker.from_env()
                try:
                    c = client.containers.get(cid)
                    c.stop(timeout=5)
                    c.remove(v=True, force=True)
                except (docker.errors.APIError, docker.errors.NotFound) as e:
                    log.debug(f"Container cleanup failed: {e}")
            elif process_info.get("mode") == "process" and (pid := process_info.get("pid")):
                try:
                    p = psutil.Process(pid)
                    if p.is_running():
                        p.terminate()
                except psutil.NoSuchProcess:
                    pass
        finally:
            await _delete_preview_state(project_id)
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

    # Load from Redis and perform liveness check
    process_info = await _load_preview_state(project_id)
    if not process_info:
        return {"status": {"status": "stopped", "url": None}}

    port = process_info.get("port")
    started_at = process_info.get("started_at", 0)
    mode = process_info.get("mode")

    if mode == "container" and (cid := process_info.get("container_id")):
        try:
            client = docker.from_env()
            c = client.containers.get(cid)
            c.reload()
            if c.status == "running":
                return {
                    "status": {
                        "url": f"http://localhost:{port}",
                        "status": "running",
                        "started_at": started_at,
                        "uptime_seconds": asyncio.get_event_loop().time() - started_at,
                    }
                }
        except docker.errors.NotFound:
            pass
        # Not running anymore
        await _delete_preview_state(project_id)
        return {"status": {"status": "stopped", "url": None}}

    if mode == "process" and (pid := process_info.get("pid")):
        try:
            p = psutil.Process(pid)
            if p.is_running():
                return {
                    "status": {
                        "url": f"http://localhost:{port}",
                        "status": "running",
                        "started_at": started_at,
                        "uptime_seconds": asyncio.get_event_loop().time() - started_at,
                    }
                }
        except psutil.NoSuchProcess:
            pass
        await _delete_preview_state(project_id)
        return {"status": {"status": "stopped", "url": None}}

    # Fallback
    await _delete_preview_state(project_id)
    return {"status": {"status": "stopped", "url": None}}
