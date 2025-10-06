import os
from arq import create_pool
from arq.connections import RedisSettings
from fastapi import WebSocket
from samokoder.core.db.models import User, Project, Project, Project, Project, Project, Project, Project, Project, Project, Project, Project
from sqlalchemy.orm import Session

async def run_samokoder_for_project(
    websocket: WebSocket, 
    user: User, 
    project: Project, 
    db: Session
):
    """
    Enqueues a background task to run Samokoder core for a specific project.
    
    :param websocket: WebSocket connection
    :param user: User object
    :param project: Project object
    :param db: Database session
    """
    ui = WebSocketUI(websocket, str(user.id))
    await ui.start()

    try:
        # Create a connection pool to Redis
        redis_pool = await create_pool(
            RedisSettings(
                host=os.getenv("REDIS_HOST", "localhost"),
                port=int(os.getenv("REDIS_PORT", 6379)),
            )
        )

        # Enqueue the job for the background worker
        job = await redis_pool.enqueue_job(
            "run_generation_task",  # This matches the function name in worker.py
            str(project.id),
            user.id
        )

        if job:
            await ui.send_message(
                f"Project generation has been queued successfully (Job ID: {job.job_id}). "
                f"You can close this window; the process will continue in the background.",
                source="system"
            )
        else:
            await ui.send_message("Error: Could not queue project generation task.", source="system")

    except Exception as e:
        await ui.send_message(f"Error submitting task to queue: {str(e)}", source="system")
        raise
    finally:
        await websocket.close()
