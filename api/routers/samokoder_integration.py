import os
from arq import create_pool
from arq.connections import RedisSettings
from fastapi import WebSocket
from samokoder.core.db.models import User, Project
from sqlalchemy.orm import Session
from samokoder.api.ws import WebSocketUI  # adjust import if needed

async def run_samokoder_for_project(
    websocket: WebSocket,
    user: User,
    project: Project,
    db: Session,
):
    """
    Поставить задачу в очередь для запуска ядра самокодера по конкретному проекту.
    """
    ui = WebSocketUI(websocket, str(user.id))
    await ui.start()

    try:
        redis_pool = await create_pool(
            RedisSettings(
                host=os.getenv("REDIS_HOST", "localhost"),
                port=int(os.getenv("REDIS_PORT", 6379)),
            )
        )

        job = await redis_pool.enqueue_job(
            "run_generation_task",
            str(project.id),
            user.id,
        )

        if job:
            await ui.send_message(
                f"Задача на генерацию проекта поставлена в очередь (Job ID: {job.job_id}). ",
                source="system",
            )
        else:
            await ui.send_message("Ошибка: не удалось поставить задачу в очередь.", source="system")

    except Exception as e:
        await ui.send_message(f"Ошибка постановки задачи в очередь: {str(e)}", source="system")
        raise
    finally:
        await websocket.close()
