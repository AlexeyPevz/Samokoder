from __future__ import annotations

from typing import Dict

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from samokoder.core.log import get_logger
from samokoder.core.config import get_config

log = get_logger(__name__)
from samokoder.core.db.models.project import Project
from samokoder.core.db.models.user import User
from samokoder.core.db.session import get_async_db
from samokoder.api.routers.samokoder_integration import run_samokoder_for_project
from samokoder.api.routers.auth import get_current_user
from datetime import datetime, timedelta
from fastapi import Header

router = APIRouter()


async def get_current_user_ws(
    token: str | None = Query(None),
    ws_token: str | None = Header(None, alias="X-WS-Token"),
    db: AsyncSession = Depends(get_async_db),
) -> User:
    credentials_exception = HTTPException(status_code=401, detail="Could not validate credentials")

    try:
        config = get_config()
        effective_token = ws_token or token
        if not effective_token:
            raise credentials_exception
        payload = jwt.decode(effective_token, config.secret_key, algorithms=["HS256"])
        token_type = payload.get("type")
        # Allow only short-lived WS tokens; keep backward compatibility with access for a while
        if token_type not in {"ws", "access"}:
            raise credentials_exception
        email: str | None = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    result = await db.execute(select(User).where(User.email == email))
    user = result.scalars().first()
    if user is None:
        raise credentials_exception
    return user


async def get_project(project_id: str, user: User, db: AsyncSession) -> Project:
    result = await db.execute(
        select(Project).where(Project.id == project_id, Project.user_id == user.id)
    )
    project = result.scalars().first()
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


class ConnectionManager:
    def __init__(self) -> None:
        self.active_connections: Dict[str, WebSocket] = {}

    async def connect(self, websocket: WebSocket, user_id: str) -> None:
        await websocket.accept()
        self.active_connections[user_id] = websocket

    def disconnect(self, user_id: str) -> None:
        self.active_connections.pop(user_id, None)

    async def send_personal_message(self, message: str, user_id: str) -> None:
        if user_id in self.active_connections:
            await self.active_connections[user_id].send_text(message)


manager = ConnectionManager()


@router.post("/workspace/token")
async def issue_workspace_token(current_user: User = Depends(get_current_user)) -> Dict[str, str]:
    """Issue a short-lived (60s) token for WebSocket authentication."""
    config = get_config()
    now = datetime.utcnow()
    exp = now + timedelta(seconds=60)
    token = jwt.encode({"sub": current_user.email, "type": "ws", "iat": now, "exp": exp}, config.secret_key, algorithm="HS256")
    return {"token": token, "expires_in": 60}


@router.websocket("/ws/{project_id}")
async def websocket_endpoint(
    websocket: WebSocket,
    project_id: str,
    user: User = Depends(get_current_user_ws),
    db: AsyncSession = Depends(get_async_db),
) -> None:
    project = await get_project(project_id, user, db)

    try:
        await run_samokoder_for_project(websocket, user, project, db)
    except WebSocketDisconnect:  # pragma: no cover - handled by FastAPI runtime
        pass
    except Exception as exc:  # pragma: no cover - runtime errors reported to client
        try:
            await websocket.send_text(f"Error: {exc}")
        except (RuntimeError, WebSocketDisconnect):
            # WebSocket already closed, can't send error message
            log.error(f"WebSocket error and failed to send error message: {exc}")
    finally:
        manager.disconnect(str(user.id))
