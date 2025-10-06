from __future__ import annotations

import asyncio
from datetime import datetime
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from samokoder.core.ui.base import AgentSource, UIBase
from samokoder.core.db.models import ProjectRun, ProjectRunStatus


class RunLogUI(UIBase):
    def __init__(self, db: AsyncSession, run: ProjectRun):
        self.db = db
        self.run = run
        self._lock = asyncio.Lock()

    def build_namespace(self):
        class Namespace:
            no_check = False
            project = None
            branch = None
            step = None
            list = False
            list_json = False
            show_config = False
            import_v0 = None
            delete = None
            email = None
            extension_version = None
            use_git = True

        return Namespace()

    async def start(self) -> bool:
        return True

    async def stop(self):
        await self._flush()

    async def _append(self, message: str) -> None:
        async with self._lock:
            if self.run.logs:
                self.run.logs += f"\n{message}"
            else:
                self.run.logs = message
            self.run.updated_at = datetime.utcnow()
            await self.db.commit()

    async def _flush(self):
        await self.db.commit()

    async def send_stream_chunk(self, chunk: str, *, source: AgentSource | None = None, project_state_id: str | None = None):
        await self._append(chunk)

    async def send_message(self, message: str, *, source: AgentSource | None = None, project_state_id: str | None = None, extra_info: str | None = None):
        await self._append(message)

    async def send_key_expired(self, message: str | None = None):
        await self._append(message or "API key expired")

    async def send_app_finished(self, app_id: str | None = None, app_name: str | None = None, folder_name: str | None = None):
        await self._append("Application build finished")

    async def send_feature_finished(self, app_id: str | None = None, app_name: str | None = None, folder_name: str | None = None):
        await self._append("Feature finished")

    async def ask_question(self, question: str, **kwargs):
        from samokoder.core.ui.base import UserInput
        return UserInput(cancelled=True)
