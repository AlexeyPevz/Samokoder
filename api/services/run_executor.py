from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from samokoder.core.agents.orchestrator import Orchestrator
from samokoder.core.config import get_config
from samokoder.core.db.models import ProjectRun, ProjectRunStatus, Project, User
from samokoder.core.db.session import SessionManager
from samokoder.core.state.state_manager import StateManager
from samokoder.api.services.stream_ui import RunLogUI

logger = logging.getLogger(__name__)


async def execute_project_run(run_id: UUID, db: AsyncSession) -> None:
    run = await db.get(ProjectRun, run_id)
    if run is None:
        logger.error("Project run %s not found", run_id)
        return

    try:
        project = await db.get(Project, run.project_id)
        user = await db.get(User, run.user_id)
        if project is None or user is None:
            raise RuntimeError("Related project or user not found")

        run.status = ProjectRunStatus.RUNNING
        run.updated_at = datetime.utcnow()
        await db.commit()

        config = get_config()
        session_manager = SessionManager(config.db)
        ui = RunLogUI(db, run)

        sm = StateManager(session_manager, ui)
        if project.gpt_pilot_state:
            await sm.load_project(project_id=project.id)
        else:
            await sm.create_project(project.name, user_id=user.id)

        orchestrator = Orchestrator(sm, ui, ui.build_namespace())
        success = await orchestrator.run()

        run.status = ProjectRunStatus.SUCCEEDED if success else ProjectRunStatus.FAILED
    except Exception as exc:  # pragma: no cover - logged for observability
        logger.exception("Project run %s failed", run_id)
        run.status = ProjectRunStatus.FAILED
        run.error = str(exc)
    finally:
        run.finished_at = datetime.utcnow()
        run.updated_at = datetime.utcnow()
        await db.commit()
