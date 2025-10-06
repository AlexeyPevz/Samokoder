import asyncio
import logging
import os
import traceback
from copy import deepcopy
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Optional
from uuid import UUID, uuid4

from sqlalchemy import inspect, select
from sqlalchemy.exc import PendingRollbackError
from tenacity import retry, stop_after_attempt, wait_fixed

from samokoder.core.config import FileSystemType, get_config
from samokoder.core.db.models import (
    Branch,
    ExecLog,
    File,
    FileContent,
    LLMRequest,
    Project,
    ProjectState,
    UserInput,
)
from samokoder.core.db.models.specification import Complexity, Specification
from samokoder.core.db.session import SessionManager
from samokoder.core.disk.ignore import IgnoreMatcher
from samokoder.core.disk.vfs import DockerVFS, LocalDiskVFS, MemoryVFS, VirtualFileSystem
from samokoder.core.llm.request_log import LLMRequestLog
from samokoder.core.proc.exec_log import ExecLog as ExecLogData
from samokoder.core.telemetry import telemetry
from samokoder.core.ui.base import UIBase
from samokoder.core.ui.base import UserInput as UserInputData
from samokoder.core.utils.text import trim_logs

if TYPE_CHECKING:  # pragma: no cover
    from samokoder.core.agents.base import BaseAgent

log = logging.getLogger(__name__)


class StateManager:
    """Manage project state lifecycle (creation, loading, persistence)."""

    current_state: Optional[ProjectState]
    next_state: Optional[ProjectState]

    def __init__(
        self,
        session_manager: SessionManager,
        ui: Optional[UIBase] = None,
        *,
        config=None,
        user=None,
    ) -> None:
        self.session_manager = session_manager
        self.ui = ui

        cfg = config if config is not None else get_config()
        try:
            self.config = deepcopy(cfg)
        except TypeError:  # MagicMock or non deepcopyable config (tests)
            self.config = cfg

        self.user = user
        self.file_system: Optional[VirtualFileSystem] = None
        self.project: Optional[Project] = None
        self.branch: Optional[Branch] = None
        self.current_state: Optional[ProjectState] = None
        self.next_state: Optional[ProjectState] = None
        self.current_session = None
        self.blockDb = False
        self.git_available = False
        self.git_used = False
        self.options = {}
        self.container = None

    # ---------------------------------------------------------------------
    # Project lifecycle
    # ---------------------------------------------------------------------
    async def list_projects(self) -> list[Project]:
        async with self.session_manager as session:
            return await Project.get_all_projects(session)

    async def create_project(
        self,
        name: str = "temp-project",
        folder_name: Optional[str] = None,
        user_id: Optional[int] = None,
    ) -> Project:
        session = self.current_session or await self.session_manager.start()
        self.current_session = session

        project = Project(
            id=uuid4(),
            user_id=user_id,
            name=name,
            folder_name=folder_name or Project.get_folder_from_project_name(name),
            samokoder_state=None,
        )
        branch = Branch(project=project)
        state = ProjectState.create_initial_state(branch)

        session.add(project)
        session.add(branch)
        session.add(state)
        await state.awaitable_attrs.files
        await session.flush()
        await session.commit()
        await session.refresh(project)

        log.info(
            "Created project %s (id=%s) with branch %s (id=%s)",
            name,
            project.id,
            branch.name,
            branch.id,
        )
        telemetry.trace("create-project", {"name": name})

        self.project = project
        self.branch = branch
        self.current_state = state
        self.next_state = state
        self.file_system = await self.init_file_system(load_existing=False)
        return project

    async def delete_project(self, project_id: UUID) -> bool:
        session = await self.session_manager.start()
        rows = await Project.delete_by_id(session, project_id)
        if rows:
            await Specification.delete_orphans(session)
            await FileContent.delete_orphans(session)
        await session.commit()
        await self.session_manager.close(session)
        if rows:
            log.info("Deleted project %s", project_id)
        return bool(rows)

    async def load_project(
        self,
        *,
        project_id: Optional[UUID] = None,
        branch_id: Optional[UUID] = None,
        step_index: Optional[int] = None,
        project_state_id: Optional[UUID] = None,
    ) -> Optional[ProjectState]:
        if self.current_session:
            await self.rollback()

        session = await self.session_manager.start()
        branch: Optional[Branch] = None
        state: Optional[ProjectState] = None

        if branch_id is not None:
            branch = await Branch.get_by_id(session, branch_id)
        elif project_id is not None:
            project = await Project.get_by_id(session, project_id)
            if project is not None:
                branch = await project.get_branch()

        if branch is None:
            await self.session_manager.close(session)
            log.debug("Unable to find branch (project_id=%s, branch_id=%s)", project_id, branch_id)
            return None

        if step_index is not None:
            state = await branch.get_state_at_step(step_index)
        elif project_state_id is not None:
            state = await ProjectState.get_by_id(session, project_state_id)
            if state and state.branch_id != branch.id:
                log.warning(
                    "Project state %s does not belong to branch %s, loading last state instead.",
                    project_state_id,
                    branch.id,
                )
                state = None

        if state is None:
            state = await branch.get_last_state()

        if state is None:
            await self.session_manager.close(session)
            log.debug(
                "Unable to load project state (project_id=%s, branch_id=%s, step_index=%s, project_state_id=%s)",
                project_id,
                branch_id,
                step_index,
                project_state_id,
            )
            return None

        await state.delete_after()
        await session.commit()
        await state.awaitable_attrs.files

        # Trim logs for better readability (same workaround as upstream)
        if state.tasks and state.current_task:
            try:
                current_index = state.tasks.index(state.current_task)
                for idx in range(current_index):
                    task = state.tasks[idx]
                    if task.get("description"):
                        task["description"] = trim_logs(task["description"])
                state.flag_tasks_as_modified()
            except Exception as exc:  # pragma: no cover - defensive
                log.warning("Error during log trimming: %s", exc)

        self.current_session = session
        self.current_state = state
        self.branch = state.branch
        self.project = state.branch.project
        self.next_state = await state.create_next_state()
        self.file_system = await self.init_file_system(load_existing=True)

        telemetry.set(
            "architecture",
            {
                "system_dependencies": self.current_state.specification.system_dependencies,
                "package_dependencies": self.current_state.specification.package_dependencies,
            },
        )
        telemetry.set("example_project", self.current_state.specification.example_project)
        telemetry.set("is_complex_app", self.current_state.specification.complexity != Complexity.SIMPLE)
        telemetry.set("templates", self.current_state.specification.templates)

        return self.current_state

    # ------------------------------------------------------------------
    # Persistence utilities
    # ------------------------------------------------------------------
    @retry(stop=stop_after_attempt(3), wait=wait_fixed(1))
    async def commit_with_retry(self) -> None:
        try:
            await self.current_session.commit()
        except PendingRollbackError as exc:  # pragma: no cover - rare
            log.warning("Session pending rollback, retrying: %s", exc)
            await self.current_session.rollback()
            if self.next_state:
                self.current_session.add(self.next_state)
            raise

    async def commit(self) -> ProjectState:
        if self.next_state is None:
            raise ValueError("No state to commit.")
        if self.current_session is None:
            raise ValueError("No database session open.")

        try:
            await self.commit_with_retry()

            self.current_session.expunge_all()
            await self.session_manager.close(self.current_session)
            self.current_session = await self.session_manager.start()

            self.current_state = self.next_state
            self.current_session.add(self.current_state)
            self.next_state = await self.current_state.create_next_state()

            for file in self.current_state.files:
                await file.awaitable_attrs.content

            telemetry.inc("num_steps")
            return self.current_state
        except Exception as exc:
            log.error("Error during commit: %s", exc)
            log.error(traceback.format_exc())
            raise

    async def rollback(self) -> None:
        if not self.current_session:
            return
        await self.current_session.rollback()
        await self.session_manager.close(self.current_session)
        self.current_session = None

    # ------------------------------------------------------------------
    # File system helpers
    # ------------------------------------------------------------------
    async def init_file_system(self, load_existing: bool) -> VirtualFileSystem:
        fs_config = getattr(self.config, "fs", None) or get_config().fs
        fs_type = fs_config.type.value if isinstance(fs_config.type, FileSystemType) else fs_config.type
        fs_type = fs_type.lower()

        if fs_type == FileSystemType.MEMORY.value or fs_type == "memory":
            return MemoryVFS()

        if fs_type == "docker":  # pragma: no cover - not used in tests
            root = self.get_full_project_root()
            return DockerVFS(root)

        if fs_type != FileSystemType.LOCAL.value and fs_type != "local":
            raise ValueError(f"Unsupported file system type: {fs_type}")

        while True:
            root = self.get_full_project_root()
            ignore_matcher = IgnoreMatcher(
                root,
                fs_config.ignore_paths,
                ignore_size_threshold=fs_config.ignore_size_threshold,
            )
            try:
                return LocalDiskVFS(root, allow_existing=load_existing, ignore_matcher=ignore_matcher)
            except FileExistsError:
                self.project.folder_name = f"{self.project.folder_name}-{uuid4().hex[:7]}"
                log.warning("Directory %s exists, changing folder to %s", root, self.project.folder_name)
                await self.current_session.commit()

    def get_full_project_root(self) -> str:
        fs_config = getattr(self.config, "fs", None) or get_config().fs
        workspace_root = fs_config.workspace_root
        if self.project is None or not self.project.folder_name:
            return os.path.join(workspace_root, "")
        return os.path.join(workspace_root, self.project.folder_name)

    def get_full_parent_project_root(self) -> str:
        fs_config = getattr(self.config, "fs", None) or get_config().fs
        if self.project is None:
            raise ValueError("No project loaded")
        return fs_config.workspace_root

    async def get_file_by_path(self, path: str) -> Optional[File]:
        return self.current_state.get_file_by_path(path) if self.current_state else None

    async def save_file(
        self,
        path: str,
        content: str,
        metadata: Optional[dict] = None,
        from_template: bool = False,
    ) -> None:
        if not self.file_system:
            self.file_system = await self.init_file_system(load_existing=True)

        try:
            original_content = self.file_system.read(path)
        except ValueError:
            original_content = ""

        self.file_system.save(path, content)
        file_hash = self.file_system.hash_string(content)
        async with self.db_blocker():
            file_content = await FileContent.store(self.current_session, file_hash, content, metadata)

        saved_file = self.next_state.save_file(path, file_content)
        telemetry.inc("created_lines", len(content.splitlines()) - len(original_content.splitlines()))
        return saved_file

    async def import_files(self) -> tuple[list[File], list[str]]:
        if not self.file_system:
            self.file_system = await self.init_file_system(load_existing=True)

        await self.current_state.awaitable_attrs.files
        known_files = {file.path: file for file in self.current_state.files}
        files_in_workspace = set()
        imported_files: list[File] = []
        removed_files: list[str] = []

        for path in self.file_system.list():
            files_in_workspace.add(path)
            content = self.file_system.read(path)
            saved_file = known_files.get(path)
            if saved_file and saved_file.content.content == content:
                continue

            file_hash = self.file_system.hash_string(content)
            file_content = await FileContent.store(self.current_session, file_hash, content)
            file = self.next_state.save_file(path, file_content, external=True)
            imported_files.append(file)

        for path, file in known_files.items():
            if path not in files_in_workspace:
                next_state_file = self.next_state.get_file_by_path(path)
                if next_state_file in self.next_state.files:
                    self.next_state.files.remove(next_state_file)
                removed_files.append(file.path)

        return imported_files, removed_files

    async def restore_files(self) -> list[File]:
        if not self.file_system:
            self.file_system = await self.init_file_system(load_existing=True)

        await self.current_state.awaitable_attrs.files
        known_files = {file.path: file for file in self.current_state.files}
        for disk_file in list(self.file_system.list()):
            if disk_file not in known_files:
                self.file_system.remove(disk_file)

        restored: list[File] = []
        for path, file in known_files.items():
            restored.append(file)
            self.file_system.save(path, file.content.content)
        return restored

    async def get_modified_files(self) -> list[str]:
        if not self.file_system:
            self.file_system = await self.init_file_system(load_existing=True)

        await self.current_state.awaitable_attrs.files
        modified: list[str] = []
        for path in self.file_system.list():
            content = self.file_system.read(path)
            saved_file = self.current_state.get_file_by_path(path)
            if not saved_file or saved_file.content.content != content:
                modified.append(path)

        for file in self.current_state.files:
            if file.path not in self.file_system.list():
                modified.append(file.path)
        return modified

    # ------------------------------------------------------------------
    # Telemetry helpers (stubs for API parity)
    # ------------------------------------------------------------------
    async def log_llm_request(self, request_log: LLMRequestLog, agent: Optional["BaseAgent"] = None) -> None:
        telemetry.record_llm_request(
            request_log.prompt_tokens + request_log.completion_tokens,
            request_log.duration,
            request_log.status != request_log.status.__class__.SUCCESS,
        )
        if not getattr(self.session_manager, "save_llm_requests", False):
            return
        async with self.db_blocker():
            LLMRequest.from_request_log(self.current_state, agent, request_log)

    async def log_command_run(self, exec_log: ExecLogData) -> None:
        telemetry.inc("num_commands")
        ExecLog.from_exec_log(self.current_state, exec_log)

    async def log_user_input(self, question: str, response: UserInputData) -> None:
        telemetry.inc("num_inputs")
        UserInput.from_user_input(self.current_state, question, response)

    @asynccontextmanager
    async def db_blocker(self):
        while self.blockDb:
            await asyncio.sleep(0.1)
        try:
            self.blockDb = True
            yield
        finally:
            self.blockDb = False


__all__ = ["StateManager"]
