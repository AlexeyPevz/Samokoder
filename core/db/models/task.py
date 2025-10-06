"""Task model for normalized project state."""
from datetime import datetime
from typing import TYPE_CHECKING, Optional
from uuid import UUID, uuid4

from sqlalchemy import ForeignKey, Index, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from samokoder.core.db.models import Base
from samokoder.core.db.types import GUID

if TYPE_CHECKING:
    from samokoder.core.db.models import Epic, ProjectState, Step


class Task(Base):
    """Normalized Task model - replaces JSONB in ProjectState.tasks."""

    __tablename__ = "tasks"
    __table_args__ = (
        UniqueConstraint("project_state_id", "task_index"),
        Index("idx_tasks_project_state_id", "project_state_id"),
        Index("idx_tasks_epic_id", "epic_id"),
        Index("idx_tasks_status", "status"),
        {"sqlite_autoincrement": True},
    )

    # Primary key and foreign keys
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    project_state_id: Mapped[UUID] = mapped_column(
        ForeignKey("project_states.id", ondelete="CASCADE"),
        nullable=False
    )
    epic_id: Mapped[Optional[UUID]] = mapped_column(
        ForeignKey("epics.id", ondelete="CASCADE")
    )

    # Task attributes
    task_index: Mapped[int] = mapped_column(nullable=False)
    description: Mapped[str] = mapped_column(nullable=False)
    instructions: Mapped[Optional[str]] = mapped_column()
    status: Mapped[str] = mapped_column(default="todo")

    # Task context and metadata
    app_data: Mapped[Optional[dict]] = mapped_column(default=None)
    relevant_files: Mapped[Optional[list[str]]] = mapped_column(default=None)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(),
        onupdate=func.now()
    )

    # Relationships
    project_state: Mapped["ProjectState"] = relationship(back_populates="task_models", lazy="raise")
    epic: Mapped[Optional["Epic"]] = relationship(back_populates="tasks", lazy="raise")
    steps: Mapped[list["Step"]] = relationship(
        back_populates="task",
        lazy="selectin",
        cascade="all,delete-orphan",
        order_by="Step.step_index"
    )

    def __repr__(self) -> str:
        return f"<Task {self.task_index}: {self.description[:50]}>"

    def to_dict(self) -> dict:
        """Convert Task to dictionary (legacy format)."""
        result = {
            "description": self.description,
            "status": self.status,
        }
        if self.instructions:
            result["instructions"] = self.instructions
        if self.app_data:
            result["app_data"] = self.app_data
        if self.relevant_files:
            result["relevant_files"] = self.relevant_files
        return result
