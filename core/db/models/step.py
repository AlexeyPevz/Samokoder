"""Step model for normalized project state."""
from datetime import datetime
from typing import TYPE_CHECKING, Optional
from uuid import UUID, uuid4

from sqlalchemy import ForeignKey, Index, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from samokoder.core.db.models import Base
from samokoder.core.db.types import GUID

if TYPE_CHECKING:
    from samokoder.core.db.models import ProjectState, Task


class Step(Base):
    """Normalized Step model - replaces JSONB in ProjectState.steps."""

    __tablename__ = "steps"
    __table_args__ = (
        UniqueConstraint("project_state_id", "step_index"),
        Index("idx_steps_project_state_id", "project_state_id"),
        Index("idx_steps_task_id", "task_id"),
        Index("idx_steps_type", "type"),
        Index("idx_steps_completed", "completed"),
        {"sqlite_autoincrement": True},
    )

    # Primary key and foreign keys
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    project_state_id: Mapped[UUID] = mapped_column(
        ForeignKey("project_states.id", ondelete="CASCADE"),
        nullable=False
    )
    task_id: Mapped[Optional[UUID]] = mapped_column(
        ForeignKey("tasks.id", ondelete="CASCADE")
    )

    # Step attributes
    step_index: Mapped[int] = mapped_column(nullable=False)
    type: Mapped[str] = mapped_column(nullable=False)  # "save_file", "command", "human_intervention", etc.
    completed: Mapped[bool] = mapped_column(default=False, server_default="0")

    # Step-specific data based on type
    # For "save_file" steps
    save_file_path: Mapped[Optional[str]] = mapped_column()

    # For "command" steps
    command: Mapped[Optional[str]] = mapped_column()
    command_id: Mapped[Optional[str]] = mapped_column()
    timeout: Mapped[Optional[int]] = mapped_column()
    check_if_fixed: Mapped[Optional[bool]] = mapped_column()

    # For "human_intervention" steps
    human_intervention_description: Mapped[Optional[str]] = mapped_column()

    # Generic step data for other fields
    step_data: Mapped[Optional[dict]] = mapped_column(default=None)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(),
        onupdate=func.now()
    )

    # Relationships
    project_state: Mapped["ProjectState"] = relationship(back_populates="step_models", lazy="raise")
    task: Mapped[Optional["Task"]] = relationship(back_populates="steps", lazy="raise")

    def __repr__(self) -> str:
        return f"<Step {self.step_index}: {self.type}>"

    def to_dict(self) -> dict:
        """Convert Step to dictionary (legacy format)."""
        result = {
            "type": self.type,
            "completed": self.completed,
        }

        # Add type-specific fields
        if self.type == "save_file" and self.save_file_path:
            result["save_file"] = {"path": self.save_file_path}
        elif self.type == "command":
            if self.command:
                result["command"] = self.command
            if self.command_id:
                result["command_id"] = self.command_id
            if self.timeout:
                result["timeout"] = self.timeout
            if self.check_if_fixed is not None:
                result["check_if_fixed"] = self.check_if_fixed
        elif self.type == "human_intervention" and self.human_intervention_description:
            result["human_intervention_description"] = self.human_intervention_description

        # Add generic step data
        if self.step_data:
            result.update(self.step_data)

        return result
