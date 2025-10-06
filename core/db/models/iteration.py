"""Iteration model for normalized project state."""
from datetime import datetime
from typing import TYPE_CHECKING, Optional
from uuid import UUID, uuid4

from sqlalchemy import ForeignKey, Index, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from samokoder.core.db.models import Base
from samokoder.core.db.types import GUID

if TYPE_CHECKING:
    from samokoder.core.db.models import ProjectState


class Iteration(Base):
    """Normalized Iteration model - replaces JSONB in ProjectState.iterations."""

    __tablename__ = "iterations"
    __table_args__ = (
        UniqueConstraint("project_state_id", "iteration_index"),
        Index("idx_iterations_project_state_id", "project_state_id"),
        Index("idx_iterations_status", "status"),
        {"sqlite_autoincrement": True},
    )

    # Primary key and foreign keys
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    project_state_id: Mapped[UUID] = mapped_column(
        ForeignKey("project_states.id", ondelete="CASCADE"),
        nullable=False
    )

    # Iteration attributes
    iteration_index: Mapped[int] = mapped_column(nullable=False)
    status: Mapped[str] = mapped_column(nullable=False)
    description: Mapped[Optional[str]] = mapped_column()

    # Bug hunting and debugging context
    bug_reproduction_description: Mapped[Optional[str]] = mapped_column()
    user_feedback: Mapped[Optional[str]] = mapped_column()
    command_id: Mapped[Optional[str]] = mapped_column()

    # Alternative solutions for problem solving
    alternative_solutions: Mapped[Optional[list[dict]]] = mapped_column(default=None)

    # Generic iteration data
    iteration_data: Mapped[Optional[dict]] = mapped_column(default=None)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(),
        onupdate=func.now()
    )

    # Relationships
    project_state: Mapped["ProjectState"] = relationship(back_populates="iteration_models", lazy="raise")

    def __repr__(self) -> str:
        return f"<Iteration {self.iteration_index}: {self.status}>"

    def to_dict(self) -> dict:
        """Convert Iteration to dictionary (legacy format)."""
        result = {
            "status": self.status,
        }

        if self.description:
            result["description"] = self.description
        if self.bug_reproduction_description:
            result["bug_reproduction_description"] = self.bug_reproduction_description
        if self.user_feedback:
            result["user_feedback"] = self.user_feedback
        if self.command_id:
            result["command_id"] = self.command_id
        if self.alternative_solutions:
            result["alternative_solutions"] = self.alternative_solutions

        # Add generic iteration data
        if self.iteration_data:
            result.update(self.iteration_data)

        return result
