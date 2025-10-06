"""Epic model for normalized project state."""
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


class Epic(Base):
    """Normalized Epic model - replaces JSONB in ProjectState.epics."""

    __tablename__ = "epics"
    __table_args__ = (
        UniqueConstraint("project_state_id", "epic_index"),
        Index("idx_epics_project_state_id", "project_state_id"),
        Index("idx_epics_name", "name"),
        {"sqlite_autoincrement": True},
    )

    # Primary key and foreign keys
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    project_state_id: Mapped[UUID] = mapped_column(
        ForeignKey("project_states.id", ondelete="CASCADE"),
        nullable=False
    )

    # Epic attributes
    epic_index: Mapped[int] = mapped_column(nullable=False)
    name: Mapped[str] = mapped_column(nullable=False)
    description: Mapped[Optional[str]] = mapped_column()
    source: Mapped[Optional[str]] = mapped_column()  # "app", "feature", "frontend", etc.
    complexity: Mapped[Optional[str]] = mapped_column()  # "simple", "moderate", "hard"
    user_review_goal: Mapped[Optional[str]] = mapped_column()

    # Status and metadata
    completed: Mapped[bool] = mapped_column(default=False, server_default="0")
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(),
        onupdate=func.now()
    )

    # Relationships
    project_state: Mapped["ProjectState"] = relationship(back_populates="epic_models", lazy="raise")
    tasks: Mapped[list["Task"]] = relationship(
        back_populates="epic",
        lazy="selectin",
        cascade="all,delete-orphan",
        order_by="Task.task_index"
    )

    def __repr__(self) -> str:
        return f"<Epic {self.name} (index={self.epic_index})>"

    def to_dict(self) -> dict:
        """Convert Epic to dictionary (legacy format)."""
        return {
            "name": self.name,
            "description": self.description,
            "source": self.source,
            "complexity": self.complexity,
            "user_review_goal": self.user_review_goal,
            "completed": self.completed,
        }
