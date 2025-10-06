"""Pydantic models for project run management."""

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field


class ProjectRunCreateRequest(BaseModel):
    """Request to start a new project run."""

    input: Optional[str] = Field(
        None,
        description="Optional user request or instructions for this run",
        max_length=2000,
    )


class ProjectRunResponse(BaseModel):
    id: UUID
    project_id: UUID
    user_id: int
    status: str
    logs: Optional[str]
    error: Optional[str]
    created_at: datetime
    updated_at: datetime
    finished_at: Optional[datetime]

    class Config:
        from_attributes = True


class ProjectRunListResponse(BaseModel):
    runs: list[ProjectRunResponse]
    total: int
