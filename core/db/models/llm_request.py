from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Float
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from samokoder.core.db.types import GUID

from samokoder.core.db.models.base import Base
from samokoder.core.db.models.project_state import ProjectState
from samokoder.core.llm.request_log import LLMRequestLog

class LLMRequest(Base):
    __tablename__ = "llm_requests"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    branch_id = Column(GUID, ForeignKey("branches.id"), nullable=False)
    project_state_id = Column(UUID(as_uuid=True), ForeignKey("project_states.id"), nullable=True)
    started_at = Column(DateTime, server_default=func.now(), nullable=False)
    agent = Column(String, nullable=True)
    provider = Column(String, nullable=False)
    model = Column(String, nullable=False)
    temperature = Column(Float, nullable=False)
    messages = Column(Text, nullable=False)  # JSON serialized
    prompts = Column(Text, nullable=False)   # JSON serialized
    response = Column(Text, nullable=True)
    prompt_tokens = Column(Integer, nullable=False)
    completion_tokens = Column(Integer, nullable=False)
    duration = Column(Float, nullable=False)
    status = Column(String, nullable=False)
    error = Column(Text, nullable=True)
    
    # Relationships
    branch = relationship("Branch", back_populates="llm_requests")
    project_state = relationship("ProjectState", back_populates="llm_requests")
    
    @classmethod
    def from_request_log(cls, project_state: ProjectState, agent, request_log: LLMRequestLog):
        """Create LLMRequest from LLMRequestLog."""
        # This is a simplified implementation
        # In a real implementation, you would save the request to the database
        pass