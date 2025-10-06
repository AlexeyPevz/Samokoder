from enum import Enum
from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel

class LLMRequestStatus(str, Enum):
    SUCCESS = "success"
    ERROR = "error"

class LLMRequestLog(BaseModel):
    """LLM request log entry."""
    
    provider: str
    model: str
    temperature: float
    prompts: List[Dict[str, Any]]
    messages: List[Dict[str, Any]] = []
    response: Optional[str] = None
    prompt_tokens: int = 0
    completion_tokens: int = 0
    duration: float = 0.0
    status: LLMRequestStatus = LLMRequestStatus.SUCCESS
    error: Optional[str] = None