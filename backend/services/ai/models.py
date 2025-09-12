"""
AI Service Models
Модели данных для AI сервиса
"""

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional

class AIProvider(Enum):
    OPENROUTER = "openrouter"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GROQ = "groq"

@dataclass
class AIRequest:
    """Структура запроса к AI"""
    messages: List[Dict[str, str]]
    model: str
    provider: AIProvider
    max_tokens: int = 4096
    temperature: float = 0.7
    user_id: str = ""
    project_id: str = ""

@dataclass
class AIResponse:
    """Структура ответа от AI"""
    content: str
    tokens_used: int
    cost_usd: float
    provider: AIProvider
    model: str
    response_time: float
    success: bool = True
    error: Optional[str] = None