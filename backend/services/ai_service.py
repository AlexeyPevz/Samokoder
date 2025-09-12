"""
AI Service - Централизованный сервис для работы с AI провайдерами
Маршрутизация, fallback, трекинг использования

Этот файл теперь является оберткой для модульной структуры AI сервисов.
Основная логика перенесена в backend/services/ai/
"""

# Импорты для обратной совместимости
from .ai.models import AIRequest, AIResponse, AIProvider
from .ai.ai_service import AIService, get_ai_service
from .ai.usage_tracker import usage_tracker

import logging
logger = logging.getLogger(__name__)

# Обратная совместимость - все классы теперь импортируются из модулей

# Глобальные функции для обратной совместимости
async def get_ai_service_instance() -> AIService:
    """Получить экземпляр AI сервиса (обратная совместимость)"""
    return await get_ai_service()

# Экспорт основных классов для обратной совместимости
__all__ = [
    'AIRequest',
    'AIResponse', 
    'AIProvider',
    'AIService',
    'get_ai_service',
    'get_ai_service_instance',
    'usage_tracker'
]