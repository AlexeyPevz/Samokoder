"""
Реальный адаптер для интеграции с GPT-Pilot
Теперь использует модульную структуру
"""

import logging
from typing import Dict, Any

from .gpt_pilot.real_adapter import SamokoderGPTPilotRealAdapter

logger = logging.getLogger(__name__)

# Экспортируем основной класс для обратной совместимости
__all__ = ['SamokoderGPTPilotRealAdapter']