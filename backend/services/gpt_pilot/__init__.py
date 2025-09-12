"""
GPT-Pilot адаптеры
"""

from .base_adapter import BaseGPTPilotAdapter
from .real_adapter import SamokoderGPTPilotRealAdapter

__all__ = [
    'BaseGPTPilotAdapter',
    'SamokoderGPTPilotRealAdapter'
]