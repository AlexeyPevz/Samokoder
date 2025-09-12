"""
AI Provider Strategy
Стратегии выбора AI провайдеров
"""

import logging
from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from enum import Enum

from backend.services.ai.models import AIProvider, AIRequest, AIResponse

logger = logging.getLogger(__name__)

class ProviderSelectionStrategy(ABC):
    """Абстрактная стратегия выбора провайдера"""
    
    @abstractmethod
    def select_provider(self, available_providers: List[AIProvider], 
                       request: AIRequest, context: Dict[str, Any]) -> Optional[AIProvider]:
        """Выбрать провайдера для запроса"""
        pass

class RoundRobinStrategy(ProviderSelectionStrategy):
    """Стратегия round-robin для выбора провайдеров"""
    
    def __init__(self):
        self._current_index = 0
    
    def select_provider(self, available_providers: List[AIProvider], 
                       request: AIRequest, context: Dict[str, Any]) -> Optional[AIProvider]:
        """Выбрать провайдера по round-robin"""
        if not available_providers:
            return None
        
        provider = available_providers[self._current_index % len(available_providers)]
        self._current_index += 1
        
        logger.debug(f"Selected provider (round-robin): {provider}")
        return provider

class CostOptimizedStrategy(ProviderSelectionStrategy):
    """Стратегия оптимизации по стоимости"""
    
    def __init__(self):
        # Стоимость за 1K токенов для каждого провайдера
        self._cost_per_1k_tokens = {
            AIProvider.GROQ: 0.0,  # Бесплатный
            AIProvider.OPENROUTER: 0.002,
            AIProvider.OPENAI: 0.002,
            AIProvider.ANTHROPIC: 0.003
        }
    
    def select_provider(self, available_providers: List[AIProvider], 
                       request: AIRequest, context: Dict[str, Any]) -> Optional[AIProvider]:
        """Выбрать самый дешевый провайдер"""
        if not available_providers:
            return None
        
        # Сортируем по стоимости
        sorted_providers = sorted(
            available_providers,
            key=lambda p: self._cost_per_1k_tokens.get(p, float('inf'))
        )
        
        provider = sorted_providers[0]
        logger.debug(f"Selected provider (cost-optimized): {provider}")
        return provider

class PerformanceStrategy(ProviderSelectionStrategy):
    """Стратегия оптимизации по производительности"""
    
    def __init__(self):
        self._response_times: Dict[AIProvider, List[float]] = {}
        self._success_rates: Dict[AIProvider, float] = {}
    
    def update_metrics(self, provider: AIProvider, response_time: float, success: bool):
        """Обновить метрики провайдера"""
        if provider not in self._response_times:
            self._response_times[provider] = []
        
        self._response_times[provider].append(response_time)
        
        # Ограничиваем историю последними 100 запросами
        if len(self._response_times[provider]) > 100:
            self._response_times[provider] = self._response_times[provider][-100:]
        
        # Обновляем success rate
        if provider not in self._success_rates:
            self._success_rates[provider] = 1.0
        
        # Простое скользящее среднее
        current_rate = self._success_rates[provider]
        new_rate = 0.9 * current_rate + 0.1 * (1.0 if success else 0.0)
        self._success_rates[provider] = new_rate
    
    def select_provider(self, available_providers: List[AIProvider], 
                       request: AIRequest, context: Dict[str, Any]) -> Optional[AIProvider]:
        """Выбрать самый быстрый и надежный провайдер"""
        if not available_providers:
            return None
        
        # Фильтруем провайдеров с достаточной надежностью
        reliable_providers = [
            p for p in available_providers 
            if self._success_rates.get(p, 1.0) > 0.8
        ]
        
        if not reliable_providers:
            reliable_providers = available_providers
        
        # Выбираем с наименьшим средним временем ответа
        best_provider = min(
            reliable_providers,
            key=lambda p: self._get_avg_response_time(p)
        )
        
        logger.debug(f"Selected provider (performance): {best_provider}")
        return best_provider
    
    def _get_avg_response_time(self, provider: AIProvider) -> float:
        """Получить среднее время ответа провайдера"""
        times = self._response_times.get(provider, [])
        return sum(times) / len(times) if times else 1.0

class LoadBalancedStrategy(ProviderSelectionStrategy):
    """Стратегия балансировки нагрузки"""
    
    def __init__(self):
        self._active_requests: Dict[AIProvider, int] = {}
        self._max_concurrent_requests = 10  # Максимум одновременных запросов
    
    def select_provider(self, available_providers: List[AIProvider], 
                       request: AIRequest, context: Dict[str, Any]) -> Optional[AIProvider]:
        """Выбрать провайдер с наименьшей нагрузкой"""
        if not available_providers:
            return None
        
        # Фильтруем провайдеров, не превышающих лимит
        available = [
            p for p in available_providers 
            if self._active_requests.get(p, 0) < self._max_concurrent_requests
        ]
        
        if not available:
            available = available_providers
        
        # Выбираем с наименьшим количеством активных запросов
        provider = min(available, key=lambda p: self._active_requests.get(p, 0))
        
        logger.debug(f"Selected provider (load-balanced): {provider}")
        return provider
    
    def start_request(self, provider: AIProvider):
        """Отметить начало запроса"""
        self._active_requests[provider] = self._active_requests.get(provider, 0) + 1
    
    def end_request(self, provider: AIProvider):
        """Отметить окончание запроса"""
        if provider in self._active_requests:
            self._active_requests[provider] = max(0, self._active_requests[provider] - 1)

class StrategyFactory:
    """Фабрика стратегий выбора провайдеров"""
    
    _strategies = {
        "round_robin": RoundRobinStrategy,
        "cost_optimized": CostOptimizedStrategy,
        "performance": PerformanceStrategy,
        "load_balanced": LoadBalancedStrategy
    }
    
    @classmethod
    def create_strategy(cls, strategy_name: str) -> ProviderSelectionStrategy:
        """Создать стратегию по имени"""
        if strategy_name not in cls._strategies:
            raise ValueError(f"Unknown strategy: {strategy_name}")
        
        return cls._strategies[strategy_name]()
    
    @classmethod
    def get_available_strategies(cls) -> List[str]:
        """Получить список доступных стратегий"""
        return list(cls._strategies.keys())