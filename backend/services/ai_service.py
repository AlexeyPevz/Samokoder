"""
AI Service - Централизованный сервис для работы с AI провайдерами
Маршрутизация, fallback, трекинг использования
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, AsyncGenerator, Any
from dataclasses import dataclass
from enum import Enum

import openai
import anthropic
import httpx
from openai import AsyncOpenAI
from anthropic import AsyncAnthropic

from config.settings import settings
from backend.patterns.circuit_breaker import circuit_breaker, CircuitBreakerConfig
from backend.core.exceptions import (
    AIServiceError, NetworkError, TimeoutError, 
    ValidationError, ConfigurationError
)

logger = logging.getLogger(__name__)

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

class AIProviderClient:
    """Базовый класс для AI провайдеров"""
    
    def __init__(self, api_key: str, provider: AIProvider):
        self.api_key = api_key
        self.provider = provider
        self.client = None
    
    async def chat_completion(self, request: AIRequest) -> AIResponse:
        """Основной метод для получения ответа от AI"""
        raise NotImplementedError
    
    async def validate_api_key(self) -> bool:
        """Проверка валидности API ключа"""
        raise NotImplementedError

class OpenRouterClient(AIProviderClient):
    """Клиент для OpenRouter"""
    
    def __init__(self, api_key: str):
        super().__init__(api_key, AIProvider.OPENROUTER)
        self.client = AsyncOpenAI(
            api_key=api_key,
            base_url="https://openrouter.ai/api/v1"
        )
    
    async def chat_completion(self, request: AIRequest) -> AIResponse:
        start_time = datetime.now()
        
        try:
            response = await self.client.chat.completions.create(
                model=request.model,
                messages=request.messages,
                max_tokens=request.max_tokens,
                temperature=request.temperature
            )
            
            response_time = (datetime.now() - start_time).total_seconds()
            
            return AIResponse(
                content=response.choices[0].message.content,
                tokens_used=response.usage.total_tokens,
                cost_usd=self._calculate_cost(response.usage.total_tokens, request.model),
                provider=self.provider,
                model=request.model,
                response_time=response_time
            )
        except httpx.TimeoutException as e:
            logger.error(f"OpenRouter timeout: {e}")
            return AIResponse(
                content="",
                tokens_used=0,
                cost_usd=0.0,
                provider=self.provider,
                model=request.model,
                response_time=(datetime.now() - start_time).total_seconds(),
                success=False,
                error=f"Timeout: {e}"
            )
        except httpx.HTTPError as e:
            logger.error(f"OpenRouter HTTP error: {e}")
            return AIResponse(
                content="",
                tokens_used=0,
                cost_usd=0.0,
                provider=self.provider,
                model=request.model,
                response_time=(datetime.now() - start_time).total_seconds(),
                success=False,
                error=f"HTTP error: {e}"
            )
        except Exception as e:
            logger.error(f"OpenRouter error: {e}")
            return AIResponse(
                content="",
                tokens_used=0,
                cost_usd=0.0,
                provider=self.provider,
                model=request.model,
                response_time=(datetime.now() - start_time).total_seconds(),
                success=False,
                error=str(e)
            )
    
    async def validate_api_key(self) -> bool:
        try:
            await self.client.models.list()
            return True
        except Exception:
            return False
    
    def _calculate_cost(self, tokens: int, model: str) -> float:
        """Расчет стоимости для OpenRouter моделей"""
        # Примерные цены (в реальности нужно получать из API)
        pricing = {
            "deepseek/deepseek-v3": 0.0,  # Бесплатная
            "qwen/qwen-2.5-coder-32b": 0.0,  # Бесплатная
            "meta-llama/llama-3.1-8b-instruct": 0.0,  # Бесплатная
        }
        cost_per_token = pricing.get(model, 0.0)
        return tokens * cost_per_token

class OpenAIClient(AIProviderClient):
    """Клиент для OpenAI"""
    
    def __init__(self, api_key: str):
        super().__init__(api_key, AIProvider.OPENAI)
        self.client = AsyncOpenAI(api_key=api_key)
    
    async def chat_completion(self, request: AIRequest) -> AIResponse:
        start_time = datetime.now()
        
        try:
            response = await self.client.chat.completions.create(
                model=request.model,
                messages=request.messages,
                max_tokens=request.max_tokens,
                temperature=request.temperature
            )
            
            response_time = (datetime.now() - start_time).total_seconds()
            
            return AIResponse(
                content=response.choices[0].message.content,
                tokens_used=response.usage.total_tokens,
                cost_usd=self._calculate_cost(response.usage.total_tokens, request.model),
                provider=self.provider,
                model=request.model,
                response_time=response_time
            )
        except httpx.TimeoutException as e:
            logger.error(f"OpenAI timeout: {e}")
            return AIResponse(
                content="",
                tokens_used=0,
                cost_usd=0.0,
                provider=self.provider,
                model=request.model,
                response_time=(datetime.now() - start_time).total_seconds(),
                success=False,
                error=f"Timeout: {e}"
            )
        except httpx.HTTPError as e:
            logger.error(f"OpenAI HTTP error: {e}")
            return AIResponse(
                content="",
                tokens_used=0,
                cost_usd=0.0,
                provider=self.provider,
                model=request.model,
                response_time=(datetime.now() - start_time).total_seconds(),
                success=False,
                error=f"HTTP error: {e}"
            )
        except Exception as e:
            logger.error(f"OpenAI error: {e}")
            return AIResponse(
                content="",
                tokens_used=0,
                cost_usd=0.0,
                provider=self.provider,
                model=request.model,
                response_time=(datetime.now() - start_time).total_seconds(),
                success=False,
                error=str(e)
            )
    
    async def validate_api_key(self) -> bool:
        try:
            await self.client.models.list()
            return True
        except Exception:
            return False
    
    def _calculate_cost(self, tokens: int, model: str) -> float:
        """Расчет стоимости для OpenAI моделей"""
        pricing = {
            "gpt-4o-mini": 0.15,  # $0.15 per 1K tokens
            "gpt-4o": 5.0,  # $5 per 1K tokens
        }
        cost_per_1k = pricing.get(model, 0.0)
        return (tokens / 1000) * cost_per_1k

class AnthropicClient(AIProviderClient):
    """Клиент для Anthropic"""
    
    def __init__(self, api_key: str):
        super().__init__(api_key, AIProvider.ANTHROPIC)
        self.client = AsyncAnthropic(api_key=api_key)
    
    async def chat_completion(self, request: AIRequest) -> AIResponse:
        start_time = datetime.now()
        
        try:
            # Конвертируем сообщения в формат Anthropic
            system_message = ""
            user_messages = []
            
            for msg in request.messages:
                if msg["role"] == "system":
                    system_message = msg["content"]
                else:
                    user_messages.append(msg)
            
            response = await self.client.messages.create(
                model=request.model,
                max_tokens=request.max_tokens,
                temperature=request.temperature,
                system=system_message if system_message else None,
                messages=user_messages
            )
            
            response_time = (datetime.now() - start_time).total_seconds()
            
            return AIResponse(
                content=response.content[0].text,
                tokens_used=response.usage.input_tokens + response.usage.output_tokens,
                cost_usd=self._calculate_cost(response.usage.input_tokens + response.usage.output_tokens, request.model),
                provider=self.provider,
                model=request.model,
                response_time=response_time
            )
        except httpx.TimeoutException as e:
            logger.error(f"Anthropic timeout: {e}")
            return AIResponse(
                content="",
                tokens_used=0,
                cost_usd=0.0,
                provider=self.provider,
                model=request.model,
                response_time=(datetime.now() - start_time).total_seconds(),
                success=False,
                error=f"Timeout: {e}"
            )
        except httpx.HTTPError as e:
            logger.error(f"Anthropic HTTP error: {e}")
            return AIResponse(
                content="",
                tokens_used=0,
                cost_usd=0.0,
                provider=self.provider,
                model=request.model,
                response_time=(datetime.now() - start_time).total_seconds(),
                success=False,
                error=f"HTTP error: {e}"
            )
        except Exception as e:
            logger.error(f"Anthropic error: {e}")
            return AIResponse(
                content="",
                tokens_used=0,
                cost_usd=0.0,
                provider=self.provider,
                model=request.model,
                response_time=(datetime.now() - start_time).total_seconds(),
                success=False,
                error=str(e)
            )
    
    async def validate_api_key(self) -> bool:
        try:
            await self.client.messages.create(
                model="claude-3-haiku-20240307",
                max_tokens=1,
                messages=[{"role": "user", "content": "test"}]
            )
            return True
        except Exception:
            return False
    
    def _calculate_cost(self, tokens: int, model: str) -> float:
        """Расчет стоимости для Anthropic моделей"""
        pricing = {
            "claude-3-haiku-20240307": 0.25,  # $0.25 per 1K tokens
            "claude-3-sonnet-20240229": 3.0,  # $3 per 1K tokens
        }
        cost_per_1k = pricing.get(model, 0.0)
        return (tokens / 1000) * cost_per_1k

class GroqClient(AIProviderClient):
    """Клиент для Groq"""
    
    def __init__(self, api_key: str):
        super().__init__(api_key, AIProvider.GROQ)
        self.base_url = "https://api.groq.com/openai/v1"
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
    
    async def chat_completion(self, request: AIRequest) -> AIResponse:
        start_time = datetime.now()
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.base_url}/chat/completions",
                    headers=self.headers,
                    json={
                        "model": request.model,
                        "messages": request.messages,
                        "max_tokens": request.max_tokens,
                        "temperature": request.temperature
                    },
                    timeout=30.0
                )
                response.raise_for_status()
                data = response.json()
            
            response_time = (datetime.now() - start_time).total_seconds()
            
            return AIResponse(
                content=data["choices"][0]["message"]["content"],
                tokens_used=data["usage"]["total_tokens"],
                cost_usd=0.0,  # Groq бесплатный
                provider=self.provider,
                model=request.model,
                response_time=response_time
            )
        except httpx.TimeoutException as e:
            logger.error(f"Groq timeout: {e}")
            return AIResponse(
                content="",
                tokens_used=0,
                cost_usd=0.0,
                provider=self.provider,
                model=request.model,
                response_time=(datetime.now() - start_time).total_seconds(),
                success=False,
                error=f"Timeout: {e}"
            )
        except httpx.HTTPError as e:
            logger.error(f"Groq HTTP error: {e}")
            return AIResponse(
                content="",
                tokens_used=0,
                cost_usd=0.0,
                provider=self.provider,
                model=request.model,
                response_time=(datetime.now() - start_time).total_seconds(),
                success=False,
                error=f"HTTP error: {e}"
            )
        except Exception as e:
            logger.error(f"Groq error: {e}")
            return AIResponse(
                content="",
                tokens_used=0,
                cost_usd=0.0,
                provider=self.provider,
                model=request.model,
                response_time=(datetime.now() - start_time).total_seconds(),
                success=False,
                error=str(e)
            )
    
    async def validate_api_key(self) -> bool:
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.base_url}/models",
                    headers=self.headers,
                    timeout=10.0
                )
                return response.status_code == 200
        except Exception:
            return False

class AIService:
    """
    Централизованный сервис для работы с AI провайдерами
    Маршрутизация, fallback, трекинг использования
    """
    
    def __init__(self, user_id: str, user_api_keys: Dict[str, str]):
        self.user_id = user_id
        self.user_api_keys = user_api_keys
        self.clients = {}
        self.usage_tracker = []
        
        # Инициализируем клиенты
        self._initialize_clients()
    
    def _initialize_clients(self):
        """Инициализация клиентов для всех провайдеров"""
        
        # OpenRouter
        if 'openrouter' in self.user_api_keys:
            self.clients[AIProvider.OPENROUTER] = OpenRouterClient(
                self.user_api_keys['openrouter']
            )
        
        # OpenAI
        if 'openai' in self.user_api_keys:
            self.clients[AIProvider.OPENAI] = OpenAIClient(
                self.user_api_keys['openai']
            )
        
        # Anthropic
        if 'anthropic' in self.user_api_keys:
            self.clients[AIProvider.ANTHROPIC] = AnthropicClient(
                self.user_api_keys['anthropic']
            )
        
        # Groq
        if 'groq' in self.user_api_keys:
            self.clients[AIProvider.GROQ] = GroqClient(
                self.user_api_keys['groq']
            )
        
        # Fallback на системные ключи если нет пользовательских (только для демо)
        if not self.clients:
            if settings.system_openrouter_key and settings.system_openrouter_key != "":
                self.clients[AIProvider.OPENROUTER] = OpenRouterClient(
                    settings.system_openrouter_key
                )
            elif settings.system_openai_key and settings.system_openai_key != "":
                self.clients[AIProvider.OPENAI] = OpenAIClient(
                    settings.system_openai_key
                )
            # Если нет системных ключей, оставляем clients пустым
    
    @circuit_breaker("ai_service", CircuitBreakerConfig(
        failure_threshold=3,
        recovery_timeout=30,
        success_threshold=2,
        timeout=60
    ))
    async def route_request(self, 
                          messages: List[Dict[str, str]], 
                          model: str = None, 
                          provider: str = None,
                          project_id: str = "",
                          max_tokens: int = 4096,
                          temperature: float = 0.7) -> AIResponse:
        """
        Маршрутизация запроса к нужному AI провайдеру
        """
        
        # Проверяем, есть ли доступные провайдеры
        if not self.clients:
            return AIResponse(
                content="",
                tokens_used=0,
                cost_usd=0.0,
                provider=AIProvider.OPENROUTER,
                model="",
                response_time=0.0,
                success=False,
                error="No AI providers configured. Please add your API keys in the settings."
            )
        
        # Определяем провайдера и модель
        if provider and provider in [p.value for p in AIProvider]:
            target_provider = AIProvider(provider)
        else:
            target_provider = self._select_best_provider()
        
        if not model:
            model = self._get_default_model_for_provider(target_provider)
        
        # Создаем запрос
        request = AIRequest(
            messages=messages,
            model=model,
            provider=target_provider,
            max_tokens=max_tokens,
            temperature=temperature,
            user_id=self.user_id,
            project_id=project_id
        )
        
        # Пытаемся выполнить запрос
        response = await self._execute_request(request)
        
        # Если не удалось, пробуем fallback
        if not response.success and len(self.clients) > 1:
            response = await self._fallback_request(request)
        
        # Трекинг использования
        await self._track_usage(response, request)
        
        return response
    
    async def _execute_request(self, request: AIRequest) -> AIResponse:
        """Выполнение запроса к выбранному провайдеру"""
        
        if request.provider not in self.clients:
            return AIResponse(
                content="",
                tokens_used=0,
                cost_usd=0.0,
                provider=request.provider,
                model=request.model,
                response_time=0.0,
                success=False,
                error=f"Provider {request.provider.value} not available"
            )
        
        client = self.clients[request.provider]
        return await client.chat_completion(request)
    
    async def _fallback_request(self, original_request: AIRequest) -> AIResponse:
        """Fallback на другой провайдер при ошибке с умной логикой"""
        
        # Определяем приоритет fallback провайдеров
        fallback_priority = [
            AIProvider.OPENROUTER,  # Бесплатные модели
            AIProvider.GROQ,        # Быстрые модели
            AIProvider.OPENAI,      # Надежные модели
            AIProvider.ANTHROPIC    # Качественные модели
        ]
        
        available_providers = [p for p in fallback_priority if p in self.clients and p != original_request.provider]
        
        logger.info(f"Trying fallback providers: {[p.value for p in available_providers]}")
        
        for provider in available_providers:
            try:
                # Создаем запрос с оптимизированными параметрами для fallback
                request = AIRequest(
                    messages=original_request.messages,
                    model=self._get_optimal_model_for_fallback(provider, original_request),
                    provider=provider,
                    max_tokens=min(original_request.max_tokens, 2048),  # Ограничиваем токены для fallback
                    temperature=original_request.temperature,
                    user_id=original_request.user_id,
                    project_id=original_request.project_id
                )
                
                response = await self._execute_request(request)
                if response.success:
                    logger.info(f"Fallback to {provider.value} successful with model {response.model}")
                    return response
                else:
                    logger.warning(f"Fallback to {provider.value} failed: {response.error}")
            except httpx.TimeoutException as e:
                logger.warning(f"Fallback to {provider.value} failed with timeout: {e}")
                continue
            except httpx.HTTPError as e:
                logger.warning(f"Fallback to {provider.value} failed with HTTP error: {e}")
                continue
            except Exception as e:
                logger.warning(f"Fallback to {provider.value} failed with exception: {e}")
                continue
        
        # Если все fallback провалились, возвращаем ошибку с деталями
        return AIResponse(
            content="",
            tokens_used=0,
            cost_usd=0.0,
            provider=original_request.provider,
            model=original_request.model,
            response_time=0.0,
            success=False,
            error=f"All {len(available_providers)} fallback providers failed. Original error: {original_request.provider.value}"
        )
    
    def _get_optimal_model_for_fallback(self, provider: AIProvider, original_request: AIRequest) -> str:
        """Выбирает оптимальную модель для fallback с учетом контекста"""
        
        # Если исходный запрос был для кодирования, выбираем модель для кодирования
        if "code" in original_request.messages[0].get("content", "").lower():
            coding_models = {
                AIProvider.OPENROUTER: "deepseek/deepseek-v3",
                AIProvider.GROQ: "llama-3-8b-8192",
                AIProvider.OPENAI: "gpt-4o-mini",
                AIProvider.ANTHROPIC: "claude-3-haiku-20240307"
            }
            return coding_models.get(provider, self._get_default_model_for_provider(provider))
        
        # Для обычных запросов используем быстрые модели
        fast_models = {
            AIProvider.OPENROUTER: "meta-llama/llama-3.1-8b-instruct",
            AIProvider.GROQ: "llama-3-8b-8192",
            AIProvider.OPENAI: "gpt-4o-mini",
            AIProvider.ANTHROPIC: "claude-3-haiku-20240307"
        }
        return fast_models.get(provider, self._get_default_model_for_provider(provider))
    
    def _select_best_provider(self) -> AIProvider:
        """Выбор лучшего доступного провайдера"""
        
        # Приоритет: OpenRouter (бесплатные модели) > Groq (быстрый) > OpenAI > Anthropic
        priority_order = [
            AIProvider.OPENROUTER,
            AIProvider.GROQ,
            AIProvider.OPENAI,
            AIProvider.ANTHROPIC
        ]
        
        for provider in priority_order:
            if provider in self.clients:
                return provider
        
        # Если ничего не найдено, возвращаем первый доступный или OpenRouter по умолчанию
        if self.clients:
            return list(self.clients.keys())[0]
        else:
            # Нет доступных провайдеров - это нормально, будет обработано в route_request
            return AIProvider.OPENROUTER
    
    def _get_default_model_for_provider(self, provider: AIProvider) -> str:
        """Получение модели по умолчанию для провайдера"""
        
        default_models = {
            AIProvider.OPENROUTER: "deepseek/deepseek-v3",
            AIProvider.OPENAI: "gpt-4o-mini",
            AIProvider.ANTHROPIC: "claude-3-haiku-20240307",
            AIProvider.GROQ: "llama-3-8b-8192"
        }
        
        return default_models.get(provider, "deepseek/deepseek-v3")
    
    async def _track_usage(self, response: AIResponse, request: AIRequest):
        """Трекинг использования для биллинга"""
        
        usage_record = {
            "timestamp": datetime.now().isoformat(),
            "user_id": self.user_id,
            "project_id": request.project_id,
            "provider": response.provider.value,
            "model": response.model,
            "tokens_used": response.tokens_used,
            "cost_usd": response.cost_usd,
            "response_time": response.response_time,
            "success": response.success,
            "error": response.error
        }
        
        self.usage_tracker.append(usage_record)
        
        # В реальном приложении здесь будет сохранение в базу данных
        logger.info(f"Usage tracked: {usage_record}")
    
    async def get_usage_stats(self) -> Dict[str, Any]:
        """Получение статистики использования"""
        
        if not self.usage_tracker:
            return {
                "total_requests": 0,
                "total_tokens": 0,
                "total_cost": 0.0,
                "success_rate": 0.0,
                "providers": {}
            }
        
        total_requests = len(self.usage_tracker)
        total_tokens = sum(record["tokens_used"] for record in self.usage_tracker)
        total_cost = sum(record["cost_usd"] for record in self.usage_tracker)
        successful_requests = sum(1 for record in self.usage_tracker if record["success"])
        success_rate = (successful_requests / total_requests) * 100 if total_requests > 0 else 0
        
        # Статистика по провайдерам
        providers = {}
        for record in self.usage_tracker:
            provider = record["provider"]
            if provider not in providers:
                providers[provider] = {
                    "requests": 0,
                    "tokens": 0,
                    "cost": 0.0,
                    "success_rate": 0.0
                }
            
            providers[provider]["requests"] += 1
            providers[provider]["tokens"] += record["tokens_used"]
            providers[provider]["cost"] += record["cost_usd"]
        
        # Расчет success rate для каждого провайдера
        for provider in providers:
            provider_records = [r for r in self.usage_tracker if r["provider"] == provider]
            successful = sum(1 for r in provider_records if r["success"])
            providers[provider]["success_rate"] = (successful / len(provider_records)) * 100 if provider_records else 0
        
        return {
            "total_requests": total_requests,
            "total_tokens": total_tokens,
            "total_cost": total_cost,
            "success_rate": success_rate,
            "providers": providers
        }
    
    async def validate_all_keys(self) -> Dict[str, bool]:
        """Проверка валидности всех API ключей"""
        
        results = {}
        
        for provider, client in self.clients.items():
            try:
                is_valid = await client.validate_api_key()
                results[provider.value] = is_valid
            except httpx.TimeoutException as e:
                logger.error(f"Timeout validating {provider.value}: {e}")
                results[provider.value] = False
            except httpx.HTTPError as e:
                logger.error(f"HTTP error validating {provider.value}: {e}")
                results[provider.value] = False
            except Exception as e:
                logger.error(f"Error validating {provider.value}: {e}")
                results[provider.value] = False
        
        return results

# Глобальный экземпляр для использования в приложении
ai_service_instance = None

def get_ai_service(user_id: str, user_api_keys: Dict[str, str]) -> AIService:
    """Получение экземпляра AI сервиса"""
    return AIService(user_id, user_api_keys)