"""
Event Bus
Шина событий для обработки событий системы
"""

import logging
import asyncio
from typing import Dict, List, Callable, Any, Optional
from abc import ABC, abstractmethod

from backend.events.base_event import BaseEvent

logger = logging.getLogger(__name__)

class EventHandler(ABC):
    """Абстрактный обработчик событий"""
    
    @abstractmethod
    async def handle(self, event: BaseEvent) -> None:
        """Обработать событие"""
        pass
    
    @abstractmethod
    def can_handle(self, event_type: str) -> bool:
        """Проверить, может ли обработчик обработать событие данного типа"""
        pass

class EventBus:
    """Шина событий"""
    
    def __init__(self):
        self._handlers: Dict[str, List[EventHandler]] = {}
        self._middleware: List[Callable] = []
        self._event_queue: asyncio.Queue = asyncio.Queue()
        self._is_running = False
        self._task: Optional[asyncio.Task] = None
    
    def register_handler(self, event_type: str, handler: EventHandler):
        """Зарегистрировать обработчик событий"""
        if event_type not in self._handlers:
            self._handlers[event_type] = []
        
        self._handlers[event_type].append(handler)
        logger.info(f"Registered handler for event type: {event_type}")
    
    def unregister_handler(self, event_type: str, handler: EventHandler):
        """Отменить регистрацию обработчика событий"""
        if event_type in self._handlers:
            try:
                self._handlers[event_type].remove(handler)
                logger.info(f"Unregistered handler for event type: {event_type}")
            except ValueError:
                logger.warning(f"Handler not found for event type: {event_type}")
    
    def add_middleware(self, middleware: Callable):
        """Добавить middleware для обработки событий"""
        self._middleware.append(middleware)
        logger.info("Added event middleware")
    
    async def publish(self, event: BaseEvent):
        """Опубликовать событие"""
        # Применяем middleware
        for middleware in self._middleware:
            event = await middleware(event)
        
        # Добавляем событие в очередь
        await self._event_queue.put(event)
        logger.debug(f"Published event: {event.event_type}")
    
    async def start(self):
        """Запустить обработку событий"""
        if self._is_running:
            return
        
        self._is_running = True
        self._task = asyncio.create_task(self._process_events())
        logger.info("Event bus started")
    
    async def stop(self):
        """Остановить обработку событий"""
        if not self._is_running:
            return
        
        self._is_running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        
        logger.info("Event bus stopped")
    
    async def _process_events(self):
        """Обрабатывать события из очереди"""
        while self._is_running:
            try:
                event = await asyncio.wait_for(self._event_queue.get(), timeout=1.0)
                await self._handle_event(event)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Error processing event: {e}")
    
    async def _handle_event(self, event: BaseEvent):
        """Обработать конкретное событие"""
        event_type = event.event_type
        
        if event_type not in self._handlers:
            logger.warning(f"No handlers for event type: {event_type}")
            return
        
        handlers = self._handlers[event_type]
        
        # Выполняем обработчики параллельно
        tasks = []
        for handler in handlers:
            if handler.can_handle(event_type):
                task = asyncio.create_task(self._execute_handler(handler, event))
                tasks.append(task)
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _execute_handler(self, handler: EventHandler, event: BaseEvent):
        """Выполнить обработчик события"""
        try:
            await handler.handle(event)
            logger.debug(f"Event {event.event_type} handled successfully")
        except Exception as e:
            logger.error(f"Error in event handler: {e}")

def get_event_bus() -> EventBus:
    """Получить шину событий (использует DI контейнер)"""
    from backend.core.dependency_injection import get_container
    container = get_container()
    return container.get(EventBus)