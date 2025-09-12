"""
Command Bus
Шина команд для обработки команд системы
"""

import logging
import asyncio
from typing import Dict, List, Callable, Any, Optional, TypeVar, Generic
from abc import ABC, abstractmethod

from backend.commands.base_command import BaseCommand

T = TypeVar('T')

logger = logging.getLogger(__name__)

class CommandHandler(ABC, Generic[T]):
    """Абстрактный обработчик команд"""
    
    @abstractmethod
    async def handle(self, command: BaseCommand[T]) -> T:
        """Обработать команду"""
        pass
    
    @abstractmethod
    def can_handle(self, command_type: str) -> bool:
        """Проверить, может ли обработчик обработать команду данного типа"""
        pass

class CommandBus:
    """Шина команд"""
    
    def __init__(self):
        self._handlers: Dict[str, List[CommandHandler]] = {}
        self._middleware: List[Callable] = []
        self._command_queue: asyncio.Queue = asyncio.Queue()
        self._is_running = False
        self._task: Optional[asyncio.Task] = None
    
    def register_handler(self, command_type: str, handler: CommandHandler):
        """Зарегистрировать обработчик команд"""
        if command_type not in self._handlers:
            self._handlers[command_type] = []
        
        self._handlers[command_type].append(handler)
        logger.info(f"Registered handler for command type: {command_type}")
    
    def unregister_handler(self, command_type: str, handler: CommandHandler):
        """Отменить регистрацию обработчика команд"""
        if command_type in self._handlers:
            try:
                self._handlers[command_type].remove(handler)
                logger.info(f"Unregistered handler for command type: {command_type}")
            except ValueError:
                logger.warning(f"Handler not found for command type: {command_type}")
    
    def add_middleware(self, middleware: Callable):
        """Добавить middleware для обработки команд"""
        self._middleware.append(middleware)
        logger.info("Added command middleware")
    
    async def execute(self, command: BaseCommand[T]) -> T:
        """Выполнить команду синхронно"""
        if not command.validate():
            raise ValueError(f"Invalid command: {command.command_type}")
        
        # Применяем middleware
        for middleware in self._middleware:
            command = await middleware(command)
        
        command_type = command.command_type
        
        if command_type not in self._handlers:
            raise ValueError(f"No handlers for command type: {command_type}")
        
        handlers = self._handlers[command_type]
        
        # Находим подходящий обработчик
        handler = None
        for h in handlers:
            if h.can_handle(command_type):
                handler = h
                break
        
        if not handler:
            raise ValueError(f"No suitable handler for command type: {command_type}")
        
        try:
            result = await handler.handle(command)
            logger.debug(f"Command {command_type} executed successfully")
            return result
        except Exception as e:
            logger.error(f"Error executing command {command_type}: {e}")
            raise
    
    async def execute_async(self, command: BaseCommand[T]) -> asyncio.Task[T]:
        """Выполнить команду асинхронно"""
        return asyncio.create_task(self.execute(command))
    
    async def queue_command(self, command: BaseCommand[T]):
        """Добавить команду в очередь для асинхронного выполнения"""
        await self._command_queue.put(command)
        logger.debug(f"Queued command: {command.command_type}")
    
    async def start(self):
        """Запустить обработку команд из очереди"""
        if self._is_running:
            return
        
        self._is_running = True
        self._task = asyncio.create_task(self._process_commands())
        logger.info("Command bus started")
    
    async def stop(self):
        """Остановить обработку команд"""
        if not self._is_running:
            return
        
        self._is_running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        
        logger.info("Command bus stopped")
    
    async def _process_commands(self):
        """Обрабатывать команды из очереди"""
        while self._is_running:
            try:
                command = await asyncio.wait_for(self._command_queue.get(), timeout=1.0)
                await self.execute(command)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Error processing command: {e}")

# Глобальная шина команд
_command_bus: Optional[CommandBus] = None

def get_command_bus() -> CommandBus:
    """Получить глобальную шину команд"""
    global _command_bus
    if _command_bus is None:
        _command_bus = CommandBus()
    return _command_bus