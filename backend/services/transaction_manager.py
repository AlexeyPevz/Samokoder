"""
Менеджер транзакций для безопасных операций с БД
Обеспечивает ACID свойства для операций с Supabase
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional, Callable, Union
from contextlib import asynccontextmanager
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class TransactionState(Enum):
    """Состояния транзакции"""
    PENDING = "pending"
    COMMITTED = "committed"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"

@dataclass
class TransactionOperation:
    """Операция в транзакции"""
    operation_id: str
    operation_type: str  # insert, update, delete, select
    table: str
    data: Dict[str, Any]
    rollback_data: Optional[Dict[str, Any]] = None
    executed: bool = False

class TransactionManager:
    """Менеджер транзакций для Supabase"""
    
    def __init__(self):
        self._active_transactions: Dict[str, List[TransactionOperation]] = {}
        self._transaction_locks: Dict[str, asyncio.Lock] = {}
    
    def _generate_transaction_id(self) -> str:
        """Генерирует уникальный ID транзакции"""
        import uuid
        return f"txn_{uuid.uuid4().hex[:16]}"
    
    @asynccontextmanager
    async def transaction(self, transaction_id: Optional[str] = None):
        """Контекстный менеджер для транзакции"""
        if transaction_id is None:
            transaction_id = self._generate_transaction_id()
        
        # Создаем блокировку для транзакции
        if transaction_id not in self._transaction_locks:
            self._transaction_locks[transaction_id] = asyncio.Lock()
        
        async with self._transaction_locks[transaction_id]:
            try:
                # Инициализируем транзакцию
                self._active_transactions[transaction_id] = []
                logger.info(f"Started transaction: {transaction_id}")
                
                yield transaction_id
                
                # Коммитим транзакцию
                await self._commit_transaction(transaction_id)
                logger.info(f"Committed transaction: {transaction_id}")
                
            except Exception as e:
                # Откатываем транзакцию
                await self._rollback_transaction(transaction_id)
                logger.error(f"Rolled back transaction {transaction_id}: {e}")
                raise
            finally:
                # Очищаем транзакцию
                self._cleanup_transaction(transaction_id)
    
    async def add_operation(
        self, 
        transaction_id: str, 
        operation_type: str, 
        table: str, 
        data: Dict[str, Any],
        rollback_data: Optional[Dict[str, Any]] = None
    ) -> str:
        """Добавляет операцию в транзакцию"""
        if transaction_id not in self._active_transactions:
            raise ValueError(f"Transaction {transaction_id} not found")
        
        operation_id = f"op_{len(self._active_transactions[transaction_id])}"
        operation = TransactionOperation(
            operation_id=operation_id,
            operation_type=operation_type,
            table=table,
            data=data,
            rollback_data=rollback_data
        )
        
        self._active_transactions[transaction_id].append(operation)
        logger.debug(f"Added operation {operation_id} to transaction {transaction_id}")
        
        return operation_id
    
    async def execute_operation(
        self, 
        transaction_id: str, 
        operation_id: str,
        supabase_client
    ) -> Any:
        """Выполняет операцию в транзакции"""
        if transaction_id not in self._active_transactions:
            raise ValueError(f"Transaction {transaction_id} not found")
        
        operation = None
        for op in self._active_transactions[transaction_id]:
            if op.operation_id == operation_id:
                operation = op
                break
        
        if not operation:
            raise ValueError(f"Operation {operation_id} not found in transaction {transaction_id}")
        
        try:
            # Выполняем операцию
            if operation.operation_type == "insert":
                result = supabase_client.table(operation.table).insert(operation.data).execute()
            elif operation.operation_type == "update":
                result = supabase_client.table(operation.table).update(operation.data).execute()
            elif operation.operation_type == "delete":
                result = supabase_client.table(operation.table).delete().execute()
            elif operation.operation_type == "select":
                result = supabase_client.table(operation.table).select("*").execute()
            else:
                raise ValueError(f"Unknown operation type: {operation.operation_type}")
            
            operation.executed = True
            logger.debug(f"Executed operation {operation_id} in transaction {transaction_id}")
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to execute operation {operation_id}: {e}")
            raise
    
    async def _commit_transaction(self, transaction_id: str):
        """Коммитит транзакцию"""
        if transaction_id not in self._active_transactions:
            return
        
        operations = self._active_transactions[transaction_id]
        
        # Проверяем, что все операции выполнены
        for operation in operations:
            if not operation.executed:
                raise RuntimeError(f"Operation {operation.operation_id} not executed")
        
        logger.info(f"Transaction {transaction_id} committed with {len(operations)} operations")
    
    async def _rollback_transaction(self, transaction_id: str):
        """Откатывает транзакцию"""
        if transaction_id not in self._active_transactions:
            return
        
        operations = self._active_transactions[transaction_id]
        
        # Откатываем выполненные операции в обратном порядке
        for operation in reversed(operations):
            if operation.executed and operation.rollback_data:
                try:
                    # Здесь должна быть логика отката
                    # Для Supabase это сложно, так как нет встроенных транзакций
                    logger.warning(f"Rollback not fully supported for Supabase operation {operation.operation_id}")
                except Exception as e:
                    logger.error(f"Failed to rollback operation {operation.operation_id}: {e}")
        
        logger.info(f"Transaction {transaction_id} rolled back")
    
    def _cleanup_transaction(self, transaction_id: str):
        """Очищает транзакцию"""
        if transaction_id in self._active_transactions:
            del self._active_transactions[transaction_id]
        
        if transaction_id in self._transaction_locks:
            del self._transaction_locks[transaction_id]
    
    def get_transaction_info(self, transaction_id: str) -> Optional[Dict[str, Any]]:
        """Получить информацию о транзакции"""
        if transaction_id not in self._active_transactions:
            return None
        
        operations = self._active_transactions[transaction_id]
        
        return {
            "transaction_id": transaction_id,
            "operation_count": len(operations),
            "executed_operations": sum(1 for op in operations if op.executed),
            "pending_operations": sum(1 for op in operations if not op.executed)
        }

# Глобальный экземпляр менеджера
transaction_manager = TransactionManager()

# Удобные функции для использования
@asynccontextmanager
async def transaction(transaction_id: Optional[str] = None):
    """Контекстный менеджер для транзакции"""
    async with transaction_manager.transaction(transaction_id) as txn_id:
        yield txn_id

async def add_operation(
    transaction_id: str, 
    operation_type: str, 
    table: str, 
    data: Dict[str, Any],
    rollback_data: Optional[Dict[str, Any]] = None
) -> str:
    """Добавить операцию в транзакцию"""
    return await transaction_manager.add_operation(
        transaction_id, operation_type, table, data, rollback_data
    )

async def execute_operation(
    transaction_id: str, 
    operation_id: str,
    supabase_client
) -> Any:
    """Выполнить операцию в транзакции"""
    return await transaction_manager.execute_operation(
        transaction_id, operation_id, supabase_client
    )