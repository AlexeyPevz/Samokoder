"""
Трейсинг и распределенная трассировка
"""

import asyncio
import logging
import time
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from contextlib import asynccontextmanager
from collections import defaultdict

logger = logging.getLogger(__name__)

@dataclass
class Span:
    """Спан трейса"""
    trace_id: str
    span_id: str
    parent_id: Optional[str]
    operation_name: str
    start_time: datetime
    end_time: Optional[datetime] = None
    duration_ms: Optional[float] = None
    tags: Dict[str, Any] = field(default_factory=dict)
    logs: List[Dict[str, Any]] = field(default_factory=list)
    status: str = "started"  # started, completed, error

@dataclass
class Trace:
    """Трейс"""
    trace_id: str
    spans: List[Span] = field(default_factory=list)
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    service_name: str = "samokoder"

class TraceManager:
    """Менеджер трейсинга"""
    
    def __init__(self):
        self.active_traces: Dict[str, Trace] = {}
        self.completed_traces: List[Trace] = []
        self.span_storage: Dict[str, Span] = {}
        self._max_traces = 1000
        self._max_spans_per_trace = 100
    
    def start_trace(self, operation_name: str, service_name: str = "samokoder") -> str:
        """Начать новый трейс"""
        trace_id = str(uuid.uuid4())
        span_id = str(uuid.uuid4())
        
        trace = Trace(
            trace_id=trace_id,
            service_name=service_name
        )
        
        span = Span(
            trace_id=trace_id,
            span_id=span_id,
            parent_id=None,
            operation_name=operation_name,
            start_time=datetime.now()
        )
        
        trace.spans.append(span)
        self.active_traces[trace_id] = trace
        self.span_storage[span_id] = span
        
        logger.debug(f"Started trace {trace_id} with span {span_id}")
        return trace_id
    
    def start_span(self, trace_id: str, operation_name: str, 
                   parent_span_id: Optional[str] = None) -> str:
        """Начать новый спан в трейсе"""
        if trace_id not in self.active_traces:
            logger.warning(f"Trace {trace_id} not found")
            return None
        
        span_id = str(uuid.uuid4())
        span = Span(
            trace_id=trace_id,
            span_id=span_id,
            parent_id=parent_span_id,
            operation_name=operation_name,
            start_time=datetime.now()
        )
        
        self.active_traces[trace_id].spans.append(span)
        self.span_storage[span_id] = span
        
        logger.debug(f"Started span {span_id} in trace {trace_id}")
        return span_id
    
    def finish_span(self, span_id: str, status: str = "completed", 
                   error: Optional[Exception] = None):
        """Завершить спан"""
        if span_id not in self.span_storage:
            logger.warning(f"Span {span_id} not found")
            return
        
        span = self.span_storage[span_id]
        span.end_time = datetime.now()
        span.duration_ms = (span.end_time - span.start_time).total_seconds() * 1000
        span.status = status
        
        if error:
            span.tags["error"] = True
            span.tags["error.message"] = str(error)
            span.logs.append({
                "timestamp": datetime.now().isoformat(),
                "level": "error",
                "message": str(error)
            })
        
        logger.debug(f"Finished span {span_id} with status {status}")
    
    def finish_trace(self, trace_id: str):
        """Завершить трейс"""
        if trace_id not in self.active_traces:
            logger.warning(f"Trace {trace_id} not found")
            return
        
        trace = self.active_traces[trace_id]
        trace.end_time = datetime.now()
        
        # Завершаем все незавершенные спаны
        for span in trace.spans:
            if span.end_time is None:
                self.finish_span(span.span_id, "timeout")
        
        # Перемещаем в завершенные трейсы
        self.completed_traces.append(trace)
        del self.active_traces[trace_id]
        
        # Очищаем старые трейсы
        if len(self.completed_traces) > self._max_traces:
            self.completed_traces = self.completed_traces[-self._max_traces:]
        
        logger.debug(f"Finished trace {trace_id}")
    
    def add_span_tag(self, span_id: str, key: str, value: Any):
        """Добавить тег к спану"""
        if span_id in self.span_storage:
            self.span_storage[span_id].tags[key] = value
    
    def add_span_log(self, span_id: str, message: str, level: str = "info", **kwargs):
        """Добавить лог к спану"""
        if span_id in self.span_storage:
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "level": level,
                "message": message,
                **kwargs
            }
            self.span_storage[span_id].logs.append(log_entry)
    
    @asynccontextmanager
    async def trace_span(self, trace_id: str, operation_name: str, 
                        parent_span_id: Optional[str] = None):
        """Контекстный менеджер для спана"""
        span_id = self.start_span(trace_id, operation_name, parent_span_id)
        try:
            yield span_id
            self.finish_span(span_id, "completed")
        except Exception as e:
            self.finish_span(span_id, "error", e)
            raise
    
    def get_trace(self, trace_id: str) -> Optional[Trace]:
        """Получить трейс по ID"""
        if trace_id in self.active_traces:
            return self.active_traces[trace_id]
        
        for trace in self.completed_traces:
            if trace.trace_id == trace_id:
                return trace
        
        return None
    
    def get_traces_by_service(self, service_name: str, limit: int = 50) -> List[Trace]:
        """Получить трейсы по сервису"""
        traces = []
        for trace in self.completed_traces:
            if trace.service_name == service_name:
                traces.append(trace)
                if len(traces) >= limit:
                    break
        return traces
    
    def get_trace_statistics(self) -> Dict[str, Any]:
        """Получить статистику трейсов"""
        total_traces = len(self.completed_traces)
        total_spans = sum(len(trace.spans) for trace in self.completed_traces)
        
        if total_traces == 0:
            return {"total_traces": 0, "total_spans": 0}
        
        durations = []
        error_count = 0
        
        for trace in self.completed_traces:
            if trace.end_time:
                duration = (trace.end_time - trace.start_time).total_seconds() * 1000
                durations.append(duration)
            
            for span in trace.spans:
                if span.status == "error":
                    error_count += 1
        
        avg_duration = sum(durations) / len(durations) if durations else 0
        error_rate = (error_count / total_spans) * 100 if total_spans > 0 else 0
        
        return {
            "total_traces": total_traces,
            "total_spans": total_spans,
            "active_traces": len(self.active_traces),
            "average_duration_ms": avg_duration,
            "error_rate_percent": error_rate
        }