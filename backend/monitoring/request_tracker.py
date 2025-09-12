"""
Трекер HTTP запросов
"""

import asyncio
import logging
import time
from datetime import datetime
from typing import Dict, Any, Optional
from fastapi import Request, Response
from backend.security.log_sanitizer import log_sanitizer

logger = logging.getLogger(__name__)

class RequestTracker:
    """Трекер HTTP запросов"""
    
    def __init__(self):
        self.active_requests: Dict[str, Dict[str, Any]] = {}
        self.request_counter = 0
    
    def start_request(self, request: Request) -> str:
        """Начать отслеживание запроса"""
        self.request_counter += 1
        request_id = f"req_{self.request_counter}_{int(time.time())}"
        
        self.active_requests[request_id] = {
            "method": request.method,
            "url": str(request.url),
            "path": request.url.path,
            "query_params": dict(request.query_params),
            "headers": dict(request.headers),
            "client_ip": request.client.host if request.client else "unknown",
            "user_agent": request.headers.get("user-agent", "unknown"),
            "start_time": time.time(),
            "timestamp": datetime.now().isoformat()
        }
        
        logger.info(f"Started tracking request {request_id}: {request.method} {request.url.path}")
        return request_id
    
    def finish_request(self, request_id: str, response: Response, 
                      success: bool = True, error: Optional[Exception] = None):
        """Завершить отслеживание запроса"""
        if request_id not in self.active_requests:
            logger.warning(f"Request {request_id} not found in active requests")
            return
        
        request_data = self.active_requests[request_id]
        end_time = time.time()
        duration = end_time - request_data["start_time"]
        
        # Обновляем данные запроса
        request_data.update({
            "status_code": response.status_code,
            "duration": duration,
            "success": success,
            "error": str(error) if error else None,
            "end_time": end_time,
            "response_size": len(response.body) if hasattr(response, 'body') else 0
        })
        
        # Логируем завершение запроса
        log_data = {
            "request_id": request_id,
            "method": request_data["method"],
            "path": request_data["path"],
            "status_code": response.status_code,
            "duration_ms": duration * 1000,
            "success": success,
            "client_ip": request_data["client_ip"]
        }
        
        if error:
            log_data["error"] = log_sanitizer(str(error))
            logger.error(f"Request {request_id} failed: {log_data}")
        else:
            logger.info(f"Request {request_id} completed: {log_data}")
        
        # Удаляем из активных запросов
        del self.active_requests[request_id]
    
    def get_active_requests(self) -> Dict[str, Dict[str, Any]]:
        """Получить активные запросы"""
        return self.active_requests.copy()
    
    def get_request_summary(self) -> Dict[str, Any]:
        """Получить сводку запросов"""
        active_count = len(self.active_requests)
        total_processed = self.request_counter
        
        # Статистика по методам
        method_counts = {}
        for req_data in self.active_requests.values():
            method = req_data["method"]
            method_counts[method] = method_counts.get(method, 0) + 1
        
        return {
            "active_requests": active_count,
            "total_processed": total_processed,
            "method_distribution": method_counts,
            "timestamp": datetime.now().isoformat()
        }
    
    def cleanup_old_requests(self, max_age_seconds: int = 300):
        """Очистить старые запросы"""
        current_time = time.time()
        old_requests = []
        
        for request_id, request_data in self.active_requests.items():
            age = current_time - request_data["start_time"]
            if age > max_age_seconds:
                old_requests.append(request_id)
        
        for request_id in old_requests:
            logger.warning(f"Cleaning up old request {request_id}")
            del self.active_requests[request_id]
        
        if old_requests:
            logger.info(f"Cleaned up {len(old_requests)} old requests")