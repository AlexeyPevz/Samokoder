"""
Универсальный сервис пагинации для всех эндпоинтов
Поддерживает различные типы пагинации и оптимизацию запросов
"""

import math
from typing import List, Dict, Any, Optional, Tuple, TypeVar, Generic
from dataclasses import dataclass
from pydantic import BaseModel, Field

T = TypeVar('T')

@dataclass
class PaginationParams:
    """Параметры пагинации"""
    page: int = 1
    limit: int = 10
    max_limit: int = 100
    offset: Optional[int] = None
    
    def __post_init__(self):
        """Валидация и нормализация параметров"""
        # Ограничиваем размер страницы
        if self.limit > self.max_limit:
            self.limit = self.max_limit
        elif self.limit < 1:
            self.limit = 1
        
        # Ограничиваем номер страницы
        if self.page < 1:
            self.page = 1
        
        # Вычисляем offset если не задан
        if self.offset is None:
            self.offset = (self.page - 1) * self.limit

class PaginatedResponse(BaseModel, Generic[T]):
    """Универсальный ответ с пагинацией"""
    items: List[T] = Field(..., description="Элементы на текущей странице")
    total: int = Field(..., description="Общее количество элементов")
    page: int = Field(..., description="Текущая страница")
    limit: int = Field(..., description="Количество элементов на странице")
    pages: int = Field(..., description="Общее количество страниц")
    has_next: bool = Field(..., description="Есть ли следующая страница")
    has_prev: bool = Field(..., description="Есть ли предыдущая страница")
    next_page: Optional[int] = Field(None, description="Номер следующей страницы")
    prev_page: Optional[int] = Field(None, description="Номер предыдущей страницы")

class PaginationService:
    """Сервис для работы с пагинацией"""
    
    @staticmethod
    def create_pagination_params(
        page: int = 1,
        limit: int = 10,
        max_limit: int = 100
    ) -> PaginationParams:
        """Создает параметры пагинации с валидацией"""
        return PaginationParams(
            page=page,
            limit=limit,
            max_limit=max_limit
        )
    
    @staticmethod
    def calculate_pagination_info(
        total_items: int,
        page: int,
        limit: int
    ) -> Dict[str, Any]:
        """Вычисляет информацию о пагинации"""
        total_pages = math.ceil(total_items / limit) if total_items > 0 else 1
        
        # Ограничиваем номер страницы
        if page > total_pages:
            page = total_pages
        elif page < 1:
            page = 1
        
        has_next = page < total_pages
        has_prev = page > 1
        
        return {
            "total": total_items,
            "page": page,
            "limit": limit,
            "pages": total_pages,
            "has_next": has_next,
            "has_prev": has_prev,
            "next_page": page + 1 if has_next else None,
            "prev_page": page - 1 if has_prev else None,
            "offset": (page - 1) * limit
        }
    
    @staticmethod
    def create_paginated_response(
        items: List[T],
        total: int,
        page: int,
        limit: int
    ) -> PaginatedResponse[T]:
        """Создает пагинированный ответ"""
        pagination_info = PaginationService.calculate_pagination_info(
            total, page, limit
        )
        
        return PaginatedResponse[T](
            items=items,
            **pagination_info
        )
    
    @staticmethod
    def validate_pagination_params(
        page: int,
        limit: int,
        max_limit: int = 100
    ) -> Tuple[int, int]:
        """Валидирует параметры пагинации"""
        # Валидация страницы
        if page < 1:
            page = 1
        
        # Валидация лимита
        if limit < 1:
            limit = 1
        elif limit > max_limit:
            limit = max_limit
        
        return page, limit

class DatabasePagination:
    """Пагинация для работы с базой данных"""
    
    @staticmethod
    def build_count_query(base_query: str, where_clause: str = "") -> str:
        """Строит запрос для подсчета общего количества записей"""
        if where_clause:
            return f"SELECT COUNT(*) FROM ({base_query}) AS count_query WHERE {where_clause}"
        else:
            return f"SELECT COUNT(*) FROM ({base_query}) AS count_query"
    
    @staticmethod
    def build_paginated_query(
        base_query: str,
        page: int,
        limit: int,
        order_by: str = "id",
        order_direction: str = "ASC",
        where_clause: str = ""
    ) -> str:
        """Строит пагинированный запрос"""
        offset = (page - 1) * limit
        
        query_parts = [base_query]
        
        if where_clause:
            query_parts.append(f"WHERE {where_clause}")
        
        query_parts.append(f"ORDER BY {order_by} {order_direction}")
        query_parts.append(f"LIMIT {limit} OFFSET {offset}")
        
        return " ".join(query_parts)
    
    @staticmethod
    def build_search_query(
        base_query: str,
        search_fields: List[str],
        search_term: str,
        page: int,
        limit: int,
        order_by: str = "id"
    ) -> Tuple[str, str]:
        """Строит запрос с поиском"""
        # Создаем условие поиска
        search_conditions = []
        for field in search_fields:
            search_conditions.append(f"{field} ILIKE '%{search_term}%'")
        
        where_clause = " OR ".join(search_conditions)
        
        # Строим запросы
        count_query = DatabasePagination.build_count_query(base_query, where_clause)
        data_query = DatabasePagination.build_paginated_query(
            base_query, page, limit, order_by, "ASC", where_clause
        )
        
        return count_query, data_query

class CursorPagination:
    """Курсорная пагинация для больших наборов данных"""
    
    @staticmethod
    def create_cursor_params(
        cursor: Optional[str] = None,
        limit: int = 10,
        max_limit: int = 100
    ) -> Dict[str, Any]:
        """Создает параметры для курсорной пагинации"""
        if limit > max_limit:
            limit = max_limit
        elif limit < 1:
            limit = 1
        
        return {
            "cursor": cursor,
            "limit": limit
        }
    
    @staticmethod
    def encode_cursor(value: Any) -> str:
        """Кодирует курсор"""
        import base64
        import json
        
        cursor_data = {"value": str(value), "timestamp": str(int(time.time()))}
        encoded = base64.b64encode(json.dumps(cursor_data).encode()).decode()
        return encoded
    
    @staticmethod
    def decode_cursor(cursor: str) -> Optional[Any]:
        """Декодирует курсор"""
        import base64
        import json
        
        try:
            decoded = base64.b64decode(cursor.encode()).decode()
            cursor_data = json.loads(decoded)
            return cursor_data.get("value")
        except Exception:
            return None

class ElasticsearchPagination:
    """Пагинация для Elasticsearch"""
    
    @staticmethod
    def build_elasticsearch_query(
        page: int,
        limit: int,
        search_body: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Строит запрос для Elasticsearch с пагинацией"""
        offset = (page - 1) * limit
        
        query = search_body.copy()
        query["from"] = offset
        query["size"] = limit
        
        return query
    
    @staticmethod
    def parse_elasticsearch_response(
        response: Dict[str, Any],
        page: int,
        limit: int
    ) -> PaginatedResponse:
        """Парсит ответ Elasticsearch в пагинированный формат"""
        hits = response.get("hits", {})
        total = hits.get("total", {}).get("value", 0)
        items = [hit["_source"] for hit in hits.get("hits", [])]
        
        return PaginationService.create_paginated_response(
            items, total, page, limit
        )

class PaginationMiddleware:
    """Middleware для автоматической пагинации"""
    
    @staticmethod
    def extract_pagination_params(request_params: Dict[str, Any]) -> PaginationParams:
        """Извлекает параметры пагинации из запроса"""
        page = int(request_params.get("page", 1))
        limit = int(request_params.get("limit", 10))
        
        return PaginationService.create_pagination_params(page, limit)
    
    @staticmethod
    def add_pagination_headers(
        response_data: PaginatedResponse,
        headers: Dict[str, str]
    ) -> Dict[str, str]:
        """Добавляет заголовки пагинации в ответ"""
        headers.update({
            "X-Total-Count": str(response_data.total),
            "X-Page": str(response_data.page),
            "X-Limit": str(response_data.limit),
            "X-Total-Pages": str(response_data.pages),
            "X-Has-Next": str(response_data.has_next).lower(),
            "X-Has-Prev": str(response_data.has_prev).lower()
        })
        
        if response_data.next_page:
            headers["X-Next-Page"] = str(response_data.next_page)
        
        if response_data.prev_page:
            headers["X-Prev-Page"] = str(response_data.prev_page)
        
        return headers

# Утилиты для работы с пагинацией
def paginate_list(
    items: List[T],
    page: int = 1,
    limit: int = 10
) -> PaginatedResponse[T]:
    """Пагинирует список в памяти"""
    total = len(items)
    offset = (page - 1) * limit
    
    paginated_items = items[offset:offset + limit]
    
    return PaginationService.create_paginated_response(
        paginated_items, total, page, limit
    )

def create_pagination_links(
    base_url: str,
    page: int,
    total_pages: int,
    limit: int,
    **query_params
) -> Dict[str, Optional[str]]:
    """Создает ссылки для пагинации"""
    def build_url(page_num: Optional[int]) -> Optional[str]:
        if page_num is None:
            return None
        
        params = query_params.copy()
        params.update({"page": page_num, "limit": limit})
        
        param_string = "&".join([f"{k}={v}" for k, v in params.items()])
        return f"{base_url}?{param_string}"
    
    return {
        "first": build_url(1) if total_pages > 1 else None,
        "prev": build_url(page - 1) if page > 1 else None,
        "next": build_url(page + 1) if page < total_pages else None,
        "last": build_url(total_pages) if total_pages > 1 else None,
        "self": build_url(page)
    }