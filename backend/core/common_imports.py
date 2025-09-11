"""
Common imports for the application
"""
from datetime import datetime, timedelta
import uuid
import logging
import asyncio
import os
import json
from typing import Dict, Any, Optional, List, Union, Type, TypeVar, Callable
from dataclasses import dataclass
from enum import Enum

# Common logging setup
def get_logger(name: str) -> logging.Logger:
    """Get logger with consistent configuration"""
    return logging.getLogger(name)

# Common type aliases
T = TypeVar('T')
JSONDict = Dict[str, Any]
OptionalDict = Optional[Dict[str, Any]]
ListDict = List[Dict[str, Any]]

# Common datetime utilities
def utc_now() -> datetime:
    """Get current UTC datetime"""
    return datetime.utcnow()

def add_days(dt: datetime, days: int) -> datetime:
    """Add days to datetime"""
    return dt + timedelta(days=days)

def add_hours(dt: datetime, hours: int) -> datetime:
    """Add hours to datetime"""
    return dt + timedelta(hours=hours)

# Common UUID utilities
def generate_uuid() -> str:
    """Generate new UUID string"""
    return str(uuid.uuid4())

def is_valid_uuid(uuid_string: str) -> bool:
    """Check if string is valid UUID"""
    try:
        uuid.UUID(uuid_string)
        return True
    except ValueError:
        return False

# Common environment utilities
def get_env_var(key: str, default: Optional[str] = None) -> Optional[str]:
    """Get environment variable with default"""
    return os.getenv(key, default)

def get_env_bool(key: str, default: bool = False) -> bool:
    """Get boolean environment variable"""
    value = os.getenv(key, str(default)).lower()
    return value in ('true', '1', 'yes', 'on')

def get_env_int(key: str, default: int = 0) -> int:
    """Get integer environment variable"""
    try:
        return int(os.getenv(key, str(default)))
    except ValueError:
        return default

# Common JSON utilities
def safe_json_loads(json_string: str, default: Any = None) -> Any:
    """Safely load JSON string"""
    try:
        return json.loads(json_string)
    except (json.JSONDecodeError, TypeError):
        return default

def safe_json_dumps(obj: Any, default: str = "{}") -> str:
    """Safely dump object to JSON string"""
    try:
        return json.dumps(obj)
    except (TypeError, ValueError):
        return default

# Common validation utilities
def is_valid_email(email: str) -> bool:
    """Check if email is valid"""
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def is_valid_password(password: str) -> bool:
    """Check if password meets requirements"""
    if len(password) < 8:
        return False
    if not any(c.isupper() for c in password):
        return False
    if not any(c.islower() for c in password):
        return False
    if not any(c.isdigit() for c in password):
        return False
    return True

# Common error handling
class CommonError(Exception):
    """Base error class"""
    pass

# Common constants
class HTTPStatus:
    """HTTP status codes"""
    OK = 200
    CREATED = 201
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    FORBIDDEN = 403
    NOT_FOUND = 404
    CONFLICT = 409
    INTERNAL_SERVER_ERROR = 500

class PaginationDefaults:
    """Pagination defaults"""
    DEFAULT_LIMIT = 10
    MAX_LIMIT = 100
    DEFAULT_OFFSET = 0

class CacheDefaults:
    """Cache defaults"""
    DEFAULT_TTL = 300  # 5 minutes
    LONG_TTL = 3600    # 1 hour
    SHORT_TTL = 60     # 1 minute