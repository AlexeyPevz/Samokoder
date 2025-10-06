"""
Application constants и magic numbers.

FIX: Вынесены из кода для централизованной конфигурации и упрощения изменений.
"""

from enum import IntEnum


class SecurityLimits(IntEnum):
    """Security-related limits."""
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION_MINUTES = 15
    ACCESS_TOKEN_EXPIRE_MINUTES = 15
    REFRESH_TOKEN_EXPIRE_DAYS = 7
    MIN_PASSWORD_LENGTH = 8


class RateLimits(IntEnum):
    """Rate limiting configuration."""
    # Authentication
    AUTH_REQUESTS_PER_MINUTE = 5
    AUTH_REQUESTS_PER_HOUR = 20
    REGISTER_REQUESTS_PER_HOUR = 3
    
    # Projects
    PROJECT_CREATES_PER_DAY = 10
    PROJECT_CREATES_PER_HOUR = 5
    PROJECT_LISTS_PER_HOUR = 50
    
    # LLM
    LLM_REQUESTS_PER_HOUR = 50
    LLM_REQUESTS_PER_DAY = 200
    
    # General
    PUBLIC_REQUESTS_PER_MINUTE = 10
    AUTHENTICATED_REQUESTS_PER_MINUTE = 100


class DatabaseLimits(IntEnum):
    """Database connection and query limits."""
    CONNECTION_POOL_SIZE = 10
    CONNECTION_POOL_MAX_OVERFLOW = 20
    CONNECTION_POOL_TIMEOUT = 30  # seconds
    QUERY_TIMEOUT = 30  # seconds
    MAX_RESULTS_PER_PAGE = 100


class RequestLimits(IntEnum):
    """HTTP request size limits (in bytes)."""
    DEFAULT_MAX_SIZE = 10 * 1024 * 1024  # 10 MB
    AUTH_MAX_SIZE = 1 * 1024  # 1 KB
    PROJECT_MAX_SIZE = 5 * 1024 * 1024  # 5 MB
    WORKSPACE_MAX_SIZE = 20 * 1024 * 1024  # 20 MB
    FILE_UPLOAD_MAX_SIZE = 50 * 1024 * 1024  # 50 MB


class LLMLimits(IntEnum):
    """LLM-related limits."""
    MAX_TOKENS_PER_REQUEST = 8000
    MAX_CONTEXT_LENGTH = 128000
    MAX_COMPLETION_TOKENS = 4000
    MAX_PARALLEL_REQUESTS = 5
    REQUEST_TIMEOUT = 60  # seconds


class HttpClientTimeouts(IntEnum):
    """HTTP client timeout configuration (seconds)."""
    CONNECT = 5
    READ = 30
    WRITE = 30
    POOL = 5


class CacheLimits(IntEnum):
    """Cache configuration."""
    REDIS_KEY_TTL = 3600  # 1 hour
    SESSION_TTL = 86400 * 7  # 7 days
    RATE_LIMIT_WINDOW = 60  # 1 minute
    

class ProjectLimits(IntEnum):
    """Project-related limits."""
    MAX_FILES_PER_PROJECT = 1000
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
    MAX_PROJECT_NAME_LENGTH = 100
    MAX_PROJECT_DESCRIPTION_LENGTH = 1000


# Application-wide constants
APP_NAME = "Samokoder"
APP_VERSION = "1.0.0"
API_V1_PREFIX = "/v1"

# Environment names
ENV_DEVELOPMENT = "development"
ENV_STAGING = "staging"
ENV_PRODUCTION = "production"
