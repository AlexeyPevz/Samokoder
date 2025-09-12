"""
Централизованные исключения для Samokoder
Заменяет общие Exception на специфичные типы ошибок
"""

class SamokoderException(Exception):
    """Базовое исключение Samokoder"""
    def __init__(self, message: str, details: dict = None):
        self.message = message
        self.details = details or {}
        super().__init__(self.message)

class AuthenticationError(SamokoderException):
    """Ошибка аутентификации"""
    pass

class AuthorizationError(SamokoderException):
    """Ошибка авторизации"""
    pass

class ValidationError(SamokoderException):
    """Ошибка валидации данных"""
    pass

class NotFoundError(SamokoderException):
    """Ресурс не найден"""
    pass

class ConflictError(SamokoderException):
    """Конфликт ресурсов"""
    pass

class RateLimitError(SamokoderException):
    """Превышен лимит запросов"""
    pass

class AIServiceError(SamokoderException):
    """Ошибка AI сервиса"""
    pass

class DatabaseError(SamokoderException):
    """Ошибка базы данных"""
    pass

class ExternalServiceError(SamokoderException):
    """Ошибка внешнего сервиса"""
    pass

class ConfigurationError(SamokoderException):
    """Ошибка конфигурации"""
    pass

class ConnectionError(SamokoderException):
    """Ошибка соединения"""
    pass

class TimeoutError(SamokoderException):
    """Ошибка таймаута"""
    pass

class EncryptionError(SamokoderException):
    """Ошибка шифрования"""
    pass

class ProjectError(SamokoderException):
    """Ошибка проекта"""
    pass

class FileSystemError(SamokoderException):
    """Ошибка файловой системы"""
    pass

class NetworkError(SamokoderException):
    """Ошибка сети"""
    pass

class CacheError(SamokoderException):
    """Ошибка кэша"""
    pass

class RedisError(SamokoderException):
    """Ошибка Redis"""
    pass

class MonitoringError(SamokoderException):
    """Ошибка мониторинга"""
    pass

def convert_to_http_exception(exception: SamokoderException) -> int:
    """Конвертирует внутренние исключения в HTTP статус коды"""
    error_mapping = {
        AuthenticationError: 401,
        AuthorizationError: 403,
        ValidationError: 400,
        NotFoundError: 404,
        ConflictError: 409,
        RateLimitError: 429,
        AIServiceError: 503,
        DatabaseError: 503,
        ExternalServiceError: 503,
        ConfigurationError: 500,
        ConnectionError: 503,
        TimeoutError: 504,
        EncryptionError: 500,
        ProjectError: 400,
        FileSystemError: 500,
        NetworkError: 503,
        CacheError: 500,
        RedisError: 503,
        MonitoringError: 500,
    }
    
    return error_mapping.get(type(exception), 500)