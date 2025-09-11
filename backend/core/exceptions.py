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

class MonitoringError(SamokoderException):
    """Ошибка мониторинга"""
    pass