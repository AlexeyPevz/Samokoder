"""
Custom exceptions for the application
"""
from fastapi import HTTPException, status
from typing import Optional, Dict, Any

class SamokoderException(Exception):
    """Base exception for Samokoder application"""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        self.message = message
        self.details = details or {}
        super().__init__(self.message)

class AuthenticationError(SamokoderException):
    """Authentication related errors"""
    pass

class AuthorizationError(SamokoderException):
    """Authorization related errors"""
    pass

class ValidationError(SamokoderException):
    """Validation related errors"""
    pass

class NotFoundError(SamokoderException):
    """Resource not found errors"""
    pass

class ConflictError(SamokoderException):
    """Resource conflict errors"""
    pass

class RateLimitError(SamokoderException):
    """Rate limiting errors"""
    pass

class AIServiceError(SamokoderException):
    """AI service related errors"""
    pass

class DatabaseError(SamokoderException):
    """Database related errors"""
    pass

class ExternalServiceError(SamokoderException):
    """External service related errors"""
    pass

def convert_to_http_exception(exc: SamokoderException) -> HTTPException:
    """Convert SamokoderException to HTTPException"""
    
    if isinstance(exc, AuthenticationError):
        return HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=exc.message,
            headers={"WWW-Authenticate": "Bearer"}
        )
    elif isinstance(exc, AuthorizationError):
        return HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=exc.message
        )
    elif isinstance(exc, ValidationError):
        return HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=exc.message
        )
    elif isinstance(exc, NotFoundError):
        return HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=exc.message
        )
    elif isinstance(exc, ConflictError):
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=exc.message
        )
    elif isinstance(exc, RateLimitError):
        return HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=exc.message
        )
    elif isinstance(exc, AIServiceError):
        return HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=exc.message
        )
    elif isinstance(exc, DatabaseError):
        return HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=exc.message
        )
    elif isinstance(exc, ExternalServiceError):
        return HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=exc.message
        )
    else:
        return HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=exc.message
        )