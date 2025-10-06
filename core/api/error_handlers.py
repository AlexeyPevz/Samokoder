"""Secure error handling to prevent information leakage (ASVS 7.4)."""
from fastapi import Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError
import logging
import uuid


logger = logging.getLogger(__name__)


async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Handle unexpected exceptions without leaking sensitive information.
    
    ASVS 7.4.1: Error messages should not reveal sensitive information.
    """
    error_id = str(uuid.uuid4())
    
    # Log full error details for debugging
    logger.exception(
        f"Unhandled exception [{error_id}]: {exc}",
        extra={
            "error_id": error_id,
            "path": request.url.path,
            "method": request.method,
            "client": request.client.host if request.client else None,
            "exception_type": type(exc).__name__
        }
    )
    
    # Return generic error to client (no sensitive info)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "An internal server error occurred",
            "error_id": error_id,  # For support to track in logs
            "type": "internal_server_error"
        }
    )


async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """
    Handle validation errors with sanitized messages.
    
    ASVS 5.1.3: Validation failures should not reveal system information.
    """
    error_id = str(uuid.uuid4())
    
    # Log validation errors
    logger.warning(
        f"Validation error [{error_id}]: {exc.errors()}",
        extra={
            "error_id": error_id,
            "path": request.url.path,
            "method": request.method
        }
    )
    
    # Sanitize error messages - remove internal details
    sanitized_errors = []
    for error in exc.errors():
        sanitized_errors.append({
            "field": ".".join(str(loc) for loc in error["loc"]),
            "message": error["msg"],
            "type": error["type"]
        })
    
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "detail": "Validation error",
            "errors": sanitized_errors,
            "error_id": error_id
        }
    )
