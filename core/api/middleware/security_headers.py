"""Security headers middleware (ASVS 14.4)."""
import os
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Add security headers to all responses.
    
    Implements ASVS 14.4 requirements for secure HTTP headers.
    """
    
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        
        environment = os.getenv("ENVIRONMENT", "development")
        
        # Content Security Policy (ASVS 14.4.3)
        if environment == "production":
            # Stricter CSP in production: no inline/eval; allow connect to self and API only
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self'; "
                "style-src 'self'; "
                "img-src 'self' data: https:; "
                "font-src 'self' data:; "
                "connect-src 'self'; "
                "frame-ancestors 'none'; "
                "base-uri 'self'; "
                "form-action 'self';"
            )
        else:
            # Relaxed CSP in non-production for DX
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self' data:; "
                "connect-src 'self'; "
                "frame-ancestors 'none'; "
                "base-uri 'self'; "
                "form-action 'self';"
            )
        
        # Prevent clickjacking (ASVS 14.4.4)
        response.headers["X-Frame-Options"] = "DENY"
        
        # Prevent MIME type sniffing (ASVS 14.4.5)
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # Enable XSS filter (ASVS 14.4.6)
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        # Referrer policy (ASVS 14.5.4)
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # HSTS - only in production with HTTPS (ASVS 9.2.1)
        if environment == "production":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )
        
        # Permissions policy (restrict features)
        response.headers["Permissions-Policy"] = (
            "geolocation=(), "
            "microphone=(), "
            "camera=(), "
            "payment=(), "
            "usb=(), "
            "magnetometer=()"
        )
        
        # Remove server header to avoid version disclosure (ASVS 14.3.3)
        response.headers.pop("Server", None)
        
        return response
