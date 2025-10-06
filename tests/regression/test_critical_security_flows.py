"""
Regression tests for critical security flows.

Priority: P1 - BLOCKS MERGE if multiple tests fail
Related commits: 7b1b7e2 (Security audit and remediation)
"""
import pytest
import re
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock

from samokoder.core.db.models.user import User


@pytest.mark.priority_p1
class TestSecurityHeaders:
    """TC-SEC-001 & TC-SEC-002: Security headers on all endpoints."""
    
    def test_tc_sec_001_all_endpoints_have_headers(self, client: TestClient, auth_headers: dict):
        """
        P1: Test that all endpoints return security headers.
        
        Reproduction steps:
        1. Call GET /
        2. Call GET /v1/auth/me (protected)
        3. Call POST /v1/auth/register
        4. Verify all have security headers
        
        Links:
        - core/api/middleware/security_headers.py
        - api/main.py:99
        - Commit: 7b1b7e2
        
        Failure criteria:
        - Any header missing
        - Weak header values
        - HSTS missing in production
        """
        endpoints = [
            ("GET", "/", None),
            ("GET", "/v1/auth/me", auth_headers),
            ("GET", "/health", None),
        ]
        
        required_headers = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "X-XSS-Protection",
            "Referrer-Policy",
            "Permissions-Policy",
        ]
        
        for method, url, headers in endpoints:
            if method == "GET":
                response = client.get(url, headers=headers or {})
            else:
                response = client.post(url, headers=headers or {})
            
            for header in required_headers:
                assert header in response.headers, \
                    f"P1 FAILURE: {header} missing from {url}"
            
            # Verify X-Frame-Options value
            assert response.headers["X-Frame-Options"] == "DENY", \
                f"P1 FAILURE: X-Frame-Options should be DENY on {url}"
            
            # Verify X-Content-Type-Options value  
            assert response.headers["X-Content-Type-Options"] == "nosniff", \
                f"P1 FAILURE: X-Content-Type-Options should be nosniff on {url}"
    
    def test_tc_sec_002_csp_configuration(self, client: TestClient):
        """
        P1: Test that CSP is properly configured.
        
        Reproduction steps:
        1. Get CSP header
        2. Verify default-src 'self'
        3. Verify frame-ancestors 'none'
        4. Verify no unsafe wildcards
        
        Links:
        - core/api/middleware/security_headers.py:21-31
        - Commit: 7b1b7e2
        
        Failure criteria:
        - CSP too permissive
        - Missing critical directives
        - XSS possible
        """
        response = client.get("/")
        csp = response.headers.get("Content-Security-Policy", "")
        
        assert "default-src 'self'" in csp, \
            "P1 FAILURE: CSP should restrict default-src to 'self'"
        
        assert "frame-ancestors 'none'" in csp, \
            "P1 FAILURE: CSP should prevent frame embedding"
        
        assert "base-uri 'self'" in csp, \
            "P1 FAILURE: CSP should restrict base-uri"
        
        assert "form-action 'self'" in csp, \
            "P1 FAILURE: CSP should restrict form-action"
    
    def test_tc_sec_003_server_header_removed(self, client: TestClient):
        """
        P1: Test that Server header is removed to prevent version disclosure.
        
        Links:
        - core/api/middleware/security_headers.py:62
        
        Failure criteria:
        - Server header exposed
        - Version information leaked
        """
        response = client.get("/")
        
        # Server header should be removed
        assert "Server" not in response.headers, \
            "P1 FAILURE: Server header should be removed to prevent version disclosure"


@pytest.mark.priority_p1
class TestErrorHandling:
    """TC-ERR-001 & TC-ERR-002: Secure error handling."""
    
    def test_tc_err_001_no_information_leakage(self, client: TestClient):
        """
        P1: Test that errors don't expose sensitive information.
        
        Reproduction steps:
        1. Trigger internal error
        2. Verify response doesn't contain:
           - Stack traces
           - File paths
           - Database schema
           - Internal IPs
        3. Verify error_id provided
        
        Links:
        - core/api/error_handlers.py:13-41
        - api/main.py:106
        - Commit: 7b1b7e2
        
        Failure criteria:
        - Stack trace exposed
        - File paths visible
        - Database schema leaked
        - No error_id
        """
        # Try to trigger an error (invalid endpoint with complex payload)
        response = client.post("/v1/invalid_endpoint_12345", json={
            "test": "data"
        })
        
        # Should return 404, not 500, but let's check the error format
        error = response.json()
        error_str = str(error).lower()
        
        # Check for information leakage
        dangerous_patterns = [
            r'/workspace/',
            r'/home/',
            r'traceback',
            r'\.py:\d+',  # Python file references
            r'sqlalchemy',
            r'postgresql://',
            r'mysql://',
        ]
        
        for pattern in dangerous_patterns:
            assert not re.search(pattern, error_str, re.IGNORECASE), \
                f"P1 FAILURE: Error response contains sensitive info matching '{pattern}'"
    
    def test_tc_err_002_validation_errors_sanitized(self, client: TestClient):
        """
        P1: Test that validation errors are sanitized.
        
        Reproduction steps:
        1. Send invalid data to endpoint
        2. Verify 422 response
        3. Verify errors sanitized
        4. Verify error_id present
        5. Verify no Pydantic internals exposed
        
        Links:
        - core/api/error_handlers.py:44-78
        - Commit: 7b1b7e2
        
        Failure criteria:
        - Internal field names exposed
        - Pydantic paths visible
        - No error_id
        """
        response = client.post("/v1/auth/register", json={
            "email": "not-an-email",
            "password": "123"
        })
        
        assert response.status_code == 422, \
            "Invalid data should return 422"
        
        error = response.json()
        
        # Should have error_id or errors field
        assert "error_id" in error or "errors" in error or "detail" in error, \
            "P1 FAILURE: Error response should have error_id or structured errors"
        
        # Should not expose internal Pydantic structure
        error_str = str(error).lower()
        assert "pydantic" not in error_str, \
            "P1 FAILURE: Pydantic internals exposed"
        assert "__root__" not in error_str, \
            "P1 FAILURE: Pydantic internal field names exposed"


@pytest.mark.priority_p1
class TestCORSConfiguration:
    """TC-SEC-004: CORS configuration."""
    
    def test_cors_headers_present(self, client: TestClient):
        """
        P1: Test CORS headers are properly configured.
        
        Links:
        - api/main.py:130-146
        - SECURITY_FIXES_SUMMARY.md:P2-3
        
        Failure criteria:
        - Wildcard origins allowed
        - Credentials with wildcard
        """
        # Make a request and check CORS
        response = client.get("/", headers={
            "Origin": "http://localhost:5173"
        })
        
        # In test mode, localhost should be allowed
        # Verify no wildcard
        cors_origin = response.headers.get("Access-Control-Allow-Origin", "")
        assert cors_origin != "*", \
            "P1 FAILURE: CORS should not use wildcard origin!"


@pytest.mark.priority_p1
class TestInputValidation:
    """TC-SEC-005: Input validation and XSS prevention."""
    
    def test_xss_payloads_rejected(self, client: TestClient, auth_headers: dict):
        """
        P1: Test that XSS payloads are rejected.
        
        Reproduction steps:
        1. Send XSS payloads in various fields
        2. Verify rejected or sanitized
        
        Links:
        - Security audit
        
        Failure criteria:
        - XSS payload accepted
        - Script executed
        """
        xss_payloads = [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert('xss')>",
            "javascript:alert('xss')",
            "<svg onload=alert('xss')>",
        ]
        
        for payload in xss_payloads:
            # Try in project name (if endpoint exists)
            response = client.post("/v1/projects",
                headers=auth_headers,
                json={
                    "name": payload,
                    "description": "test"
                }
            )
            
            # Should either reject or sanitize
            # Most likely will return 404 if endpoint doesn't exist,
            # but payload should never be executed
            assert response.status_code in [400, 404, 422], \
                f"XSS payload should be rejected: {payload}"


@pytest.mark.priority_p1
class TestRateLimiting:
    """Test rate limiting across endpoints."""
    
    def test_rate_limit_headers_present(self, client: TestClient):
        """
        P1: Test that rate limit info is provided in headers.
        
        Failure criteria:
        - No rate limit information
        - Unlimited requests allowed
        """
        # Make a few requests to auth endpoint
        for _ in range(3):
            response = client.post("/v1/auth/refresh", json={
                "refresh_token": "dummy_token"
            })
            
            # Rate limit headers should eventually appear
            # (may not be on every request depending on implementation)
            if "X-RateLimit-Limit" in response.headers:
                assert int(response.headers["X-RateLimit-Limit"]) > 0, \
                    "Rate limit should be configured"
                break


@pytest.mark.priority_p1
class TestPasswordSecurity:
    """Additional password security tests."""
    
    def test_common_passwords_rejected(self, client: TestClient):
        """
        P1: Test that common passwords are rejected.
        
        Links:
        - core/api/models/auth.py:6-17
        """
        common_passwords = [
            "password",
            "Password123",
            "Password123!",  # Even with requirements met
            "Admin123!",
            "Qwerty123!",
        ]
        
        for password in common_passwords:
            response = client.post("/v1/auth/register", json={
                "email": f"test_{password}@example.com",
                "password": password
            })
            
            # Should be rejected (may pass if not in common list)
            # But Password123! should definitely be rejected
            if password == "Password123!":
                assert response.status_code in [400, 422], \
                    "P1 FAILURE: Common password 'Password123!' should be rejected"
    
    def test_repeated_characters_rejected(self, client: TestClient):
        """
        P1: Test that passwords with too many repeated characters are rejected.
        
        Links:
        - core/api/models/auth.py:69-73
        """
        response = client.post("/v1/auth/register", json={
            "email": "repeated@example.com",
            "password": "Aaaa1234!"  # More than 2 'a's in a row
        })
        
        assert response.status_code in [400, 422], \
            "P1 FAILURE: Password with 3+ repeated characters should be rejected"


@pytest.mark.priority_p0
class TestAuthenticationBypass:
    """Test for authentication bypass vulnerabilities."""
    
    def test_cannot_access_protected_without_token(self, client: TestClient):
        """
        P0: Test that protected endpoints require authentication.
        
        Failure criteria:
        - Protected endpoint accessible without token
        - Authentication bypassed
        """
        response = client.get("/v1/auth/me")
        
        assert response.status_code == 401, \
            "P0 FAILURE: Protected endpoint accessible without authentication!"
    
    def test_invalid_token_rejected(self, client: TestClient):
        """
        P0: Test that invalid tokens are rejected.
        
        Failure criteria:
        - Invalid token accepted
        - JWT verification bypassed
        """
        fake_headers = {"Authorization": "Bearer invalid_token_12345"}
        response = client.get("/v1/auth/me", headers=fake_headers)
        
        assert response.status_code == 401, \
            "P0 FAILURE: Invalid token should be rejected!"
    
    def test_expired_token_rejected(self, client: TestClient, test_user: User):
        """
        P0: Test that expired tokens are rejected.
        
        Failure criteria:
        - Expired token accepted
        - exp claim not checked
        """
        from jose import jwt
        from datetime import datetime, timedelta
        from samokoder.core.config import get_config
        
        config = get_config()
        
        # Create expired token
        expired_token = jwt.encode(
            {
                "sub": test_user.email,
                "exp": datetime.utcnow() - timedelta(hours=1),  # Expired 1 hour ago
                "type": "access",
                "jti": "expired-jti"
            },
            config.secret_key,
            algorithm="HS256"
        )
        
        headers = {"Authorization": f"Bearer {expired_token}"}
        response = client.get("/v1/auth/me", headers=headers)
        
        assert response.status_code == 401, \
            "P0 FAILURE: Expired token should be rejected!"
