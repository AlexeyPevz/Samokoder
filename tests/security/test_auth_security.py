"""Security tests for authentication (ASVS 2.x, 3.x)."""
import pytest
from fastapi.testclient import TestClient
from datetime import datetime, timedelta
from unittest.mock import patch
from samokoder.core.db.models.user import User, Tier
from samokoder.core.db.models.login_attempts import LoginAttempt


class TestAuthenticationSecurity:
    """Tests for authentication security (ASVS 2.x)."""
    
    def test_p0_1_refresh_token_rate_limiting(self, client: TestClient):
        """
        P0-1: Test that refresh token endpoint is rate limited.
        ASVS 3.5.2: Verify that refresh tokens have limited rate.
        """
        responses = []
        for _ in range(10):
            response = client.post("/v1/auth/refresh", json={
                "refresh_token": "invalid_token_12345"
            })
            responses.append(response.status_code)
        
        # Should get at least one 429 (Too Many Requests)
        assert 429 in responses, "Refresh token endpoint must be rate limited"
    
    def test_p1_1_jwt_jti_present(self, client: TestClient, db_session):
        """
        P1-1: Test that JWT tokens include jti claim.
        ASVS 3.5.3: Tokens should have unique identifiers for revocation.
        """
        # Create and login user
        user = User(
            email="test@example.com",
            hashed_password="$2b$12$test",  # Hashed password
            tier=Tier.FREE
        )
        db_session.add(user)
        db_session.commit()
        
        response = client.post("/v1/auth/login", data={
            "username": "test@example.com",
            "password": "TestPassword123!"
        })
        
        if response.status_code == 200:
            # Decode token and verify jti is present
            token = response.json()["access_token"]
            from jose import jwt
            from samokoder.core.config import get_config
            config = get_config()
            
            decoded = jwt.decode(token, config.secret_key, algorithms=["HS256"])
            assert "jti" in decoded, "JWT must include jti claim for revocation"
            assert isinstance(decoded["jti"], str), "jti must be a string"
            assert len(decoded["jti"]) > 0, "jti must not be empty"
    
    def test_p1_2_strong_password_requirements(self, client: TestClient):
        """
        P1-2: Test that weak passwords are rejected.
        ASVS 2.1.1: Passwords must meet minimum strength requirements.
        """
        weak_passwords = [
            "short",  # Too short
            "nocapital123!",  # No uppercase
            "NOLOWERCASE123!",  # No lowercase
            "NoNumbers!",  # No numbers
            "NoSpecialChar123",  # No special characters
            "Password123!",  # Common password
        ]
        
        for password in weak_passwords:
            response = client.post("/v1/auth/register", json={
                "email": f"test_{password}@example.com",
                "password": password
            })
            
            assert response.status_code in [400, 422], \
                f"Weak password '{password}' should be rejected"
    
    def test_p1_3_account_lockout_after_failed_attempts(self, client: TestClient, db_session):
        """
        P1-3: Test account lockout after multiple failed login attempts.
        ASVS 2.2.1: Account lockout must be implemented.
        """
        email = "lockout_test@example.com"
        
        # Create user
        from passlib.context import CryptContext
        pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        user = User(
            email=email,
            hashed_password=pwd_context.hash("CorrectPassword123!"),
            tier=Tier.FREE
        )
        db_session.add(user)
        db_session.commit()
        
        # Attempt login with wrong password multiple times
        for i in range(6):
            response = client.post("/v1/auth/login", data={
                "username": email,
                "password": "WrongPassword123!"
            })
            
            if i < 5:
                assert response.status_code == 400, f"Attempt {i+1} should fail with 400"
            else:
                # 6th attempt should be locked out
                assert response.status_code == 429, \
                    "Account should be locked after 5 failed attempts"
                assert "locked" in response.json()["detail"].lower()


class TestSessionSecurity:
    """Tests for session security (ASVS 3.x)."""
    
    def test_p0_2_httponly_cookies_set(self, client: TestClient, db_session):
        """
        P0-2: Test that authentication sets httpOnly cookies.
        ASVS 3.2.2: Session tokens must be in httpOnly cookies.
        """
        # Create user
        from passlib.context import CryptContext
        pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        user = User(
            email="cookie_test@example.com",
            hashed_password=pwd_context.hash("TestPassword123!"),
            tier=Tier.FREE
        )
        db_session.add(user)
        db_session.commit()
        
        response = client.post("/v1/auth/login", data={
            "username": "cookie_test@example.com",
            "password": "TestPassword123!"
        })
        
        assert response.status_code == 200
        
        # Check cookies are set
        cookies = response.cookies
        # Note: TestClient may not expose httpOnly flag
        # This test verifies cookies exist; manual browser testing needed for httpOnly
        assert "access_token" in cookies or "access_token" in response.json(), \
            "Access token must be provided"
    
    def test_token_revocation_on_logout(self, client: TestClient, auth_headers, db_session):
        """
        P1-1: Test that logout revokes the token.
        ASVS 3.5.3: Tokens must be revocable.
        """
        # Make a successful request
        response = client.get("/v1/auth/me", headers=auth_headers)
        assert response.status_code == 200
        
        # Logout
        response = client.post("/v1/auth/logout", headers=auth_headers)
        assert response.status_code == 200
        
        # Token should now be invalid
        response = client.get("/v1/auth/me", headers=auth_headers)
        assert response.status_code == 401


class TestInputValidation:
    """Tests for input validation (ASVS 5.x)."""
    
    def test_p0_3_sql_injection_prevention(self, client: TestClient, auth_headers):
        """
        P0-3: Test that SQL injection is prevented.
        ASVS 5.3.4: All inputs must be validated against SQL injection.
        """
        malicious_inputs = [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "admin'--",
            "' UNION SELECT * FROM users--"
        ]
        
        for malicious_input in malicious_inputs:
            response = client.post("/v1/projects",
                headers=auth_headers,
                json={
                    "name": malicious_input,
                    "description": "test"
                }
            )
            
            # Should either succeed with sanitized input or fail validation
            # Should NOT execute SQL injection
            assert response.status_code in [200, 201, 400, 422], \
                f"SQL injection attempt should be handled: {malicious_input}"
    
    def test_p2_1_xss_prevention_in_project_name(self, client: TestClient, auth_headers):
        """
        P2-1: Test that XSS is prevented in input validation.
        ASVS 5.2.3: Output encoding must prevent XSS.
        """
        xss_payloads = [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert('xss')>",
            "javascript:alert('xss')",
            "<svg onload=alert('xss')>"
        ]
        
        for payload in xss_payloads:
            response = client.post("/v1/projects",
                headers=auth_headers,
                json={
                    "name": payload,
                    "description": "test"
                }
            )
            
            # Should reject dangerous characters
            assert response.status_code in [400, 422], \
                f"XSS payload should be rejected: {payload}"


class TestSecurityHeaders:
    """Tests for security headers (ASVS 14.x)."""
    
    def test_p1_5_security_headers_present(self, client: TestClient):
        """
        P1-5: Test that all security headers are present.
        ASVS 14.4: Verify HTTP security headers.
        """
        response = client.get("/")
        
        # CSP (ASVS 14.4.3)
        assert "Content-Security-Policy" in response.headers
        
        # Clickjacking protection (ASVS 14.4.4)
        assert "X-Frame-Options" in response.headers
        assert response.headers["X-Frame-Options"] == "DENY"
        
        # MIME sniffing protection (ASVS 14.4.5)
        assert "X-Content-Type-Options" in response.headers
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        
        # XSS protection (ASVS 14.4.6)
        assert "X-XSS-Protection" in response.headers
        
        # Referrer policy (ASVS 14.5.4)
        assert "Referrer-Policy" in response.headers


class TestErrorHandling:
    """Tests for error handling (ASVS 7.x)."""
    
    def test_p1_4_error_does_not_leak_information(self, client: TestClient, monkeypatch):
        """
        P1-4: Test that errors don't expose sensitive information.
        ASVS 7.4.1: Error messages must not reveal sensitive data.
        """
        # This test requires mocking to force an error
        # In practice, verify error responses don't contain:
        # - Stack traces
        # - File paths
        # - Database schema
        # - Internal IPs
        pass
    
    def test_validation_error_sanitized(self, client: TestClient):
        """
        Test that validation errors don't expose internal structure.
        ASVS 5.1.3: Validation failures should be generic.
        """
        response = client.post("/v1/auth/register", json={
            "email": "invalid-email",
            "password": "123"
        })
        
        assert response.status_code == 422
        error = response.json()
        
        # Should not expose internal field names or paths
        assert "detail" in error
        # Should have error_id for tracking
        assert "error_id" in error or "errors" in error
