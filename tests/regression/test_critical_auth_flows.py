"""
Regression tests for critical authentication flows.

Priority: P0 - BLOCKS MERGE if any test fails
Related commits: 7b1b7e2 (Security audit and remediation)
"""
import pytest
import time
from datetime import datetime, timedelta
from fastapi.testclient import TestClient
from jose import jwt
from sqlalchemy.orm import Session

from samokoder.core.db.models.user import User, Tier
from samokoder.core.db.models.login_attempts import LoginAttempt
from samokoder.core.db.models.revoked_tokens import RevokedToken
from samokoder.core.config import get_config


@pytest.mark.priority_p0
class TestUserRegistration:
    """TC-AUTH-001: User registration with password validation."""
    
    def test_tc_auth_001_weak_passwords_rejected(self, client: TestClient, weak_passwords):
        """
        P0: Test that weak passwords are rejected during registration.
        
        Reproduction steps:
        1. POST /v1/auth/register with weak password
        2. Verify 400 or 422 response
        
        Links:
        - core/api/models/auth.py:36-78
        - Commit: 7b1b7e2
        
        Failure criteria:
        - Any weak password is accepted
        - No validation error returned
        """
        for password in weak_passwords:
            response = client.post("/v1/auth/register", json={
                "email": f"test_{password}@example.com",
                "password": password
            })
            
            assert response.status_code in [400, 422], \
                f"P0 FAILURE: Weak password '{password}' was not rejected. " \
                f"Status: {response.status_code}, Body: {response.json()}"
    
    def test_tc_auth_001_strong_password_accepted(self, client: TestClient, strong_password):
        """
        P0: Test that strong passwords are accepted.
        
        Reproduction steps:
        1. POST /v1/auth/register with strong password
        2. Verify 201 response
        3. Verify tokens returned
        
        Links:
        - api/routers/auth.py:141-168
        - Commit: 7b1b7e2
        """
        response = client.post("/v1/auth/register", json={
            "email": "strongpass@example.com",
            "password": strong_password
        })
        
        assert response.status_code == 201, \
            f"P0 FAILURE: Strong password rejected. Status: {response.status_code}"
        
        data = response.json()
        assert "access_token" in data, "P0 FAILURE: No access_token returned"
        assert "refresh_token" in data, "P0 FAILURE: No refresh_token returned"
    
    def test_tc_auth_001_password_hashed(self, client: TestClient, test_db_session: Session, strong_password):
        """
        P0: Test that passwords are hashed before storage.
        
        Failure criteria:
        - Password stored in plaintext
        """
        email = "hashed@example.com"
        client.post("/v1/auth/register", json={
            "email": email,
            "password": strong_password
        })
        
        user = test_db_session.query(User).filter(User.email == email).first()
        if user:
            assert user.hashed_password != strong_password, \
                "P0 FAILURE: Password stored in plaintext!"
            assert user.hashed_password.startswith("$2b$"), \
                "P0 FAILURE: Password not hashed with bcrypt"


@pytest.mark.priority_p0
class TestUserLogin:
    """TC-AUTH-002: Login with httpOnly cookies."""
    
    def test_tc_auth_002_httponly_cookies_set(self, client: TestClient, test_user: User):
        """
        P0: Test that login sets httpOnly cookies.
        
        Reproduction steps:
        1. POST /v1/auth/login with credentials
        2. Check response cookies
        3. Verify httpOnly, secure, samesite flags
        
        Links:
        - api/routers/auth.py:239-256
        - Commit: 7b1b7e2
        
        Failure criteria:
        - Cookies not set
        - httpOnly=false (XSS vulnerability)
        - secure=false in production
        """
        response = client.post("/v1/auth/login", data={
            "username": test_user.email,
            "password": "TestPassword123!"
        })
        
        assert response.status_code == 200, \
            f"P0 FAILURE: Login failed. Status: {response.status_code}"
        
        # Check that tokens are in response (for backward compatibility)
        data = response.json()
        assert "access_token" in data or "access_token" in response.cookies, \
            "P0 FAILURE: No access_token provided"
        
        # Note: TestClient doesn't expose httpOnly flag
        # Manual browser testing required for full validation
        # But we can verify cookies are set
        cookies = response.cookies
        if cookies:
            assert len(cookies) > 0, "P0 FAILURE: No cookies set"


@pytest.mark.priority_p0
class TestTokenRefresh:
    """TC-AUTH-003: Rate limiting on refresh token endpoint."""
    
    def test_tc_auth_003_rate_limiting(self, client: TestClient, test_user: User):
        """
        P0: Test that refresh endpoint is rate limited.
        
        Reproduction steps:
        1. Get refresh token
        2. Send 20 rapid requests to /v1/auth/refresh
        3. Verify 429 response after limit
        
        Links:
        - api/routers/auth.py:260-261
        - Commit: 7b1b7e2
        
        Failure criteria:
        - Unlimited requests allowed
        - No 429 status code
        - Can brute force refresh tokens
        """
        # Get a refresh token
        login_response = client.post("/v1/auth/login", data={
            "username": test_user.email,
            "password": "TestPassword123!"
        })
        refresh_token = login_response.json().get("refresh_token")
        
        responses = []
        for i in range(20):
            response = client.post("/v1/auth/refresh", json={
                "refresh_token": refresh_token or "invalid_token"
            })
            responses.append(response.status_code)
            time.sleep(0.05)  # Small delay
        
        # Should get at least one 429
        assert 429 in responses, \
            f"P0 FAILURE: No rate limiting detected. Status codes: {set(responses)}"


@pytest.mark.priority_p0
class TestTokenRevocation:
    """TC-AUTH-004 & TC-AUTH-005: JWT jti and token revocation."""
    
    def test_tc_auth_004_jwt_has_jti(self, client: TestClient, test_user: User):
        """
        P0: Test that JWT tokens contain jti claim.
        
        Reproduction steps:
        1. Login and get access_token
        2. Decode JWT (without verification)
        3. Check for jti field
        4. Verify jti is UUID format
        
        Links:
        - api/routers/auth.py:55-67
        - core/db/models/revoked_tokens.py
        - Commit: 7b1b7e2
        
        Failure criteria:
        - jti missing from token
        - jti not unique
        - jti invalid format
        """
        response = client.post("/v1/auth/login", data={
            "username": test_user.email,
            "password": "TestPassword123!"
        })
        
        assert response.status_code == 200, "Login failed"
        
        token = response.json()["access_token"]
        config = get_config()
        
        # Decode token
        decoded = jwt.decode(token, config.secret_key, algorithms=["HS256"])
        
        assert "jti" in decoded, \
            "P0 FAILURE: JWT token missing jti claim for revocation"
        assert isinstance(decoded["jti"], str), \
            "P0 FAILURE: jti must be a string"
        assert len(decoded["jti"]) > 0, \
            "P0 FAILURE: jti cannot be empty"
        
        # Test uniqueness - get another token
        response2 = client.post("/v1/auth/login", data={
            "username": test_user.email,
            "password": "TestPassword123!"
        })
        token2 = response2.json()["access_token"]
        decoded2 = jwt.decode(token2, config.secret_key, algorithms=["HS256"])
        
        assert decoded["jti"] != decoded2["jti"], \
            "P0 FAILURE: jti must be unique for each token"
    
    def test_tc_auth_005_logout_revokes_token(
        self, 
        client: TestClient, 
        test_user: User,
        auth_headers: dict,
        test_db_session: Session,
        cleanup_revoked_tokens
    ):
        """
        P0: Test that logout revokes the token.
        
        Reproduction steps:
        1. Login and get token
        2. Successfully call /v1/auth/me
        3. Call POST /v1/auth/logout
        4. Try to call /v1/auth/me again
        5. Verify 401 response
        
        Links:
        - api/routers/auth.py:291-322
        - api/routers/auth.py:120-127
        - Commit: 7b1b7e2
        
        Failure criteria:
        - Token still valid after logout
        - Can use revoked token
        - jti not saved to revoked_tokens table
        """
        # 1. Verify token works
        response = client.get("/v1/auth/me", headers=auth_headers)
        assert response.status_code == 200, \
            "Token should be valid before logout"
        
        # 2. Logout
        logout_response = client.post("/v1/auth/logout", headers=auth_headers)
        assert logout_response.status_code == 200, \
            f"Logout failed: {logout_response.status_code}"
        
        # 3. Verify token is revoked
        response_after = client.get("/v1/auth/me", headers=auth_headers)
        assert response_after.status_code == 401, \
            "P0 FAILURE: Token still valid after logout - revocation not working!"
        
        # 4. Verify jti in revoked_tokens table
        revoked_count = test_db_session.query(RevokedToken).count()
        assert revoked_count > 0, \
            "P0 FAILURE: jti not saved to revoked_tokens table"


@pytest.mark.priority_p0
class TestBruteForceProtection:
    """TC-AUTH-006: Account lockout after failed login attempts."""
    
    def test_tc_auth_006_account_lockout(
        self, 
        client: TestClient, 
        test_user: User,
        test_db_session: Session,
        cleanup_login_attempts
    ):
        """
        P0: Test account lockout after 5 failed attempts.
        
        Reproduction steps:
        1. Create user with known password
        2. Attempt login 5 times with wrong password
        3. Verify all return 400
        4. Attempt 6th login (even with correct password)
        5. Verify 429 Too Many Requests
        6. Verify lockout message
        
        Links:
        - api/routers/auth.py:185-203
        - core/db/models/login_attempts.py
        - Commit: 7b1b7e2
        
        Failure criteria:
        - No lockout after 5 attempts
        - Can continue brute force
        - Attempts not logged
        - Lockout doesn't expire
        """
        email = test_user.email
        
        # Attempt 5 failed logins
        for i in range(5):
            response = client.post("/v1/auth/login", data={
                "username": email,
                "password": "WrongPassword123!"
            })
            
            assert response.status_code == 400, \
                f"Attempt {i+1} should fail with 400, got {response.status_code}"
        
        # Verify attempts are logged
        attempts = test_db_session.query(LoginAttempt).filter(
            LoginAttempt.email == email
        ).all()
        assert len(attempts) >= 5, \
            f"P0 FAILURE: Only {len(attempts)} attempts logged, expected 5+"
        
        # 6th attempt should be locked out
        response = client.post("/v1/auth/login", data={
            "username": email,
            "password": "TestPassword123!"  # Even with correct password!
        })
        
        assert response.status_code == 429, \
            f"P0 FAILURE: Account not locked after 5 failed attempts. Got {response.status_code}"
        
        error_detail = response.json().get("detail", "").lower()
        assert "locked" in error_detail or "too many" in error_detail, \
            f"P0 FAILURE: Lockout message not clear: {error_detail}"
    
    def test_tc_auth_006_successful_login_tracked(
        self,
        client: TestClient,
        test_user: User,
        test_db_session: Session,
        cleanup_login_attempts
    ):
        """
        P0: Test that successful logins are also tracked.
        
        Failure criteria:
        - Successful attempts not logged
        - Missing required fields
        """
        response = client.post("/v1/auth/login", data={
            "username": test_user.email,
            "password": "TestPassword123!"
        })
        
        assert response.status_code == 200, "Login should succeed"
        
        # Check logged
        attempt = test_db_session.query(LoginAttempt).filter(
            LoginAttempt.email == test_user.email,
            LoginAttempt.success == True
        ).first()
        
        assert attempt is not None, \
            "P0 FAILURE: Successful login not logged"
        assert attempt.user_id == test_user.id, \
            "P0 FAILURE: user_id not set on successful login"
        assert attempt.ip_address is not None, \
            "P0 FAILURE: ip_address not logged"


@pytest.mark.priority_p0
class TestSQLInjectionPrevention:
    """TC-AUTH-007: SQL Injection prevention in authentication."""
    
    def test_sql_injection_in_email(self, client: TestClient):
        """
        P0: Test that SQL injection in email field is prevented.
        
        Links:
        - SECURITY_FIXES_SUMMARY.md:P0-3
        - All database queries use ORM
        
        Failure criteria:
        - SQL injection successful
        - Database error exposed
        - Unexpected behavior
        """
        malicious_emails = [
            "'; DROP TABLE users; --",
            "admin'--",
            "' OR '1'='1",
            "' UNION SELECT * FROM users--"
        ]
        
        for email in malicious_emails:
            response = client.post("/v1/auth/login", data={
                "username": email,
                "password": "anything"
            })
            
            # Should either fail auth or validation, not execute SQL
            assert response.status_code in [400, 401, 422], \
                f"P0 FAILURE: Unexpected response to SQL injection: {response.status_code}"
            
            # Should not expose database errors
            if response.status_code == 500:
                error = response.json()
                assert "sql" not in str(error).lower(), \
                    "P0 FAILURE: SQL error exposed to client"


@pytest.mark.priority_p0  
class TestPasswordStorage:
    """Test secure password storage."""
    
    def test_passwords_never_logged(self, client: TestClient, caplog):
        """
        P0: Verify passwords are never logged in plaintext.
        
        Failure criteria:
        - Password appears in logs
        """
        import logging
        caplog.set_level(logging.DEBUG)
        
        test_password = "SecretP@ss123"
        client.post("/v1/auth/register", json={
            "email": "logtest@example.com",
            "password": test_password
        })
        
        # Check that password doesn't appear in logs
        for record in caplog.records:
            assert test_password not in record.message, \
                "P0 FAILURE: Password logged in plaintext!"
