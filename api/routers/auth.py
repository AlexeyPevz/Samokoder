"""Authentication routes for Samokoder API.

The focus is on providing a secure registration/login flow with
refresh tokens and GitHub OAuth integration.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta
from typing import Optional
from typing import Annotated

import httpx
from fastapi import APIRouter, Body, Depends, HTTPException, status, Request, Response
from samokoder.api.middleware.rate_limiter import limiter, get_rate_limit
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from samokoder.core.api.models.auth import (
    AuthResponse,
    LoginRequest,
    RegisterRequest,
    TokenRefreshRequest,
    TokenRefreshResponse,
)
from samokoder.core.api.models.base import UserResponse
from samokoder.core.config import get_config
from samokoder.core.db.models.user import Tier, User
from samokoder.core.db.models.revoked_tokens import RevokedToken
from samokoder.core.db.models.login_attempts import LoginAttempt
from samokoder.core.db.session import get_async_db
from samokoder.core.security.audit_logger import audit_logger
from samokoder.core.config.constants import SecurityLimits  # FIX: Use constants

logger = logging.getLogger(__name__)

router = APIRouter()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# FIX: Use constants from config instead of magic numbers
ACCESS_TOKEN_EXPIRE_MINUTES = SecurityLimits.ACCESS_TOKEN_EXPIRE_MINUTES
REFRESH_TOKEN_EXPIRE_DAYS = SecurityLimits.REFRESH_TOKEN_EXPIRE_DAYS
MAX_LOGIN_ATTEMPTS = SecurityLimits.MAX_LOGIN_ATTEMPTS
LOCKOUT_DURATION_MINUTES = SecurityLimits.LOCKOUT_DURATION_MINUTES


def _create_token(*, data: dict, secret: str, expires_delta: timedelta, token_type: str) -> str:
    """Create a signed JWT token with jti for revocation (P1-1)."""
    to_encode = data.copy()
    now = datetime.utcnow()
    expire = now + expires_delta
    jti = str(uuid.uuid4())  # P1-1: Add jti for token revocation
    to_encode.update({
        "exp": expire,
        "iat": now,
        "type": token_type,
        "jti": jti
    })
    return jwt.encode(to_encode, secret, algorithm="HS256")


def _create_auth_response(user: User, config) -> AuthResponse:
    """Return AuthResponse with access/refresh tokens for the user."""
    access_token = _create_token(
        data={"sub": user.email},
        secret=config.secret_key,
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        token_type="access",
    )
    refresh_token = _create_token(
        data={"sub": user.email},
        secret=config.app_secret_key,
        expires_delta=timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        token_type="refresh",
    )
    return AuthResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user_id=user.id,
        email=user.email,
    )


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


async def _get_user_by_email(db: AsyncSession, email: str) -> Optional[User]:
    result = await db.execute(select(User).where(User.email == email))
    return result.scalars().first()


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_async_db),
) -> User:
    """Resolve the current user from the access token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        config = get_config()
        payload = jwt.decode(token, config.secret_key, algorithms=["HS256"])
        if payload.get("type") != "access":
            raise credentials_exception
        
        # P1-1: Check if token is revoked
        jti = payload.get("jti")
        if jti:
            result = await db.execute(
                select(RevokedToken).where(RevokedToken.jti == jti)
            )
            if result.scalars().first():
                raise credentials_exception
        
        email: Optional[str] = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = await _get_user_by_email(db, email=email)
    if user is None:
        raise credentials_exception
    return user


async def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """
    Require admin privileges (P0-1).
    
    Raises:
        HTTPException: If user is not an administrator
    """
    if not current_user.is_admin:
        logger.warning(f"Unauthorized admin access attempt by user {current_user.id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator privileges required"
        )
    return current_user


@router.post("/auth/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit(get_rate_limit("auth"))  # FIX: Добавлен rate limit для защиты от bruteforce/email enumeration
async def register(
    request: Request,
    payload: Annotated[RegisterRequest, Body()],
    db: AsyncSession = Depends(get_async_db),
) -> AuthResponse:
    """Register a new user and return auth tokens."""
    existing = await _get_user_by_email(db, email=payload.email)
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists")

    hashed_password = pwd_context.hash(payload.password)
    user = User(email=payload.email, hashed_password=hashed_password, tier=Tier.FREE)
    db.add(user)
    try:
        await db.commit()
        await db.refresh(user)
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists") from exc
    except Exception as exc:  # pragma: no cover - unexpected DB errors
        await db.rollback()
        logger.exception("Registration failed: %s", exc)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Registration failed") from exc

    config = get_config()
    return _create_auth_response(user, config)


@router.post("/auth/login", response_model=AuthResponse)
@limiter.limit(get_rate_limit("auth"))
async def login(
    request: Request,
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(OAuth2PasswordRequestForm),
    db: AsyncSession = Depends(get_async_db),
):
    """Authenticate the user with email/password."""
    try:
        login_payload = LoginRequest(email=form_data.username, password=form_data.password)
    except ValidationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=exc.errors()) from exc

    # P1-3: Check for account lockout due to failed attempts
    recent_attempts = await db.execute(
        select(LoginAttempt)
        .where(
            LoginAttempt.email == login_payload.email,
            LoginAttempt.created_at >= datetime.utcnow() - timedelta(minutes=LOCKOUT_DURATION_MINUTES)
        )
        .order_by(LoginAttempt.created_at.desc())
    )
    attempts = recent_attempts.scalars().all()
    
    failed_attempts = [a for a in attempts if not a.success]
    if len(failed_attempts) >= MAX_LOGIN_ATTEMPTS:
        logger.warning(f"Account locked for {login_payload.email} due to too many failed attempts")
        audit_logger.log_account_lockout(login_payload.email, request.client.host if request.client else "unknown", len(failed_attempts))
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Account temporarily locked due to too many failed login attempts. Try again in {LOCKOUT_DURATION_MINUTES} minutes."
        )

    user = await _get_user_by_email(db, email=login_payload.email)
    client_ip = request.client.host if request.client else "unknown"
    
    if not user or not verify_password(login_payload.password, user.hashed_password):
        # P1-3: Record failed attempt
        attempt = LoginAttempt(
            email=login_payload.email,
            ip_address=client_ip,
            success=False,
            user_agent=request.headers.get("User-Agent", "")
        )
        db.add(attempt)
        await db.commit()
        
        audit_logger.log_authentication(login_payload.email, client_ip, False)
        logger.warning(f"Failed login attempt for {login_payload.email} from {client_ip}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid credentials")

    # P1-3: Record successful attempt
    attempt = LoginAttempt(
        email=login_payload.email,
        ip_address=client_ip,
        success=True,
        user_id=user.id,
        user_agent=request.headers.get("User-Agent", "")
    )
    db.add(attempt)
    await db.commit()
    
    audit_logger.log_authentication(user.email, client_ip, True, user_id=user.id)

    config = get_config()
    auth_response = _create_auth_response(user, config)
    
    # P0-2: Set httpOnly cookies for tokens
    response.set_cookie(
        key="access_token",
        value=auth_response.access_token,
        httponly=True,
        secure=config.environment == "production",
        samesite="strict",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )
    response.set_cookie(
        key="refresh_token",
        value=auth_response.refresh_token,
        httponly=True,
        secure=config.environment == "production",
        samesite="strict",
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60
    )
    
    return auth_response


@router.post("/auth/refresh", response_model=TokenRefreshResponse)
@limiter.limit(get_rate_limit("auth"))  # P0-1: Add rate limiting
async def refresh_token(
    request: Request,  # P0-1: Required for rate limiting
    payload: TokenRefreshRequest
):
    """Issue a new access token based on refresh token."""
    config = get_config()
    try:
        decoded = jwt.decode(payload.refresh_token, config.app_secret_key, algorithms=["HS256"])
        if decoded.get("type") != "refresh":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
        email = decoded.get("sub")
        if email is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
    except JWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token") from exc

    new_access_token = _create_token(
        data={"sub": email},
        secret=config.secret_key,
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        token_type="access",
    )
    return TokenRefreshResponse(
        access_token=new_access_token,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/auth/logout")
async def logout(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_async_db)
):
    """Revoke the current access token (P1-1)."""
    try:
        config = get_config()
        payload = jwt.decode(token, config.secret_key, algorithms=["HS256"])
        jti = payload.get("jti")
        exp = payload.get("exp")
        user_email = payload.get("sub")
        
        if jti and exp:
            # Store revoked token
            revoked = RevokedToken(
                jti=jti,
                expires_at=datetime.fromtimestamp(exp),
                reason="logout"
            )
            db.add(revoked)
            await db.commit()
            
            # Audit log
            user = await _get_user_by_email(db, user_email)
            if user:
                audit_logger.log_token_revocation(user.id, jti, "logout")
            
    except JWTError:
        pass
    
    return {"message": "Successfully logged out"}


@router.get("/auth/me", response_model=UserResponse)
async def read_current_user(current_user: User = Depends(get_current_user)):
    """Return basic profile information for the current user."""
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        tier=current_user.tier.value,
        created_at=current_user.created_at,
        projects_count=len(current_user.projects or []),
    )


@router.get("/auth/github")
async def github_auth(user: User = Depends(get_current_user)):
    """Initiate GitHub OAuth flow."""
    config = get_config()
    if not config.github_client_id or not config.github_client_secret:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="GitHub OAuth is not configured")

    state_payload = {"sub": str(user.id), "exp": datetime.utcnow() + timedelta(minutes=10)}
    state_token = jwt.encode(state_payload, config.secret_key, algorithm="HS256")

    return RedirectResponse(
        f"https://github.com/login/oauth/authorize?client_id={config.github_client_id}&state={state_token}&scope=repo"
    )


@router.get("/auth/github/callback")
async def github_auth_callback(code: str, state: str, db: AsyncSession = Depends(get_async_db)):
    """GitHub OAuth callback that links the GitHub token to the user."""
    config = get_config()
    try:
        payload = jwt.decode(state, config.secret_key, algorithms=["HS256"])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid state token")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid state token")

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalars().first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            "https://github.com/login/oauth/access_token",
            json={
                "client_id": config.github_client_id,
                "client_secret": config.github_client_secret,
                "code": code,
            },
            headers={"Accept": "application/json"},
        )

    if token_response.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to get access token from GitHub: {token_response.text}",
        )

    access_token = token_response.json().get("access_token")
    if not access_token:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Could not retrieve access token")

    user.set_encrypted_github_token(access_token, config.secret_key)
    await db.commit()

    return RedirectResponse(url="/settings")
