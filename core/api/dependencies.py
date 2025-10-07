"""
Shared dependencies for API routes.
This module provides the async version of get_current_user for all routes.
"""
from typing import Optional
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from samokoder.core.db.session import get_async_db
from samokoder.core.db.models.user import User
from samokoder.core.db.models.revoked_tokens import RevokedToken
from samokoder.core.config import get_config

# OAuth2 scheme with auto_error=False to support both cookie and header auth
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)


async def get_current_user(
    request: Request,
    token: Optional[str] = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_async_db),
) -> User:
    """
    Get the currently authenticated user from JWT token.
    Supports both cookie-based (httpOnly) and Authorization header auth.
    Cookie takes precedence for security.
    
    Raises:
        HTTPException: If token is invalid or user not found
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # Try cookie first (more secure with httpOnly), then Authorization header as fallback
    access_token = request.cookies.get("access_token")
    if not access_token and token:
        access_token = token
    
    if not access_token:
        raise credentials_exception

    try:
        config = get_config()
        payload = jwt.decode(access_token, config.secret_key, algorithms=["HS256"])
        if payload.get("type") != "access":
            raise credentials_exception
        
        # Check if token is revoked
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

    # Get user from database
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalars().first()
    if user is None:
        raise credentials_exception
    
    # Store user in request state for rate limiting middleware
    request.state.user = user
    
    return user
