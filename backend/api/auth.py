"""
Authentication endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, status
from backend.models.requests import LoginRequest, RegisterRequest
from backend.models.responses import LoginResponse, RegisterResponse
from backend.auth.dependencies import get_current_user
from backend.middleware.rate_limit_middleware import auth_rate_limit
from backend.services.connection_pool import connection_pool_manager
from backend.services.encryption import EncryptionService
from backend.services.supabase_manager import execute_supabase_operation
import logging
from datetime import datetime, timedelta
import uuid

logger = logging.getLogger(__name__)

router = APIRouter()

@router.post("/login", response_model=LoginResponse)
async def login(
    credentials: LoginRequest,
    rate_limit: dict = Depends(auth_rate_limit)
):
    """User login endpoint"""
    try:
        supabase = connection_pool_manager.get_supabase_client()
        
        # Authenticate with Supabase
        response = supabase.auth.sign_in_with_password({
            "email": credentials.email,
            "password": credentials.password
        })
        
        if not response.user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
        
        # Get user profile
        profile_response = await execute_supabase_operation(
            supabase.table("profiles").select("*").eq("id", response.user.id)
        )
        
        if not profile_response.data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User profile not found"
            )
        
        profile = profile_response.data[0]
        
        return LoginResponse(
            access_token=response.session.access_token,
            token_type="bearer",
            user_id=str(profile["id"]),
            email=profile["email"],
            message="Успешный вход"
        )
        
    except Exception as e:
        logger.error(f"Login failed for {credentials.email}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed"
        )

@router.post("/register", response_model=RegisterResponse)
async def register(
    user_data: RegisterRequest,
    rate_limit: dict = Depends(auth_rate_limit)
):
    """User registration endpoint"""
    try:
        supabase = connection_pool_manager.get_supabase_client()
        
        # Register user with Supabase
        response = supabase.auth.sign_up({
            "email": user_data.email,
            "password": user_data.password
        })
        
        if not response.user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Registration failed"
            )
        
        # Create user profile
        profile_data = {
            "id": response.user.id,
            "email": user_data.email,
            "full_name": user_data.full_name,
            "subscription_tier": "free",
            "subscription_status": "active"
        }
        
        profile_response = await execute_supabase_operation(
            supabase.table("profiles").insert(profile_data)
        )
        
        if not profile_response.data:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create user profile"
            )
        
        # Create default user settings
        settings_data = {
            "user_id": response.user.id,
            "default_model": "deepseek/deepseek-v3",
            "default_provider": "openrouter",
            "theme": "light"
        }
        
        await execute_supabase_operation(
            supabase.table("user_settings").insert(settings_data)
        )
        
        return RegisterResponse(
            user_id=str(response.user.id),
            email=user_data.email,
            message="Пользователь успешно зарегистрирован"
        )
        
    except Exception as e:
        logger.error(f"Registration failed for {user_data.email}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed"
        )

@router.post("/logout")
async def logout(current_user: dict = Depends(get_current_user)):
    """User logout endpoint"""
    try:
        supabase = connection_pool_manager.get_supabase_client()
        supabase.auth.sign_out()
        
        return {"message": "Успешный выход"}
        
    except Exception as e:
        logger.error(f"Logout failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Logout failed"
        )

@router.get("/me")
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """Get current user information"""
    return current_user