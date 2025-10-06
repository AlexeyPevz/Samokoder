from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Dict, Any
import logging  # FIX: Replace print with logger

from samokoder.core.db.session import get_async_db
from samokoder.core.db.models.user import User
from samokoder.core.config import get_config
from samokoder.api.routers.auth import get_current_user
from samokoder.core.api.middleware.tier_limits import get_tier_info

logger = logging.getLogger(__name__)  # FIX: Logger instance
router = APIRouter()

class GitHubTokenRequest(BaseModel):
    token: str

class UserProfileResponse(BaseModel):
    id: int
    email: str
    tier: str
    projects_monthly_count: int
    projects_total: int

@router.post("/user/github-token")
async def set_github_token(
    request: GitHubTokenRequest, 
    user: User = Depends(get_current_user), 
    db: AsyncSession = Depends(get_async_db)
):
    """
    Set the user's GitHub access token.
    """
    try:
        logger.info(f"Setting GitHub token for user {user.id}")  # FIX: print → logger
        config = get_config()
        user.set_encrypted_github_token(request.token, config.secret_key)
        await db.commit()
        logger.info(f"GitHub token set successfully for user {user.id}")  # FIX: print → logger
        return {"message": "GitHub token has been set successfully."}
    except Exception as e:
        logger.error(f"Error setting GitHub token for user {user.id}: {e}", exc_info=True)  # FIX: print → logger
        await db.rollback()
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/user/profile", response_model=UserProfileResponse)
async def get_user_profile(user: User = Depends(get_current_user)):  # P2-1: FIXED - now async
    """
    Get the current user's profile.
    """
    return {
        "id": user.id,
        "email": user.email,
        "tier": user.tier.value,
        "projects_monthly_count": user.projects_monthly_count,
        "projects_total": user.projects_total
    }


@router.get("/user/tier", response_model=Dict[str, Any])
async def get_user_tier_info(tier_info: Dict = Depends(get_tier_info)):
    """
    Get detailed information about the current user's tier, including limits and available features.
    """
    return tier_info
