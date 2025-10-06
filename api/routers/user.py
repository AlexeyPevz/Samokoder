from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from samokoder.core.db.session import get_async_db
from samokoder.core.db.models.user import User
from samokoder.core.config import get_config
from samokoder.api.routers.auth import get_current_user

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
async def set_github_token(request: GitHubTokenRequest, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_async_db)):
    """
    Set the user's GitHub access token.
    """
    try:
        print(f"Setting GitHub token for user {user.id}")
        config = get_config()
        user.set_encrypted_github_token(request.token, config.secret_key)
        await db.commit()
        print(f"GitHub token set successfully for user {user.id}")
        return {"message": "GitHub token has been set successfully."}
    except Exception as e:
        print(f"Error setting GitHub token for user {user.id}: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/user/profile", response_model=UserProfileResponse)
def get_user_profile(user: User = Depends(get_current_user)):
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
