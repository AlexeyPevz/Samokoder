from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from samokoder.core.db.session import get_async_db
from samokoder.core.db.models.user import User
from samokoder.core.config import get_config
from samokoder.api.routers.auth import get_current_user

router = APIRouter()

class GitVerseTokenRequest(BaseModel):
    token: str

@router.post("/user/gitverse-token")
async def set_gitverse_token(  # P2-1: FIXED - now async
    request: GitVerseTokenRequest, 
    user: User = Depends(get_current_user), 
    db: AsyncSession = Depends(get_async_db)  # P2-1: FIXED - async session
):
    """
    Set the user's GitVerse access token.
    """
    config = get_config()
    user.set_encrypted_gitverse_token(request.token, config.secret_key)
    await db.commit()  # P2-1: FIXED - await commit
    return {"message": "GitVerse token has been set successfully."}
