from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from samokoder.core.db.session import get_db
from samokoder.core.db.models.user import User
from samokoder.core.config import get_config
from samokoder.api.routers.auth import get_current_user

router = APIRouter()

class GitVerseTokenRequest(BaseModel):
    token: str

@router.post("/user/gitverse-token")
def set_gitverse_token(request: GitVerseTokenRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Set the user's GitVerse access token.
    """
    config = get_config()
    user.set_encrypted_gitverse_token(request.token, config.secret_key)
    db.commit()
    return {"message": "GitVerse token has been set successfully."}
