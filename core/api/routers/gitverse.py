from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from samokoder.core.api.dependencies import get_current_user  # Async version with cookie support
from samokoder.core.db.models.user import User
from samokoder.core.state.state_manager import StateManager
from cryptography.fernet import Fernet, InvalidToken
from git import Repo
import tempfile
import shutil
import os
import requests
from samokoder.core.config import get_config
from samokoder.core.log import get_logger

log = get_logger(__name__)
router = APIRouter(prefix="/api/v1", tags=["gitverse"])

class GitVerseConnect(BaseModel):
    token: str

class GitVersePush(BaseModel):
    repo_url: str

@router.post("/user/gitverse-connect")
async def gitverse_connect(connect: GitVerseConnect, current_user: User = Depends(get_current_user)):
    f = Fernet(get_config().secret_key.encode())
    encrypted_token = f.encrypt(connect.token.encode()).decode()
    current_user.gitverse_token = encrypted_token
    await current_user.save()
    return {"status": "connected"}

@router.post("/projects/{project_id}/gitverse-push")
async def gitverse_push(project_id: str, request: GitVersePush, current_user: User = Depends(get_current_user)):
    sm = StateManager.from_project_id(project_id, current_user.id)
    if not sm.project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    f = Fernet(get_config().secret_key.encode())
    try:
        if not current_user.gitverse_token:
            raise HTTPException(status_code=400, detail="GitVerse token not configured")
        gitverse_token = f.decrypt(current_user.gitverse_token.encode()).decode()
    except (TypeError, ValueError, InvalidToken, AttributeError) as e:
        log.error(f"Failed to decrypt gitverse token: {e}")
        raise HTTPException(status_code=400, detail="GitVerse token invalid or corrupted")
    
    repo_url = request.repo_url
    repo_name = repo_url.split('/')[-1] if '/' in repo_url else f"project-{project_id}"
    
    with tempfile.TemporaryDirectory() as temp_dir:
        clone_url = f"https://x-access-token:{gitverse_token}@gitverse.ru/{repo_url}.git"
        try:
            repo = Repo.clone_from(clone_url, temp_dir)
        except Exception as e:
            log.warning(f"Clone failed, creating repo: {e}")
            create_repo = requests.post(
                "https://api.gitverse.ru/user/repos",
                headers={"Authorization": f"token {gitverse_token}"},
                json={"name": repo_name, "private": True}
            )
            if create_repo.status_code != 201:
                raise HTTPException(status_code=500, detail=f"Failed to create repo: {create_repo.text}")
            repo = Repo.clone_from(clone_url, temp_dir)
        
        project_root = sm.get_full_project_root()
        if not os.path.exists(project_root):
            raise HTTPException(status_code=404, detail="Project root not found")
        
        for src in os.listdir(project_root):
            src_path = os.path.join(project_root, src)
            dst_path = os.path.join(temp_dir, src)
            if os.path.isdir(src_path):
                shutil.copytree(src_path, dst_path, dirs_exist_ok=True)
            else:
                shutil.copy2(src_path, dst_path)
        
        repo.git.add(all=True)
        repo.index.commit("Update from Samokoder")
        origin = repo.remote('origin')
        origin.push()
    
    return {"status": "pushed"}
