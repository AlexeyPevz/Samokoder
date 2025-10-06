from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from samokoder.core.api.dependencies import get_current_user
from samokoder.core.db.models.user import User
from cryptography.fernet import Fernet
from git import Repo
import tempfile
import shutil
import os
from samokoder.core.config import get_config
from samokoder.core.state.state_manager import StateManager

router = APIRouter(prefix="/api/v1", tags=["github"])

class GitHubConnect(BaseModel):
    token: str

@router.post("/user/github-connect")
async def github_connect(connect: GitHubConnect, current_user: User = Depends(get_current_user)):
    f = Fernet(get_config().secret_key.encode())
    encrypted_token = f.encrypt(connect.token.encode()).decode()
    current_user.github_token = encrypted_token
    await current_user.save()
    return {"status": "connected"}

@router.post("/projects/{project_id}/github-push")
async def github_push(project_id: str, repo_url: str, current_user: User = Depends(get_current_user)):
    sm = StateManager.from_project_id(project_id, current_user.id)
    if not sm.project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    f = Fernet(get_config().secret_key.encode())
    github_token = f.decrypt(current_user.github_token.encode()).decode()
    
    with tempfile.TemporaryDirectory() as temp_dir:
        clone_url = f"https://x-access-token:{github_token}@github.com/{repo_url}.git"
        repo = Repo.clone_from(clone_url, temp_dir)
        
        project_root = sm.get_full_project_root()
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
