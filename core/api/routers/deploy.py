from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
import requests
from samokoder.core.api.dependencies import get_current_user
from samokoder.core.db.models.user import User
from samokoder.core.state.state_manager import StateManager
from cryptography.fernet import Fernet
from git import Repo
import tempfile
import shutil
import os
from samokoder.core.config import get_config
from samokoder.core.log import get_logger

log = get_logger(__name__)
router = APIRouter(prefix="/api/v1", tags=["deploy"])

class DeployRequest(BaseModel):
    repo_url: str | None = None

@router.post("/projects/{project_id}/deploy")
async def deploy_project(project_id: str, request: DeployRequest, current_user: User = Depends(get_current_user)):
    sm = StateManager.from_project_id(project_id, current_user.id)
    if not sm.project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    f = Fernet(get_config().secret_key.encode())
    github_token = f.decrypt(current_user.github_token.encode()).decode()
    
    repo_name = f"project-{project_id}-deploy"
    repo_full_name = None
    
    if not request.repo_url:
        create_repo = requests.post(
            "https://api.github.com/user/repos",
            headers={"Authorization": f"token {github_token}"},
            json={"name": repo_name, "private": True, "auto_init": True}
        )
        if create_repo.status_code != 201:
            raise HTTPException(status_code=500, detail="Failed to create GitHub repo")
        repo_data = create_repo.json()
        repo_full_name = repo_data['full_name']
        clone_url = repo_data['clone_url']
    else:
        repo_full_name = request.repo_url
        clone_url = f"https://github.com/{repo_full_name}.git"
    
    auth_clone_url = clone_url.replace('https://github.com/', f'https://x-access-token:{github_token}@github.com/')
    
    with tempfile.TemporaryDirectory() as temp_dir:
        if not request.repo_url:
            repo = Repo.init(temp_dir)
            repo.git.checkout(['-b', 'main'])
        else:
            repo = Repo.clone_from(auth_clone_url, temp_dir)
        
        project_root = sm.get_full_project_root()
        if os.path.exists(project_root):
            for item in os.listdir(project_root):
                src_path = os.path.join(project_root, item)
                dst_path = os.path.join(temp_dir, item)
                if os.path.isdir(src_path):
                    if os.path.exists(dst_path):
                        shutil.rmtree(dst_path)
                    shutil.copytree(src_path, dst_path, dirs_exist_ok=True)
                else:
                    shutil.copy2(src_path, dst_path)
        
        repo.git.add(all=True)
        repo.index.commit("Deploy from Samokoder")
        
        origin_url = auth_clone_url
        if not repo.remotes:
            repo.create_remote('origin', origin_url)
        else:
            repo.remotes.origin.set_url(origin_url)
        
        origin = repo.remote('origin')
        origin.push(refspec='main:main', set_upstream=True)
    
    vercel_token = get_config().vercel_token
    deploy_url = f"https://github.com/{repo_full_name}"
    if vercel_token:
        vercel_response = requests.post(
            "https://api.vercel.com/v13/projects",
            headers={"Authorization": f"Bearer {vercel_token}"},
            json={
                "name": repo_name,
                "gitRepository": {"type": "github", "repo": repo_full_name},
                "framework": "vite"
            }
        )
        if vercel_response.status_code in [200, 201]:
            deploy_url = vercel_response.json().get('domains', [f"{repo_name}.vercel.app"])[0]
    
    return {"deploy_url": deploy_url, "repo_full_name": repo_full_name}
