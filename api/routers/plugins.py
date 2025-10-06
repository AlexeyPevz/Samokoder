from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from samokoder.core.db.session import get_db
from samokoder.core.db.models.user import User
from samokoder.core.plugins.base import plugin_manager
from samokoder.api.routers.auth import get_current_user
from samokoder.core.api.middleware.tier_limits import require_git_push_access
from typing import Dict, Any, List
import json

router = APIRouter()

@router.get("/plugins")
async def get_plugins(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get all available plugins
    
    :param user: Current user
    :param db: Database session
    :return: List of plugins
    """
    try:
        plugins = await plugin_manager.get_all_plugins()
        plugin_list = []
        for plugin in plugins:
            plugin_list.append({
                "name": plugin.name,
                "version": plugin.version,
                "description": plugin.description,
                "enabled": plugin.enabled
            })
        return {
            "plugins": plugin_list
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting plugins: {str(e)}")


@router.get("/plugins/{plugin_name}")
async def get_plugin_info(
    plugin_name: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get information about a specific plugin
    
    :param plugin_name: Name of the plugin
    :param user: Current user
    :param db: Database session
    :return: Plugin information
    """
    try:
        plugin = await plugin_manager.get_plugin(plugin_name)
        if not plugin:
            raise HTTPException(status_code=404, detail=f"Plugin {plugin_name} not found")
        
        return {
            "name": plugin.name,
            "version": plugin.version,
            "description": plugin.description,
            "enabled": plugin.enabled
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting plugin info: {str(e)}")


@router.post("/plugins/{plugin_name}/enable")
async def enable_plugin(
    plugin_name: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Enable a plugin
    
    :param plugin_name: Name of the plugin
    :param user: Current user
    :param db: Database session
    :return: Result
    """
    try:
        plugin = await plugin_manager.get_plugin(plugin_name)
        if not plugin:
            raise HTTPException(status_code=404, detail=f"Plugin {plugin_name} not found")
        
        plugin.enabled = True
        return {
            "success": True,
            "message": f"Plugin {plugin_name} enabled"
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error enabling plugin: {str(e)}")


@router.post("/plugins/{plugin_name}/disable")
async def disable_plugin(
    plugin_name: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Disable a plugin
    
    :param plugin_name: Name of the plugin
    :param user: Current user
    :param db: Database session
    :return: Result
    """
    try:
        plugin = await plugin_manager.get_plugin(plugin_name)
        if not plugin:
            raise HTTPException(status_code=404, detail=f"Plugin {plugin_name} not found")
        
        plugin.enabled = False
        return {
            "success": True,
            "message": f"Plugin {plugin_name} disabled"
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error disabling plugin: {str(e)}")


@router.get("/plugins/{plugin_name}/settings")
async def get_plugin_settings(
    plugin_name: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get user settings for a plugin
    
    :param plugin_name: Name of the plugin
    :param user: Current user
    :param db: Database session
    :return: Plugin settings
    """
    try:
        plugin = await plugin_manager.get_plugin(plugin_name)
        if not plugin:
            raise HTTPException(status_code=404, detail=f"Plugin {plugin_name} not found")
        
        settings = await plugin.get_user_settings(user, db)
        return {
            "plugin": plugin_name,
            "settings": settings
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting plugin settings: {str(e)}")


@router.post("/plugins/{plugin_name}/settings")
async def update_plugin_settings(
    plugin_name: str,
    settings: Dict[str, Any],
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Update user settings for a plugin
    
    :param plugin_name: Name of the plugin
    :param settings: New settings
    :param user: Current user
    :param db: Database session
    :return: Result
    """
    try:
        plugin = await plugin_manager.get_plugin(plugin_name)
        if not plugin:
            raise HTTPException(status_code=404, detail=f"Plugin {plugin_name} not found")
        
        success = await plugin.update_user_settings(user, settings, db)
        if success:
            return {
                "success": True,
                "message": f"Settings updated for plugin {plugin_name}"
            }
        else:
            raise HTTPException(status_code=500, detail=f"Failed to update settings for plugin {plugin_name}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error updating plugin settings: {str(e)}")


@router.post("/plugins/{plugin_name}/github/create-repo")
async def create_github_repo(
    plugin_name: str,
    project_id: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    _git_check = Depends(require_git_push_access)  # Tier-based git operations access
):
    """
    Create a GitHub repository for a project
    
    :param plugin_name: Name of the plugin (should be 'github')
    :param project_id: Project ID
    :param user: Current user
    :param db: Database session
    :return: Result
    """
    try:
        # Verify plugin is GitHub plugin
        if plugin_name != "github":
            raise HTTPException(status_code=400, detail="This endpoint is only for GitHub plugin")
        
        plugin = await plugin_manager.get_plugin(plugin_name)
        if not plugin:
            raise HTTPException(status_code=404, detail=f"Plugin {plugin_name} not found")
        
        # Get project
        from samokoder.core.db.models.project import Project
        project = db.query(Project).filter(
            Project.id == project_id,
            Project.user_id == user.id
        ).first()
        
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        
        # Create repository
        success = await plugin.create_repository(user, project, db)
        if success:
            return {
                "success": True,
                "message": f"GitHub repository created for project {project.name}"
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to create GitHub repository")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating GitHub repository: {str(e)}")