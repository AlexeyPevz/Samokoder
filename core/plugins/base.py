from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from samokoder.core.db.models.user import User
from samokoder.core.db.models.project import Project
from sqlalchemy.orm import Session


class BasePlugin(ABC):
    """Base class for all plugins"""
    
    def __init__(self, name: str, version: str, description: str):
        self.name = name
        self.version = version
        self.description = description
        self.enabled = True
    
    @abstractmethod
    async def initialize(self) -> bool:
        """Initialize the plugin"""
        pass
    
    @abstractmethod
    async def cleanup(self) -> None:
        """Clean up plugin resources"""
        pass
    
    @abstractmethod
    async def on_project_created(self, project: Project, user: User, db: Session) -> None:
        """Called when a project is created"""
        pass
    
    @abstractmethod
    async def on_project_build(self, project: Project, user: User, db: Session) -> None:
        """Called when a project is built"""
        pass
    
    @abstractmethod
    async def on_project_deploy(self, project: Project, user: User, db: Session) -> None:
        """Called when a project is deployed"""
        pass
    
    @abstractmethod
    async def get_project_info(self, project: Project, user: User, db: Session) -> Dict[str, Any]:
        """Get plugin-specific project information"""
        pass
    
    @abstractmethod
    async def get_user_settings(self, user: User, db: Session) -> Dict[str, Any]:
        """Get plugin-specific user settings"""
        pass
    
    @abstractmethod
    async def update_user_settings(self, user: User, settings: Dict[str, Any], db: Session) -> bool:
        """Update plugin-specific user settings"""
        pass


class PluginManager:
    """Manager for loading and managing plugins"""
    
    def __init__(self):
        self.plugins: Dict[str, BasePlugin] = {}
        self.plugin_configs: Dict[str, Dict[str, Any]] = {}
    
    async def register_plugin(self, plugin: BasePlugin) -> None:
        """Register a plugin"""
        self.plugins[plugin.name] = plugin
        await plugin.initialize()
    
    async def unregister_plugin(self, plugin_name: str) -> None:
        """Unregister a plugin"""
        if plugin_name in self.plugins:
            await self.plugins[plugin_name].cleanup()
            del self.plugins[plugin_name]
    
    async def load_plugins(self) -> None:
        """Load all available plugins"""
        # In a real implementation, we would dynamically load plugins
        # from a plugins directory or registry
        pass
    
    async def get_plugin(self, plugin_name: str) -> Optional[BasePlugin]:
        """Get a plugin by name"""
        return self.plugins.get(plugin_name)
    
    async def get_all_plugins(self) -> List[BasePlugin]:
        """Get all registered plugins"""
        return list(self.plugins.values())
    
    async def on_project_event(self, event: str, project: Project, user: User, db: Session) -> None:
        """Handle project events for all plugins"""
        for plugin in self.plugins.values():
            if plugin.enabled:
                try:
                    if event == "created":
                        await plugin.on_project_created(project, user, db)
                    elif event == "build":
                        await plugin.on_project_build(project, user, db)
                    elif event == "deploy":
                        await plugin.on_project_deploy(project, user, db)
                except Exception as e:
                    log.error(f"Error in plugin {plugin.name} during {event} event: {e}", exc_info=True)
    
    async def get_project_info_from_plugins(self, project: Project, user: User, db: Session) -> Dict[str, Any]:
        """Get project information from all plugins"""
        project_info = {}
        for plugin_name, plugin in self.plugins.items():
            if plugin.enabled:
                try:
                    info = await plugin.get_project_info(project, user, db)
                    project_info[plugin_name] = info
                except Exception as e:
                    log.error(f"Error getting project info from plugin {plugin_name}: {e}", exc_info=True)
        return project_info


# Global instance
plugin_manager = PluginManager()