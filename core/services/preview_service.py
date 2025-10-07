"""
DEPRECATED: This file is a stub/mock implementation and is NOT used in production.
The actual preview service is implemented in api/routers/preview.py

This file should be removed in a future cleanup.
"""
import asyncio
import os
import subprocess
from typing import Dict, Optional
from samokoder.core.db.models.project import Project
from samokoder.core.db.session import get_db
from sqlalchemy.orm import Session


class PreviewService:
    """
    DEPRECATED: Stub implementation - DO NOT USE
    
    Service for managing live previews of projects.
    Use api/routers/preview.py endpoints instead.
    """
    
    def __init__(self):
        self.running_previews: Dict[str, Dict] = {}  # project_id -> {process, port, url}
    
    async def start_preview(self, project_id: str) -> Dict[str, str]:
        """
        Start a live preview for a project
        
        :param project_id: Project ID
        :return: Preview information
        """
        # Check if preview is already running
        if project_id in self.running_previews:
            return self.running_previews[project_id]
        
        # Get project from database
        db: Session = next(get_db())
        try:
            project = db.query(Project).filter(Project.id == project_id).first()
            if not project:
                raise ValueError("Project not found")
            
            # Determine project type and start appropriate preview server
            project_type = await self._determine_project_type(project_id)
            preview_info = await self._start_preview_server(project_id, project_type)
            
            # Store preview info
            self.running_previews[project_id] = preview_info
            
            return preview_info
        finally:
            db.close()
    
    async def stop_preview(self, project_id: str) -> bool:
        """
        Stop a live preview for a project
        
        :param project_id: Project ID
        :return: True if stopped successfully
        """
        if project_id not in self.running_previews:
            return False
        
        preview_info = self.running_previews[project_id]
        process = preview_info.get("process")
        
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        
        del self.running_previews[project_id]
        return True
    
    async def get_preview_status(self, project_id: str) -> Dict[str, str]:
        """
        Get the status of a project preview
        
        :param project_id: Project ID
        :return: Preview status
        """
        if project_id not in self.running_previews:
            return {"status": "stopped", "url": None}
        
        preview_info = self.running_previews[project_id]
        process = preview_info.get("process")
        
        if process and process.poll() is None:
            return {"status": "running", "url": preview_info.get("url")}
        else:
            # Process has stopped, clean up
            del self.running_previews[project_id]
            return {"status": "stopped", "url": None}
    
    async def _determine_project_type(self, project_id: str) -> str:
        """
        Determine the project type based on project files
        
        :param project_id: Project ID
        :return: Project type
        """
        # For now, we'll return a default type
        # In a real implementation, we would analyze project files
        return "javascript"  # Default to JavaScript/Node.js project
    
    async def _start_preview_server(self, project_id: str, project_type: str) -> Dict[str, str]:
        """
        Start the appropriate preview server based on project type
        
        :param project_id: Project ID
        :param project_type: Project type
        :return: Preview information
        """
        project_path = f"/workspace/projects/{project_id}"
        
        # Ensure project directory exists
        os.makedirs(project_path, exist_ok=True)
        
        if project_type == "javascript":
            return await self._start_javascript_preview(project_path, project_id)
        elif project_type == "python":
            return await self._start_python_preview(project_path, project_id)
        else:
            # Default to simple HTTP server
            return await self._start_simple_preview(project_path, project_id)
    
    async def _start_javascript_preview(self, project_path: str, project_id: str) -> Dict[str, str]:
        """
        Start a JavaScript project preview (npm run dev or similar)
        
        :param project_path: Path to project
        :param project_id: Project ID
        :return: Preview information
        """
        # Check if package.json exists
        package_json_path = os.path.join(project_path, "package.json")
        if not os.path.exists(package_json_path):
            # Fallback to simple HTTP server
            return await self._start_simple_preview(project_path, project_id)
        
        # Try to start development server
        try:
            # Check for common development scripts
            dev_scripts = ["dev", "start", "serve"]
            
            # For now, we'll just simulate starting a server
            # In a real implementation, we would parse package.json and start the appropriate script
            port = 3000 + hash(project_id) % 1000  # Generate a unique port
            url = f"http://localhost:{port}"
            
            # Simulate starting process safely
            process = await asyncio.create_subprocess_exec(
                "sleep", "3600",  # Simulate a long-running process
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            return {
                "process": process,
                "port": str(port),
                "url": url,
                "type": "javascript"
            }
        except Exception as e:
            # Fallback to simple HTTP server
            return await self._start_simple_preview(project_path, project_id)
    
    async def _start_python_preview(self, project_path: str, project_id: str) -> Dict[str, str]:
        """
        Start a Python project preview
        
        :param project_path: Path to project
        :param project_id: Project ID
        :return: Preview information
        """
        port = 3000 + hash(project_id) % 1000  # Generate a unique port
        url = f"http://localhost:{port}"
        
        # Simulate starting process safely
        process = await asyncio.create_subprocess_exec(
            "sleep", "3600",  # Simulate a long-running process
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        return {
            "process": process,
            "port": str(port),
            "url": url,
            "type": "python"
        }
    
    async def _start_simple_preview(self, project_path: str, project_id: str) -> Dict[str, str]:
        """
        Start a simple HTTP server for static files
        
        :param project_path: Path to project
        :param project_id: Project ID
        :return: Preview information
        """
        port = 3000 + hash(project_id) % 1000  # Generate a unique port
        url = f"http://localhost:{port}"
        
        # Change to project directory and start HTTP server safely
        try:
            import shlex
            process = await asyncio.create_subprocess_exec(
                "python3", "-m", "http.server", str(port),
                cwd=project_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            return {
                "process": process,
                "port": str(port),
                "url": url,
                "type": "static"
            }
        except Exception as e:
            # If python3 is not available, try python (fallback)
            try:
                process = await asyncio.create_subprocess_exec(
                    "python", "-m", "SimpleHTTPServer", str(port),
                    cwd=project_path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                return {
                    "process": process,
                    "port": str(port),
                    "url": url,
                    "type": "static"
                }
            except Exception as e2:
                # If no HTTP server is available, return basic info
                return {
                    "process": None,
                    "port": str(port),
                    "url": url,
                    "type": "static",
                    "error": "No HTTP server available"
                }


# Global instance
preview_service = PreviewService()