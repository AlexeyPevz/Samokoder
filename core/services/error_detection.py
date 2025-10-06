import asyncio
import json
import os
import re
from typing import Dict, List, Optional
from samokoder.core.db.models.project import Project
from samokoder.core.db.session import get_db
from sqlalchemy.orm import Session


class ErrorDetectionService:
    """Service for detecting errors in project builds"""
    
    def __init__(self):
        self.error_patterns = {
            "javascript": [
                r"Error: (.+)",
                r"ReferenceError: (.+) is not defined",
                r"TypeError: (.+)",
                r"SyntaxError: (.+)",
                r"Cannot find module '(.+)'"
            ],
            "python": [
                r"Error: (.+)",
                r"ImportError: (.+)",
                r"ModuleNotFoundError: (.+)",
                r"SyntaxError: (.+)",
                r"TypeError: (.+)"
            ],
            "build": [
                r"Failed to compile.",
                r"Build failed with \d+ error(s)?",
                r"Error: (.+)",
                r"ERROR in (.+)"
            ]
        }
    
    async def detect_errors(self, project_id: str, log_content: str) -> List[Dict]:
        """
        Detect errors in build logs
        
        :param project_id: Project ID
        :param log_content: Build log content
        :return: List of detected errors
        """
        errors = []
        project_type = await self._get_project_type(project_id)
        
        # Check for language-specific errors
        if project_type in self.error_patterns:
            for pattern in self.error_patterns[project_type]:
                matches = re.finditer(pattern, log_content, re.MULTILINE)
                for match in matches:
                    errors.append({
                        "type": project_type,
                        "message": match.group(0),
                        "details": match.groups(),
                        "line": self._get_line_number(log_content, match.start())
                    })
        
        # Check for general build errors
        for pattern in self.error_patterns["build"]:
            matches = re.finditer(pattern, log_content, re.MULTILINE)
            for match in matches:
                errors.append({
                    "type": "build",
                    "message": match.group(0),
                    "details": match.groups(),
                    "line": self._get_line_number(log_content, match.start())
                })
        
        return errors
    
    async def _get_project_type(self, project_id: str) -> str:
        """
        Determine project type based on project files
        
        :param project_id: Project ID
        :return: Project type (javascript, python, etc.)
        """
        # Get project from database
        db: Session = next(get_db())
        try:
            project = db.query(Project).filter(Project.id == project_id).first()
            if not project:
                return "unknown"
            
            # For now, we'll return a default type
            # In a real implementation, we would analyze project files
            return "javascript"
        finally:
            db.close()
    
    def _get_line_number(self, text: str, position: int) -> int:
        """
        Get line number for a position in text
        
        :param text: Text content
        :param position: Position in text
        :return: Line number
        """
        return text[:position].count('\n') + 1
    
    async def should_show_fix_button(self, project_id: str, log_content: str) -> bool:
        """
        Determine if fix button should be shown based on errors
        
        :param project_id: Project ID
        :param log_content: Build log content
        :return: True if fix button should be shown
        """
        errors = await self.detect_errors(project_id, log_content)
        return len(errors) > 0


# Global instance
error_detection_service = ErrorDetectionService()
