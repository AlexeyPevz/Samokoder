"""
File service contracts
"""
from typing import Protocol, Optional, List, Dict, Any, BinaryIO
from uuid import UUID
from pathlib import Path

class FileServiceProtocol(Protocol):
    """Protocol for file service implementations"""
    
    async def read_file(self, file_path: str, project_id: UUID, user_id: UUID) -> Optional[str]:
        """Read file content"""
        ...
    
    async def write_file(self, file_path: str, content: str, project_id: UUID, user_id: UUID) -> bool:
        """Write file content"""
        ...
    
    async def delete_file(self, file_path: str, project_id: UUID, user_id: UUID) -> bool:
        """Delete file"""
        ...
    
    async def rename_file(self, old_path: str, new_path: str, project_id: UUID, user_id: UUID) -> bool:
        """Rename file"""
        ...
    
    async def list_files(self, directory_path: str, project_id: UUID, user_id: UUID) -> List[Dict[str, Any]]:
        """List files in directory"""
        ...
    
    async def create_directory(self, directory_path: str, project_id: UUID, user_id: UUID) -> bool:
        """Create directory"""
        ...
    
    async def delete_directory(self, directory_path: str, project_id: UUID, user_id: UUID) -> bool:
        """Delete directory"""
        ...
    
    async def rename_directory(self, old_path: str, new_path: str, project_id: UUID, user_id: UUID) -> bool:
        """Rename directory"""
        ...
    
    async def get_file_info(self, file_path: str, project_id: UUID, user_id: UUID) -> Optional[Dict[str, Any]]:
        """Get file information"""
        ...
    
    async def upload_file(self, file_path: str, file_content: BinaryIO, project_id: UUID, user_id: UUID) -> bool:
        """Upload file"""
        ...
    
    async def download_file(self, file_path: str, project_id: UUID, user_id: UUID) -> Optional[BinaryIO]:
        """Download file"""
        ...
    
    async def export_project(self, project_id: UUID, user_id: UUID, format: str = "zip") -> Optional[Path]:
        """Export project"""
        ...
    
    async def import_project(self, project_data: BinaryIO, user_id: UUID) -> Optional[UUID]:
        """Import project"""
        ...

class FileRepositoryProtocol(Protocol):
    """Protocol for file repository implementations"""
    
    async def find_by_path(self, file_path: str, project_id: UUID) -> Optional[Dict[str, Any]]:
        """Find file by path and project ID"""
        ...
    
    async def find_by_project(self, project_id: UUID, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """Find files by project ID"""
        ...
    
    async def save(self, file_data: Dict[str, Any]) -> Dict[str, Any]:
        """Save file record"""
        ...
    
    async def update(self, file_id: UUID, file_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update file record"""
        ...
    
    async def delete(self, file_id: UUID) -> bool:
        """Delete file record"""
        ...
    
    async def delete_by_project(self, project_id: UUID) -> bool:
        """Delete all files for project"""
        ...