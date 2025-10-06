"""Path validation utilities for security."""
import os
from pathlib import Path
from typing import Optional


class PathTraversalError(Exception):
    """Raised when path traversal is detected."""
    pass


def validate_workspace_path(workspace_root: str, requested_path: str) -> str:
    """
    Validate that requested path is within workspace boundaries.
    
    Args:
        workspace_root: Absolute path to workspace root
        requested_path: Path requested by user (relative or absolute)
        
    Returns:
        Normalized safe path within workspace
        
    Raises:
        PathTraversalError: If path is outside workspace
    """
    # Convert to Path objects
    workspace = Path(workspace_root).resolve()
    
    # Handle both relative and absolute paths
    if os.path.isabs(requested_path):
        requested = Path(requested_path).resolve()
    else:
        requested = (workspace / requested_path).resolve()
    
    # Check if requested path is within workspace
    try:
        requested.relative_to(workspace)
    except ValueError:
        raise PathTraversalError(
            f"Path '{requested_path}' is outside workspace boundaries"
        )
    
    # Additional checks for suspicious patterns
    suspicious_patterns = ['..', '~', '$', '\\', ':']
    for pattern in suspicious_patterns:
        if pattern in str(requested_path):
            raise PathTraversalError(
                f"Suspicious pattern '{pattern}' in path '{requested_path}'"
            )
    
    return str(requested)


def sanitize_filename(filename: str, max_length: int = 255) -> str:
    """
    Sanitize filename for safe storage.
    
    Args:
        filename: Original filename
        max_length: Maximum allowed length
        
    Returns:
        Sanitized filename
    """
    # Remove path separators and null bytes
    sanitized = filename.replace('/', '_').replace('\\', '_').replace('\0', '')
    
    # Remove leading dots (hidden files)
    sanitized = sanitized.lstrip('.')
    
    # Limit length
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
    
    # Ensure not empty
    if not sanitized:
        sanitized = 'unnamed'
    
    return sanitized