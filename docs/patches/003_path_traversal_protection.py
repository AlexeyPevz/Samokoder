"""
Патч 003: Защита от Path Traversal в workspace endpoints

Проблема: /workspace/{project_id}/files/{path} принимает ../../etc/passwd
Риск: Arbitrary file read → data leak, credentials exposure
CVSS: 7.5 (HIGH) - Information Disclosure

Решение: Whitelist validation для file paths
"""

from pathlib import Path
from uuid import UUID
from fastapi import HTTPException


def validate_workspace_path(project_id: UUID, path: str, workspace_root: str = "/app/workspace") -> Path:
    """
    Validate that file path is within workspace directory.
    
    Защита от:
    - Path traversal (../../etc/passwd)
    - Symlink attacks
    - Absolute path injection (/etc/passwd)
    
    Args:
        project_id: Project UUID
        path: Requested file path (user input)
        workspace_root: Root workspace directory
        
    Returns:
        Resolved safe path within workspace
        
    Raises:
        HTTPException: 400 if path is invalid or outside workspace
        
    Examples:
        >>> validate_workspace_path(uuid4(), "src/main.py", "/app/workspace")
        Path("/app/workspace/abc-123/src/main.py")
        
        >>> validate_workspace_path(uuid4(), "../../etc/passwd", "/app/workspace")
        HTTPException(400, "Invalid file path")
    """
    # Build workspace directory for this project
    project_workspace = Path(workspace_root) / str(project_id)
    project_workspace_resolved = project_workspace.resolve()
    
    # Resolve requested path (follows symlinks, normalizes ..)
    requested_path = (project_workspace / path).resolve()
    
    # Check 1: Path must be within workspace
    # .resolve() canonicalizes path, so ../../ attacks are prevented
    if not str(requested_path).startswith(str(project_workspace_resolved)):
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_path",
                "message": "Invalid file path (path traversal detected)",
                "path": path,
            }
        )
    
    # Check 2: Path must not be absolute (prevent /etc/passwd)
    if Path(path).is_absolute():
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_path",
                "message": "Absolute paths not allowed",
                "path": path,
            }
        )
    
    # Check 3: Path must not contain null bytes
    if '\x00' in path:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_path",
                "message": "Null bytes not allowed in path",
                "path": path,
            }
        )
    
    return requested_path


# ============================================================================
# PATCH: Apply to api/routers/workspace.py
# ============================================================================

"""
# BEFORE (VULNERABLE):

@router.get("/workspace/{project_id}/files/{path:path}")
async def get_file(project_id: UUID, path: str):
    file_path = f"workspace/{project_id}/{path}"  # ⚠️ No validation!
    return FileResponse(file_path)


# AFTER (SECURE):

from patches.path_traversal_protection import validate_workspace_path

@router.get("/workspace/{project_id}/files/{path:path}")
async def get_file(project_id: UUID, path: str):
    safe_path = validate_workspace_path(project_id, path)  # ✅ Validated
    
    if not safe_path.exists():
        raise HTTPException(404, "File not found")
    
    if not safe_path.is_file():
        raise HTTPException(400, "Path is not a file")
    
    return FileResponse(safe_path)
"""


# ============================================================================
# TEST
# ============================================================================

import pytest
from uuid import uuid4


@pytest.mark.parametrize("malicious_path,expected_error", [
    ("../../etc/passwd", "path traversal detected"),
    ("../../../etc/shadow", "path traversal detected"),
    ("/etc/passwd", "Absolute paths not allowed"),
    ("src/../../../../../../etc/hosts", "path traversal detected"),
    ("src/main.py\x00.txt", "Null bytes not allowed"),
])
def test_path_traversal_blocked(malicious_path: str, expected_error: str):
    """Test that malicious paths are blocked."""
    project_id = uuid4()
    
    with pytest.raises(HTTPException) as exc_info:
        validate_workspace_path(project_id, malicious_path, "/tmp/test_workspace")
    
    assert exc_info.value.status_code == 400
    assert expected_error in str(exc_info.value.detail)


def test_valid_paths_allowed():
    """Test that valid paths are allowed."""
    project_id = uuid4()
    workspace = Path("/tmp/test_workspace")
    
    # Create test workspace
    project_dir = workspace / str(project_id)
    project_dir.mkdir(parents=True, exist_ok=True)
    
    valid_paths = [
        "src/main.py",
        "README.md",
        "package.json",
        "src/components/Button.tsx",
    ]
    
    for path in valid_paths:
        safe_path = validate_workspace_path(project_id, path, str(workspace))
        assert str(safe_path).startswith(str(project_dir))
        print(f"✓ Valid path allowed: {path}")


if __name__ == "__main__":
    # Run tests
    print("Testing path traversal protection...")
    test_valid_paths_allowed()
    print("\n✅ All tests passed")
