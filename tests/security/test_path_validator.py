"""Tests for path validation security."""
import pytest
from pathlib import Path
import tempfile

from core.security.path_validator import (
    validate_workspace_path, 
    sanitize_filename,
    PathTraversalError
)


class TestPathValidation:
    """Test path validation for security."""
    
    def setup_method(self):
        """Create temporary workspace for tests."""
        self.temp_dir = tempfile.mkdtemp()
        self.workspace = Path(self.temp_dir) / "workspace"
        self.workspace.mkdir()
        
    def test_valid_relative_path(self):
        """Test validation of valid relative paths."""
        result = validate_workspace_path(str(self.workspace), "project/file.py")
        assert "project/file.py" in result
        assert str(self.workspace) in result
        
    def test_valid_nested_path(self):
        """Test deeply nested but valid paths."""
        result = validate_workspace_path(
            str(self.workspace), 
            "a/b/c/d/e/f/file.txt"
        )
        assert "a/b/c/d/e/f/file.txt" in result
        
    def test_path_traversal_parent_dir(self):
        """Test detection of parent directory traversal."""
        with pytest.raises(PathTraversalError):
            validate_workspace_path(str(self.workspace), "../etc/passwd")
            
    def test_path_traversal_absolute(self):
        """Test detection of absolute path escape."""
        with pytest.raises(PathTraversalError):
            validate_workspace_path(str(self.workspace), "/etc/passwd")
            
    def test_path_traversal_hidden(self):
        """Test detection of hidden traversal attempts."""
        with pytest.raises(PathTraversalError):
            validate_workspace_path(str(self.workspace), "project/../../etc/passwd")
            
    def test_suspicious_patterns(self):
        """Test detection of suspicious patterns."""
        suspicious_paths = [
            "~/.ssh/id_rsa",
            "$HOME/.bashrc", 
            "file\\..\\..\\etc",
            "C:\\Windows\\System32"
        ]
        
        for path in suspicious_paths:
            with pytest.raises(PathTraversalError):
                validate_workspace_path(str(self.workspace), path)


class TestFilenameSanitization:
    """Test filename sanitization."""
    
    def test_remove_path_separators(self):
        """Test removal of path separators."""
        assert sanitize_filename("../../etc/passwd") == ".._.._etc_passwd"
        assert sanitize_filename("C:\\Windows\\file.txt") == "C:_Windows_file.txt"
        
    def test_remove_null_bytes(self):
        """Test removal of null bytes."""
        assert sanitize_filename("file\0.txt") == "file.txt"
        
    def test_remove_leading_dots(self):
        """Test removal of leading dots."""
        assert sanitize_filename("...hidden") == "hidden"
        assert sanitize_filename(".gitignore") == "gitignore"
        
    def test_length_limit(self):
        """Test filename length limiting."""
        long_name = "a" * 300
        result = sanitize_filename(long_name, max_length=255)
        assert len(result) == 255
        
    def test_empty_filename(self):
        """Test handling of empty filenames."""
        assert sanitize_filename("") == "unnamed"
        assert sanitize_filename("...") == "unnamed"