"""End-to-end tests for project generation flow."""
import pytest
import asyncio
from uuid import uuid4
from pathlib import Path

from core.db.models.project import Project
from core.db.models.project_state import ProjectState, IterationStatus
from worker.main import run_generation_task


@pytest.mark.e2e
@pytest.mark.asyncio
class TestProjectGenerationE2E:
    """Test complete project generation flow."""
    
    async def test_simple_todo_app_generation(self, db_session, test_user):
        """Test generation of a simple todo app."""
        # Create project
        project = Project(
            id=uuid4(),
            user_id=test_user.id,
            name="Simple Todo App",
            description="A basic todo list application with React"
        )
        db_session.add(project)
        await db_session.commit()
        
        # Run generation
        success = await run_generation_task(
            project_id=str(project.id),
            user_id=test_user.id
        )
        
        assert success is True
        
        # Verify project state
        await db_session.refresh(project)
        state = await db_session.get(ProjectState, project.state.id)
        
        assert state is not None
        assert state.current_iteration.status == IterationStatus.COMPLETED
        
        # Verify generated files
        workspace_path = Path(f"workspace/{project.folder_name}")
        assert workspace_path.exists()
        
        # Check key files exist
        expected_files = [
            "package.json",
            "src/App.jsx",  
            "src/components/TodoList.jsx",
            "README.md"
        ]
        
        for file_path in expected_files:
            assert (workspace_path / file_path).exists(), f"Missing {file_path}"
            
    async def test_generation_with_errors(self, db_session, test_user):
        """Test that generation handles errors gracefully."""
        # Create project with problematic description
        project = Project(
            id=uuid4(),
            user_id=test_user.id,
            name="Broken Project",
            description="Create an app that violates physics laws and breaks reality"
        )
        db_session.add(project)
        await db_session.commit()
        
        # Run generation - should handle errors
        success = await run_generation_task(
            project_id=str(project.id),
            user_id=test_user.id
        )
        
        # Even with errors, should complete with some result
        assert success is True
        
        await db_session.refresh(project)
        state = await db_session.get(ProjectState, project.state.id)
        
        # Should have attempted bug fixing
        assert any(
            "BugHunter" in step.get("agent", "") 
            for step in state.steps
        )
        
    @pytest.mark.parametrize("tech_stack", [
        "React + Node.js",
        "Vue + Express", 
        "Angular + NestJS"
    ])
    async def test_different_tech_stacks(self, db_session, test_user, tech_stack):
        """Test generation with different technology stacks."""
        project = Project(
            id=uuid4(),
            user_id=test_user.id,
            name=f"App with {tech_stack}",
            description=f"Create a simple app using {tech_stack}"
        )
        db_session.add(project)
        await db_session.commit()
        
        success = await run_generation_task(
            project_id=str(project.id),
            user_id=test_user.id
        )
        
        assert success is True
        
        # Verify appropriate files for tech stack
        workspace_path = Path(f"workspace/{project.folder_name}")
        
        if "React" in tech_stack:
            assert (workspace_path / "package.json").exists()
            assert any(
                (workspace_path / "src").glob("*.jsx") or
                (workspace_path / "src").glob("*.tsx")
            )