import re
import uuid
from typing import Dict, List, Optional

from sqlalchemy.orm import Session

from samokoder.core.agents.base import BaseAgent
from samokoder.core.db.models.project import Project
from samokoder.core.db.models.project_state import IterationStatus
from samokoder.core.db.session import get_db
from samokoder.core.state.state_manager import StateManager
from samokoder.core.ui.base import UIBase


class ErrorFixingAgent(BaseAgent):
    """Agent for automatically fixing errors in projects"""

    agent_type = "error_fixing"
    display_name = "Error Fixing Assistant"

    def __init__(self, state_manager: StateManager, ui: UIBase):
        self.state_manager = state_manager
        self.ui = ui

    async def fix_errors(self, project_id: str, errors: List[Dict]) -> bool:
        """
        Fix errors in a project
        
        :param project_id: Project ID
        :param errors: List of errors to fix
        :return: True if errors were fixed successfully
        """
        try:
            # Get project from database
            db: Session = next(get_db())
            project = db.query(Project).filter(Project.id == project_id).first()
            if not project:
                await self.ui.send_message("Project not found", source="system")
                return False

            # Analyze errors and create fixing plan
            fixing_plan = await self._create_fixing_plan(errors)

            # Execute fixing plan
            success = await self._execute_fixing_plan(fixing_plan, project)

            return success
        except Exception as e:
            await self.ui.send_message(f"Error while fixing: {str(e)}", source="system")
            return False
        finally:
            db.close()

    async def _create_fixing_plan(self, errors: List[Dict]) -> List[Dict]:
        """
        Create a plan for fixing errors
        
        :param errors: List of errors
        :return: List of fixing actions
        """
        fixing_plan = []

        for error in errors:
            action = await self._determine_fixing_action(error)
            if action:
                fixing_plan.append(action)

        return fixing_plan

    async def _determine_fixing_action(self, error: Dict) -> Optional[Dict]:
        """
        Determine the appropriate action to fix an error
        
        :param error: Error details
        :return: Fixing action or None
        """
        error_message = error.get("message", "")

        # Handle common errors
        if "Cannot find module" in error_message:
            # Extract module name
            module_match = re.search(r"Cannot find module '(.+)'", error_message)
            if module_match:
                module_name = module_match.group(1)
                return {
                    "type": "install_dependency",
                    "module": module_name,
                    "description": f"The build failed. Install the missing dependency: {module_name}",
                }

        elif "ReferenceError" in error_message and "is not defined" in error_message:
            return {
                "type": "add_import_or_definition",
                "description": f"The build failed with a ReferenceError: {error_message}. Analyze the code and add the missing import or variable definition.",
            }

        elif "SyntaxError" in error_message:
            return {
                "type": "fix_syntax",
                "description": f"The build failed with a SyntaxError: {error_message}. Analyze the code and fix the syntax.",
            }

        # For other errors, create a generic fixing task
        return {
            "type": "investigate_and_fix",
            "error": error,
            "description": f"The build failed with an error: {error_message}. Investigate and fix the issue.",
        }

    async def _execute_fixing_plan(self, fixing_plan: List[Dict], project: Project) -> bool:
        """
        Execute the fixing plan by creating development tasks for the Developer agent.
        
        :param fixing_plan: List of fixing actions
        :param project: Project object
        :return: True if all actions were created successfully
        """
        for action in fixing_plan:
            await self.ui.send_message(f"Creating task to: {action['description']}", source="system")
            await self._create_developer_task(action["description"])
        
        return True

    async def _create_developer_task(self, description: str):
        """
        Create a new development iteration for the Developer agent to act upon.
        
        :param description: The prompt/description for the development task.
        """
        new_iteration = {
            "id": uuid.uuid4().hex,
            "user_feedback": description,
            "description": description,
            "status": IterationStatus.IMPLEMENT_SOLUTION,
            # Add other necessary fields for an iteration
            "user_feedback_qa": None,
            "alternative_solutions": [],
            "attempts": 1,
            "bug_hunting_cycles": [],
        }
        self.state_manager.next_state.iterations.append(new_iteration)
        self.state_manager.next_state.flag_iterations_as_modified()
        await self.state_manager.commit()


# Factory function to create error fixing agent
def create_error_fixing_agent(state_manager: StateManager, ui: UIBase) -> ErrorFixingAgent:
    return ErrorFixingAgent(state_manager, ui)