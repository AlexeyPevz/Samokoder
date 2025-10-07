import asyncio
import os
from typing import List, Optional, Union

from samokoder.core.agents.architect import Architect
from samokoder.core.agents.base import BaseAgent
from samokoder.core.agents.bug_hunter import BugHunter
from samokoder.core.agents.cicd import CICDAgent
from samokoder.core.agents.code_monkey import CodeMonkey
from samokoder.core.agents.developer import Developer
from samokoder.core.agents.error_handler import ErrorHandler
from samokoder.core.agents.executor import Executor
from samokoder.core.agents.external_docs import ExternalDocumentation
from samokoder.core.agents.frontend import Frontend
from samokoder.core.agents.git import GitMixin
from samokoder.core.agents.human_input import HumanInput
from samokoder.core.agents.importer import Importer
from samokoder.core.agents.legacy_handler import LegacyHandler
from samokoder.core.agents.problem_solver import ProblemSolver
from samokoder.core.agents.response import AgentResponse, ResponseType
from samokoder.core.agents.spec_writer import SpecWriter
from samokoder.core.agents.task_completer import TaskCompleter
from samokoder.core.agents.tech_lead import TechLead
from samokoder.core.agents.tech_writer import TechnicalWriter
from samokoder.core.agents.troubleshooter import Troubleshooter
from samokoder.core.db.models.project_state import IterationStatus, TaskStatus
from samokoder.core.log import get_logger
from samokoder.core.telemetry import telemetry

log = get_logger(__name__)


class Orchestrator(BaseAgent, GitMixin):
    """
    Main agent that controls the flow of the process.

    Based on the current state of the project, the orchestrator invokes
    all other agents. It is also responsible for determining when each
    step is done and the project state needs to be committed to the database.
    """

    agent_type = "orchestrator"
    display_name = "Orchestrator"

    async def run(self) -> bool:
        """
        Run the Orchestrator agent.

        :return: True if the Orchestrator exited successfully, False otherwise.
        """
        response = None

        log.info(f"Starting {__name__}.Orchestrator")

        container = self.state_manager.container
        self.executor = Executor(self.state_manager, self.ui, container=container)
        self.process_manager = self.executor.process_manager
        # Chat feature disabled pending full implementation
        # self.chat = None

        await self.init_ui()
        await self.offline_changes_check()

        await self.install_dependencies()

        if self.args.use_git and await self.check_git_installed():
            await self.init_git_if_needed()

        # TODO: consider refactoring this into two loop; the outer with one iteration per comitted step,
        # and the inner which runs the agents for the current step until they're done. This would simplify
        # handle_done() and let us do other per-step processing (eg. describing files) in between agent runs.
        while True:
            await self.update_stats()

            agent = self.create_agent(response)

            # In case where agent is a list, run all agents in parallel.
            # Only one agent type can be run in parallel at a time (for now). See handle_parallel_responses().
            if isinstance(agent, list):
                tasks = [single_agent.run() for single_agent in agent]
                log.debug(
                    f"Running agents {[a.__class__.__name__ for a in agent]} (step {self.current_state.step_index})"
                )
                responses = await asyncio.gather(*tasks)
                response = self.handle_parallel_responses(agent[0], responses)

                should_update_knowledge_base = any(
                    "src/pages/" in single_agent.step.get("save_file", {}).get("path", "")
                    or "src/api/" in single_agent.step.get("save_file", {}).get("path", "")
                    or len(single_agent.step.get("related_api_endpoints")) > 0
                    for single_agent in agent
                )

                if should_update_knowledge_base:
                    files_with_implemented_apis = [
                        {
                            "path": single_agent.step.get("save_file", {}).get("path", None),
                            "related_api_endpoints": single_agent.step.get("related_api_endpoints"),
                            "line": 0,  # Line number not available from API endpoints
                        }
                        for single_agent in agent
                        if len(single_agent.step.get("related_api_endpoints")) > 0
                    ]
                    await self.state_manager.update_apis(files_with_implemented_apis)
                    await self.state_manager.update_implemented_pages_and_apis()

            else:
                log.debug(f"Running agent {agent.__class__.__name__} (step {self.current_state.step_index})")
                response = await agent.run()

            if response.type == ResponseType.EXIT:
                log.debug(f"Agent {agent.__class__.__name__} requested exit")
                break

            if response.type == ResponseType.DONE:
                response = await self.handle_done(agent, response)
                continue

        # Rollback any uncommitted changes to prevent data corruption
        if self.next_state and self.next_state != self.current_state:
            log.warning("Uncommitted changes detected in next_state, rolling back")
            await self.state_manager.rollback()
        return True

    async def install_dependencies(self):
        # First check if package.json exists
        package_json_path = os.path.join(self.state_manager.get_full_project_root(), "package.json")
        if not os.path.exists(package_json_path):
            # Skip if no package.json found
            return

        # Then check if node_modules directory exists
        node_modules_path = os.path.join(self.state_manager.get_full_project_root(), "node_modules")
        if not os.path.exists(node_modules_path):
            await self.send_message("Installing project dependencies...")
            await self.process_manager.run_command("npm install", show_output=False)

    def handle_parallel_responses(self, agent: BaseAgent, responses: List[AgentResponse]) -> AgentResponse:
        """
        Handle responses from agents that were run in parallel.

        This method is called when multiple agents are run in parallel, and it
        should return a single response that represents the combined responses
        of all agents.

        :param agent: The original agent that was run in parallel.
        :param responses: List of responses from all agents.
        :return: Combined response.
        """
        response = AgentResponse.done(agent)
        if isinstance(agent, CodeMonkey):
            files = []
            for single_response in responses:
                if single_response.type == ResponseType.INPUT_REQUIRED:
                    files += single_response.data.get("files", [])
                    break
            if files:
                response = AgentResponse.input_required(agent, files)
            return response
        else:
            raise ValueError(f"Unhandled parallel agent type: {agent.__class__.__name__}")

    async def offline_changes_check(self):
        """
        Check for changes outside Samokoder.

        If there are changes, ask the user if they want to keep them, and
        import if needed.
        """

        log.info("Checking for offline changes.")
        modified_files = await self.state_manager.get_modified_files_with_content()

        if self.state_manager.workspace_is_empty():
            # NOTE: this will currently get triggered on a new project, but will do
            # nothing as there's no files in the database.
            log.info("Detected empty workspace, restoring state from the database.")
            await self.state_manager.restore_files()
        elif modified_files:
            await self.send_message(f"We found {len(modified_files)} new and/or modified files.")
            await self.ui.send_modified_files(modified_files)
            hint = "".join(
                [
                    "If you would like Samokoder to import those changes, click 'Yes'.\n",
                    "Clicking 'No' means Samokoder will restore (overwrite) all files to the last stored state.\n",
                ]
            )
            use_changes = await self.ask_question(
                question="Would you like to keep your changes?",
                buttons={
                    "yes": "Yes, keep my changes",
                    "no": "No, restore last Samokoder state",
                },
                buttons_only=True,
                hint=hint,
            )
            if use_changes.button == "yes":
                log.debug("Importing offline changes into Samokoder.")
                await self.import_files()
            else:
                log.debug("Restoring last stored state.")
                await self.state_manager.restore_files()

        log.info("Offline changes check done.")

    async def handle_done(self, agent: BaseAgent, response: AgentResponse) -> AgentResponse:
        """
        Handle the DONE response from the agent and commit current state to the database.

        This also checks for any files created or modified outside Samokoder and
        imports them. If any of the files require input from the user, the returned response
        will trigger the HumanInput agent to ask the user to provide the required input.

        """
        n_epics = len(self.next_state.epics)
        n_finished_epics = n_epics - len(self.next_state.unfinished_epics)
        n_tasks = len(self.next_state.tasks)
        n_finished_tasks = n_tasks - len(self.next_state.unfinished_tasks)
        n_iterations = len(self.next_state.iterations)
        n_finished_iterations = n_iterations - len(self.next_state.unfinished_iterations)
        n_steps = len(self.next_state.steps)
        n_finished_steps = n_steps - len(self.next_state.unfinished_steps)

        log.debug(
            f"Agent {agent.__class__.__name__} is done, "
            f"committing state for step {self.current_state.step_index}: "
            f"{n_finished_epics}/{n_epics} epics, "
            f"{n_finished_tasks}/{n_tasks} tasks, "
            f"{n_finished_iterations}/{n_iterations} iterations, "
            f"{n_finished_steps}/{n_steps} dev steps."
        )
        await self.state_manager.commit()

        # If there are any new or modified files changed outside Samokoder,
        # this is a good time to add them to the project. If any of them have
        # INPUT_REQUIRED, we'll first ask the user to provide the required input.
        import_files_response = await self.import_files()

        # If any of the files are missing metadata/descriptions, those need to be filled-in
        missing_descriptions = [file.path for file in self.current_state.files if not file.meta.get("description")]
        if missing_descriptions:
            log.debug(f"Some files are missing descriptions: {', '.join(missing_descriptions)}, requesting analysis")
            return AgentResponse.describe_files(self)

        return import_files_response

    def create_agent(self, prev_response: Optional[AgentResponse]) -> Union[List[BaseAgent], BaseAgent]:
        """
        Creates the next agent to run based on the current project state and the previous agent's response.
        This method uses a routing table to determine which agent to create, making the logic declarative and easier to maintain.
        """
        state = self.current_state

        # Helper functions to safely access state properties
        def get_current_task_status(st):
            return st.current_task.get("status") if st.current_task else None

        def get_current_iteration_status(st):
            return st.current_iteration.get("status") if st.current_iteration else None

        # Routing table: list of (condition, agent_class_or_marker, constructor_kwargs_config)
        agent_routing_table = [
            # Based on previous agent's response
            (lambda pr, st: pr and pr.type in [ResponseType.CANCEL, ResponseType.ERROR], ErrorHandler, {"prev_response": True}),
            (lambda pr, st: pr and pr.type == ResponseType.DESCRIBE_FILES, CodeMonkey, {"prev_response": True}),
            (lambda pr, st: pr and pr.type == ResponseType.INPUT_REQUIRED, HumanInput, {"prev_response": True}),
            (lambda pr, st: pr and pr.type == ResponseType.IMPORT_PROJECT, Importer, {"prev_response": True}),
            (lambda pr, st: pr and pr.type == ResponseType.EXTERNAL_DOCS_REQUIRED, ExternalDocumentation, {"prev_response": True}),
            (lambda pr, st: pr and pr.type == ResponseType.UPDATE_SPECIFICATION, SpecWriter, {"prev_response": True}),

            # Based on project state
            (lambda pr, st: not st.epics or (st.current_epic and st.current_epic.get("source") == "frontend"), Frontend, {"process_manager": True}),
            (lambda pr, st: not st.specification.description, SpecWriter, {"process_manager": True}),
            (lambda pr, st: not st.specification.architecture, Architect, {"process_manager": True}),
            (lambda pr, st: not st.get_file_by_path(".github/workflows/ci.yml"), CICDAgent, {}),
            (lambda pr, st: not st.unfinished_tasks or (st.specification.templates and not st.files), TechLead, {"process_manager": True}),

            # Based on current task status
            (lambda pr, st: get_current_task_status(st) == TaskStatus.REVIEWED, TechnicalWriter, {}),
            (lambda pr, st: get_current_task_status(st) in [TaskStatus.DOCUMENTED, TaskStatus.SKIPPED], TaskCompleter, {"process_manager": True}),

            # Based on steps and iterations
            (lambda pr, st: not st.steps and not st.iterations, Developer, {}),
            (lambda pr, st: st.current_step, "step_handler", {}),  # Special marker for step handling

            # Based on current iteration status
            (lambda pr, st: get_current_iteration_status(st) in [IterationStatus.HUNTING_FOR_BUG, IterationStatus.START_PAIR_PROGRAMMING, IterationStatus.AWAITING_USER_TEST, IterationStatus.AWAITING_BUG_REPRODUCTION], BugHunter, {}),
            (lambda pr, st: get_current_iteration_status(st) in [IterationStatus.AWAITING_LOGGING, IterationStatus.AWAITING_BUG_FIX, IterationStatus.IMPLEMENT_SOLUTION], Developer, {}),
            (lambda pr, st: get_current_iteration_status(st) == IterationStatus.FIND_SOLUTION, Troubleshooter, {}),
            (lambda pr, st: get_current_iteration_status(st) == IterationStatus.PROBLEM_SOLVER, ProblemSolver, {}),
            (lambda pr, st: get_current_iteration_status(st) == IterationStatus.NEW_FEATURE_REQUESTED, SpecWriter, {}),

            # Fallback
            (lambda pr, st: True, Troubleshooter, {}),
        ]

        for condition, agent_class_or_marker, kwargs_config in agent_routing_table:
            if condition(prev_response, state):
                # Handle the special case for step-based agent creation
                if agent_class_or_marker == "step_handler":
                    # TODO: this can be parallelized in the future
                    return self.create_agent_for_step(state.current_step)

                # Prepare constructor arguments for the agent
                kwargs = {"state_manager": self.state_manager, "ui": self.ui}
                if kwargs_config.get("prev_response"):
                    kwargs["prev_response"] = prev_response
                if kwargs_config.get("process_manager"):
                    kwargs["process_manager"] = self.process_manager

                agent_class = agent_class_or_marker
                return agent_class(**kwargs)

        # This should be unreachable if the routing table has a fallback
        raise ValueError("No agent could be created for the current state.")

    def create_agent_for_step(self, step: dict) -> Union[List[BaseAgent], BaseAgent]:
        step_type = step.get("type")
        if step_type == "save_file":
            steps = self.current_state.get_steps_of_type("save_file")
            parallel = []
            for step in steps:
                parallel.append(CodeMonkey(self.state_manager, self.ui, step=step))
            return parallel
        elif step_type == "command":
            return self.executor.for_step(step)
        elif step_type == "human_intervention":
            return HumanInput(self.state_manager, self.ui, step=step)
        elif step_type == "review_task":
            return LegacyHandler(self.state_manager, self.ui, data={"type": "review_task"})
        elif step_type == "create_readme":
            return TechnicalWriter(self.state_manager, self.ui)
        elif step_type == "utility_function":
            return Developer(self.state_manager, self.ui)
        else:
            raise ValueError(f"Unknown step type: {step_type}")

    async def import_files(self) -> Optional[AgentResponse]:
        imported_files, removed_paths = await self.state_manager.import_files()
        if not imported_files and not removed_paths:
            return None

        if imported_files:
            log.info(f"Imported new/changed files to project: {', '.join(f.path for f in imported_files)}")
        if removed_paths:
            log.info(f"Removed files from project: {', '.join(removed_paths)}")

        input_required_files: list[dict[str, int]] = []
        for file in imported_files:
            for line in self.state_manager.get_input_required(file.content.content, file.path):
                input_required_files.append({"file": file.path, "line": line})

        if input_required_files:
            # This will trigger the HumanInput agent to ask the user to provide the required changes
            # If the user changes anything (removes the "required changes"), the file will be re-imported.
            return AgentResponse.input_required(self, input_required_files)

        # Commit the newly imported file
        log.debug(f"Committing imported/removed files as a separate step {self.current_state.step_index}")
        await self.state_manager.commit()
        return None

    async def init_ui(self):
        await self.ui.send_project_root(self.state_manager.get_full_project_root())
        await self.ui.loading_finished()

        if self.current_state.epics:
            if len(self.current_state.epics) > 3:
                # We only want to send previous features, ie. exclude current one and the initial project (first epic)
                await self.ui.send_features_list([e["description"] for e in self.current_state.epics[2:-1]])

        if self.current_state.specification.description:
            await self.ui.send_project_description(self.current_state.specification.description)

    async def update_stats(self):
        if self.current_state.steps and self.current_state.current_step:
            source = self.current_state.current_step.get("source")
            source_steps = self.current_state.get_last_iteration_steps()
            await self.ui.send_step_progress(
                source_steps.index(self.current_state.current_step) + 1,
                len(source_steps),
                self.current_state.current_step,
                source,
            )

        total_files = 0
        total_lines = 0
        for file in self.current_state.files:
            total_files += 1
            total_lines += len(file.content.content.splitlines())

        telemetry.set("num_files", total_files)
        telemetry.set("num_lines", total_lines)

        stats = telemetry.get_project_stats()
        await self.ui.send_project_stats(stats)
