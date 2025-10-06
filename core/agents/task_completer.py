from samokoder.core.agents.base import BaseAgent
from samokoder.core.agents.git import GitMixin
from samokoder.core.agents.response import AgentResponse
from samokoder.core.log import get_logger
from samokoder.core.telemetry import telemetry
from samokoder.core.services.email_service import send_email

log = get_logger(__name__)


class TaskCompleter(BaseAgent, GitMixin):
    agent_type = "samokoder"
    display_name = "Samokoder"
    async def run(self) -> AgentResponse:
        if self.state_manager.git_available and self.state_manager.git_used:
            await self.git_commit()
            await self.git_push()

        task_description = self.current_state.current_task["description"]
        current_task_index1 = self.current_state.tasks.index(self.current_state.current_task) + 1
        self.next_state.action = f"Task #{current_task_index1} complete"
        self.next_state.complete_task()
        await self.state_manager.log_task_completed()
        tasks = self.current_state.tasks
        source = self.current_state.current_epic.get("source", "app")
        await self.ui.send_task_progress(
            current_task_index1,
            len(tasks),
            task_description,
            source,
            "done",
            self.current_state.get_source_index(source),
            tasks,
        )

        # Send email notification
        try:
            user_email = self.current_state.user.email
            project_name = self.state_manager.project.name
            subject = f"Задача выполнена в проекте '{project_name}'"
            body = f"""
            <html>
                <body>
                    <h2>Задача завершена!</h2>
                    <p>Задача была успешно выполнена в вашем проекте <strong>{project_name}</strong>.</p>
                    <p><strong>Задача:</strong> {task_description}</p>
                    <p>Вы можете просмотреть изменения в <a href="https://mas.ai-touragent.store/workspace/{self.state_manager.project.id}">вашем проекте</a>.</p>
                </body>
            </html>
            """
            send_email(user_email, subject, body)
        except Exception as e:
            log.error(f"Failed to send completion email: {e}")

        await telemetry.trace_code_event(
            "task-end",
            {
                "task_index": current_task_index1,
                "num_tasks": len(self.current_state.tasks),
                "num_epics": len(self.current_state.epics),
                "num_iterations": len(self.current_state.iterations),
            },
        )

        if current_task_index1 == len(tasks):
            if source == "app":
                await self.ui.send_app_finished(
                    app_id=str(self.state_manager.project.id),
                    app_name=self.state_manager.project.name,
                    folder_name=self.state_manager.project.folder_name,
                )
            elif source == "feature":
                await self.ui.send_feature_finished(
                    app_id=str(self.state_manager.project.id),
                    app_name=self.state_manager.project.name,
                    folder_name=self.state_manager.project.folder_name,
                )

        return AgentResponse.done(self)
