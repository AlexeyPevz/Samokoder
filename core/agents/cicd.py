from samokoder.core.agents.base import BaseAgent
from samokoder.core.agents.convo import AgentConvo
from samokoder.core.agents.response import AgentResponse
from samokoder.core.llm.parser import YAMLParser
from samokoder.core.log import get_logger

log = get_logger(__name__)

class CICDAgent(BaseAgent):
    agent_type = "cicd"
    display_name = "CI/CD Specialist"

    async def run(self) -> AgentResponse:
        """
        Generates a CI/CD pipeline configuration file for the project.
        """
        await self.ui.send_message("Generating CI/CD pipeline configuration...", source=self.ui_source)

        llm = self.get_llm()
        convo = AgentConvo(self).template(
            "generate_cicd",
            architecture=self.current_state.specification.architecture,
            dependencies=self.current_state.specification.package_dependencies,
        )

        response: str = await llm(convo, parser=YAMLParser())

        # TODO: The LLM might return the YAML inside a code block. 
        # We should parse it out.
        # For now, assume the response is clean YAML.
        cicd_yaml = response

        await self.state_manager.save_file(".github/workflows/ci.yml", cicd_yaml)

        await self.ui.send_message("CI/CD pipeline configuration has been generated.", source=self.ui_source)
        
        # This agent's job is done, it doesn't need to be part of the main loop after this.
        return AgentResponse.done(self)
