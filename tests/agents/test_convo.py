from unittest.mock import AsyncMock, MagicMock, patch

from pydantic import BaseModel, Field

from samokoder.core.agents.convo import AgentConvo


@patch("samokoder.core.config.get_config")
def test_init(mock_get_config):
    mock_get_config.return_value.prompt.paths = ["some/path"]
    """Test that init stores the agent instance and adds a system message."""
    agent = MagicMock(agent_type="spec-writer", current_state=None)
    convo = AgentConvo(agent)
    assert convo.agent_instance == agent
    assert len(convo.messages) == 1
    assert convo.messages[0]["role"] == "system"


@patch("samokoder.core.config.get_config")
def test_fork(mock_get_config):
    mock_get_config.return_value.prompt.paths = ["some/path"]
    """Test that fork() creates a new AgentConvo instance, not base Convo."""
    agent = MagicMock(agent_type="spec-writer", current_state=None)
    convo = AgentConvo(agent)
    child = convo.fork()
    assert child.agent_instance == agent

    child.template("ask_questions")

    assert len(convo.messages) == 1
    assert len(child.messages) == 2


@patch("samokoder.core.config.get_config")
def test_require_schema(mock_get_config):
    mock_get_config.return_value.prompt.paths = ["some/path"]
    """Test that require_schema() adds a message with the schema description."""

    class MyModel(BaseModel):
        name: str = Field(description="User name")
        age: int

    agent = MagicMock(agent_type="spec-writer", current_state=None)
    convo = AgentConvo(agent).require_schema(MyModel)
    assert len(convo.messages) == 2
    assert '"description": "User name"' in convo.messages[1]["content"]
