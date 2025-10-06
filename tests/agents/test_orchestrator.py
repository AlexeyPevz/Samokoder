import pytest
from unittest.mock import MagicMock, patch

from samokoder.core.agents.orchestrator import Orchestrator
from samokoder.core.agents.spec_writer import SpecWriter
from samokoder.core.agents.architect import Architect
from samokoder.core.agents.tech_lead import TechLead
from samokoder.core.agents.response import AgentResponse, ResponseType

# Mark all tests in this file as asyncio
pytestmark = pytest.mark.asyncio


@pytest.fixture
def mock_state_manager():
    """Fixture to create a mock StateManager with a mock state."""
    state_manager = MagicMock()
    state_manager.current_state = MagicMock()
    return state_manager


def test_create_agent_initial_state_no_spec(mock_state_manager):
    """Test that SpecWriter is created when the specification description is missing."""
    # Arrange
    mock_state_manager.current_state.epics = [{"source": "app"}] # Not frontend
    mock_state_manager.current_state.specification.description = None
    orchestrator = Orchestrator(state_manager=mock_state_manager, ui=MagicMock())

    # Act
    agent = orchestrator.create_agent(prev_response=None)

    # Assert
    assert isinstance(agent, SpecWriter)


def test_create_agent_no_architecture(mock_state_manager):
    """Test that Architect is created when architecture is missing."""
    # Arrange
    mock_state_manager.current_state.epics = [{"source": "app"}]
    mock_state_manager.current_state.specification.description = "A cool project"
    mock_state_manager.current_state.specification.architecture = None
    orchestrator = Orchestrator(state_manager=mock_state_manager, ui=MagicMock())

    # Act
    agent = orchestrator.create_agent(prev_response=None)

    # Assert
    assert isinstance(agent, Architect)


def test_create_agent_no_tasks(mock_state_manager):
    """Test that TechLead is created when there are no unfinished tasks."""
    # Arrange
    mock_state_manager.current_state.epics = [{"source": "app"}]
    mock_state_manager.current_state.specification.description = "A cool project"
    mock_state_manager.current_state.specification.architecture = "Clean Architecture"
    mock_state_manager.current_state.get_file_by_path.return_value = True # ci.yml exists
    mock_state_manager.current_state.unfinished_tasks = []
    orchestrator = Orchestrator(state_manager=mock_state_manager, ui=MagicMock())

    # Act
    agent = orchestrator.create_agent(prev_response=None)

    # Assert
    assert isinstance(agent, TechLead)


def test_create_agent_handles_error_response(mock_state_manager):
    """Test that ErrorHandler is created on receiving an ERROR response."""
    # Arrange
    orchestrator = Orchestrator(state_manager=mock_state_manager, ui=MagicMock())
    error_response = AgentResponse(type=ResponseType.ERROR, data=None)

    # Act
    # We need to patch the ErrorHandler to check if it's instantiated
    with patch('samokoder.core.agents.orchestrator.ErrorHandler') as mock_error_handler:
        orchestrator.create_agent(prev_response=error_response)
        # Assert
        mock_error_handler.assert_called_once()


def test_create_agent_step_handler(mock_state_manager):
    """Test that the step handler is called when there is a current step."""
    # Arrange
    mock_state_manager.current_state.epics = [{"source": "app"}]
    mock_state_manager.current_state.specification.description = "A cool project"
    mock_state_manager.current_state.specification.architecture = "Clean Architecture"
    mock_state_manager.current_state.get_file_by_path.return_value = True
    mock_state_manager.current_state.unfinished_tasks = [{"description": "a task"}]
    mock_state_manager.current_state.steps = [{"type": "command"}]
    mock_state_manager.current_state.current_step = {"type": "command"}
    orchestrator = Orchestrator(state_manager=mock_state_manager, ui=MagicMock())
    orchestrator.create_agent_for_step = MagicMock(return_value="step_agent")

    # Act
    agent = orchestrator.create_agent(prev_response=None)

    # Assert
    orchestrator.create_agent_for_step.assert_called_once_with({"type": "command"})
    assert agent == "step_agent"


def test_create_agent_fallback_agent(mock_state_manager):
    """Test that the fallback agent (Troubleshooter) is created when no other conditions match."""
    # Arrange
    mock_state_manager.current_state.epics = [{"source": "app"}]
    mock_state_manager.current_state.specification.description = "A cool project"
    mock_state_manager.current_state.specification.architecture = "Clean Architecture"
    mock_state_manager.current_state.get_file_by_path.return_value = True
    mock_state_manager.current_state.unfinished_tasks = [{"description": "a task"}]
    mock_state_manager.current_state.steps = []
    mock_state_manager.current_state.current_step = None
    mock_state_manager.current_state.unfinished_iterations = []
    mock_state_manager.current_state.current_task = {"status": "in_progress"}
    orchestrator = Orchestrator(state_manager=mock_state_manager, ui=MagicMock())

    # Act
    with patch('samokoder.core.agents.orchestrator.Troubleshooter') as mock_troubleshooter:
        orchestrator.create_agent(prev_response=None)
        # Assert
        mock_troubleshooter.assert_called_once()