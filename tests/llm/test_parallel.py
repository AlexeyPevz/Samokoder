import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock

from samokoder.core.llm.parallel import gather_llm_requests

# Mark all tests in this file as asyncio
pytestmark = pytest.mark.asyncio


async def mock_llm_call(duration: float, return_value: any = "success", exception: Exception = None):
    """A mock function to simulate an LLM call."""
    await asyncio.sleep(duration)
    if exception:
        raise exception
    return return_value


async def test_gather_llm_requests_basic():
    """Test that requests are gathered and results are in the correct order."""
    requests = [
        (mock_llm_call, (0.1,), {"return_value": "res1"}),
        (mock_llm_call, (0.05,), {"return_value": "res2"}),
        (mock_llm_call, (0.15,), {"return_value": "res3"}),
    ]

    results = await gather_llm_requests(requests)

    assert results == ["res1", "res2", "res3"]


async def test_gather_llm_requests_with_concurrency_limit():
    """Test that the semaphore correctly limits concurrent executions."""
    start_time = asyncio.get_event_loop().time()

    # Three tasks of 0.2s each, with concurrency limit of 2.
    # Expected duration is ~0.4s (2 run, then 1 runs).
    requests = [
        (mock_llm_call, (0.2,), {}),
        (mock_llm_call, (0.2,), {}),
        (mock_llm_call, (0.2,), {}),
    ]

    await gather_llm_requests(requests, max_concurrent=2)

    end_time = asyncio.get_event_loop().time()
    duration = end_time - start_time

    # Assert that the execution took roughly 0.4s, not 0.6s (parallel) or 0.2s (fully parallel)
    assert 0.38 < duration < 0.5


async def test_gather_llm_requests_exception_handling_return_exceptions_false():
    """Test that an exception in one request fails the entire gather when return_exceptions is False."""
    requests = [
        (mock_llm_call, (0.1,), {"return_value": "res1"}),
        (mock_llm_call, (0.1,), {"exception": ValueError("LLM Error")}),
        (mock_llm_call, (0.1,), {"return_value": "res3"}),
    ]

    with pytest.raises(ValueError, match="LLM Error"):
        await gather_llm_requests(requests, return_exceptions=False)


async def test_gather_llm_requests_exception_handling_return_exceptions_true():
    """Test that exceptions are returned as results when return_exceptions is True."""
    requests = [
        (mock_llm_call, (0.1,), {"return_value": "res1"}),
        (mock_llm_call, (0.1,), {"exception": ValueError("LLM Error")}),
        (mock_llm_call, (0.1,), {"return_value": "res3"}),
    ]

    results = await gather_llm_requests(requests, return_exceptions=True)

    assert len(results) == 3
    assert results[0] == "res1"
    assert isinstance(results[1], ValueError)
    assert str(results[1]) == "LLM Error"
    assert results[2] == "res3"


async def test_gather_llm_requests_empty_list():
    """Test that an empty list of requests returns an empty list."""
    results = await gather_llm_requests([])
    assert results == []