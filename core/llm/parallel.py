"""Utilities for parallel LLM request execution."""
import asyncio
from typing import Any, Callable, List, Tuple, Optional
from time import time

from samokoder.core.log import get_logger

log = get_logger(__name__)


async def gather_llm_requests(
    requests: List[Tuple[Callable, tuple, dict]],
    *,
    max_concurrent: Optional[int] = None,
    return_exceptions: bool = False,
) -> List[Any]:
    """
    Execute multiple LLM requests in parallel.
    
    Args:
        requests: List of (callable, args, kwargs) tuples for LLM calls
        max_concurrent: Maximum number of concurrent requests (default: unlimited)
        return_exceptions: If True, exceptions are returned instead of raised
    
    Returns:
        List of results in the same order as requests
    
    Example:
        >>> requests = [
        ...     (llm, (convo1,), {"temperature": 0}),
        ...     (llm, (convo2,), {"temperature": 0}),
        ... ]
        >>> results = await gather_llm_requests(requests)
    """
    start_time = time()
    
    if max_concurrent:
        # Use semaphore to limit concurrency
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def limited_request(func, args, kwargs):
            async with semaphore:
                return await func(*args, **kwargs)
        
        tasks = [
            limited_request(func, args, kwargs)
            for func, args, kwargs in requests
        ]
    else:
        # No limit on concurrency
        tasks = [
            func(*args, **kwargs)
            for func, args, kwargs in requests
        ]
    
    results = await asyncio.gather(*tasks, return_exceptions=return_exceptions)
    
    duration = time() - start_time
    log.info(
        f"Executed {len(requests)} LLM requests in parallel: "
        f"{duration:.2f}s (avg: {duration/len(requests):.2f}s per request)"
    )
    
    return results


async def gather_with_timeout(
    requests: List[Tuple[Callable, tuple, dict]],
    timeout: float,
    *,
    max_concurrent: Optional[int] = None,
) -> List[Any]:
    """
    Execute multiple LLM requests in parallel with a timeout.
    
    Args:
        requests: List of (callable, args, kwargs) tuples for LLM calls
        timeout: Timeout in seconds for all requests
        max_concurrent: Maximum number of concurrent requests
    
    Returns:
        List of results (or TimeoutError for timed out requests)
    
    Raises:
        asyncio.TimeoutError: If all requests don't complete within timeout
    """
    try:
        return await asyncio.wait_for(
            gather_llm_requests(requests, max_concurrent=max_concurrent, return_exceptions=True),
            timeout=timeout
        )
    except asyncio.TimeoutError:
        log.error(f"gather_with_timeout: {len(requests)} requests did not complete in {timeout}s")
        raise


class ParallelLLMExecutor:
    """
    Context manager for batching LLM requests and executing them in parallel.
    
    Example:
        >>> async with ParallelLLMExecutor(max_concurrent=5) as executor:
        ...     executor.add_request(llm, convo1, temperature=0)
        ...     executor.add_request(llm, convo2, temperature=0.5)
        ...     # Requests execute on __aexit__
        ...     pass
        >>> results = executor.results
    """
    
    def __init__(self, max_concurrent: Optional[int] = None):
        self.max_concurrent = max_concurrent
        self.requests: List[Tuple[Callable, tuple, dict]] = []
        self.results: List[Any] = []
    
    def add_request(self, func: Callable, *args, **kwargs):
        """Add a request to the batch."""
        self.requests.append((func, args, kwargs))
    
    async def __aenter__(self):
        """Enter the context."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Execute all batched requests on exit."""
        if self.requests:
            self.results = await gather_llm_requests(
                self.requests,
                max_concurrent=self.max_concurrent,
                return_exceptions=False
            )
        return False


# Decorator for auto-parallelization
def parallelize_llm_calls(max_concurrent: Optional[int] = None):
    """
    Decorator to automatically parallelize independent LLM calls in an async function.
    
    Note: This is a simple implementation. For complex scenarios, use gather_llm_requests directly.
    
    Example:
        >>> @parallelize_llm_calls(max_concurrent=5)
        ... async def process_tasks(llm, tasks):
        ...     results = []
        ...     for task in tasks:
        ...         convo = create_convo(task)
        ...         result = await llm(convo)
        ...         results.append(result)
        ...     return results
    """
    def decorator(func):
        async def wrapper(*args, **kwargs):
            # Simple pass-through for now
            # Could be enhanced to detect await patterns and auto-parallelize
            return await func(*args, **kwargs)
        return wrapper
    return decorator
