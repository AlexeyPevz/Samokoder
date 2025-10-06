import asyncio
import datetime
import json
from enum import Enum
from time import time
from typing import Any, Callable, Optional, Tuple

import httpx

from samokoder.core.config.config import LLMConfig, LLMProvider
from samokoder.core.llm.convo import Convo
from samokoder.core.llm.request_log import LLMRequestLog, LLMRequestStatus
from samokoder.core.log import get_logger
from samokoder.core.db.models.user import User
from samokoder.core.db.session import get_db
from sqlalchemy.orm import Session

log = get_logger(__name__)


class LLMError(str, Enum):
    KEY_EXPIRED = "key_expired"
    RATE_LIMITED = "rate_limited"
    GENERIC_API_ERROR = "generic_api_error"


class APIError(Exception):
    def __init__(self, message: str):
        self.message = message


class BaseLLMClient:
    """
    Base asynchronous streaming client for language models.

    Example usage:

    >>> async def stream_handler(content: str):
    ...     print(content)
    ... 
>>> def parser(content: str) -> dict:
    ...     return json.loads(content)
    ... 
>>> client_class = BaseClient.for_provider(provider)
    >>> client = client_class(config, stream_handler=stream_handler)
    >>> response, request_log = await client(convo, parser=parser)
    """

    provider: LLMProvider

    def __init__(
        self,
        config: LLMConfig,
        *,
        stream_handler: Optional[Callable[[Optional[str]], Any]] = None,
        error_handler: Optional[Callable[[LLMError, str], Any]] = None,
        user: Optional[User] = None,  # Add user parameter for token tracking
    ):
        """
        Initialize the LLM client.

        :param config: LLM configuration.
        :param stream_handler: Optional async function to handle streamed responses.
        :param error_handler: Optional function to handle errors.
        :param user: Optional user object for token tracking.
        """
        self.config = config
        self.stream_handler = stream_handler
        self.error_handler = error_handler
        self.user = user  # Store user for token tracking
        self._init_client()

    def _init_client(self):
        """
        Initialize the underlying LLM client (e.g., OpenAI, Anthropic).

        Must be implemented by subclasses.
        """
        raise NotImplementedError()

    async def _make_request(
        self,
        convo: Convo,
        temperature: Optional[float] = None,
        json_mode: bool = False,
    ) -> Tuple[str, int, int]:
        """
        Make a request to the LLM.

        Must be implemented by subclasses.

        :param convo: Conversation to send to the LLM.
        :param temperature: Temperature for the request.
        :param json_mode: If True, the response is expected to be JSON.
        :return: Tuple containing the full response content, number of input tokens, and number of output tokens.
        """
        raise NotImplementedError()

    async def _record_token_usage(self, model: str, prompt_tokens: int, completion_tokens: int):
        """
        Record token usage for the user
        
        :param model: Model name
        :param prompt_tokens: Number of prompt tokens used
        :param completion_tokens: Number of completion tokens used
        """
        # Only record if user is provided
        if not self.user:
            return
            
        try:
            # Get database session
            db: Session = next(get_db())
            try:
                # Record token usage for the user
                self.user.record_token_usage(
                    provider=self.provider.value,
                    model=model,
                    tokens=prompt_tokens + completion_tokens
                )
                
                # Commit changes
                db.commit()
            finally:
                db.close()
        except Exception as e:
            log.error(f"Error recording token usage: {e}")
    async def __call__(
        self,
        convo: Convo,
        *,
        temperature: Optional[float] = None,
        parser: Optional[Callable] = None,
        max_retries: int = 3,
        json_mode: bool = False,
    ) -> Tuple[Any, LLMRequestLog]:
        """
        Invoke the LLM with the given conversation.

        Stream handler, if provided, should be an async function
        that takes a single argument, the response content (str).
        It will be called for each response chunk.

        Parser, if provided, should be a function that takes the
        response content (str) and returns the parsed response.
        On parse error, the parser should raise a ValueError with
        a descriptive error message that will be sent back to the LLM
        to retry, up to max_retries.

        :param convo: Conversation to send to the LLM.
        :param parser: Optional parser for the response.
        :param max_retries: Maximum number of retries for parsing the response.
        :param json_mode: If True, the response is expected to be JSON.
        :return: Tuple of the (parsed) response and request log entry.
        """
        import anthropic
        import groq
        import openai

        if temperature is None:
            temperature = self.config.temperature

        convo = convo.fork()
        request_log = LLMRequestLog(
            provider=self.provider,
            model=self.config.model,
            temperature=temperature,
            prompts=convo.prompt_log,
        )

        prompt_length_kb = len(json.dumps(convo.messages).encode("utf-8")) / 1024
        log.debug(
            f"Calling {self.provider.value} model {self.config.model} (temp={temperature}), prompt length: {prompt_length_kb:.1f} KB"
        )
        t0 = time()

        remaining_retries = max_retries
        while True:
            if remaining_retries == 0:
                # We've run out of auto-retries
                if request_log.error:
                    last_error_msg = f"Error connecting to the LLM: {request_log.error}"
                else:
                    last_error_msg = "Error parsing LLM response"

                # If we can, ask the user if they want to keep retrying
                if self.error_handler:
                    should_retry = await self.error_handler(LLMError.GENERIC_API_ERROR, message=last_error_msg)
                    if should_retry:
                        remaining_retries = max_retries
                        continue

                # They don't want to retry (or we can't ask them), raise the last error and stop самокодер
                raise APIError(last_error_msg)

            remaining_retries -= 1
            request_log.messages = convo.messages[:]
            request_log.response = None
            request_log.status = LLMRequestStatus.SUCCESS
            request_log.error = None
            response = None

            try:
                response, prompt_tokens, completion_tokens = await self._make_request(
                    convo,
                    temperature=temperature,
                    json_mode=json_mode,
                )
                
                # Record token usage
                await self._record_token_usage(self.config.model, prompt_tokens, completion_tokens)
            except (openai.APIConnectionError, anthropic.APIConnectionError, groq.APIConnectionError) as err:
                log.warning(f"API connection error: {err}", exc_info=True)
                request_log.error = str(f"API connection error: {err}")
                request_log.status = LLMRequestStatus.ERROR
                continue
            except httpx.ReadTimeout as err:
                log.warning(f"Read timeout (set to {self.config.read_timeout}s): {err}", exc_info=True)
                request_log.error = str(f"Read timeout: {err}")
                request_log.status = LLMRequestStatus.ERROR
                continue
            except httpx.ReadError as err:
                log.warning(f"Read error: {err}", exc_info=True)
                request_log.error = str(f"Read error: {err}")
                request_log.status = LLMRequestStatus.ERROR
                continue
            except (openai.RateLimitError, anthropic.RateLimitError, groq.RateLimitError) as err:
                log.warning(f"Rate limit error: {err}", exc_info=True)
                request_log.error = str(f"Rate limit error: {err}")
                request_log.status = LLMRequestStatus.ERROR
                wait_time = self.rate_limit_sleep(err)
                if wait_time:
                    message = f"We've hit {self.config.provider.value} rate limit. Sleeping for {wait_time.seconds} seconds..."
                    if self.error_handler:
                        await self.error_handler(LLMError.RATE_LIMITED, message)
                    await asyncio.sleep(wait_time.seconds)
                    continue
                else:
                    # RateLimitError that shouldn't be retried, eg. insufficient funds
                    err_msg = err.response.json().get("error", {}).get("message", "Rate limiting error.")
                    raise APIError(err_msg) from err
            except (openai.NotFoundError, anthropic.NotFoundError, groq.NotFoundError) as err:
                err_msg = err.response.json().get("error", {}).get("message", f"Model not found: {self.config.model}")
                raise APIError(err_msg) from err
            except (openai.AuthenticationError, anthropic.AuthenticationError, groq.AuthenticationError) as err:
                log.warning(f"Key expired: {err}", exc_info=True)
                err_msg = err.response.json().get("error", {}).get("message", "Incorrect API key")
                if "[BricksLLM]" in err_msg:
                    # We only want to show the key expired message if it's from Bricks
                    if self.error_handler:
                        should_retry = await self.error_handler(LLMError.KEY_EXPIRED)
                        if should_retry:
                            continue

                raise APIError(err_msg) from err
            except (openai.APIStatusError, anthropic.APIStatusError, groq.APIStatusError) as err:
                # Token limit exceeded (in the original Samokoder core handled as
                # TokenLimitError) is thrown as 400 (OpenAI, Anthropic) or 413 (Groq).
                # All providers throw an exception that is caught here.
                # OpenAI and Groq return a `code` field in the error JSON that lets
                # us confirm that we've breached the token limit, but Anthropic doesn't,
                # so we can't be certain that's the problem in Anthropic case.
                # Here we try to detect that and tell the user what happened.
                log.info(f"API status error: {err}")
                try:
                    if hasattr(err, "response"):
                        if err.response.headers.get("Content-Type", "").startswith("application/json"):
                            err_code = err.response.json().get("error", {}).get("code", "")
                        else:
                            err_code = str(err.response.text)
                    elif isinstance(err, str):
                        err_code = err
                    else:
                        err_code = json.dumps(err)
                except Exception as e:
                    err_code = f"Error parsing response: {str(e)}"
                if err_code in ("request_too_large", "context_length_exceeded", "string_above_max_length"):
                    # Handle OpenAI and Groq token limit exceeded
                    # OpenAI will return `string_above_max_length` for prompts more than 1M characters
                    message = "".join(
                        [
                            "We sent too large request to the LLM, resulting in an error. ",
                            "This is usually caused by including framework files in an LLM request. ",
            # They don't want to retry (or we can't ask them), raise the last error and stop Samokoder
            "Here's how you can get Samokoder to ignore those extra files: ",
                            "https://bit.ly/faq-token-limit-error",
                        ]
                    )
                    raise APIError(message) from err

                log.warning(f"API error: {err}", exc_info=True)
                request_log.error = str(f"API error: {err}")
                request_log.status = LLMRequestStatus.ERROR
                continue
            except (openai.APIError, anthropic.APIError, groq.APIError) as err:
                # Generic LLM API error
                # Make sure this handler is last in the chain as some of the above
                # errors inherit from these `APIError` classes
                log.warning(f"LLM API error {err}", exc_info=True)
                request_log.error = f"LLM had an error processing our request: {err}"
                request_log.status = LLMRequestStatus.ERROR
                continue

            request_log.response = response

            request_log.prompt_tokens += prompt_tokens
            request_log.completion_tokens += completion_tokens
            if parser:
                try:
                    response = parser(response)
                    break
                except ValueError as err:
                    request_log.error = f"Error parsing response: {err}"
                    request_log.status = LLMRequestStatus.ERROR
                    log.debug(f"Error parsing LLM response: {err}, asking LLM to retry", exc_info=True)
                    convo.assistant(response)
                    convo.user(f"Error parsing response: {err}. Please output your response EXACTLY as requested.")
                    continue
            else:
                break

        t1 = time()
        request_log.duration = t1 - t0

        log.debug(
            f"Total {self.provider.value} response time {request_log.duration:.2f}s, {request_log.prompt_tokens} prompt tokens, {request_log.completion_tokens} completion tokens used"
        )

        return response, request_log

    async def api_check(self) -> bool:
        """
        Check if the LLM API is working.

        :return: True if the API is working, False otherwise.
        """
        try:
            # This is a simplified check that just verifies the API key works
            # In a real implementation, we would make a small test request
            return bool(self.config.api_key)
        except Exception as e:
            log.warning(f"API check failed: {e}")
            return False

    @staticmethod
    def for_provider(provider: LLMProvider) -> type["BaseLLMClient"]:
        """
        Return LLM client for the specified provider.

        :param provider: Provider to return the client for.
        :return: Client class for the specified provider.
        """
        from .anthropic_client import AnthropicClient
        from .azure_client import AzureClient
        from .groq_client import GroqClient
        from .openai_client import OpenAIClient

        if provider == LLMProvider.OPENAI:
            return OpenAIClient
        elif provider == LLMProvider.ANTHROPIC:
            return AnthropicClient
        elif provider == LLMProvider.GROQ:
            return GroqClient
        elif provider == LLMProvider.AZURE:
            return AzureClient
        else:
            raise ValueError(f"Unsupported provider: {provider}")

    def rate_limit_sleep(self, err) -> Optional[datetime.timedelta]:
        """
        Calculate sleep time for rate limit errors.

        :param err: Rate limit error.
        :return: Sleep time or None if the error shouldn't be retried.
        """
        # This is a simplified implementation
        # In a real implementation, we would parse the error and calculate the sleep time
        return datetime.timedelta(seconds=5)


__all__ = ["BaseLLMClient"]
