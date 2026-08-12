"""Production OpenAI / OpenAI-compatible API client.

Implements the provider-agnostic :class:`~sentrix.dual_llm.base.LLMClient`
interface. Because the OpenAI SDK speaks to any OpenAI-compatible endpoint
(vLLM, Ollama, LM Studio, ...) via a configurable ``base_url``, this single
client also covers self-hosted / local open-weight models.

Same retry / auth / error-handling rigor as the Anthropic client — this is
a security product; the second provider is not a stub.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any

from sentrix.dual_llm.base import (
    APIError,
    AuthError,
    LLMClient,
    LLMError,
    LLMResponse,
    RateLimitError,
)

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "gpt-4o"


@dataclass
class OpenAIConfig:
    api_key: str = ""
    model: str = field(default=DEFAULT_MODEL)
    base_url: str | None = None
    max_retries: int = 3
    base_delay: float = 1.0
    max_delay: float = 30.0
    timeout: float = 120.0


class OpenAIClient(LLMClient):
    DEFAULT_MODEL = DEFAULT_MODEL

    def __init__(self, config: OpenAIConfig | None = None):
        self._config = config or OpenAIConfig()
        self._client: Any = None
        self._load_config()

    def _load_config(self) -> None:
        if not self._config.api_key:
            self._config.api_key = os.environ.get("OPENAI_API_KEY", "")
        if not self._config.api_key:
            raise AuthError(
                "OPENAI_API_KEY not set. Set the environment variable "
                "or pass api_key to OpenAIConfig."
            )
        self._config.model = os.environ.get(
            "SENTRIX_LLM_MODEL", self._config.model
        )

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        try:
            import openai
        except ImportError:
            raise LLMError(
                "openai package not installed. Run: pip install openai"
            )
        kwargs: dict[str, Any] = {
            "api_key": self._config.api_key,
            "timeout": self._config.timeout,
        }
        if self._config.base_url:
            kwargs["base_url"] = self._config.base_url
        self._client = openai.OpenAI(**kwargs)
        return self._client

    def generate(
        self,
        messages: list[dict],
        model: str | None = None,
        max_tokens: int = 4096,
        temperature: float = 0.0,
    ) -> LLMResponse:
        client = self._get_client()
        kwargs: dict[str, Any] = self._request_kwargs(
            model=model, max_tokens=max_tokens, temperature=temperature, messages=messages
        )

        last_error: Exception | None = None
        last_status = "unknown"
        for attempt in range(self._config.max_retries):
            try:
                response = client.chat.completions.create(**kwargs)
                return self._build_response(response, kwargs)
            except Exception as e:
                if isinstance(e, APIError):
                    raise
                last_error = e
                status = self._classify_error(e)
                last_status = status
                if status == "auth":
                    raise AuthError(
                        f"Authentication failed: {e}"
                    ) from e
                if status in ("rate_limit", "overloaded"):
                    delay = min(
                        self._config.base_delay * (2 ** attempt),
                        self._config.max_delay,
                    )
                    logger.warning(
                        "%s (attempt %d/%d). Retrying in %.1fs...",
                        "Rate limited" if status == "rate_limit" else "API overloaded",
                        attempt + 1,
                        self._config.max_retries,
                        delay,
                    )
                    time.sleep(delay)
                    continue
                if attempt == self._config.max_retries - 1:
                    raise APIError(
                        f"API call failed after {self._config.max_retries} "
                        f"attempts: {e}"
                    ) from e
                time.sleep(self._config.base_delay)

        if last_status == "rate_limit":
            raise RateLimitError(
                f"Rate limit exceeded after {self._config.max_retries} "
                f"attempts: {last_error}"
            ) from last_error
        raise APIError(
            f"API call failed after {self._config.max_retries} attempts: "
            f"{last_error}"
        ) from last_error

    def generate_with_retry(
        self,
        messages: list[dict],
        **kwargs: Any,
    ) -> LLMResponse:
        return self.generate(messages, **kwargs)

    def _classify_error(self, error: Exception) -> str:
        msg = str(error).lower()
        if "authentication" in msg or "api key" in msg or "unauthorized" in msg:
            return "auth"
        if "rate" in msg or "429" in msg or "too many" in msg or "quota" in msg:
            return "rate_limit"
        if "overloaded" in msg or "529" in msg or "capacity" in msg:
            return "overloaded"
        if "timeout" in msg or "timed out" in msg:
            return "timeout"
        return "unknown"

    def _request_kwargs(
        self,
        model: str | None,
        max_tokens: int,
        temperature: float,
        messages: list[dict],
    ) -> dict[str, Any]:
        """Build the ChatCompletions request body — overridable by subclasses
        (e.g. DeepSeek appends provider-specific extra_body options)."""
        return {
            "model": model or self._config.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": messages,
        }

    def _build_response(self, response: Any, kwargs: dict[str, Any]) -> LLMResponse:
        """Translate a raw ChatCompletions response into an LLMResponse —
        overridable by subclasses that need provider-specific guards."""
        text = response.choices[0].message.content or ""
        return LLMResponse(
            text=text,
            model=getattr(response, "model", kwargs["model"]),
            usage={
                "input_tokens": getattr(response.usage, "prompt_tokens", 0),
                "output_tokens": getattr(response.usage, "completion_tokens", 0),
            },
        )
