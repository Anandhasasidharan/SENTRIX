"""Provider-agnostic LLM client interface for the dual-LLM layer.

The ONLY contract PrivilegedLLM and QuarantinedLLM depend on. Any provider
(Anthropic, OpenAI, local OpenAI-compatible endpoints, ...) implements
:class:`LLMClient` and returns :class:`LLMResponse` — provider-specific
response parsing lives in exactly one place per client implementation.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


class LLMError(Exception):
    """Base error for all LLM client failures."""


class AuthError(LLMError):
    """Authentication failed (missing/invalid API key)."""


class RateLimitError(LLMError):
    """Provider rate-limited the request."""


class APIError(LLMError):
    """Provider API call failed after retries."""


@dataclass
class LLMResponse:
    """Sentrix-owned, provider-agnostic completion result."""

    text: str
    usage: dict[str, int] = field(default_factory=dict)
    model: str = ""
    reasoning: str | None = None

    @property
    def content(self) -> str:
        """Backward-compat alias for code that read ``.content``."""
        return self.text


class LLMClient(ABC):
    """The single interface the dual-LLM layer depends on.

    Subclasses define a ``DEFAULT_MODEL`` class attribute so the planner /
    quarantine layer never hardcodes a provider model string.
    """

    DEFAULT_MODEL: str = ""

    @abstractmethod
    def generate(
        self,
        messages: list[dict],
        model: str,
        max_tokens: int,
    ) -> LLMResponse:
        """Complete a chat from ``messages`` using ``model``.

        Concrete clients may accept additional optional kwargs (e.g.
        temperature), but must be callable with exactly these three.
        """


class CallableLLMClient(LLMClient):
    """Backward-compat adapter: wraps a bare callable as an :class:`LLMClient`.

    Preserves the historical call convention ``fn(model=..., messages=...,
    max_tokens=...)`` and normalizes provider-shaped responses (Anthropic
    content blocks, ``.text``, ``.content``, plain ``str``) into
    :class:`LLMResponse`.
    """

    DEFAULT_MODEL = "claude-sonnet-4-20250514"

    def __init__(self, fn: Callable[..., Any], default_model: str = DEFAULT_MODEL):
        self._fn = fn
        self._default_model = default_model

    def generate(
        self,
        messages: list[dict],
        model: str,
        max_tokens: int,
    ) -> LLMResponse:
        model = model or self._default_model
        raw = self._fn(model=model, messages=messages, max_tokens=max_tokens)
        return self._normalize(raw, model)

    @staticmethod
    def _normalize(raw: Any, model: str) -> LLMResponse:
        if isinstance(raw, LLMResponse):
            return raw
        if isinstance(raw, str):
            return LLMResponse(text=raw, model=model)

        content = getattr(raw, "content", None)
        if content is None:
            content = getattr(raw, "text", None)
        if content is None:
            raise LLMError(
                f"Unrecognized response shape from callable llm_client: {raw!r}"
            )

        usage = getattr(raw, "usage", None) or {}
        if isinstance(usage, dict):
            usage_dict: dict[str, int] = usage
        else:
            usage_dict = {
                "input_tokens": getattr(usage, "input_tokens", 0),
                "output_tokens": getattr(usage, "output_tokens", 0),
            }

        if isinstance(content, list):
            if content and hasattr(content[0], "text"):
                return LLMResponse(
                    text=content[0].text,
                    model=getattr(raw, "model", model),
                    usage=usage_dict,
                )
            raise LLMError(f"Unrecognized content block shape: {content!r}")
        if isinstance(content, str):
            return LLMResponse(
                text=content,
                model=getattr(raw, "model", model),
                usage=usage_dict,
            )
        raise LLMError(f"Unrecognized response content shape: {content!r}")
