"""DeepSeek API client (OpenAI-ChatCompletions-compatible).

DeepSeek speaks the OpenAI ChatCompletions wire format at
https://api.deepseek.com, so this client reuses OpenAIClient's request /
response / retry / auth / error handling wholesale — only the endpoint,
env var, default model, and two provider-specific behaviors differ.

Provider-specific behavior (verified live against the API):

* ``deepseek-v4-flash`` is a thinking model: it always emits hidden
  ``reasoning_content`` that consumes output tokens BEFORE the final
  ``content``. With a small ``max_tokens`` budget the request can return
  ``content=""`` even though tokens were spent. Rather than silently
  returning an empty plan (the wrong failure mode for a security
  control), ``DeepSeekClient`` raises an explanatory ``APIError`` when
  this happens.

* The ``chat_template_kwargs.thinking.type=disabled`` knob is sent
  best-effort when ``disable_thinking=True`` (default). The official API
  currently accepts but ignores it (reasoning_content is still
  produced); vLLM-hosted deepseek deployments may honor it.

Model note: the real model name is "deepseek-v4-flash". The legacy
"deepseek-chat" / "deepseek-reasoner" aliases are scheduled for retirement
and now silently route to deepseek-v4-flash's non-thinking / thinking
modes, so use the real name directly.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from sentrix.dual_llm.base import APIError, AuthError
from sentrix.dual_llm.openai_client import OpenAIClient, OpenAIConfig

DEFAULT_MODEL = "deepseek-v4-flash"

BASE_URL = "https://api.deepseek.com"


@dataclass
class DeepSeekConfig(OpenAIConfig):
    model: str = DEFAULT_MODEL
    base_url: str | None = BASE_URL
    disable_thinking: bool = True


class DeepSeekClient(OpenAIClient):
    DEFAULT_MODEL = DEFAULT_MODEL

    def __init__(self, config: DeepSeekConfig | None = None):
        super().__init__(config or DeepSeekConfig())

    def _load_config(self) -> None:
        if not self._config.api_key:
            self._config.api_key = os.environ.get("DEEPSEEK_API_KEY", "")
        if not self._config.api_key:
            raise AuthError(
                "DEEPSEEK_API_KEY not set. Set the environment variable "
                "or pass api_key to DeepSeekConfig."
            )
        self._config.model = os.environ.get(
            "SENTRIX_LLM_MODEL", self._config.model
        )

    def _request_kwargs(
        self,
        model: str | None,
        max_tokens: int,
        temperature: float,
        messages: list[dict],
    ) -> dict[str, Any]:
        kwargs = super()._request_kwargs(model, max_tokens, temperature, messages)
        if self._config.disable_thinking:
            kwargs["extra_body"] = {
                "chat_template_kwargs": {"thinking": {"type": "disabled"}}
            }
        return kwargs

    def _build_response(self, response: Any, kwargs: dict[str, Any]) -> Any:
        message = response.choices[0].message
        text = message.content or ""
        if not text:
            reasoning = getattr(message, "reasoning_content", None)
            raise APIError(
                "Empty completion from deepseek-v4-flash: the model spent its "
                "max_tokens budget on hidden reasoning_content "
                f"(reasoning_content={reasoning!r}). Increase max_tokens."
            )
        from sentrix.dual_llm.base import LLMResponse

        return LLMResponse(
            text=text,
            model=getattr(response, "model", kwargs["model"]),
            usage={
                "input_tokens": getattr(response.usage, "prompt_tokens", 0),
                "output_tokens": getattr(response.usage, "completion_tokens", 0),
            },
            reasoning=getattr(message, "reasoning_content", None) or None,
        )
