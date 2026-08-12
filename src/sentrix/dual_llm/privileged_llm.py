from __future__ import annotations

from collections.abc import Callable

from sentrix.dual_llm.base import CallableLLMClient, LLMClient, LLMError
from sentrix.dual_llm.context_manager import ContextManager
from sentrix.models.events import LLMRole, Provenance, TraceEvent


class PrivilegedLLM:
    def __init__(
        self,
        context_manager: ContextManager,
        llm_client: LLMClient | Callable | None = None,
        model: str | None = None,
    ):
        self._ctx = context_manager
        if llm_client is not None and not isinstance(llm_client, LLMClient):
            if callable(llm_client):
                llm_client = CallableLLMClient(llm_client)
            else:
                raise TypeError(
                    f"llm_client must be an LLMClient or callable, got "
                    f"{type(llm_client).__name__}"
                )
        self._llm = llm_client
        self._model = model
        self._agent_id: str = ""

    @property
    def agent_id(self) -> str:
        return self._agent_id

    def configure(self, agent_id: str, system_prompt: str) -> None:
        self._agent_id = agent_id
        self._ctx.add_privileged_message(
            {"role": "system", "content": system_prompt}
        )

    def add_user_query(self, query: str, session_id: str) -> TraceEvent:
        self._ctx.add_privileged_message({"role": "user", "content": query})
        return TraceEvent(
            agent_id=self._agent_id,
            session_id=session_id,
            source_role=LLMRole.PRIVILEGED,
            provenance=Provenance.TRUSTED,
            content=query,
        )

    def _resolve_model(self) -> str | None:
        if self._model:
            return self._model
        default = getattr(self._llm, "DEFAULT_MODEL", None) if self._llm else None
        if default:
            return default
        return None

    def plan(self, session_id: str) -> str | None:
        if not self._llm:
            return None
        model = self._resolve_model()
        if model is None:
            raise LLMError(
                "No model specified: pass model= to PrivilegedLLM or use "
                "an LLMClient that defines DEFAULT_MODEL"
            )
        response = self._llm.generate(
            messages=self._ctx.privileged.messages,
            model=model,
            max_tokens=4096,
        )
        content = response.text
        self._ctx.add_privileged_message(
            {"role": "assistant", "content": content}
        )
        return content

    def record_tool_result(
        self, tool_name: str, result: str, provenance: Provenance, session_id: str
    ) -> TraceEvent:
        message = {
            "role": "user",
            "content": f"Tool '{tool_name}' returned: {result[:2000]}",
        }
        self._ctx.add_privileged_message(message)
        return TraceEvent(
            agent_id=self._agent_id,
            session_id=session_id,
            source_role=LLMRole.PRIVILEGED,
            provenance=provenance,
            tool_result=result[:2000],
        )
