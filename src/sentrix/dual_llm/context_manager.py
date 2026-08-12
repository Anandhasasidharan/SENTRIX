from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

from sentrix.models.events import Provenance


@dataclass(frozen=True)
class IsolatedContext:
    role: str
    messages: list[dict] = field(default_factory=list)
    provenance: Provenance = Provenance.TRUSTED
    allowed_tools: list[str] = field(default_factory=list)


class ContextIsolationError(RuntimeError):
    pass


class ContextManager:
    def __init__(self):
        self._privileged = IsolatedContext(
            role="privileged",
            provenance=Provenance.TRUSTED,
        )
        self._quarantined = IsolatedContext(
            role="quarantined",
            provenance=Provenance.UNTRUSTED,
            allowed_tools=[],
        )

    @property
    def privileged(self) -> IsolatedContext:
        return self._privileged

    @property
    def quarantined(self) -> IsolatedContext:
        return self._quarantined

    def add_privileged_message(self, message: dict) -> None:
        if message.get("role") == "tool":
            self._ensure_no_untrusted_data(message.get("content", ""))
        privileged = self._privileged
        object.__setattr__(privileged, "messages", [*privileged.messages, message])

    def add_quarantined_message(self, message: dict) -> None:
        quarantined = self._quarantined
        object.__setattr__(quarantined, "messages", [*quarantined.messages, message])

    def verify_isolation(self) -> bool:
        quarantined_tools = self._quarantined.allowed_tools
        if quarantined_tools:
            raise ContextIsolationError(
                f"Quarantined LLM has {len(quarantined_tools)} tool(s) configured — "
                "must have zero tool access"
            )
        return True

    def _ensure_no_untrusted_data(self, content: str) -> None:
        if not content:
            return
        quarantined_content = " ".join(
            m.get("content", "") for m in self._quarantined.messages
        )
        if not quarantined_content:
            return
        overlap = self._find_overlap(content, quarantined_content)
        if overlap:
            raise ContextIsolationError(
                f"Untrusted data leaked into privileged context: '{overlap[:100]}...'"
            )

    def _find_overlap(self, text_a: str, text_b: str) -> str:
        min_overlap = 20
        for i in range(len(text_a) - min_overlap + 1):
            chunk = text_a[i : i + min_overlap]
            if chunk in text_b:
                return chunk
        return ""
