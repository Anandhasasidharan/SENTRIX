from __future__ import annotations

from collections.abc import Callable

from sentrix.core.provenance_tracker import ProvenanceTracker, TaintLabel
from sentrix.dual_llm.context_manager import ContextManager
from sentrix.models.events import (
    ActionVerdict,
    DetectorLayer,
    Provenance,
    ToolCall,
    TraceEvent,
)
from sentrix.models.policy import AgentPolicy


class PolicyNotConfiguredError(Exception):
    """Raised when check_tool_call() is called before configure() for the agent."""


class ReferenceMonitor:
    def __init__(self, context_manager: ContextManager, use_rfc8707: bool = False):
        self._ctx = context_manager
        self._provenance = ProvenanceTracker(use_rfc8707=use_rfc8707)
        self._policy: AgentPolicy | None = None
        self._agent_id: str = ""
        self._on_block: Callable[[TraceEvent], None] | None = None

    def configure(
        self,
        agent_id: str,
        policy: AgentPolicy,
        on_block: Callable[[TraceEvent], None] | None = None,
    ) -> None:
        self._agent_id = agent_id
        self._policy = policy
        self._on_block = on_block

    @property
    def provenance(self) -> ProvenanceTracker:
        return self._provenance

    def tag_untrusted_data(self, data_id: str, source: str) -> None:
        self._provenance.tag(
            data_id,
            TaintLabel(
                provenance=Provenance.UNTRUSTED,
                sources=[source],
                sensitivity="confidential",
            ),
        )

    def tag_trusted_data(self, data_id: str, source: str) -> None:
        self._provenance.tag(
            data_id,
            TaintLabel(
                provenance=Provenance.TRUSTED,
                sources=[source],
                sensitivity="public",
            ),
        )

    def check_tool_call(        self, tool_name: str, arguments: dict, data_ids: list[str] | None = None, session_id: str = ""
    ) -> tuple[ActionVerdict, TraceEvent | None]:
        event = TraceEvent(
            agent_id=self._agent_id,
            session_id=session_id,
            tool_call=ToolCall(
                tool_name=tool_name,
                arguments=arguments,
                provenance=self._resolve_provenance(data_ids or []),
            ),
        )

        if not self._policy:
            raise PolicyNotConfiguredError(
                f"check_tool_call() called for agent '{self._agent_id}' but no policy has been configured. "
                f"Call monitor.configure(agent_id, policy) first."
            )

        allowed, reason = self._policy.check_tool(tool_name)
        if not allowed:
            event.verdict = ActionVerdict.BLOCKED
            event.blocked_by = DetectorLayer.REFERENCE_MONITOR
            event.metadata["block_reason"] = reason
            if self._on_block:
                self._on_block(event)
            return ActionVerdict.BLOCKED, event

        for data_id in data_ids or []:
            if self._provenance.is_untrusted(data_id):
                sensitivity = self._provenance.get_sensitivity(data_id)
                if not self._policy.check_data_sensitivity(sensitivity):
                    event.verdict = ActionVerdict.BLOCKED
                    event.blocked_by = DetectorLayer.REFERENCE_MONITOR
                    event.metadata["block_reason"] = (
                        f"Untrusted data '{data_id}' exceeds max sensitivity"
                    )
                    if self._on_block:
                        self._on_block(event)
                    return ActionVerdict.BLOCKED, event

        event.verdict = ActionVerdict.ALLOWED
        return ActionVerdict.ALLOWED, event

    def emit_blocked_event(self, event: TraceEvent) -> None:
        """Route a pre-built blocked event through the same on_block hook
        (timeline / DAG / stream / classifier scoring) that tool-call
        blocks use, so narrated-action denials surface identically."""
        event.verdict = ActionVerdict.BLOCKED
        event.blocked_by = DetectorLayer.REFERENCE_MONITOR
        if self._on_block:
            self._on_block(event)

    def _resolve_provenance(self, data_ids: list[str]) -> Provenance:
        if not data_ids:
            return Provenance.TRUSTED
        provs = [self._provenance.get(did).provenance for did in data_ids]
        if Provenance.UNTRUSTED in provs:
            return Provenance.UNTRUSTED
        if Provenance.DERIVED in provs:
            return Provenance.DERIVED
        return Provenance.TRUSTED
