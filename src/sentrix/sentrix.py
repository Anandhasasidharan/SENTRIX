from __future__ import annotations

import logging
import os
from collections.abc import Callable
from typing import Any

from sentrix.classifier.detector import Classifier
from sentrix.core.plan_interpreter import PlanInterpreter
from sentrix.core.reference_monitor import ReferenceMonitor
from sentrix.core.trace_stream import StreamCollector, TraceStream
from sentrix.dual_llm.base import CallableLLMClient, LLMClient
from sentrix.dual_llm.context_manager import ContextManager
from sentrix.dual_llm.privileged_llm import PrivilegedLLM
from sentrix.dual_llm.quarantined_llm import QuarantinedLLM
from sentrix.models.events import (
    ActionVerdict, DetectorLayer, LLMRole, Provenance, ToolCall, TraceEvent,
)
from sentrix.models.policy import AgentPolicy
from sentrix.replay.timeline import AttackDAGBuilder, Timeline
from sentrix.reporting.report_generator import ReportGenerator
from sentrix.static_analysis.taint_tracker import TaintTracker

logger = logging.getLogger(__name__)


class Sentrix:
    def __init__(
        self,
        llm_client: LLMClient | Callable | None = None,
        api_key: str | None = None,
        provider: str = "auto",
        classifier_threshold: float = 0.5,
        use_embeddings: bool = True,
        trace_stream: TraceStream | None = None,
        use_rfc8707: bool = False,
    ):
        self._ctx = ContextManager()
        self._monitor = ReferenceMonitor(self._ctx, use_rfc8707=use_rfc8707)
        self._llm_client = self._resolve_llm_client(llm_client, api_key, provider)
        self._privileged = PrivilegedLLM(self._ctx, self._llm_client)
        self._quarantined = QuarantinedLLM(self._ctx, self._llm_client)
        self._classifier = Classifier(
            threshold=classifier_threshold,
            use_embeddings=use_embeddings,
        )
        self._timeline = Timeline()
        self._dag_builder = AttackDAGBuilder()
        self._reporter = ReportGenerator(self._timeline, self._dag_builder)
        self._taint = TaintTracker()
        self._agent_id: str = ""
        self._trace_stream = trace_stream or TraceStream()
        self._stream_collector = StreamCollector(self._trace_stream)
        self._plan_interpreter = PlanInterpreter(
            self._privileged, self._quarantined, self._monitor,
            self._ctx, self._trace_stream,
        )

    @property
    def use_rfc8707(self) -> bool:
        return self._monitor.provenance.use_rfc8707

    def _resolve_llm_client(
        self,
        llm_client: LLMClient | Callable | None,
        api_key: str | None,
        provider: str = "auto",
    ) -> LLMClient | None:
        if llm_client is not None:
            if isinstance(llm_client, LLMClient):
                return llm_client
            if callable(llm_client):
                logger.info(
                    "Wrapping callable llm_client in CallableLLMClient adapter"
                )
                return CallableLLMClient(llm_client)
            raise TypeError(
                f"llm_client must be an LLMClient instance or a callable, "
                f"got {type(llm_client).__name__}"
            )

        provider = (provider or "auto").lower()
        if provider == "auto":
            if api_key or os.environ.get("ANTHROPIC_API_KEY"):
                provider = "anthropic"
            elif os.environ.get("OPENAI_API_KEY"):
                provider = "openai"
            elif os.environ.get("DEEPSEEK_API_KEY"):
                provider = "deepseek"
            else:
                logger.info(
                    "No LLM provider configured (no ANTHROPIC_API_KEY / "
                    "OPENAI_API_KEY / DEEPSEEK_API_KEY set) — running in "
                    "offline mode. LLM calls will return None. Set a "
                    "provider API key for full dual-LLM functionality."
                )
                return None

        try:
            if provider == "anthropic":
                from sentrix.dual_llm.anthropic_client import AnthropicClient, LLMConfig
                client = AnthropicClient(LLMConfig(api_key=api_key or ""))
                logger.info("Connected to Anthropic API (model: %s)", client.DEFAULT_MODEL)
                return client
            if provider == "openai":
                from sentrix.dual_llm.openai_client import OpenAIClient, OpenAIConfig
                client = OpenAIClient(OpenAIConfig(api_key=api_key or ""))
                logger.info(
                    "Connected to OpenAI-compatible API (model: %s)", client.DEFAULT_MODEL
                )
                return client
            if provider == "deepseek":
                from sentrix.dual_llm.deepseek_client import DeepSeekClient, DeepSeekConfig
                client = DeepSeekClient(DeepSeekConfig(api_key=api_key or ""))
                logger.info("Connected to DeepSeek API (model: %s)", client.DEFAULT_MODEL)
                return client
            logger.warning(
                "Unknown LLM provider %r — running in offline mode.", provider
            )
            return None
        except Exception as e:
            logger.warning("Failed to initialize %s client: %s", provider, e)
            return None

    @property
    def monitor(self) -> ReferenceMonitor:
        return self._monitor

    @property
    def classifier(self) -> Classifier:
        return self._classifier

    @property
    def timeline(self) -> Timeline:
        return self._timeline

    @property
    def privileged(self) -> PrivilegedLLM:
        return self._privileged

    @property
    def quarantined(self) -> QuarantinedLLM:
        return self._quarantined

    @property
    def trace_stream(self) -> TraceStream:
        return self._trace_stream

    @property
    def plan_interpreter(self) -> PlanInterpreter:
        return self._plan_interpreter

    @property
    def agent_id(self) -> str:
        return self._agent_id

    def _publish_to_stream(self, event: TraceEvent, session_id: str = "") -> None:
        self._stream_collector.emit(
            event, session_id, self._agent_id,
            metadata={"session_id": session_id},
        )

    def configure_agent(
        self,
        agent_id: str,
        policy: AgentPolicy,
        system_prompt: str = "",
    ) -> None:
        self._agent_id = agent_id

        self._ctx.verify_isolation()
        self._privileged.configure(agent_id, system_prompt)
        self._quarantined.configure(agent_id)
        self._monitor.configure(agent_id, policy, on_block=self._on_block)
        self._plan_interpreter.configure(agent_id, policy)

    def process_user_query(self, query: str, session_id: str = "") -> TraceEvent:
        classifier_result = self._classifier.analyze_query(query)
        event = self._privileged.add_user_query(query, session_id)
        event.classifier_score = classifier_result.composite_score
        if classifier_result.triggered:
            event.verdict = ActionVerdict.FLAGGED
            event.blocked_by = DetectorLayer.CLASSIFIER
        self._timeline.add_event(event)
        self._dag_builder.add_event(event)
        self._publish_to_stream(event, session_id)
        return event

    def process_untrusted_content(
        self, content: str, source_label: str, session_id: str = ""
    ) -> TraceEvent:
        data_id = f"untrusted:{source_label}:{id(content)}"
        self._monitor.tag_untrusted_data(data_id, source_label)

        event = self._quarantined.process_untrusted(
            content, source_label, session_id
        )

        classifier_result = self._classifier.analyze_query(content)
        event.classifier_score = classifier_result.composite_score
        if classifier_result.triggered:
            event.verdict = ActionVerdict.FLAGGED
            event.blocked_by = DetectorLayer.CLASSIFIER

        self._timeline.add_event(event)
        self._dag_builder.add_event(event)
        self._publish_to_stream(event, session_id)
        return event

    def check_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        data_ids: list[str] | None = None,
        session_id: str = "",
    ) -> tuple[ActionVerdict, TraceEvent]:
        verdict, event = self._monitor.check_tool_call(
            tool_name, arguments, data_ids, session_id=session_id
        )

        classifier_result = self._classifier.analyze_tool_call(
            tool_name, str(arguments)
        )
        event.classifier_score = classifier_result.composite_score

        if verdict == ActionVerdict.ALLOWED and classifier_result.triggered:
            event.verdict = ActionVerdict.FLAGGED
            event.blocked_by = DetectorLayer.CLASSIFIER
            verdict = ActionVerdict.FLAGGED

        self._timeline.add_event(event)
        self._dag_builder.add_event(event)
        self._publish_to_stream(event, session_id)
        return verdict, event

    def _on_block(self, event: TraceEvent) -> None:
        classifier_result = self._classifier.analyze_query(
            str(event.tool_call) if event.tool_call else ""
        )
        event.classifier_score = classifier_result.composite_score

    def execute_plan(self, plan_text: str, session_id: str = "") -> Any:
        self._plan_interpreter.configure(self._agent_id)
        result = self._plan_interpreter.interpret(plan_text, session_id=session_id)
        for step_result in result.step_results:
            event_verdict = ActionVerdict.BLOCKED if step_result["verdict"] == "blocked" else (
                ActionVerdict.FLAGGED if step_result["verdict"] == "flagged" else ActionVerdict.ALLOWED
            )
            event = TraceEvent(
                agent_id=self._agent_id,
                session_id=session_id,
                tool_call=ToolCall(
                    tool_name=step_result["tool"],
                    arguments=step_result["arguments"],
                    provenance=Provenance.TRUSTED,
                ),
                verdict=event_verdict,
                blocked_by=DetectorLayer.REFERENCE_MONITOR if step_result["verdict"] == "blocked" else None,
                metadata={"plan_step": step_result.get("step", 0), "block_reason": step_result.get("block_reason", "")},
            )
            self._timeline.add_event(event)
            self._dag_builder.add_event(event)
            self._publish_to_stream(event, session_id)

        if result.narrated_unmediated_actions:
            event = TraceEvent(
                agent_id=self._agent_id,
                session_id=session_id,
                source_role=LLMRole.PRIVILEGED,
                tool_call=ToolCall(
                    tool_name="narrated_action",
                    arguments={"phrases": result.narrated_unmediated_actions},
                    provenance=Provenance.TRUSTED,
                ),
                verdict=ActionVerdict.BLOCKED,
                blocked_by=DetectorLayer.REFERENCE_MONITOR,
                metadata={
                    "block_reason": "Plan narrates completion without a backing tool call",
                    "narrated_actions": result.narrated_unmediated_actions,
                },
            )
            self._timeline.add_event(event)
            self._dag_builder.add_event(event)
            self._publish_to_stream(event, session_id)

        if result.narrated_with_mediation:
            event = TraceEvent(
                agent_id=self._agent_id,
                session_id=session_id,
                source_role=LLMRole.PRIVILEGED,
                tool_call=ToolCall(
                    tool_name="narrated_with_mediation",
                    arguments={"phrases": result.narrated_with_mediation},
                    provenance=Provenance.TRUSTED,
                ),
                verdict=ActionVerdict.FLAGGED,
                metadata={
                    "block_reason": "Plan narrates tool usage alongside mediated calls (informational)",
                    "narrated_actions": result.narrated_with_mediation,
                },
            )
            self._timeline.add_event(event)
            self._dag_builder.add_event(event)
            self._publish_to_stream(event, session_id)
        return result

    def scan_tool_code(self, path: str) -> list[Any]:
        return self._taint.scan_directory(path)

    def generate_report(self, session_id: str = "", taint_results: list[Any] | None = None) -> Any:
        return self._reporter.generate(session_id, taint_results=taint_results)

    def get_eval_summary(self, session_id: str = "") -> dict:
        return self._dag_builder.summary(session_id, self._timeline)
