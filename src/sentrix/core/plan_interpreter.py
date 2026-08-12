from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from sentrix.core.plan_consistency import detect_narrated_actions
from sentrix.core.reference_monitor import ReferenceMonitor
from sentrix.core.trace_stream import StreamEvent, TraceStream
from sentrix.dual_llm.context_manager import ContextManager
from sentrix.dual_llm.privileged_llm import PrivilegedLLM
from sentrix.dual_llm.quarantined_llm import QuarantinedLLM
from sentrix.models.events import (
    ActionVerdict,
    DetectorLayer,
    LLMRole,
    Provenance,
    ToolCall,
    TraceEvent,
)
from sentrix.models.policy import AgentPolicy


@dataclass
class PlanStep:
    step_number: int
    action: str
    tool: str
    arguments: dict[str, Any]
    data_refs: list[str] = field(default_factory=list)
    description: str = ""
    depends_on: list[int] = field(default_factory=list)
    status: str = "resolved"


@dataclass
class PlanResult:
    plan_text: str
    steps: list[PlanStep]
    session_id: str = ""
    agent_id: str = ""
    step_results: list[dict[str, Any]] = field(default_factory=list)
    all_allowed: bool = True
    blocked_steps: int = 0
    narrated_unmediated_actions: list[str] = field(default_factory=list)
    narrated_with_mediation: list[str] = field(default_factory=list)
    unresolved_steps: list[dict[str, Any]] = field(default_factory=list)


class PlanInterpreter:
    def __init__(
        self,
        privileged: PrivilegedLLM,
        quarantined: QuarantinedLLM,
        monitor: ReferenceMonitor,
        ctx: ContextManager,
        trace_stream: TraceStream | None = None,
        tool_executor: Callable[[str, dict[str, Any]], str] | None = None,
    ):
        self._privileged = privileged
        self._quarantined = quarantined
        self._monitor = monitor
        self._ctx = ctx
        self._trace_stream = trace_stream
        self._tool_executor = tool_executor or self._default_executor
        self._agent_id = ""
        self._policy: AgentPolicy | None = None

    def configure(self, agent_id: str, policy: AgentPolicy | None = None) -> None:
        self._agent_id = agent_id
        self._policy = policy

    def interpret(self, plan_text: str, session_id: str = "") -> PlanResult:
        steps = self._parse_plan(plan_text)
        result = PlanResult(
            plan_text=plan_text,
            steps=steps,
            session_id=session_id,
            agent_id=self._agent_id,
        )

        step_outputs: dict[int, str] = {}
        completed_steps: set[int] = set()

        for step in steps:
            if step.status == "unresolved":
                result.unresolved_steps.append(
                    {
                        "step": step.step_number,
                        "phrase": step.tool,
                        "verdict": "unresolved",
                        "reason": "Tool reference could not be confidently mapped "
                        "to a tool in the active policy",
                    }
                )
                continue
            unresolved_deps = [d for d in step.depends_on if d not in completed_steps]
            if unresolved_deps:
                continue

            data_ids = self._resolve_data_refs(step, step_outputs)
            verdict, event = self._monitor.check_tool_call(
                step.tool, step.arguments, data_ids, session_id=session_id
            )

            step_info = {
                "step": step.step_number,
                "tool": step.tool,
                "arguments": step.arguments,
                "verdict": verdict.value,
            }

            if verdict == ActionVerdict.BLOCKED:
                result.all_allowed = False
                result.blocked_steps += 1
                step_info["block_reason"] = event.metadata.get("block_reason", "Unknown")
                step_info["output"] = None
                result.step_results.append(step_info)
                self._emit_stream_event(event, session_id)
                continue

            if verdict == ActionVerdict.FLAGGED:
                result.all_allowed = False
                step_info["verdict"] = "flagged"

            try:
                output = self._tool_executor(step.tool, step.arguments)
            except Exception as ex:
                output = f"<error: {ex}>"

            step_outputs[step.step_number] = output
            completed_steps.add(step.step_number)
            step_info["output"] = output[:500]

            tool_provenance = self._resolve_output_provenance(data_ids)
            self._privileged.record_tool_result(
                step.tool, output, tool_provenance, session_id
            )

            self._emit_stream_event(event, session_id)
            result.step_results.append(step_info)

        mediated_tools = [
            s["tool"] for s in result.step_results
            if s.get("verdict") in ("allowed", "flagged", "blocked")
        ]
        unmediated, with_mediation = detect_narrated_actions(
            plan_text, mediated_tools
        )
        if unmediated:
            phrases = [f["phrase"] for f in unmediated]
            result.narrated_unmediated_actions = phrases
            result.all_allowed = False
            event = TraceEvent(
                agent_id=self._agent_id,
                session_id=session_id,
                source_role=LLMRole.PRIVILEGED,
                provenance=Provenance.TRUSTED,
                content=plan_text[:1000],
                tool_call=ToolCall(
                    tool_name="narrated_action",
                    arguments={"phrases": phrases},
                    provenance=Provenance.TRUSTED,
                ),
                verdict=ActionVerdict.BLOCKED,
                blocked_by=DetectorLayer.REFERENCE_MONITOR,
                metadata={
                    "block_reason": "Plan narrates completion without a backing tool call",
                    "narrated_actions": phrases,
                    "mediated_tools": mediated_tools,
                },
            )
            self._monitor.emit_blocked_event(event)
            self._emit_stream_event(event, session_id)

        if with_mediation:
            result.narrated_with_mediation = [
                f["phrase"] for f in with_mediation
            ]
            event = TraceEvent(
                agent_id=self._agent_id,
                session_id=session_id,
                source_role=LLMRole.PRIVILEGED,
                provenance=Provenance.TRUSTED,
                content=plan_text[:1000],
                tool_call=ToolCall(
                    tool_name="narrated_with_mediation",
                    arguments={"phrases": result.narrated_with_mediation},
                    provenance=Provenance.TRUSTED,
                ),
                verdict=ActionVerdict.FLAGGED,
                metadata={
                    "block_reason": "Plan narrates tool usage alongside mediated calls (informational)",
                    "narrated_actions": result.narrated_with_mediation,
                    "mediated_tools": mediated_tools,
                },
            )
            self._emit_stream_event(event, session_id)

        return result

    def _parse_plan(self, plan_text: str) -> list[PlanStep]:
        plan_text = self._clean_markup(plan_text)
        steps: list[PlanStep] = []
        seen_steps: set[int] = set()

        json_blocks = re.findall(
            r'```(?:json)?\s*(\{.*?\}|\[.*?\])\s*```', plan_text, re.DOTALL
        )
        for block in json_blocks:
            try:
                parsed = json.loads(block)
                if isinstance(parsed, dict):
                    parsed = [parsed]
                for item in parsed:
                    step = self._parse_step_from_dict(item, steps)
                    if step and step.step_number not in seen_steps:
                        seen_steps.add(step.step_number)
                        steps.append(step)
            except (json.JSONDecodeError, ValueError):
                pass

        if not steps:
            steps = self._parse_plan_textual(plan_text)

        return sorted(steps, key=lambda s: s.step_number)

    def _parse_step_from_dict(self, item: dict, existing: list[PlanStep]) -> PlanStep | None:
        if "tool" not in item:
            return None
        step_number = item.get("step", len(existing) + 1)
        return PlanStep(
            step_number=step_number,
            action=item.get("action", "call"),
            tool=item["tool"],
            arguments=item.get("arguments", {}),
            data_refs=item.get("data_refs", item.get("data_ids", [])),
            description=item.get("description", ""),
            depends_on=item.get("depends_on", []),
        )

    TOOL_PATTERN = re.compile(
        r'(?:step\s*#?(\d+)[:\s]*)?'
        r'\b(use|call|invoke|run|execute)\s+`?(\w+)`?'
        r'(?:\s*(?:with|using)\s+arguments?\s*[:\s]*'
        r'(\{.*?\}|\[.*?\]))?',
        re.IGNORECASE,
    )

    ARG_PATTERN = re.compile(
        r'(?:(\w+)\s*[=:]\s*'
        r'(?:"([^"]*)"|\'([^\']*)\'|`([^`]*)`|(\{[^}]*\})|(\S+)))'
    )

    # XML-style tool-call markup: <invoke name="exec_command">...</invoke>,
    # <tool name="X">, <tool_call name="X">, <call name="X">.
    XML_INVOKE_PATTERN = re.compile(
        r'<\s*(?:invoke|tool_call|tool|call)\s+name=["\']([\w.:\-]+)["\'][^>]*>',
        re.IGNORECASE,
    )

    XML_PARAM_PATTERN = re.compile(
        r'<\s*parameter(?:\s+name=["\']([\w.:\-]+)["\'])?\s*>\s*(.*?)\s*<\s*/\s*parameter\s*>',
        re.IGNORECASE | re.DOTALL,
    )

    XML_TAG_STRIP = re.compile(r'<[^>]+>')

    # Backticked literal tool identifiers, e.g. `exec_command`, `list_dir`.
    LITERAL_TOOL_PATTERN = re.compile(r'`([a-z_][a-z0-9_\-]*)`', re.IGNORECASE)

    # Words that follow a verb in prose without naming a tool.
    ARTICLE_WORDS = {
        "the", "a", "an", "this", "that", "it", "its", "your", "their", "our",
        "with", "for", "and", "or", "on", "to", "of", "via", "using", "by",
        "from", "in", "at", "us", "you",
    }

    # "run" as a noun, not a verb: preceded by a determiner/adjective marker.
    NOUN_RUN_PATTERN = re.compile(
        r'\b(a|an|the|scheduled|test|first|next|dry|trial|practice|daily|weekly|'
        r'full|quick|slow|per|each|every)\s+\w{1,4}\s*$',
        re.IGNORECASE,
    )

    # Descriptive tool references -> canonical tool names. Resolution is
    # only active for tools present in the configured policy, so the table
    # stays generic while activation stays policy-driven.
    DESCRIPTIVE_ALIASES = {
        "directory listing": "list_dir",
        "list directory": "list_dir",
        "list directories": "list_dir",
        "list the directory": "list_dir",
        "list files": "list_dir",
        "list the files": "list_dir",
        "list all files": "list_dir",
        "directory listing tool": "list_dir",
        "read file": "read_file",
        "read the file": "read_file",
        "read files": "read_file",
        "read a file": "read_file",
        "read the readme": "read_file",
        "read the document": "read_file",
        "read the report": "read_file",
        "file reading": "read_file",
        "send email": "send_email",
        "send an email": "send_email",
        "send the email": "send_email",
        "send emails": "send_email",
        "search the web": "search_web",
        "search web": "search_web",
        "searching the web": "search_web",
        "search the internet": "search_web",
        "web search": "search_web",
        "store memory": "store_memory",
        "store a memory": "store_memory",
        "save to memory": "store_memory",
        "run command": "exec_command",
        "run the command": "exec_command",
        "run commands": "exec_command",
        "run a command": "exec_command",
        "run the script": "exec_command",
        "run a script": "exec_command",
        "run a cleanup script": "exec_command",
        "run the following": "exec_command",
        "execute command": "exec_command",
        "execute the command": "exec_command",
        "execute commands": "exec_command",
        "execute a script": "exec_command",
        "execute the script": "exec_command",
        "shell command": "exec_command",
        "shell commands": "exec_command",
        "command line": "exec_command",
        "delete file": "delete_file",
        "delete the file": "delete_file",
        "delete files": "delete_file",
        "delete the files": "delete_file",
        "delete a file": "delete_file",
        "delete all files": "delete_file",
        "remove the file": "delete_file",
        "remove files": "delete_file",
        "modify system": "modify_system",
        "modify the system": "modify_system",
        "change system": "modify_system",
        "change the system": "modify_system",
        "system settings": "modify_system",
        "system configuration": "modify_system",
        "update the system": "modify_system",
    }

    _ARG_KEY_PATTERN = re.compile(r'^[a-z_][a-z0-9_]*$')

    # Markup noise the model emits around tool-call blocks. DeepSeek's
    # terminal-tuned output styles XML with ANSI SGR codes inside tags
    # (<\x1b[1minvoke ...>) and sometimes wraps tags in ||DSML|| markers
    # written with fullwidth pipe characters. Normalize before matching.
    ANSI_STRIP = re.compile("\u001b\\[[0-9;]*[A-Za-z]")
    DSML_WRAP_PATTERN = re.compile(r"\|{1,2}\s*DSML\s*\|{1,2}")
    _FULLWIDTH_TABLE = {
        i: i - 0xFEE0 for i in range(0xFF01, 0xFF5F)
    }

    DATA_REF_PATTERN = re.compile(
        r'data[_\s]*(?:id|ref|from)\s*[=:]\s*["\']?([\w_:]+)["\']?'
    )

    def _policy_tools(self) -> set[str]:
        if self._policy:
            return {
                t.lower()
                for t in [*self._policy.allowed_tools, *self._policy.blocked_tools]
            }
        return set(self.DESCRIPTIVE_ALIASES.values())

    def _alias_lookup(self, window: str) -> str | None:
        """Resolve a phrase window to a policy-active tool via aliases."""
        tools = self._policy_tools()
        lowered = window.lower()
        for phrase, tool in self.DESCRIPTIVE_ALIASES.items():
            if tool not in tools:
                continue
            if phrase in lowered:
                return tool
        return None

    def _is_noun_run(self, plan_text: str, match: re.Match) -> bool:
        """True when 'run' is a plain noun (e.g. 'the scheduled run date')."""
        preceding = plan_text[: match.start() + len(match.group(2))]
        return bool(self.NOUN_RUN_PATTERN.search(preceding))

    def _extract_xml_params(self, plan_text: str, start: int) -> dict[str, Any]:
        segment = plan_text[start : start + 600]
        params: dict[str, Any] = {}
        positional: list[str] = []
        for name, value in self.XML_PARAM_PATTERN.findall(segment):
            value = self.XML_TAG_STRIP.sub("", value).strip()
            if name:
                params[name] = value
            else:
                positional.append(value)
        if positional and not params:
            return {"args": positional}
        return params

    def _resolve_tool_reference(
        self, verb: str, word: str, plan_text: str, match: re.Match
    ) -> tuple[str, str, str]:
        """Return (tool, status, display) for a TOOL_PATTERN match."""
        policy_tools = self._policy_tools()
        w = word.lower()

        if w in policy_tools:
            return word, "resolved", word

        backticked = bool(plan_text[match.start() : match.end()].count("`"))
        if backticked and re.match(r"^[a-z_][a-z0-9_\-]*$", word):
            return word, "resolved", word

        after = plan_text[match.end() : match.end() + 60]
        tokens = re.findall(r"[a-z0-9]+", after, re.IGNORECASE)

        if w in self.ARTICLE_WORDS:
            literal = self.LITERAL_TOOL_PATTERN.search(after)
            if literal:
                return literal.group(1), "resolved", literal.group(1)
            for width in (6, 5, 4, 3, 2, 1):
                if not tokens[:width]:
                    continue
                tool = self._alias_lookup(" ".join([verb, word, *tokens[:width]]))
                if tool:
                    return tool, "resolved", tool
            display = " ".join([verb, word, *tokens[:4]])
            return display.strip(), "unresolved", display.strip()

        tool = self._alias_lookup(" ".join([verb, word, *tokens[:4]]))
        if tool:
            return tool, "resolved", tool
        return " ".join([verb, word]), "unresolved", " ".join([verb, word])

    def _clean_markup(self, plan_text: str) -> str:
        """Normalize markup noise the model emits around tool-call blocks."""
        plan_text = self.ANSI_STRIP.sub("", plan_text)
        plan_text = plan_text.translate(self._FULLWIDTH_TABLE)
        plan_text = self.DSML_WRAP_PATTERN.sub("", plan_text)
        return plan_text

    def _parse_plan_textual(self, plan_text: str) -> list[PlanStep]:
        plan_text = self._clean_markup(plan_text)
        candidates: list[tuple[int, str, str, dict[str, Any], str]] = []

        for m in self.XML_INVOKE_PATTERN.finditer(plan_text):
            tool = m.group(1)
            args = self._extract_xml_params(plan_text, m.end())
            candidates.append((m.start(), "xml", tool, args, "resolved"))

        for m in self.TOOL_PATTERN.finditer(plan_text):
            verb = m.group(2)
            word = m.group(3)
            if verb and verb.lower() == "run" and self._is_noun_run(plan_text, m):
                continue
            tool, status, display = self._resolve_tool_reference(
                verb, word, plan_text, m
            )
            args: dict[str, Any] = {}
            if status == "resolved" and m.group(4):
                try:
                    args = json.loads(m.group(4))
                except (json.JSONDecodeError, ValueError):
                    args = {}
            elif status == "resolved":
                line_start = plan_text.rfind("\n", 0, m.start()) + 1
                line_end = plan_text.find("\n", m.end())
                if line_end == -1:
                    line_end = len(plan_text)
                window = plan_text[line_start:line_end]
                for arg_match in self.ARG_PATTERN.finditer(window):
                    key = arg_match.group(1)
                    if not self._ARG_KEY_PATTERN.match(key):
                        continue
                    value = (
                        arg_match.group(2)
                        or arg_match.group(3)
                        or arg_match.group(4)
                        or arg_match.group(5)
                        or arg_match.group(6)
                    )
                    args[key] = value
            candidates.append((m.start(), "tool", tool, args, status))

        for m in self.LITERAL_TOOL_PATTERN.finditer(plan_text):
            tool = m.group(1)
            candidates.append((m.start(), "literal", tool, {}, "resolved"))

        normalized = plan_text.lower().replace("’", "'")
        for phrase, tool in self.DESCRIPTIVE_ALIASES.items():
            if tool not in self._policy_tools():
                continue
            start = 0
            while True:
                idx = normalized.find(phrase, start)
                if idx == -1:
                    break
                candidates.append((idx, "alias", tool, {}, "resolved"))
                start = idx + len(phrase)
        candidates.sort(key=lambda c: (c[0], {"xml": 0, "tool": 1, "literal": 2, "alias": 3}[c[1]]))

        steps: list[PlanStep] = []
        seen: set[tuple[str, str]] = set()
        last_end = -1
        counter = 0
        data_refs = list(
            dict.fromkeys(self.DATA_REF_PATTERN.findall(plan_text))
        )
        for pos, kind, tool, args, status in candidates:
            if pos < last_end:
                continue
            if (tool, status) in seen:
                continue
            seen.add((tool, status))
            last_end = pos + max(len(tool), 1)
            counter += 1
            steps.append(PlanStep(
                step_number=counter,
                action="call" if status == "resolved" else "reference",
                tool=tool,
                arguments=args,
                data_refs=data_refs if status == "resolved" else [],
                description=f"Call {tool}" if status == "resolved" else tool,
                status=status,
            ))

        return steps

    def _resolve_data_refs(
        self, step: PlanStep, outputs: dict[int, str]
    ) -> list[str]:
        data_ids: list[str] = []
        for dep in step.depends_on:
            if dep in outputs:
                data_ids.append(f"plan:step_{dep}")
        for ref in step.data_refs:
            data_ids.append(ref)
        return data_ids

    def _resolve_output_provenance(self, data_ids: list[str]) -> Provenance:
        if not data_ids:
            return Provenance.TRUSTED
        tracker = self._monitor.provenance
        provs = [tracker.get(did).provenance for did in data_ids]
        if Provenance.UNTRUSTED in provs:
            return Provenance.DERIVED
        if Provenance.DERIVED in provs:
            return Provenance.DERIVED
        return Provenance.TRUSTED

    def _default_executor(self, tool: str, args: dict[str, Any]) -> str:
        return f"<simulated result for {tool}({args})>"

    def _emit_stream_event(self, event: TraceEvent, session_id: str = "") -> None:
        if self._trace_stream:
            self._trace_stream.publish(StreamEvent(
                event=event,
                session_id=session_id,
                agent_id=self._agent_id,
                metadata={"interpreter": "plan"},
            ))
