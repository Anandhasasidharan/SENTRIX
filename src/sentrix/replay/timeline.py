from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone

from sentrix.models.events import ActionVerdict, AttackDAGNode, DetectorLayer, TraceEvent


class Timeline:
    def __init__(self):
        self._events: list[TraceEvent] = []
        self._agent_colors: dict[str, str] = {}
        self._color_palette = [
            "#4A90D9", "#E57373", "#81C784", "#FFB74D", "#BA68C8",
            "#4DB6AC", "#FF8A65", "#A1887F", "#90A4AE", "#F06292",
        ]
        self._next_color = 0

    def add_event(self, event: TraceEvent) -> None:
        self._events.append(event)
        if event.agent_id and event.agent_id not in self._agent_colors:
            self._agent_colors[event.agent_id] = self._color_palette[
                self._next_color % len(self._color_palette)
            ]
            self._next_color += 1

    def get_events(
        self,
        session_id: str | None = None,
        agent_id: str | None = None,
        limit: int = 1000,
    ) -> list[TraceEvent]:
        events = self._events
        if session_id:
            events = [e for e in events if e.session_id == session_id]
        if agent_id:
            events = [e for e in events if e.agent_id == agent_id]
        return sorted(events, key=lambda e: e.timestamp)[:limit]

    def get_event_count(self, session_id: str | None = None) -> int:
        if session_id:
            return sum(1 for e in self._events if e.session_id == session_id)
        return len(self._events)

    def render_text_timeline(self, session_id: str, max_events: int = 50) -> str:
        events = self.get_events(session_id=session_id, limit=max_events)
        lines = []
        lines.append(f"=== Sentrix Session Timeline: {session_id} ===\n")
        for i, event in enumerate(events):
            ts = event.timestamp.strftime("%H:%M:%S.%f")[:12]
            agent = event.agent_id[:20]
            role = event.source_role.value if event.source_role else "?"
            verdict = event.verdict.value if event.verdict else "info"
            marker = {
                ActionVerdict.ALLOWED: "ALLOW",
                ActionVerdict.BLOCKED: "BLOCK",
                ActionVerdict.FLAGGED: "FLAG",
            }.get(event.verdict, "INFO")

            if event.tool_call:
                detail = f"tool_call: {event.tool_call.tool_name}({dict(list(event.tool_call.arguments.items())[:2])})"
            elif event.content:
                detail = f"content: {event.content[:80]}..."
            elif event.tool_result:
                detail = f"tool_result: {event.tool_result[:80]}..."
            else:
                detail = "(no content)"

            blocked = ""
            if event.blocked_by:
                blocked = f" [blocked_by: {event.blocked_by.value}]"

            lines.append(
                f"[{ts}] {marker:6s} | {agent:20s} | {role:12s} | {detail}{blocked}"
            )
        return "\n".join(lines)


class AttackDAGBuilder:
    def __init__(self):
        self._dag: dict[str, AttackDAGNode] = {}

    def add_event(self, event: TraceEvent) -> AttackDAGNode:
        node = AttackDAGNode(
            event_id=event.id,
            agent_id=event.agent_id,
            tool_name=event.tool_call.tool_name if event.tool_call else None,
            verdict=event.verdict,
            blocked_by=event.blocked_by,
            parent_id=event.parent_event_id,
        )
        self._dag[event.id] = node

        if event.parent_event_id and event.parent_event_id in self._dag:
            parent = self._dag[event.parent_event_id]
            parent.children.append(node)

        return node

    def build_dag(self, session_id: str, timeline: Timeline) -> AttackDAGNode | None:
        events = timeline.get_events(session_id=session_id)
        root_events = []
        for event in events:
            node = self.add_event(event)
            if not event.parent_event_id:
                root_events.append(node)

        if not root_events:
            return None

        root = AttackDAGNode(
            event_id="root",
            agent_id="system",
            tool_name=None,
            verdict=None,
            blocked_by=None,
            children=root_events,
        )
        return root

    def render_ascii_dag(self, dag: AttackDAGNode, indent: str = "") -> str:
        lines = []
        marker = {
            ActionVerdict.ALLOWED: "✓",
            ActionVerdict.BLOCKED: "✗",
            ActionVerdict.FLAGGED: "⚠",
        }.get(dag.verdict, "○")

        tool_info = f" [{dag.tool_name}]" if dag.tool_name else ""
        blocked = f" (blocked_by: {dag.blocked_by.value})" if dag.blocked_by else ""
        lines.append(f"{indent}{marker} {dag.agent_id}{tool_info}{blocked}")

        for child in dag.children:
            lines.append(self.render_ascii_dag(child, indent + "  │"))
        return "\n".join(lines)

    def summary(self, session_id: str, timeline: Timeline) -> dict:
        dag = self.build_dag(session_id, timeline)
        events = timeline.get_events(session_id=session_id)
        total = len(events)
        blocked = sum(1 for e in events if e.verdict == ActionVerdict.BLOCKED)
        allowed = sum(1 for e in events if e.verdict == ActionVerdict.ALLOWED)
        flagged = sum(1 for e in events if e.verdict == ActionVerdict.FLAGGED)

        by_layer = defaultdict(list)
        for e in events:
            if e.blocked_by:
                by_layer[e.blocked_by].append(e)

        return {
            "session_id": session_id,
            "total_events": total,
            "allowed": allowed,
            "blocked": blocked,
            "flagged": flagged,
            "blocked_by_layer": {
                k.value: len(v) for k, v in by_layer.items()
            },
            "dag": self.render_ascii_dag(dag) if dag else "(empty)",
        }
