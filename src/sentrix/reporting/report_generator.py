from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from sentrix.models.events import (
    ActionVerdict,
    AttackDAGNode,
    DetectorLayer,
    IncidentReport,
    TraceEvent,
)
from sentrix.replay.timeline import AttackDAGBuilder, Timeline


class ReportGenerator:
    def __init__(self, timeline: Timeline, dag_builder: AttackDAGBuilder):
        self._timeline = timeline
        self._dag_builder = dag_builder

    def generate(
        self,
        session_id: str,
        root_cause: str | None = None,
        taint_results: list[Any] | None = None,
    ) -> IncidentReport:
        events = self._timeline.get_events(session_id=session_id)
        dag = self._dag_builder.build_dag(session_id, self._timeline)

        affected_agents = list(set(e.agent_id for e in events))
        affected_tools = list(
            set(
                e.tool_call.tool_name
                for e in events
                if e.tool_call and e.verdict in (ActionVerdict.BLOCKED, ActionVerdict.FLAGGED)
            )
        )
        affected_data = list(
            set(
                e.metadata.get("affected_data", "")
                for e in events
                if e.metadata.get("affected_data")
            )
        )

        blast_radius = self._assess_blast_radius(events)
        recommendations = self._generate_recommendations(events)
        recommendations = self._add_taint_recommendations(recommendations, taint_results)

        verdicts_by_layer: dict[DetectorLayer, list[ActionVerdict]] = defaultdict(list)
        for e in events:
            if e.blocked_by:
                if e.verdict:
                    verdicts_by_layer[e.blocked_by].append(e.verdict)

        return IncidentReport(
            session_id=session_id,
            root_cause=root_cause or self._infer_root_cause(events),
            affected_agents=affected_agents,
            affected_tools=affected_tools,
            affected_data=affected_data or ["(not tracked)"],
            blast_radius=blast_radius,
            timeline=events,
            attack_dag=dag or AttackDAGNode(event_id="empty", agent_id="none"),
            verdicts_by_layer=dict(verdicts_by_layer),
            recommendations=recommendations,
        )

    def _infer_root_cause(self, events: list[TraceEvent]) -> str:
        blocked = [e for e in events if e.verdict == ActionVerdict.BLOCKED]
        if not blocked:
            first = events[0] if events else None
            if first and first.content:
                return f"Initial query detected as potentially malicious: '{first.content[:100]}...'"
            return "Unknown — no blocked events recorded"

        root = blocked[0]
        if root.metadata.get("block_reason"):
            return f"Blocked by {root.blocked_by.value}: {root.metadata['block_reason']}"
        return f"Blocked by {root.blocked_by.value} — tool call to '{root.tool_call.tool_name if root.tool_call else 'unknown'}'"

    def _assess_blast_radius(self, events: list[TraceEvent]) -> str:
        blocked = sum(1 for e in events if e.verdict == ActionVerdict.BLOCKED)
        flagged = sum(1 for e in events if e.verdict == ActionVerdict.FLAGGED)
        allowed = sum(1 for e in events if e.verdict == ActionVerdict.ALLOWED)

        parts = []
        if blocked:
            parts.append(f"{blocked} tool call(s) blocked")
        if flagged:
            parts.append(f"{flagged} event(s) flagged")
        if allowed:
            parts.append(f"{allowed} event(s) allowed (may include benign operations)")

        agent_count = len(set(e.agent_id for e in events))
        parts.append(f"{agent_count} agent(s) involved")

        return ". ".join(parts) + "."

    def _generate_recommendations(self, events: list[TraceEvent]) -> list[str]:
        recs = []
        blocked_events = [e for e in events if e.verdict == ActionVerdict.BLOCKED]
        by_layer = defaultdict(list)
        for e in blocked_events:
            if e.blocked_by:
                by_layer[e.blocked_by].append(e)

        if DetectorLayer.REFERENCE_MONITOR in by_layer:
            recs.append(
                "Review and tighten capability policies for affected agents. "
                "Consider restricting tool access further or adding provenance requirements."
            )
        if DetectorLayer.CLASSIFIER in by_layer:
            recs.append(
                "Classifier layer caught events missed by the reference monitor. "
                "Review classifier rules and consider promoting patterns to the monitor policy."
            )
        if DetectorLayer.STATIC_ANALYSIS not in by_layer:
            recs.append(
                "Run static taint analysis on agent tool-integration code to identify "
                "P2Xi vulnerabilities before deployment."
            )

        tools_in_blocked = set(
            e.tool_call.tool_name for e in blocked_events if e.tool_call
        )
        for tool in tools_in_blocked:
            recs.append(
                f"Review tool '{tool}' — repeated blocked calls suggest "
                f"it is a high-risk integration point."
            )

        if not recs:
            recs.append("No incidents detected. Review current policies for potential gaps.")

        return recs

    def _add_taint_recommendations(
        self, recs: list[str], taint_results: list[Any] | None,
    ) -> list[str]:
        if not taint_results:
            return recs
        high_sev = [
            f for r in taint_results
            for f in getattr(r, 'flaws', [])
            if getattr(f, 'severity', '') == 'high'
        ]
        low_sev = [
            f for r in taint_results
            for f in getattr(r, 'flaws', [])
            if getattr(f, 'severity', '') == 'low'
        ]
        total = len(high_sev) + len(low_sev)
        if total > 0:
            recs.insert(0, (
                f"Static taint analysis found {total} P2Xi flow(s): "
                f"{len(high_sev)} high-severity (unvalidated), "
                f"{len(low_sev)} low-severity (validated). "
                f"Prioritize remediation of unvalidated paths."
            ))
        return recs

    def _render_taint_section(self, taint_results: list[Any] | None) -> str:
        if not taint_results:
            return ""
        lines = ["\n## Static Taint Analysis Findings\n"]
        has_any = False
        for r in taint_results:
            for f in getattr(r, 'flaws', []):
                has_any = True
                validated = " [validated]" if getattr(f, 'validated', False) else ""
                lines.append(
                    f"- {'🔴' if getattr(f, 'severity', '') == 'high' else '🟡'} "
                    f"`{getattr(f, 'file_path', '?')}:{getattr(f, 'line_number', '?')}` "
                    f"{getattr(f, 'source', '?')} → {getattr(f, 'sink', '?')} "
                    f"({getattr(f, 'sink_type', '?')}){validated}"
                )
        if not has_any:
            lines.append("_No P2Xi vulnerabilities detected._")
        return "\n".join(lines) + "\n"

    def render_markdown(self, report: IncidentReport, taint_results: list[Any] | None = None) -> str:
        lines = []
        lines.append(f"# Sentrix Incident Report: {report.id}")
        lines.append(f"**Session:** `{report.session_id}`")
        lines.append(f"**Timestamp:** {report.timestamp.isoformat()}")
        lines.append("")
        lines.append("## Root Cause")
        lines.append(f"{report.root_cause}")
        lines.append("")
        lines.append("## Blast Radius")
        lines.append(f"{report.blast_radius}")
        lines.append("")
        lines.append("## Affected Assets")
        lines.append(f"- **Agents:** {', '.join(report.affected_agents) if report.affected_agents else 'None'}")
        lines.append(f"- **Tools:** {', '.join(report.affected_tools) if report.affected_tools else 'None'}")
        lines.append(f"- **Data:** {', '.join(report.affected_data) if report.affected_data else 'None'}")
        lines.append("")
        lines.append("## Verdicts by Layer")
        for layer, verdicts in report.verdicts_by_layer.items():
            lines.append(f"- **{layer.value}:** {len(verdicts)} event(s)")
        lines.append("")
        taint_section = self._render_taint_section(taint_results)
        if taint_section:
            lines.append(taint_section)
        lines.append("## Attack DAG")
        dag_str = self._dag_builder.render_ascii_dag(report.attack_dag)
        lines.append("```")
        lines.append(dag_str)
        lines.append("```")
        lines.append("")
        lines.append("## Timeline")
        timeline_str = self._timeline.render_text_timeline(report.session_id, max_events=20)
        lines.append("```")
        lines.append(timeline_str)
        lines.append("```")
        lines.append("")
        lines.append("## Recommendations")
        for i, rec in enumerate(report.recommendations, 1):
            lines.append(f"{i}. {rec}")
        lines.append("")
        lines.append("---")
        lines.append(f"*Generated by Sentrix v0.1.0 at {datetime.now(timezone.utc).isoformat()}*")
        return "\n".join(lines)
