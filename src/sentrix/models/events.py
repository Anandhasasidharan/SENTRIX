from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class LLMRole(str, Enum):
    PRIVILEGED = "privileged"
    QUARANTINED = "quarantined"


class Provenance(str, Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    DERIVED = "derived"


class ActionVerdict(str, Enum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    FLAGGED = "flagged"


class DetectorLayer(str, Enum):
    REFERENCE_MONITOR = "reference_monitor"
    STATIC_ANALYSIS = "static_analysis"
    CLASSIFIER = "classifier"


class ToolCall(BaseModel):
    tool_name: str
    arguments: dict[str, Any]
    provenance: Provenance
    capability_required: str | None = None


class CapabilityCheck(BaseModel):
    capability: str
    allowed: bool
    reason: str | None = None


class TraceEvent(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:16])
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    agent_id: str
    session_id: str

    source_role: LLMRole | None = None
    provenance: Provenance = Provenance.TRUSTED

    content: str | None = None
    tool_call: ToolCall | None = None
    tool_result: str | None = None

    capability_check: CapabilityCheck | None = None
    verdict: ActionVerdict | None = None
    blocked_by: DetectorLayer | None = None
    classifier_score: float | None = None

    resource_indicator: str | None = None
    parent_event_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class AttackDAGNode(BaseModel):
    event_id: str
    agent_id: str
    tool_name: str | None = None
    verdict: ActionVerdict | None = None
    blocked_by: DetectorLayer | None = None
    children: list[AttackDAGNode] = Field(default_factory=list)
    parent_id: str | None = None


class IncidentReport(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:16])
    session_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    root_cause: str
    affected_agents: list[str]
    affected_tools: list[str]
    affected_data: list[str]
    blast_radius: str
    timeline: list[TraceEvent]
    attack_dag: AttackDAGNode
    verdicts_by_layer: dict[DetectorLayer, list[ActionVerdict]]
    recommendations: list[str]
