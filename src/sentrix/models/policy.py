from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class CapabilityEffect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    FLAG = "flag"


class DataSensitivity(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class CapabilityRule(BaseModel):
    capability: str
    effect: CapabilityEffect = CapabilityEffect.DENY
    tool_pattern: str | None = None
    data_sensitivity_max: DataSensitivity | None = None
    provenance_required: str | None = None
    reason: str | None = None


class AgentPolicy(BaseModel):
    agent_id: str
    capabilities: list[CapabilityRule] = Field(default_factory=list)
    default_effect: CapabilityEffect = CapabilityEffect.DENY

    allowed_tools: list[str] = Field(default_factory=list)
    blocked_tools: list[str] = Field(default_factory=list)
    max_sensitivity: DataSensitivity = DataSensitivity.INTERNAL

    def check_tool(self, tool_name: str, data_provenance: str | None = None) -> tuple[bool, str]:
        if tool_name in self.blocked_tools:
            return False, f"Tool '{tool_name}' is explicitly blocked"

        if self.allowed_tools and tool_name not in self.allowed_tools:
            return False, f"Tool '{tool_name}' is not in the allowed list"

        if self.allowed_tools and tool_name in self.allowed_tools:
            return True, f"Tool '{tool_name}' is in the allowed list"

        for cap in self.capabilities:
            if cap.tool_pattern and cap.tool_pattern in tool_name:
                if cap.effect == CapabilityEffect.ALLOW:
                    return True, cap.reason or f"Allowed by capability '{cap.capability}'"
                return False, cap.reason or f"Denied by capability '{cap.capability}'"

        if self.default_effect == CapabilityEffect.ALLOW:
            return True, "Allowed by default"
        return False, "Denied by default (no matching capability rule)"

    def check_data_sensitivity(self, sensitivity: DataSensitivity | str) -> bool:
        levels = {
            DataSensitivity.PUBLIC: 0,
            DataSensitivity.INTERNAL: 1,
            DataSensitivity.CONFIDENTIAL: 2,
            DataSensitivity.RESTRICTED: 3,
        }
        if isinstance(sensitivity, str):
            for enum_val in DataSensitivity:
                if enum_val.value == sensitivity:
                    sensitivity = enum_val
                    break
            else:
                return False
        return levels[sensitivity] <= levels[self.max_sensitivity]
