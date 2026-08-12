from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from sentrix.models.events import Provenance

URI_PATTERN = re.compile(
    r'^resource://([a-zA-Z0-9._-]+)/([a-zA-Z0-9._-]+)/([a-zA-Z0-9._/-]+)$'
)


@dataclass(frozen=True)
class Rfc8707ResourceIndicator:
    authority: str
    resource_type: str
    resource_id: str

    @classmethod
    def from_uri(cls, uri: str) -> Rfc8707ResourceIndicator:
        m = URI_PATTERN.match(uri)
        if not m:
            raise ValueError(f"Invalid RFC 8707 resource indicator: {uri!r}")
        return cls(authority=m.group(1), resource_type=m.group(2), resource_id=m.group(3))

    def to_uri(self) -> str:
        return f"resource://{self.authority}/{self.resource_type}/{self.resource_id}"

    def matches(self, other: Rfc8707ResourceIndicator) -> bool:
        return self.authority == other.authority

    def scope_prefix(self) -> str:
        return f"resource://{self.authority}/"


@dataclass
class Rfc8707TaintLabel:
    provenance: Provenance
    sources: list[str] = field(default_factory=list)
    sensitivity: str = "public"
    resource_indicator: Rfc8707ResourceIndicator | None = None

    def merge(self, other: Rfc8707TaintLabel) -> Rfc8707TaintLabel:
        if self.provenance == Provenance.UNTRUSTED or other.provenance == Provenance.UNTRUSTED:
            merged_provenance = Provenance.UNTRUSTED
        elif self.provenance == Provenance.DERIVED or other.provenance == Provenance.DERIVED:
            merged_provenance = Provenance.DERIVED
        else:
            merged_provenance = Provenance.TRUSTED

        merged_sources = list(set(self.sources + other.sources))
        merged_sensitivity = max(
            [self.sensitivity, other.sensitivity],
            key=lambda s: ["public", "internal", "confidential", "restricted"].index(s)
            if s in ["public", "internal", "confidential", "restricted"]
            else 0,
        )

        merged_resource = self.resource_indicator or other.resource_indicator

        return Rfc8707TaintLabel(
            provenance=merged_provenance,
            sources=merged_sources,
            sensitivity=merged_sensitivity,
            resource_indicator=merged_resource,
        )


class Rfc8707ProvenanceTracker:
    def __init__(self):
        self._labels: dict[str, Rfc8707TaintLabel] = {}

    def tag(self, uri_str: str, label: Rfc8707TaintLabel) -> None:
        parsed = Rfc8707ResourceIndicator.from_uri(uri_str)
        label.resource_indicator = parsed
        self._labels[uri_str] = label

    def get(self, uri_str: str) -> Rfc8707TaintLabel:
        return self._labels.get(
            uri_str,
            Rfc8707TaintLabel(
                provenance=Provenance.TRUSTED,
                sources=["unknown"],
                resource_indicator=Rfc8707ResourceIndicator.from_uri(
                    uri_str if "://" in uri_str else f"resource://unknown/default/{uri_str}"
                ) if "://" in uri_str else None,
            ),
        )

    def track_operation(
        self, input_uris: list[str], output_uri: str, operation: str = "transform"
    ) -> Rfc8707TaintLabel:
        inputs = [self.get(u) for u in input_uris]
        merged = inputs[0]
        for inp in inputs[1:]:
            merged = merged.merge(inp)

        merged.sources.append(f"{operation}:{output_uri}")

        try:
            parsed = Rfc8707ResourceIndicator.from_uri(output_uri)
            merged.resource_indicator = parsed
        except ValueError:
            pass

        self._labels[output_uri] = merged
        return merged

    def is_untrusted(self, uri_str: str) -> bool:
        return self.get(uri_str).provenance == Provenance.UNTRUSTED

    def get_sensitivity(self, uri_str: str) -> str:
        return self.get(uri_str).sensitivity

    def check_confused_deputy(
        self, requested_uri: str, authorized_scope: str
    ) -> bool:
        try:
            parsed = Rfc8707ResourceIndicator.from_uri(requested_uri)
        except ValueError:
            return False
        return parsed.scope_prefix() == authorized_scope or requested_uri.startswith(authorized_scope)
