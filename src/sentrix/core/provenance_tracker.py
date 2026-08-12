from __future__ import annotations

from dataclasses import dataclass, field

from sentrix.models.events import Provenance


@dataclass
class TaintLabel:
    provenance: Provenance
    sources: list[str] = field(default_factory=list)
    sensitivity: str = "public"

    def merge(self, other: TaintLabel) -> TaintLabel:
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
        return TaintLabel(
            provenance=merged_provenance,
            sources=merged_sources,
            sensitivity=merged_sensitivity,
        )


class ProvenanceTracker:
    def __init__(self, use_rfc8707: bool = False):
        self._use_rfc8707 = use_rfc8707
        self._labels: dict[str, TaintLabel] = {}
        if use_rfc8707:
            from sentrix.core.rfc8707_provenance import Rfc8707ProvenanceTracker
            self._rfc8707 = Rfc8707ProvenanceTracker()
        else:
            self._rfc8707 = None

    @property
    def use_rfc8707(self) -> bool:
        return self._use_rfc8707

    def tag(self, data_id: str, label: TaintLabel) -> None:
        if self._rfc8707:
            from sentrix.core.rfc8707_provenance import Rfc8707TaintLabel
            rfc_label = Rfc8707TaintLabel(
                provenance=label.provenance,
                sources=label.sources,
                sensitivity=label.sensitivity,
            )
            self._rfc8707.tag(data_id, rfc_label)
        else:
            self._labels[data_id] = label

    def get(self, data_id: str) -> TaintLabel:
        if self._rfc8707:
            result = self._rfc8707.get(data_id)
            return TaintLabel(
                provenance=result.provenance,
                sources=result.sources,
                sensitivity=result.sensitivity,
            )
        return self._labels.get(
            data_id, TaintLabel(provenance=Provenance.TRUSTED, sources=["unknown"])
        )

    def track_operation(
        self, input_ids: list[str], output_id: str, operation: str = "transform"
    ) -> TaintLabel:
        if self._rfc8707:
            result = self._rfc8707.track_operation(input_ids, output_id, operation)
            return TaintLabel(
                provenance=result.provenance,
                sources=result.sources,
                sensitivity=result.sensitivity,
            )
        inputs = [self.get(oid) for oid in input_ids]
        merged = inputs[0]
        for inp in inputs[1:]:
            merged = merged.merge(inp)

        merged.sources.append(f"{operation}:{output_id}")
        self._labels[output_id] = merged
        return merged

    def is_untrusted(self, data_id: str) -> bool:
        if self._rfc8707:
            return self._rfc8707.is_untrusted(data_id)
        return self.get(data_id).provenance == Provenance.UNTRUSTED

    def get_sensitivity(self, data_id: str) -> str:
        if self._rfc8707:
            return self._rfc8707.get_sensitivity(data_id)
        return self.get(data_id).sensitivity

    def check_confused_deputy(self, requested_uri: str, authorized_scope: str) -> bool:
        if self._rfc8707:
            return self._rfc8707.check_confused_deputy(requested_uri, authorized_scope)
        return True
