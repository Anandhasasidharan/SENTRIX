import pytest

from sentrix.core.rfc8707_provenance import (
    Rfc8707ProvenanceTracker,
    Rfc8707ResourceIndicator,
    Rfc8707TaintLabel,
)
from sentrix.core.provenance_tracker import ProvenanceTracker, TaintLabel
from sentrix.models.events import Provenance


class TestRfc8707ResourceIndicator:
    def test_from_uri_valid(self):
        ri = Rfc8707ResourceIndicator.from_uri("resource://sentrix/data/email/inbox/msg-123")
        assert ri.authority == "sentrix"
        assert ri.resource_type == "data"
        assert ri.resource_id == "email/inbox/msg-123"

    def test_from_uri_invalid_raises(self):
        with pytest.raises(ValueError):
            Rfc8707ResourceIndicator.from_uri("not-a-valid-uri")

    def test_to_uri(self):
        ri = Rfc8707ResourceIndicator(authority="sentrix", resource_type="data", resource_id="workspace/doc-1")
        assert ri.to_uri() == "resource://sentrix/data/workspace/doc-1"

    def test_matches_same_authority(self):
        a = Rfc8707ResourceIndicator.from_uri("resource://server-a/data/file-1")
        b = Rfc8707ResourceIndicator.from_uri("resource://server-a/data/file-2")
        assert a.matches(b)

    def test_matches_different_authority(self):
        a = Rfc8707ResourceIndicator.from_uri("resource://server-a/data/file-1")
        b = Rfc8707ResourceIndicator.from_uri("resource://server-b/data/file-1")
        assert not a.matches(b)

    def test_scope_prefix(self):
        ri = Rfc8707ResourceIndicator(authority="sentrix", resource_type="data", resource_id="*")
        assert ri.scope_prefix() == "resource://sentrix/"


class TestRfc8707TaintLabel:
    def test_merge_untrusted_wins(self):
        a = Rfc8707TaintLabel(provenance=Provenance.UNTRUSTED, sources=["web"], sensitivity="confidential")
        b = Rfc8707TaintLabel(provenance=Provenance.TRUSTED, sources=["user"], sensitivity="public")
        merged = a.merge(b)
        assert merged.provenance == Provenance.UNTRUSTED
        assert "web" in merged.sources
        assert "user" in merged.sources

    def test_merge_sensitivity_max_wins(self):
        a = Rfc8707TaintLabel(provenance=Provenance.TRUSTED, sensitivity="public")
        b = Rfc8707TaintLabel(provenance=Provenance.TRUSTED, sensitivity="restricted")
        merged = a.merge(b)
        assert merged.sensitivity == "restricted"

    def test_merge_preserves_resource_indicator(self):
        ri = Rfc8707ResourceIndicator(authority="srv", resource_type="data", resource_id="x")
        a = Rfc8707TaintLabel(provenance=Provenance.TRUSTED, resource_indicator=ri)
        b = Rfc8707TaintLabel(provenance=Provenance.TRUSTED)
        merged = a.merge(b)
        assert merged.resource_indicator == ri


class TestRfc8707ProvenanceTracker:
    def setup_method(self):
        self.tracker = Rfc8707ProvenanceTracker()

    def test_tag_and_get(self):
        label = Rfc8707TaintLabel(provenance=Provenance.UNTRUSTED, sources=["email"], sensitivity="confidential")
        self.tracker.tag("resource://sentrix/data/email/inbox/1", label)
        result = self.tracker.get("resource://sentrix/data/email/inbox/1")
        assert result.provenance == Provenance.UNTRUSTED
        assert result.sensitivity == "confidential"

    def test_get_default_for_unknown(self):
        result = self.tracker.get("resource://sentrix/data/unknown/1")
        assert result.provenance == Provenance.TRUSTED

    def test_is_untrusted(self):
        label = Rfc8707TaintLabel(provenance=Provenance.UNTRUSTED)
        self.tracker.tag("resource://sentrix/data/web/page-1", label)
        assert self.tracker.is_untrusted("resource://sentrix/data/web/page-1")
        assert not self.tracker.is_untrusted("resource://sentrix/data/unknown/1")

    def test_track_operation_merges_inputs(self):
        a = Rfc8707TaintLabel(provenance=Provenance.TRUSTED, sources=["user"])
        b = Rfc8707TaintLabel(provenance=Provenance.UNTRUSTED, sources=["web"])
        self.tracker.tag("resource://sentrix/data/user/input-1", a)
        self.tracker.tag("resource://sentrix/data/web/page-1", b)

        result = self.tracker.track_operation(
            ["resource://sentrix/data/user/input-1", "resource://sentrix/data/web/page-1"],
            "resource://sentrix/data/derived/output-1",
            operation="summarize",
        )
        assert result.provenance == Provenance.UNTRUSTED
        assert "summarize:resource://sentrix/data/derived/output-1" in result.sources

    def test_confused_deputy_allows_same_scope(self):
        assert self.tracker.check_confused_deputy(
            "resource://sentrix/data/file-1", "resource://sentrix/"
        )

    def test_confused_deputy_blocks_different_scope(self):
        assert not self.tracker.check_confused_deputy(
            "resource://sentrix/data/file-1", "resource://other-srv/"
        )


class TestProvenanceTrackerDualMode:
    def test_legacy_mode_default(self):
        pt = ProvenanceTracker()
        assert not pt.use_rfc8707

    def test_rfc8707_mode(self):
        pt = ProvenanceTracker(use_rfc8707=True)
        assert pt.use_rfc8707

    def test_legacy_mode_still_works(self):
        pt = ProvenanceTracker(use_rfc8707=False)
        pt.tag("data-1", TaintLabel(provenance=Provenance.UNTRUSTED))
        assert pt.is_untrusted("data-1")

    def test_rfc8707_mode_delegates(self):
        pt = ProvenanceTracker(use_rfc8707=True)
        pt.tag("resource://sentrix/data/x", TaintLabel(provenance=Provenance.UNTRUSTED))
        assert pt.is_untrusted("resource://sentrix/data/x")

    def test_rfc8707_confused_deputy_delegates(self):
        pt = ProvenanceTracker(use_rfc8707=True)
        assert pt.check_confused_deputy("resource://a/data/x", "resource://a/")
        assert not pt.check_confused_deputy("resource://a/data/x", "resource://b/")

    def test_legacy_confused_deputy_always_true(self):
        pt = ProvenanceTracker(use_rfc8707=False)
        assert pt.check_confused_deputy("anything", "anything")
