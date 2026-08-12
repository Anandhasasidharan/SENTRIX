import pytest

from sentrix.dual_llm.context_manager import ContextIsolationError, ContextManager
from sentrix.models.events import Provenance


class TestContextManager:
    def test_isolation_enforced(self):
        ctx = ContextManager()
        assert ctx.verify_isolation()

    def test_privileged_accepts_user_message(self):
        ctx = ContextManager()
        ctx.add_privileged_message({"role": "user", "content": "hello"})
        assert len(ctx.privileged.messages) == 1

    def test_quarantined_accepts_message(self):
        ctx = ContextManager()
        ctx.add_quarantined_message({"role": "user", "content": "untrusted data"})
        assert len(ctx.quarantined.messages) == 1

    def test_no_tools_on_quarantined(self):
        ctx = ContextManager()
        assert ctx.verify_isolation()

    def test_privileged_provenance_is_trusted(self):
        ctx = ContextManager()
        assert ctx.privileged.provenance == Provenance.TRUSTED

    def test_quarantined_provenance_is_untrusted(self):
        ctx = ContextManager()
        assert ctx.quarantined.provenance == Provenance.UNTRUSTED

    def test_quarantined_has_no_tools(self):
        ctx = ContextManager()
        assert ctx.quarantined.allowed_tools == []

    def test_contexts_are_separate_objects(self):
        ctx = ContextManager()
        ctx.add_privileged_message({"role": "user", "content": "trusted"})
        ctx.add_quarantined_message({"role": "user", "content": "untrusted"})
        assert len(ctx.privileged.messages) == 1
        assert len(ctx.quarantined.messages) == 1
        assert ctx.privileged.messages[0]["content"] == "trusted"
        assert ctx.quarantined.messages[0]["content"] == "untrusted"
