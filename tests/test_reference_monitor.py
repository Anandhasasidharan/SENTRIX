import pytest

from sentrix.core.reference_monitor import PolicyNotConfiguredError, ReferenceMonitor
from sentrix.dual_llm.context_manager import ContextManager
from sentrix.models.events import ActionVerdict, Provenance
from sentrix.models.policy import (
    AgentPolicy,
    CapabilityEffect,
    CapabilityRule,
    DataSensitivity,
)


@pytest.fixture
def monitor():
    ctx = ContextManager()
    rm = ReferenceMonitor(ctx)
    policy = AgentPolicy(
        agent_id="test_agent",
        allowed_tools=["read_file", "list_files"],
        blocked_tools=["delete_file", "exec_command"],
        capabilities=[
            CapabilityRule(
                capability="read",
                effect=CapabilityEffect.ALLOW,
                tool_pattern="read_file",
            ),
        ],
        max_sensitivity=DataSensitivity.INTERNAL,
    )
    rm.configure("test_agent", policy)
    return rm


class TestReferenceMonitor:
    def test_allows_configured_tool(self, monitor):
        verdict, event = monitor.check_tool_call("read_file", {"path": "/safe/file.txt"})
        assert verdict == ActionVerdict.ALLOWED
        assert event.verdict == ActionVerdict.ALLOWED

    def test_blocks_explicitly_blocked_tool(self, monitor):
        verdict, event = monitor.check_tool_call("delete_file", {"path": "/etc/passwd"})
        assert verdict == ActionVerdict.BLOCKED
        assert event.verdict == ActionVerdict.BLOCKED
        assert event.blocked_by is not None

    def test_blocks_unlisted_tool(self, monitor):
        verdict, event = monitor.check_tool_call("unknown_tool", {})
        assert verdict == ActionVerdict.BLOCKED

    def test_blocks_untrusted_data_exceeds_sensitivity(self, monitor):
        monitor.tag_untrusted_data("evil_data", "web_page")
        verdict, event = monitor.check_tool_call(
            "read_file", {"path": "/data/secret.txt"}, data_ids=["evil_data"]
        )
        assert verdict == ActionVerdict.BLOCKED

    def test_allows_trusted_data(self, monitor):
        monitor.tag_trusted_data("safe_data", "user_input")
        verdict, event = monitor.check_tool_call(
            "read_file", {"path": "/data/public.txt"}, data_ids=["safe_data"]
        )
        assert verdict == ActionVerdict.ALLOWED

    def test_on_block_callback(self, monitor):
        blocked_events = []

        def on_block(event):
            blocked_events.append(event)

        ctx = ContextManager()
        rm = ReferenceMonitor(ctx)
        policy = AgentPolicy(
            agent_id="test_agent",
            blocked_tools=["danger_tool"],
        )
        rm.configure("test_agent", policy, on_block=on_block)
        rm.check_tool_call("danger_tool", {})
        assert len(blocked_events) == 1
        assert blocked_events[0].tool_call.tool_name == "danger_tool"

    def test_no_policy_raises_error(self, monitor):
        ctx = ContextManager()
        rm = ReferenceMonitor(ctx)
        rm.configure("test_agent", None)
        with pytest.raises(PolicyNotConfiguredError):
            rm.check_tool_call("anything", {"foo": "bar"})

    def test_provenance_tracking(self, monitor):
        monitor.tag_untrusted_data("web_data", "web_page")
        assert monitor.provenance.is_untrusted("web_data")
        monitor.tag_trusted_data("user_data", "user_input")
        assert not monitor.provenance.is_untrusted("user_data")
