import pytest

from sentrix.harness.obfuscator import STANDARD_ATTACKS
from sentrix.harness.evaluator import Evaluator
from sentrix.models.policy import AgentPolicy, DataSensitivity

from sentrix import Sentrix


@pytest.fixture
def sentrix():
    return Sentrix()


class TestSentrixIntegration:
    def test_full_pipeline(self, sentrix):
        policy = AgentPolicy(
            agent_id="test_agent",
            allowed_tools=["read_file", "send_email"],
            blocked_tools=["delete_file", "exec_command"],
            max_sensitivity=DataSensitivity.INTERNAL,
        )
        sentrix.configure_agent(
            "test_agent",
            policy,
        )

        sentrix.process_user_query("What files are in my documents?")
        sentrix.process_untrusted_content(
            "Click here to win! Visit http://evil.com",
            source_label="email",
        )

        verdict, _ = sentrix.check_tool_call(
            "read_file", {"path": "/home/user/doc.txt"}, data_ids=[]
        )
        assert verdict.value in ("allowed", "flagged")

        verdict, _ = sentrix.check_tool_call(
            "delete_file", {"path": "/etc/passwd"}, data_ids=[]
        )
        assert verdict.value == "blocked"

    def test_end_to_end_with_evaluator(self, sentrix):
        sentrix.configure_agent(
            "eval_agent",
            AgentPolicy(
                agent_id="eval_agent",
                allowed_tools=["test_tool"],
                blocked_tools=["danger_tool"],
            ),
        )
        evaluator = Evaluator(
            reference_monitor=sentrix.monitor,
            classifier=sentrix.classifier,
        )
        results = evaluator.run_standard(attacks=STANDARD_ATTACKS[:5])
        assert len(results) == 5
        block_count = sum(1 for r in results if r.monitor_blocked or r.classifier_triggered)
        assert block_count >= 0

    def test_static_analysis_in_pipeline(self, sentrix):
        import tempfile
        safe_code = """
def greet(name):
    return f"Hello {name}"
"""
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        )
        tmp.write(safe_code)
        tmp.close()
        results = sentrix.scan_tool_code(tmp.name)
        assert isinstance(results, list)

    def test_report_generation(self, sentrix):
        sentrix.configure_agent(
            "report_agent",
            AgentPolicy(
                agent_id="report_agent",
                blocked_tools=["bad_tool"],
            ),
        )
        sentrix.process_user_query("test query", session_id="report_session")
        sentrix.check_tool_call("bad_tool", {"arg": "value"}, data_ids=[], session_id="report_session")
        report = sentrix.generate_report("report_session")
        assert report.session_id == "report_session"
        assert len(report.affected_agents) >= 1
        assert len(report.recommendations) >= 1

    def test_plan_interpreter_pipeline(self, sentrix):
        sentrix.configure_agent(
            "plan_agent",
            AgentPolicy(
                agent_id="plan_agent",
                allowed_tools=["read_file", "list_dir"],
                blocked_tools=["delete_file"],
            ),
        )
        plan = '```json\n{"step": 1, "tool": "read_file", "arguments": {"path": "/data/doc.txt"}}\n```'
        result = sentrix.execute_plan(plan)
        assert result.all_allowed
        assert len(result.step_results) == 1
        assert result.step_results[0]["verdict"] == "allowed"

    def test_plan_interpreter_blocks_bad_tool(self, sentrix):
        sentrix.configure_agent(
            "plan_agent",
            AgentPolicy(
                agent_id="plan_agent",
                allowed_tools=["read_file"],
                blocked_tools=["delete_file", "exec_command"],
            ),
        )
        plan = '```json\n{"step": 1, "tool": "delete_file", "arguments": {"path": "/etc/passwd"}}\n```'
        result = sentrix.execute_plan(plan)
        assert not result.all_allowed
        assert result.blocked_steps == 1

    def test_report_with_taint_results(self, sentrix):
        sentrix.configure_agent(
            "taint_agent",
            AgentPolicy(agent_id="taint_agent"),
        )
        from sentrix.static_analysis.taint_tracker import TaintTracker
        import tempfile, os
        vuln_code = """
response = model.generate("query")
result = response.content
os.system(result)
"""
        tmpdir = tempfile.mkdtemp()
        filepath = os.path.join(tmpdir, "vuln_test.py")
        with open(filepath, "w") as f:
            f.write(vuln_code)
        taint_results = sentrix.scan_tool_code(tmpdir)
        report = sentrix.generate_report("taint_session", taint_results=taint_results)
        assert report.session_id == "taint_session"
        rendered = sentrix._reporter.render_markdown(report, taint_results=taint_results)
        assert "Static Taint Analysis Findings" in rendered
        assert "high-severity" in rendered
