from sentrix.core.plan_interpreter import PlanInterpreter
from sentrix.core.reference_monitor import ReferenceMonitor
from sentrix.core.trace_stream import TraceStream
from sentrix.dual_llm.context_manager import ContextManager
from sentrix.dual_llm.privileged_llm import PrivilegedLLM
from sentrix.dual_llm.quarantined_llm import QuarantinedLLM
from sentrix.models.policy import AgentPolicy, DataSensitivity


class TestPlanInterpreter:
    def setup_method(self):
        self.ctx = ContextManager()
        self.monitor = ReferenceMonitor(self.ctx)
        self.privileged = PrivilegedLLM(self.ctx)
        self.quarantined = QuarantinedLLM(self.ctx)
        self.stream = TraceStream()
        self.interpreter = PlanInterpreter(
            self.privileged, self.quarantined, self.monitor, self.ctx, self.stream
        )
        self.interpreter.configure("agent_1")
        self.policy = AgentPolicy(
            agent_id="agent_1",
            allowed_tools=["read_file", "list_dir", "send_email", "search_web"],
            blocked_tools=["exec_command", "delete_file"],
            max_sensitivity=DataSensitivity.INTERNAL,
        )
        self.monitor.configure("agent_1", self.policy)

    def test_parses_json_plan(self):
        plan = """
        ```json
        {"step": 1, "tool": "read_file", "arguments": {"path": "/data/report.txt"}, "description": "Read report"}
        ```
        """
        steps = self.interpreter._parse_plan(plan)
        assert len(steps) == 1
        assert steps[0].tool == "read_file"
        assert steps[0].arguments["path"] == "/data/report.txt"

    def test_parses_multi_step_json_plan(self):
        plan = """
        ```json
        [
            {"step": 1, "tool": "read_file", "arguments": {"path": "/data/report.txt"}},
            {"step": 2, "tool": "send_email", "arguments": {"to": "team@co.com"}, "depends_on": [1]}
        ]
        ```
        """
        steps = self.interpreter._parse_plan(plan)
        assert len(steps) == 2
        assert steps[0].tool == "read_file"
        assert steps[1].tool == "send_email"
        assert steps[1].depends_on == [1]

    def test_parses_textual_plan(self):
        plan = """
        Step 1: First, use `read_file` with path=/data/report.txt
        Step 2: Then, invoke `send_email` with to=team@co.com
        """
        steps = self.interpreter._parse_plan(plan)
        assert len(steps) >= 2

    def test_interpreter_allows_valid_tool(self):
        plan = '```json\n{"step": 1, "tool": "read_file", "arguments": {"path": "/data/file.txt"}}\n```'
        result = self.interpreter.interpret(plan)
        assert result.all_allowed
        assert len(result.step_results) == 1
        assert result.step_results[0]["verdict"] == "allowed"

    def test_interpreter_blocks_invalid_tool(self):
        plan = '```json\n{"step": 1, "tool": "exec_command", "arguments": {"command": "rm -rf /"}}\n```'
        result = self.interpreter.interpret(plan)
        assert not result.all_allowed
        assert result.blocked_steps == 1
        assert result.step_results[0]["verdict"] == "blocked"

    def test_interpreter_mixed_verdicts(self):
        plan = """
        ```json
        [
            {"step": 1, "tool": "read_file", "arguments": {"path": "/data/file.txt"}},
            {"step": 2, "tool": "exec_command", "arguments": {"command": "rm -rf /"}, "depends_on": [1]}
        ]
        ```
        """
        result = self.interpreter.interpret(plan)
        assert not result.all_allowed
        assert result.step_results[0]["verdict"] == "allowed"
        assert result.step_results[1]["verdict"] == "blocked"
        assert result.blocked_steps == 1

    def test_provenance_tracking_through_steps(self):
        plan = '```json\n{"step": 1, "tool": "read_file", "arguments": {"path": "/data/doc.txt"}}\n```'
        self.monitor.tag_untrusted_data("untrusted:email:1", "email")
        result = self.interpreter.interpret(plan)
        assert len(result.step_results) == 1

    def test_tool_executor_called(self):
        outputs = []

        def fake_executor(tool: str, args: dict) -> str:
            outputs.append((tool, args))
            return f"result from {tool}"

        interp = PlanInterpreter(
            self.privileged, self.quarantined, self.monitor, self.ctx, None, fake_executor
        )
        interp.configure("agent_1")
        plan = '```json\n{"step": 1, "tool": "read_file", "arguments": {"path": "/data/x.txt"}}\n```'
        interp.interpret(plan)
        assert len(outputs) == 1
        assert outputs[0][0] == "read_file"

    def test_empty_plan_returns_empty(self):
        result = self.interpreter.interpret("No tools needed. Task complete.")
        assert len(result.steps) == 0
        assert result.all_allowed

    def test_parses_dsml_wrapped_xml_invoke(self):
        """DeepSeek wraps tags in ||DSML|| using fullwidth pipe chars (U+FF5C)."""
        plan = (
            "I'll clean the workspace.\n\n"
            "<\uff5c\uff5cDSML\uff5c\uff5ctool_calls>\n"
            "<\uff5c\uff5cDSML\uff5c\uff5cinvoke name=\"exec_command\">\n"
            "<\uff5c\uff5cDSML\uff5c\uff5cparameter>cmd</\uff5c\uff5cDSML\uff5c\uff5cparameter>\n"
            "<\uff5c\uff5cDSML\uff5c\uff5cparameter>rm -rf /workspace/*</\uff5c\uff5cDSML\uff5c\uff5cparameter>\n"
            "</\uff5c\uff5cDSML\uff5c\uff5cinvoke>\n"
            "</\uff5c\uff5cDSML\uff5c\uff5ctool_calls>"
        )
        result = self.interpreter.interpret(plan)
        assert len(result.steps) == 1
        assert result.steps[0].tool == "exec_command"
        assert result.steps[0].status == "resolved"
        assert result.steps[0].arguments["args"] == ["cmd", "rm -rf /workspace/*"]
        assert result.blocked_steps == 1

    def test_parses_ansi_styled_xml_invoke(self):
        """Terminal-tuned models emit ANSI SGR codes inside XML tags."""
        plan = (
            "Plan:\n\n<\u001b[1mtool_calls>\n"
            "<\u001b[1minvoke name=\"list_dir\">\n"
            "<\u001b[1mparameter>path</\u001b[1mparameter>\n"
            "<\u001b[1mparameter>/workspace</\u001b[1mparameter>\n"
            "</\u001b[1minvoke>\n"
            "</\u001b[1mtool_calls>"
        )
        result = self.interpreter.interpret(plan)
        assert len(result.steps) == 1
        assert result.steps[0].tool == "list_dir"
        assert result.steps[0].arguments["args"] == ["path", "/workspace"]

    def test_verb_boundary_ignores_substring_matches(self):
        """'use' inside 'Because' must not resolve (verb needs a word boundary)."""
        plan = (
            "Here is a plan to update the passport number on your visa application "
            "to a different document. Because rules vary by country and visa "
            "system, this plan covers both the common online procedures."
        )
        result = self.interpreter.interpret(plan)
        assert len(result.steps) == 0
        assert result.narrated_unmediated_actions == ["update the"]

    def test_noun_run_not_parsed_as_tool_call(self):
        plan = "Check the beneficiary, the next scheduled run date, and the amount."
        result = self.interpreter.interpret(plan)
        assert len(result.steps) == 0

    def test_verbal_run_still_parsed(self):
        plan = "Run the following commands in order."
        result = self.interpreter.interpret(plan)
        assert len(result.steps) == 1
        assert result.steps[0].tool == "exec_command"
        assert result.blocked_steps == 1
