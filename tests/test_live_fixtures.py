"""Corpus regression: replay recorded live-benchmark plans through the parser.

Loads `tests/fixtures/live_results/live_benchmark_results.json` (if the
re-run has populated it) and asserts that re-interpreting each stored
`plan_text` reproduces the recorded outcome. This pins the parser against
real deepseek-v4-flash output — the exact failure mode of the 131/138
artifact run. Skips cleanly when the fixtures are absent.

Drift from an intentional parser change must be reflected by regenerating
the fixtures, not by editing this test.
"""

import json
from pathlib import Path

import pytest

from sentrix.core.plan_interpreter import PlanInterpreter
from sentrix.core.reference_monitor import ReferenceMonitor
from sentrix.dual_llm.context_manager import ContextManager
from sentrix.dual_llm.privileged_llm import PrivilegedLLM
from sentrix.dual_llm.quarantined_llm import QuarantinedLLM
from sentrix.harness.live_runner import LiveOutcome, classify_result
from sentrix.models.policy import AgentPolicy, DataSensitivity

FIXTURES = Path(__file__).parent / "fixtures" / "live_results" / "live_benchmark_results.json"

DOJO_POLICY = AgentPolicy(
    agent_id="dojo_agent",
    allowed_tools=["read_file", "list_dir", "send_email", "search_web", "store_memory"],
    blocked_tools=["delete_file", "exec_command", "modify_system"],
    capabilities=[],
    max_sensitivity=DataSensitivity.INTERNAL,
)

pytestmark = pytest.mark.skipif(
    not FIXTURES.exists(),
    reason="live benchmark fixtures not present; run examples/live_benchmark.py first",
)


@pytest.fixture(scope="module")
def fixture_payload():
    return json.loads(FIXTURES.read_text())


@pytest.fixture(scope="module")
def interpreter():
    ctx = ContextManager()
    monitor = ReferenceMonitor(ctx)
    privileged = PrivilegedLLM(ctx)
    quarantined = QuarantinedLLM(ctx)
    interp = PlanInterpreter(privileged, quarantined, monitor, ctx)
    interp.configure("dojo_agent", DOJO_POLICY)
    monitor.configure("dojo_agent", DOJO_POLICY)
    return interp


def _derive(row: dict, interp: PlanInterpreter) -> LiveOutcome:
    result = interp.interpret(row["plan_text"])
    classified = classify_result(
        plan_text=row["plan_text"],
        planned_steps=result.steps,
        unresolved_steps=result.unresolved_steps,
        blocked_steps=[
            s for s in result.step_results if s.get("verdict") == "blocked"
        ],
        narrated_actions=result.narrated_unmediated_actions,
    )
    return classified.outcome


def test_fixture_schema_version(fixture_payload):
    assert fixture_payload["schema_version"] == 2
    rows = fixture_payload["tasks"]
    assert len(rows) == 54
    assert all(
        r["outcome"] in {o.value for o in LiveOutcome} for r in rows
    ), "every row must carry the explicit outcome enum"
    assert all("plan_text" in r and r["plan_text"] for r in rows), (
        "plan_text must be stored in full — truncation corrupted the first "
        "run's evidence"
    )


def test_every_row_replays_to_its_recorded_outcome(fixture_payload, interpreter):
    mismatches = []
    for row in fixture_payload["tasks"]:
        derived = _derive(row, interpreter)
        if derived.value != row["outcome"]:
            mismatches.append(
                (row["id"], row["outcome"], derived.value)
            )
    assert not mismatches, f"outcome drift vs fixtures: {mismatches}"


def test_blocked_rows_have_real_policy_denials(fixture_payload, interpreter):
    for row in fixture_payload["tasks"]:
        if row["outcome"] != "blocked_policy":
            continue
        assert row["blocked_steps"], (
            f"{row['id']}: blocked_policy row must list the denied tools"
        )
        for tool in row["blocked_steps"]:
            allowed, reason = DOJO_POLICY.check_tool(tool)
            assert not allowed, (
                f"{row['id']}: {tool!r} was recorded as blocked but policy "
                f"allows it — blocked_steps must be genuine denials "
                f"(explicit blocklist or allowlist default-deny), never "
                f"parser junk that slipped through"
            )
            assert "blocked" in reason or "allowed list" in reason


def test_unresolved_rows_are_never_policy_denials(fixture_payload, interpreter):
    for row in fixture_payload["tasks"]:
        if row["outcome"] != "unresolved_reference":
            continue
        assert row["blocked_steps"] == []
        assert row["monitor_blocked"] is False
        assert row["unresolved_steps"], f"{row['id']}: must name the unresolved refs"


def test_narrated_completion_is_a_separate_signal(fixture_payload, interpreter):
    """Narration flag must be reproducible from the stored plan and must
    never be the *only* reason a row reads as mediated — it is a distinct
    signal from the outcome enum."""
    narrated = [r for r in fixture_payload["tasks"] if r["narrated_completion"]]
    for r in narrated:
        result = interpreter.interpret(r["plan_text"])
        assert result.narrated_unmediated_actions, (
            f"{r['id']}: narrated_completion flag must reproduce from the "
            f"stored plan_text (it is a data-level signal, not a label)"
        )
    for r in fixture_payload["tasks"]:
        if "banking_3" in r["id"]:
            assert r["outcome"] != "blocked_policy", (
                "banking_3 must never read as a policy block: it is a "
                "narration/refusal case by construction"
            )
