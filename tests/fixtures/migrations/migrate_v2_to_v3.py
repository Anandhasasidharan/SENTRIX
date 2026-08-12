"""Migrate live-benchmark fixtures from schema v2 to v3.

v3 splits the single `narrated_completion` boolean into two explicit
phrase lists (see `src/sentrix/harness/live_runner.py::TaskRow`):

- `narrated_unmediated`      — case (a): action narrated with NO
  mediated call backing it (safety-critical, BLOCKED via reference
  monitor).
- `narrated_with_mediation`  — case (b): narration overlapping
  mediated tool usage (informational, FLAGGED only).

The values are re-derived from each stored `plan_text` through the real
interpreter, and the migration refuses to write if re-classification
drifts any recorded `outcome`. This exists so the v2->v3 derivation is
reproducible rather than a one-off /tmp script — the same class of
temporary-location loss that destroyed the original raw plans (see
`tests/fixtures/live_results/README.md`).

Run from the repo root:

    .venv/bin/python tests/fixtures/migrations/migrate_v2_to_v3.py

The script is single-use: it asserts the input is still schema v2.
"""

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT))

from sentrix.core.plan_interpreter import PlanInterpreter  # noqa: E402
from sentrix.core.reference_monitor import ReferenceMonitor  # noqa: E402
from sentrix.dual_llm.context_manager import ContextManager  # noqa: E402
from sentrix.dual_llm.privileged_llm import PrivilegedLLM  # noqa: E402
from sentrix.dual_llm.quarantined_llm import QuarantinedLLM  # noqa: E402
from sentrix.harness.live_runner import classify_result  # noqa: E402
from sentrix.models.policy import AgentPolicy, DataSensitivity  # noqa: E402

FIXTURES = REPO_ROOT / "tests" / "fixtures" / "live_results" / "live_benchmark_results.json"

DOJO_POLICY = AgentPolicy(
    agent_id="dojo_agent",
    allowed_tools=["read_file", "list_dir", "send_email", "search_web", "store_memory"],
    blocked_tools=["delete_file", "exec_command", "modify_system"],
    capabilities=[],
    max_sensitivity=DataSensitivity.INTERNAL,
)


def main() -> None:
    payload = json.loads(FIXTURES.read_text())
    assert payload["schema_version"] == 2, (
        f"expected schema v2 input, got v{payload['schema_version']}"
    )
    rows = payload["tasks"]

    ctx = ContextManager()
    monitor = ReferenceMonitor(ctx)
    interp = PlanInterpreter(PrivilegedLLM(ctx), QuarantinedLLM(ctx), monitor, ctx)
    interp.configure("dojo_agent", DOJO_POLICY)
    monitor.configure("dojo_agent", DOJO_POLICY)

    drifted = []
    for r in rows:
        result = interp.interpret(r["plan_text"])
        classified = classify_result(
            plan_text=r["plan_text"],
            planned_steps=result.steps,
            unresolved_steps=result.unresolved_steps,
            blocked_steps=[s for s in result.step_results if s.get("verdict") == "blocked"],
            narrated_unmediated=result.narrated_unmediated_actions,
            narrated_with_mediation=result.narrated_with_mediation,
        )
        if classified.outcome.value != r["outcome"]:
            drifted.append((r["id"], r["outcome"], classified.outcome.value))
        r["narrated_unmediated"] = list(result.narrated_unmediated_actions)
        r["narrated_with_mediation"] = list(result.narrated_with_mediation)
        if "narrated_completion" in r:
            del r["narrated_completion"]

    assert not drifted, f"outcome drift — aborting: {drifted}"

    payload["schema_version"] = 3
    FIXTURES.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")

    unmediated = sum(1 for r in rows if r["narrated_unmediated"])
    with_med = sum(1 for r in rows if r["narrated_with_mediation"])
    print(
        f"rows={len(rows)} narrated_unmediated={unmediated} "
        f"narrated_with_mediation={with_med} schema={payload['schema_version']}"
    )


if __name__ == "__main__":
    main()