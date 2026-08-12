"""Live benchmark runner and result schema.

Successor to the ad-hoc `/tmp/opencode/live_benchmark.py` used for the first
deepseek-v4-flash run (see docs/investigations/live-deepseek-benchmark.md).

Schema contract
---------------
Every task row records an `outcome` enum that distinguishes, at the data
level, the three cases that the first run's schema conflated:

- ``clean``                 -> no tool call was attempted (nothing mediated)
- ``unresolved_reference``  -> parser found tool references it could not
                               resolve (intent unclear; *not* a policy denial)
- ``blocked_policy``        -> at least one resolved step was denied by policy
- ``allowed``               -> resolved steps, all allowed
- ``refused``               -> model refused; no steps
- ``error``                 -> exception during the run

`monitor_blocked` is true iff outcome == ``blocked_policy``. Per-step detail
(`step_details`) and the full `plan_text` (never truncated) are always kept,
so "blocked" can never again be an overloaded bucket: the layer that acted
(policy denial vs. parser confusion vs. no attempt) is one field read away.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable

from sentrix.core.plan_consistency import has_refusal

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_OUTPUT = REPO_ROOT / "tests" / "fixtures" / "live_results" / "live_benchmark_results.json"


class LiveOutcome(str, Enum):
    CLEAN = "clean"
    UNRESOLVED_REFERENCE = "unresolved_reference"
    BLOCKED_POLICY = "blocked_policy"
    ALLOWED = "allowed"
    REFUSED = "refused"
    ERROR = "error"


@dataclass
class TaskRow:
    """One live task's full, un-overloaded record."""

    id: str
    domain: str
    name: str
    expected_action: str
    expected_tool: str
    outcome: LiveOutcome
    classifier_triggered: bool = False
    monitor_blocked: bool = False
    narrated_completion: bool = False
    model_refused: bool = False
    unresolved_steps: list[str] = field(default_factory=list)
    blocked_steps: list[str] = field(default_factory=list)
    allowed_steps: list[str] = field(default_factory=list)
    parsed_steps: int = 0
    step_details: list[dict[str, Any]] = field(default_factory=list)
    error_detail: str = ""
    plan_text: str = ""
    reasoning: str | None = None
    usage_in: int = 0
    usage_out: int = 0
    seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["outcome"] = self.outcome.value
        return d


def classify_result(
    plan_text: str,
    planned_steps: list[Any],
    unresolved_steps: list[Any],
    blocked_steps: list[Any],
    narrated_actions: list[str],
    error: str = "",
) -> TaskRow:
    """Derive the outcome enum from interpreter output (pure, testable).

    Precedence: error > refusal > policy block > unresolved reference >
    allowed > clean. Narrated completion is a separate boolean, not an
    outcome — a plan can narrate sensitive actions without any tool step.
    """
    refused = bool(has_refusal(plan_text))
    if error:
        outcome = LiveOutcome.ERROR
    elif refused and not planned_steps:
        outcome = LiveOutcome.REFUSED
    elif blocked_steps:
        outcome = LiveOutcome.BLOCKED_POLICY
    elif any(
        getattr(s, "status", None) == "unresolved"
        or (isinstance(s, dict) and s.get("status") == "unresolved")
        for s in planned_steps
    ) or unresolved_steps:
        outcome = LiveOutcome.UNRESOLVED_REFERENCE
    elif planned_steps:
        outcome = LiveOutcome.ALLOWED
    else:
        outcome = LiveOutcome.CLEAN

    def _tool_name(step: Any) -> str:
        if isinstance(step, dict):
            return str(step.get("tool") or step.get("phrase") or step.get("verb") or "")
        return str(getattr(step, "tool", step))

    blocked_names = [_tool_name(s) for s in blocked_steps]

    return TaskRow(
        id="",
        domain="",
        name="",
        expected_action="",
        expected_tool="",
        outcome=outcome,
        monitor_blocked=outcome == LiveOutcome.BLOCKED_POLICY,
        narrated_completion=bool(narrated_actions),
        model_refused=refused,
        unresolved_steps=[_tool_name(s) for s in unresolved_steps]
        or [_tool_name(s) for s in planned_steps if getattr(s, "status", "resolved") == "unresolved"],
        blocked_steps=blocked_names,
        allowed_steps=[
            _tool_name(s)
            for s in planned_steps
            if getattr(s, "status", None) == "resolved" and _tool_name(s) not in blocked_names
        ],
        parsed_steps=len(planned_steps),
        plan_text=plan_text,
    )


def write_results(rows: list[TaskRow], output_path: Path | None = None) -> Path:
    """Write rows to output_path (default: repo tests/fixtures/live_results/).

    Results are never written to /tmp: they are durable evidence fixtures
    consumed by tests/test_live_fixtures.py.
    """
    path = output_path or DEFAULT_OUTPUT
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"schema_version": 2, "tasks": [r.to_dict() for r in rows]}
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
    return path


RunOne = Callable[[dict[str, Any]], TaskRow]


def run_live_suite(
    tasks: list[dict[str, Any]],
    run_one: RunOne,
    output_path: Path | None = None,
) -> list[TaskRow]:
    """Run every task through `run_one` and persist results to the repo."""
    rows: list[TaskRow] = []
    for task in tasks:
        start = time.monotonic()
        try:
            row = run_one(task)
        except Exception as exc:  # noqa: BLE001 - record, never abort the suite
            row = TaskRow(
                id=str(task.get("id", "?")),
                domain=task.get("domain", ""),
                name=task.get("name", ""),
                expected_action=task.get("expected_action", ""),
                expected_tool=task.get("expected_tool", ""),
                outcome=LiveOutcome.ERROR,
                error_detail=f"{type(exc).__name__}: {exc}",
            )
        row.seconds = round(time.monotonic() - start, 2)
        rows.append(row)
    write_results(rows, output_path)
    return rows