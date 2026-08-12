#!/usr/bin/env python3
"""Live deepseek-v4-flash benchmark driver (successor to the /tmp runner).

Drives the full Sentrix stack against a live, non-Anthropic provider and
records results with the un-overloaded schema from
`sentrix.harness.live_runner` — results land directly in
`tests/fixtures/live_results/` (never /tmp), where they double as durable
evidence and regression fixtures.

Run:
    DEEPSEEK_API_KEY=... python -m examples.live_benchmark [--agentdojo|--agentdyn|--all] [--output PATH]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentrix import Sentrix
from sentrix.harness.agentdojo import AGENTDOJO_TASKS
from sentrix.harness.agentdyn import AGENTDYN_TASKS
from sentrix.harness.live_runner import (
    TaskRow,
    classify_result,
    run_live_suite,
)
from sentrix.models.events import ActionVerdict
from sentrix.models.policy import AgentPolicy, DataSensitivity

MAX_TOKENS = 4096  # deepseek-v4-flash spends budget on reasoning_content; see findings doc


def run_one(task: dict[str, Any], sentrix: Sentrix) -> TaskRow:
    session_id = f"live:{task['id']}"
    user_event = sentrix.process_user_query(task["payload"], session_id=session_id)
    classifier_triggered = user_event.verdict == ActionVerdict.FLAGGED

    response = sentrix._privileged._llm.generate(
        messages=sentrix._privileged._ctx.privileged.messages,
        model=sentrix._privileged._resolve_model() or "deepseek-v4-flash",
        max_tokens=MAX_TOKENS,
    )
    plan_text = response.text
    sentrix._privileged._ctx.add_privileged_message(
        {"role": "assistant", "content": plan_text}
    )

    result = sentrix.execute_plan(plan_text, session_id=session_id)

    row = classify_result(
        plan_text=plan_text,
        planned_steps=result.steps,
        unresolved_steps=result.unresolved_steps,
        blocked_steps=[
            s for s in result.step_results if s.get("verdict") == "blocked"
        ],
        narrated_actions=result.narrated_unmediated_actions,
    )
    row.id = task["id"]
    row.domain = task.get("domain", "")
    row.name = task.get("name", "")
    row.expected_action = task.get("expected_action", "")
    row.expected_tool = task.get("expected_tool", "")
    row.classifier_triggered = classifier_triggered
    row.step_details = [
        {
            "step": s.get("step"),
            "tool": s.get("tool"),
            "verdict": s.get("verdict"),
            "reason": s.get("reason", ""),
        }
        for s in result.step_results
    ] + [
        {
            "step": s.get("step"),
            "phrase": s.get("phrase"),
            "verdict": "unresolved",
            "reason": s.get("reason", ""),
        }
        for s in result.unresolved_steps
    ]
    row.reasoning = getattr(response, "reasoning", None)
    usage = getattr(response, "usage", {}) or {}
    row.usage_in = usage.get("input_tokens", 0)
    row.usage_out = usage.get("output_tokens", 0)
    return row


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--suite", choices=["agentdojo", "agentdyn", "all"], default="all"
    )
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()

    tasks: list[dict[str, Any]] = []
    if args.suite in ("agentdojo", "all"):
        tasks += AGENTDOJO_TASKS
    if args.suite in ("agentdyn", "all"):
        tasks += AGENTDYN_TASKS

    sentrix = Sentrix(provider="deepseek")
    sentrix.configure_agent(
        agent_id="dojo_agent",
        policy=AgentPolicy(
            agent_id="dojo_agent",
            allowed_tools=["read_file", "list_dir", "send_email", "search_web", "store_memory"],
            blocked_tools=["delete_file", "exec_command", "modify_system"],
            capabilities=[],
            max_sensitivity=DataSensitivity.INTERNAL,
        ),
    )

    def runner(task: dict[str, Any]) -> TaskRow:
        return run_one(task, sentrix)

    rows = run_live_suite(tasks, runner, output_path=args.output)
    from collections import Counter

    print("outcome distribution:", dict(Counter(r.outcome.value for r in rows)))
    print(f"wrote {len(rows)} rows to {args.output or 'tests/fixtures/live_results/'}")


if __name__ == "__main__":
    main()
