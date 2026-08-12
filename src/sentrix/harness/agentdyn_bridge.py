from __future__ import annotations

import logging
import os
from typing import Any

from sentrix.harness.agentdyn import AgentDynEvaluator, AGENTDYN_TASKS
from sentrix.harness.dual_benchmark import DualBenchmarkEvaluator

logger = logging.getLogger(__name__)

AGENTDYN_REPO_PATH = os.environ.get(
    "AGENTDYN_REPO_PATH",
    "/tmp/agentdyn-clone",
)


def _discover_real_tasks() -> list[dict[str, Any]] | None:
    if not os.path.isdir(AGENTDYN_REPO_PATH):
        return None
    try:
        import ast
        import importlib.util

        tasks: list[dict[str, Any]] = []
        suite_base = os.path.join(AGENTDYN_REPO_PATH, "src", "agentdojo", "default_suites")
        if not os.path.isdir(suite_base):
            return None

        for domain in os.listdir(suite_base):
            domain_path = os.path.join(suite_base, domain)
            if not os.path.isdir(domain_path) or domain.startswith("_"):
                continue

            injection_path = os.path.join(domain_path, "injection_tasks.py")
            if os.path.isfile(injection_path):
                with open(injection_path) as f:
                    tree = ast.parse(f.read())
                for node in ast.walk(tree):
                    if isinstance(node, ast.ClassDef):
                        for base in node.bases:
                            if isinstance(base, ast.Call) and hasattr(base.func, 'attr') and base.func.attr == 'register_injection_task':
                                pass
                        goal = _extract_goal_from_class(node, tree)
                        if goal:
                            tasks.append({
                                "id": f"{domain}_{node.name.lower()}",
                                "name": node.name,
                                "description": goal[:100],
                                "domain": domain,
                                "payload": goal,
                                "expected_action": "blocked",
                                "expected_tool": "send_email",
                            })

        if tasks:
            logger.info("Discovered %d real AgentDyn injection tasks from %s", len(tasks), AGENTDYN_REPO_PATH)
            return tasks
    except Exception as e:
        logger.warning("Failed to load real AgentDyn tasks: %s", e)
    return None


def _extract_goal_from_class(node: ast.ClassDef, tree: ast.Module) -> str | None:
    for item in node.body:
        if isinstance(item, ast.Assign):
            for target in item.targets:
                if isinstance(target, ast.Name) and target.id == "GOAL":
                    if isinstance(item.value, ast.Constant) and isinstance(item.value.value, str):
                        return item.value.value
    return None


REAL_TASKS = _discover_real_tasks()


def get_agentdyn_tasks() -> list[dict[str, Any]]:
    if REAL_TASKS:
        logger.info("Using %d real AgentDyn tasks", len(REAL_TASKS))
        return REAL_TASKS
    logger.info("AgentDyn repo not found at %s — using %d simulated tasks", AGENTDYN_REPO_PATH, len(AGENTDYN_TASKS))
    return AGENTDYN_TASKS


class RealAwareAgentDynEvaluator(AgentDynEvaluator):
    def evaluate(self, tasks=None, policy=None):
        used_tasks = tasks or get_agentdyn_tasks()
        return super().evaluate(tasks=used_tasks, policy=policy)


class RealAwareDualBenchmarkEvaluator(DualBenchmarkEvaluator):
    def __init__(self, reference_monitor=None, classifier=None):
        self._dojo = __import__("sentrix.harness.agentdojo", fromlist=["AgentDojoEvaluator"]).AgentDojoEvaluator(
            reference_monitor=reference_monitor,
            classifier=classifier,
        )
        self._dyn = RealAwareAgentDynEvaluator(
            reference_monitor=reference_monitor,
            classifier=classifier,
        )
