from __future__ import annotations

from typing import Any

from sentrix.harness.agentdojo import AGENTDOJO_TASKS, AgentDojoEvaluator
from sentrix.harness.agentdyn import AGENTDYN_TASKS, AgentDynEvaluator
from sentrix.models.policy import AgentPolicy


class DualBenchmarkEvaluator:
    def __init__(self, reference_monitor=None, classifier=None):
        self._dojo = AgentDojoEvaluator(
            reference_monitor=reference_monitor,
            classifier=classifier,
        )
        self._dyn = AgentDynEvaluator(
            reference_monitor=reference_monitor,
            classifier=classifier,
        )

    def evaluate(
        self,
        policy: AgentPolicy | None = None,
    ) -> dict[str, Any]:
        dojo_report = self._dojo.evaluate(policy=policy)
        dyn_report = self._dyn.evaluate(policy=policy)

        dojo_rate_str = dojo_report["block_rate"]
        dyn_rate_str = dyn_report["block_rate"]

        dojo_rate = float(dojo_rate_str.rstrip("%")) / 100
        dyn_rate = float(dyn_rate_str.rstrip("%")) / 100

        all_domains = sorted(
            set(list(dojo_report["by_domain"].keys()) + list(dyn_report["by_domain"].keys()))
        )

        comparison_by_domain = {}
        for domain in all_domains:
            dojo_d = dojo_report["by_domain"].get(domain, {"total": 0, "correct": 0, "block_rate": "N/A"})
            dyn_d = dyn_report["by_domain"].get(domain, {"total": 0, "correct": 0, "block_rate": "N/A"})
            comparison_by_domain[domain] = {
                "agentdojo": dojo_d,
                "agentdyn": dyn_d,
                "delta": (
                    f"{(float(dojo_d['block_rate'].rstrip('%')) - float(dyn_d['block_rate'].rstrip('%'))) / 100:+.0%}"
                    if dojo_d["block_rate"] != "N/A" and dyn_d["block_rate"] != "N/A"
                    else "N/A"
                ),
            }

        return {
            "agentdojo": {
                "total": dojo_report["total"],
                "correct": dojo_report["correct"],
                "missed": dojo_report["missed"],
                "block_rate": dojo_report["block_rate"],
                "by_domain": dojo_report["by_domain"],
            },
            "agentdyn": {
                "total": dyn_report["total"],
                "correct": dyn_report["correct"],
                "missed": dyn_report["missed"],
                "block_rate": dyn_report["block_rate"],
                "by_domain": dyn_report["by_domain"],
            },
            "comparison": {
                "agentdojo_rate": dojo_rate_str,
                "agentdyn_rate": dyn_rate_str,
                "delta": f"{dyn_rate - dojo_rate:+.0%}",
                "note": (
                    "AgentDyn includes dynamic/open-ended tasks, mixed benign+malicious context, "
                    "and delayed-reveal instructions — making it a harder benchmark than AgentDojo. "
                    "A lower block rate on AgentDyn is expected and honest."
                ),
            },
            "by_domain": comparison_by_domain,
        }
