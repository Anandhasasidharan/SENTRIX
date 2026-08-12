from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sentrix.classifier.detector import Classifier
from sentrix.harness.obfuscator import AttackTemplate, MCP_SPECIFIC_ATTACKS, STANDARD_ATTACKS
from sentrix.harness.obfuscator import Obfuscator
from sentrix.models.events import ActionVerdict, DetectorLayer, TraceEvent
from sentrix.replay.timeline import AttackDAGBuilder, Timeline


@dataclass
class AttackResult:
    attack_name: str
    domain: str
    original_payload: str
    obfuscated_payload: str | None = None
    obfuscation_technique: str | None = None
    monitor_blocked: bool = False
    classifier_triggered: bool = False
    got_through: bool = False
    details: str = ""


@dataclass
class EvalSummary:
    domain: str
    total_attacks: int
    blocked: int
    block_rate: float
    got_through: int
    results: list[AttackResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "total": self.total_attacks,
            "blocked": self.blocked,
            "block_rate": f"{self.block_rate:.1%}",
            "got_through": self.got_through,
        }


class Evaluator:
    def __init__(self, reference_monitor=None, classifier: Classifier | None = None):
        self._monitor = reference_monitor
        self._classifier = classifier or Classifier(threshold=0.5)
        self._obfuscator = Obfuscator(seed=42)
        self._results: list[AttackResult] = []
        self._timeline = Timeline()
        self._dag_builder = AttackDAGBuilder()

    def set_monitor(self, monitor) -> None:
        self._monitor = monitor

    def run_standard(self, attacks: list[AttackTemplate] | None = None) -> list[AttackResult]:
        targets = attacks or STANDARD_ATTACKS
        results: list[AttackResult] = []
        for attack in targets:
            result = self._test_single(attack, obfuscate=False)
            self._results.append(result)
            results.append(result)
        return results

    def run_obfuscated(
        self,
        attacks: list[AttackTemplate] | None = None,
        techniques: list[str] | None = None,
    ) -> list[AttackResult]:
        targets = attacks or STANDARD_ATTACKS
        results: list[AttackResult] = []
        for attack in targets:
            result = self._test_single(attack, obfuscate=True, techniques=techniques)
            self._results.append(result)
            results.append(result)
        return results

    def _test_single(
        self,
        attack: AttackTemplate,
        obfuscate: bool = False,
        techniques: list[str] | None = None,
    ) -> AttackResult:
        payload = attack.payload
        obfuscated_payload = None
        obfuscation_technique = None

        if obfuscate:
            tech = techniques or ["base64", "braille", "homoglyph", "paraphrase_polite"]
            obfuscation_technique = tech[0]
            obfuscated_payload = self._obfuscator.apply_random(payload, tech)
            test_input = obfuscated_payload
        else:
            test_input = payload

        result = AttackResult(
            attack_name=attack.name,
            domain=attack.domain,
            original_payload=payload,
        )

        classifier_result = self._classifier.analyze_query(test_input)
        result.classifier_triggered = classifier_result.triggered

        if self._monitor:
            verdict, event = self._monitor.check_tool_call(
                tool_name="test_tool",
                arguments={"input": test_input},
                data_ids=[],
            )
            if event:
                self._timeline.add_event(event)
                self._dag_builder.add_event(event)

            if verdict == ActionVerdict.BLOCKED:
                result.monitor_blocked = True
                result.got_through = False
                result.details = event.metadata.get("block_reason", "Blocked by reference monitor")
            else:
                result.monitor_blocked = False
                result.got_through = not classifier_result.triggered
                result.details = (
                    "Caught by classifier"
                    if classifier_result.triggered
                    else "Got through all defenses"
                )
        else:
            result.monitor_blocked = False
            if classifier_result.triggered:
                result.got_through = False
                result.details = "Caught by classifier"
            else:
                result.got_through = True
                result.details = "No monitor configured, passed classifier"

        if obfuscate:
            result.obfuscated_payload = obfuscated_payload
            result.obfuscation_technique = obfuscation_technique

        return result

    def summary_by_domain(self) -> list[EvalSummary]:
        domains: dict[str, list[AttackResult]] = {}
        for r in self._results:
            domains.setdefault(r.domain, []).append(r)

        summaries = []
        for domain, results in sorted(domains.items()):
            blocked = sum(1 for r in results if r.monitor_blocked or r.classifier_triggered)
            got_through = sum(1 for r in results if r.got_through)
            summaries.append(
                EvalSummary(
                    domain=domain,
                    total_attacks=len(results),
                    blocked=blocked,
                    block_rate=blocked / max(len(results), 1),
                    got_through=got_through,
                    results=results,
                )
            )
        return summaries

    def run_mcp_specific(
        self,
        attacks: list[AttackTemplate] | None = None,
    ) -> list[AttackResult]:
        targets = attacks or MCP_SPECIFIC_ATTACKS
        results: list[AttackResult] = []
        for attack in targets:
            result = self._test_single(attack, obfuscate=False)
            self._results.append(result)
            results.append(result)

            if "resource-quota" in attack.payload.lower() or "quota" in attack.payload.lower():
                if not result.monitor_blocked:
                    result.details += " [GAP: no resource-quota dimension in capability policy]"
        return results

    def compare_block_rates(self) -> dict[str, Any]:
        standard_results = [r for r in self._results if not r.obfuscated_payload]
        obfuscated_results = [r for r in self._results if r.obfuscated_payload]

        def block_count(results: list[AttackResult]) -> int:
            return sum(1 for r in results if r.monitor_blocked or r.classifier_triggered)

        return {
            "standard": {
                "total": len(standard_results),
                "blocked": block_count(standard_results),
                "block_rate": f"{block_count(standard_results) / max(len(standard_results), 1):.1%}",
                "got_through": len(standard_results) - block_count(standard_results),
            },
            "obfuscated": {
                "total": len(obfuscated_results),
                "blocked": block_count(obfuscated_results),
                "block_rate": f"{block_count(obfuscated_results) / max(len(obfuscated_results), 1):.1%}",
                "got_through": len(obfuscated_results) - block_count(obfuscated_results),
            },
            "delta": {
                "block_rate_change": (
                    f"{(block_count(obfuscated_results) / max(len(obfuscated_results), 1) - block_count(standard_results) / max(len(standard_results), 1)):.1%}"
                    if standard_results and obfuscated_results
                    else "N/A"
                ),
            },
        }
