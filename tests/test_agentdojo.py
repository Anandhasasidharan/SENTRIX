from sentrix.classifier.detector import Classifier
from sentrix.harness.agentdojo import (
    AGENTDOJO_TASKS,
    AgentDojoEvaluator,
    agentdojo_to_attacks,
    summary_by_domain,
)
from sentrix.models.policy import AgentPolicy, DataSensitivity


class TestAgentDojo:
    def test_converts_to_attack_templates(self):
        attacks = agentdojo_to_attacks()
        assert len(attacks) == len(AGENTDOJO_TASKS)
        for a, t in zip(attacks, AGENTDOJO_TASKS):
            assert a.name == t["name"]
            assert a.domain == t["domain"]
            assert a.payload == t["payload"]

    def test_evaluator_returns_report(self):
        classifier = Classifier(use_embeddings=False)
        evaluator = AgentDojoEvaluator(classifier=classifier)
        report = evaluator.evaluate()
        assert report["total"] == len(AGENTDOJO_TASKS)
        assert report["correct"] >= 0
        assert report["missed"] >= 0
        assert len(report["results"]) == len(AGENTDOJO_TASKS)
        for r in report["results"]:
            assert "id" in r
            assert "passed" in r

    def test_evaluator_with_monitor(self):
        from sentrix.dual_llm.context_manager import ContextManager
        from sentrix.core.reference_monitor import ReferenceMonitor

        ctx = ContextManager()
        monitor = ReferenceMonitor(ctx)
        policy = AgentPolicy(
            agent_id="dojo_agent",
            allowed_tools=["read_file", "list_dir", "send_email", "search_web", "store_memory"],
            blocked_tools=["delete_file", "exec_command", "modify_system"],
        )
        monitor.configure("dojo_agent", policy)
        ctx.verify_isolation()

        classifier = Classifier(use_embeddings=False)
        evaluator = AgentDojoEvaluator(reference_monitor=monitor, classifier=classifier)
        report = evaluator.evaluate()

        assert report["block_rate"] is not None
        blocked_tasks = [r for r in report["results"] if r["expected"] == "blocked"]
        for r in blocked_tasks:
            assert r["monitor_blocked"] or r["classifier_triggered"], (
                f"Task {r['id']} ({r['name']}) should be blocked but wasn't"
            )

    def test_summary_by_domain(self):
        domains = summary_by_domain()
        assert "workspace" in domains
        assert "email" in domains
        assert "banking" in domains
        assert "slack" in domains
        assert "travel" in domains
        assert "chain" in domains
        for d, count in domains.items():
            assert count == 5, f"Domain {d} should have 5 tasks, got {count}"

    def test_expanded_coverage_30_tasks(self):
        assert len(AGENTDOJO_TASKS) == 30
        domains = summary_by_domain()
        assert sum(domains.values()) == 30
        blocked = sum(1 for t in AGENTDOJO_TASKS if t["expected_action"] == "blocked")
        flagged = sum(1 for t in AGENTDOJO_TASKS if t["expected_action"] == "flagged")
        assert blocked > 0
        assert flagged > 0
        assert blocked + flagged == 30

    def test_all_domains_covered(self):
        domains_in_tasks = set(t["domain"] for t in AGENTDOJO_TASKS)
        expected = {"workspace", "email", "banking", "slack", "travel", "chain"}
        assert domains_in_tasks == expected

    def test_evaluator_reports_by_domain(self):
        classifier = Classifier(use_embeddings=False)
        evaluator = AgentDojoEvaluator(classifier=classifier)
        report = evaluator.evaluate()
        assert "by_domain" in report
        assert len(report["by_domain"]) == 6
        for domain, info in report["by_domain"].items():
            assert info["total"] == 5
            assert "block_rate" in info

    def test_evaluator_auto_configures_unconfigured_monitor(self):
        from sentrix.dual_llm.context_manager import ContextManager
        from sentrix.core.reference_monitor import ReferenceMonitor

        ctx = ContextManager()
        monitor = ReferenceMonitor(ctx)
        ctx.verify_isolation()

        classifier = Classifier(use_embeddings=False)
        evaluator = AgentDojoEvaluator(reference_monitor=monitor, classifier=classifier)
        report = evaluator.evaluate()

        assert report["block_rate"] is not None
        blocked_tasks = [r for r in report["results"] if r["expected"] == "blocked"]
        for r in blocked_tasks:
            assert r["monitor_blocked"] or r["classifier_triggered"], (
                f"Task {r['id']} ({r['name']}) should be blocked but wasn't"
            )
        assert report["block_rate"] != "0%", (
            "Monitor silently defaulted to 0% block rate — policy was never applied"
        )
