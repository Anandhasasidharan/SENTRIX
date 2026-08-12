from sentrix.classifier.detector import Classifier
from sentrix.harness.agentdyn import (
    AGENTDYN_TASKS,
    AgentDynEvaluator,
    agentdyn_to_attacks,
    summary_by_domain,
)
from sentrix.harness.dual_benchmark import DualBenchmarkEvaluator
from sentrix.models.policy import AgentPolicy, DataSensitivity


class TestAgentDyn:
    def test_converts_to_attack_templates(self):
        attacks = agentdyn_to_attacks()
        assert len(attacks) == len(AGENTDYN_TASKS)
        for a, t in zip(attacks, AGENTDYN_TASKS):
            assert a.name == t["name"]
            assert a.domain == t["domain"]
            assert a.payload == t["payload"]

    def test_evaluator_returns_report(self):
        classifier = Classifier(use_embeddings=False)
        evaluator = AgentDynEvaluator(classifier=classifier)
        report = evaluator.evaluate()
        assert report["total"] == len(AGENTDYN_TASKS)
        assert report["correct"] >= 0
        assert report["missed"] >= 0
        assert "by_domain" in report

    def test_evaluator_with_monitor(self):
        from sentrix.dual_llm.context_manager import ContextManager
        from sentrix.core.reference_monitor import ReferenceMonitor

        ctx = ContextManager()
        monitor = ReferenceMonitor(ctx)
        policy = AgentPolicy(
            agent_id="agentdyn_agent",
            allowed_tools=["read_file", "list_dir", "send_email", "search_web", "store_memory"],
            blocked_tools=["delete_file", "exec_command", "modify_system"],
        )
        monitor.configure("agentdyn_agent", policy)
        ctx.verify_isolation()

        classifier = Classifier(use_embeddings=False)
        evaluator = AgentDynEvaluator(reference_monitor=monitor, classifier=classifier)
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

    def test_expanded_coverage_24_tasks(self):
        assert len(AGENTDYN_TASKS) == 24
        domains = summary_by_domain()
        assert sum(domains.values()) == 24
        for d, count in domains.items():
            assert count == 4, f"Domain {d} should have 4 tasks, got {count}"

    def test_evaluator_reports_by_domain(self):
        classifier = Classifier(use_embeddings=False)
        evaluator = AgentDynEvaluator(classifier=classifier)
        report = evaluator.evaluate()
        assert "by_domain" in report
        assert len(report["by_domain"]) == 6
        for domain, info in report["by_domain"].items():
            assert info["total"] == 4
            assert "block_rate" in info


class TestDualBenchmark:
    def test_dual_benchmark_returns_both_reports(self):
        from sentrix.dual_llm.context_manager import ContextManager
        from sentrix.core.reference_monitor import ReferenceMonitor

        ctx = ContextManager()
        monitor = ReferenceMonitor(ctx)
        policy = AgentPolicy(
            agent_id="dual_agent",
            allowed_tools=["read_file", "list_dir", "send_email", "search_web", "store_memory"],
            blocked_tools=["delete_file", "exec_command", "modify_system"],
        )
        monitor.configure("dual_agent", policy)

        classifier = Classifier(use_embeddings=False)
        evaluator = DualBenchmarkEvaluator(reference_monitor=monitor, classifier=classifier)
        report = evaluator.evaluate()

        assert "agentdojo" in report
        assert "agentdyn" in report
        assert "comparison" in report
        assert report["agentdojo"]["block_rate"] is not None
        assert report["agentdyn"]["block_rate"] is not None
        assert report["comparison"]["delta"] is not None

    def test_dual_benchmark_by_domain(self):
        classifier = Classifier(use_embeddings=False)
        evaluator = DualBenchmarkEvaluator(classifier=classifier)
        report = evaluator.evaluate()

        assert "by_domain" in report
        for domain, data in report["by_domain"].items():
            assert "agentdojo" in data
            assert "agentdyn" in data
            assert "delta" in data
