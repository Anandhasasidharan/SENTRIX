from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class DetectionResult:
    detected: bool
    score: float
    pattern_name: str
    evidence: str
    severity: str = "medium"


INJECTION_PATTERNS: list[tuple[str, str, str]] = [
    ("ignore_previous", r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|commands|directives)", "high"),
    ("forget_instructions", r"(?i)(forget|disregard|override|overwrite)\s+(your\s+|all\s+|any\s+)?(prior\s+|previous\s+)?(instructions|rules|guidelines|prompt|directions|commands|directives)", "high"),
    ("role_play", r"(?i)you\s+are\s+(now|from\s+now\s+on)\s+(\w+\s*)+", "medium"),
    ("system_prompt_extract", r"(?i)(output|print|show|reveal|display|leak)\s+(all\s+)?(your\s+)?(system\s+)?(instructions|prompt|rules)|initialization|system\s+prompt", "high"),
    ("delimiter_escape", r"(?i)(ignore|bypass|break\s+out\s+of)\s+(delimiter|boundary|marker|tag)", "medium"),
    ("hypothetical", r"(?i)(hypothetical|imagine|pretend)\s+(scenario|situation|you\s+are)", "low"),
    ("tool_hijack", r"(?i)(call|invoke|execute|run)\s+(tool|function|command|action|delete)", "high"),
    ("data_exfil", r"(?i)(send|upload|exfiltrate|transmit|forward|copy)\s+(data|file|content|info)\s+(to|via|using)", "high"),
]


MEMORY_POISON_PATTERNS: list[tuple[str, str, str]] = [
    ("identity_rewrite", r"(?i)(actually|from\s+now\s+on)\s+(my|your)\s+(name|role|identity|creator)\s+is", "high"),
    ("instruction_injection", r"(?i)(remember|store|save|record)\s+(this\s+)?(instruction|command|rule)", "high"),
    ("authority_override", r"(?i)I\s+am\s+(your\s+)?(creator|owner|administrator|system)", "medium"),
]


TOOL_ANOMALY_PATTERNS: list[tuple[str, str, str]] = [
    ("high_frequency", r"(?i)(repeated|cascade|chain|recursive|loop)\s+(call|invocation)", "medium"),
    ("privilege_escalation", r"(?i)(admin|sudo|root|superuser|elevate|escalate)", "high"),
    ("credential_access", r"(?i)(password|token|api[_-]?key|secret|credential|auth)", "high"),
]


class PatternDetector:
    def __init__(self):
        self._patterns: list[tuple[str, re.Pattern, str]] = []
        for name, pattern_str, severity in (
            INJECTION_PATTERNS + MEMORY_POISON_PATTERNS + TOOL_ANOMALY_PATTERNS
        ):
            self._patterns.append((name, re.compile(pattern_str), severity))

    def scan(self, text: str) -> list[DetectionResult]:
        results: list[DetectionResult] = []
        for name, compiled, severity in self._patterns:
            match = compiled.search(text)
            if match:
                results.append(
                    DetectionResult(
                        detected=True,
                        score=1.0,
                        pattern_name=name,
                        evidence=match.group(),
                        severity=severity,
                    )
                )
        return results

    def score_text(self, text: str) -> float:
        matches = self.scan(text)
        if not matches:
            return 0.0
        severity_weights = {"low": 0.3, "medium": 0.6, "high": 1.0}
        return min(
            1.0,
            sum(severity_weights.get(m.severity, 0.5) for m in matches)
            / max(len(matches), 1),
        )


class ClassifierResult:
    def __init__(self):
        self.injection_results: list[DetectionResult] = []
        self.memory_results: list[DetectionResult] = []
        self.tool_results: list[DetectionResult] = []
        self.composite_score: float = 0.0
        self.triggered: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "triggered": self.triggered,
            "composite_score": self.composite_score,
            "injection_detections": [
                {"pattern": r.pattern_name, "severity": r.severity, "evidence": r.evidence}
                for r in self.injection_results
            ],
            "memory_detections": [
                {"pattern": r.pattern_name, "severity": r.severity, "evidence": r.evidence}
                for r in self.memory_results
            ],
            "tool_anomalies": [
                {"pattern": r.pattern_name, "severity": r.severity, "evidence": r.evidence}
                for r in self.tool_results
            ],
        }


class Classifier:
    def __init__(self, threshold: float = 0.5, use_embeddings: bool = True):
        self._pattern_detector = PatternDetector()
        self._threshold = threshold
        self._embedding: Any = None
        if use_embeddings:
            try:
                from sentrix.classifier.embedding import EmbeddingClassifier
                emb = EmbeddingClassifier(threshold=0.65)
                emb.fit()
                self._embedding = emb
            except Exception as exc:
                import logging
                logging.getLogger(__name__).warning(
                    "Embedding classifier unavailable: %s. "
                    "Falling back to regex-only.", exc
                )
                self._embedding = None

    def analyze_query(self, query: str) -> ClassifierResult:
        result = ClassifierResult()
        result.injection_results = self._pattern_detector.scan(query)
        result.composite_score = self._pattern_detector.score_text(query)
        result.triggered = result.composite_score >= self._threshold

        if self._embedding and not result.triggered:
            emb_result = self._embedding.analyze(query)
            if emb_result.triggered:
                result.injection_results.extend(emb_result.injection_results)
                result.composite_score = max(result.composite_score, emb_result.composite_score)
                result.triggered = True

        return result

    def analyze_tool_call(self, tool_name: str, arguments: str) -> ClassifierResult:
        result = ClassifierResult()
        combined = f"{tool_name}: {arguments}"
        result.injection_results = self._pattern_detector.scan(combined)
        result.tool_results = [
            r for r in result.injection_results
            if r.pattern_name in [p[0] for p in TOOL_ANOMALY_PATTERNS]
        ]
        result.composite_score = self._pattern_detector.score_text(combined)
        result.triggered = result.composite_score >= self._threshold

        if self._embedding and not result.triggered:
            emb_result = self._embedding.analyze(combined)
            if emb_result.triggered:
                result.injection_results.extend(emb_result.injection_results)
                result.composite_score = max(result.composite_score, emb_result.composite_score)
                result.triggered = True

        return result

    def analyze_memory_diff(self, old: str, new: str) -> ClassifierResult:
        result = ClassifierResult()
        diff = self._compute_diff(old, new)
        result.memory_results = self._pattern_detector.scan(diff)
        new_content = self._extract_new_content(old, new)
        result.injection_results = self._pattern_detector.scan(new_content)
        combined = diff + " " + new_content
        result.composite_score = self._pattern_detector.score_text(combined)
        result.triggered = result.composite_score >= self._threshold

        if self._embedding and not result.triggered:
            emb_result = self._embedding.analyze(combined)
            if emb_result.triggered:
                result.injection_results.extend(emb_result.injection_results)
                result.composite_score = max(result.composite_score, emb_result.composite_score)
                result.triggered = True

        return result

    def _compute_diff(self, old: str, new: str) -> str:
        old_lines = set(old.splitlines())
        new_lines = new.splitlines()
        return "\n".join(line for line in new_lines if line not in old_lines)

    def _extract_new_content(self, old: str, new: str) -> str:
        if new.startswith(old):
            return new[len(old) :]
        return self._compute_diff(old, new)
