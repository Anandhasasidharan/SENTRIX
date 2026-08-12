from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class TaintFlow:
    source: str
    sink: str
    file_path: str
    line_number: int
    source_type: str = "llm_output"
    sink_type: str = "unknown"
    validated: bool = False
    severity: str = "medium"


@dataclass
class AnalysisResult:
    file_path: str
    flaws: list[TaintFlow] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


VALIDATION_FUNCTIONS: set[str] = {
    "sanitize", "sanitize_input", "sanitize_sql", "sanitize_html",
    "validate_input", "validate_sql", "validate_path", "validate_url",
    "escape_shell", "escape_shell_arg", "shell_escape",
    "clean_input", "cleanse", "purify",
    "is_safe_path", "is_valid_url", "is_valid_email",
}

SENSITIVE_SINKS: dict[str, str] = {
    "subprocess.run": "shell_execution",
    "subprocess.Popen": "shell_execution",
    "os.system": "shell_execution",
    "os.popen": "shell_execution",
    "exec": "code_execution",
    "eval": "code_execution",
    "open": "file_write",
    "write": "file_write",
    "writelines": "file_write",
    "pathlib.Path.write_text": "file_write",
    "pathlib.Path.write_bytes": "file_write",
    "requests.post": "outbound_request",
    "requests.get": "outbound_request",
    "httpx.post": "outbound_request",
    "httpx.get": "outbound_request",
    "cursor.execute": "db_query",
    "db.session.execute": "db_query",
    "conn.execute": "db_query",
}

LLM_OUTPUT_SOURCES = {
    "response.content",
    "completion.text",
    "message.content",
    "llm_response",
    "model.generate",
    "client.generate",
}


class TaintTracker:
    def __init__(self):
        self.results: list[AnalysisResult] = []

    def scan_file(self, filepath: str | Path) -> AnalysisResult:
        path = Path(filepath)
        result = AnalysisResult(file_path=str(path))
        try:
            tree = ast.parse(path.read_text(), filename=str(path))
        except SyntaxError as e:
            result.errors.append(f"Syntax error: {e}")
            self.results.append(result)
            return result

        visitor = _TaintVisitor(str(path))
        visitor.visit(tree)
        result.flaws = visitor.flows
        result.errors = visitor.errors
        self.results.append(result)
        return result

    def scan_directory(self, directory: str | Path) -> list[AnalysisResult]:
        path = Path(directory)
        results = []
        for pyfile in path.rglob("*.py"):
            if "site-packages" in str(pyfile) or ".venv" in str(pyfile):
                continue
            results.append(self.scan_file(pyfile))
        return results


class _TaintVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.flows: list[TaintFlow] = []
        self.errors: list[str] = []
        self._tainted_vars: dict[str, int] = {}
        self._validated_vars: set[str] = set()

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Call):
            call = node.value
            call_name = self._get_call_name(call)
            if call_name in VALIDATION_FUNCTIONS:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        for arg in call.args:
                            arg_name = self._get_value_name(arg)
                            if arg_name and arg_name in self._tainted_vars:
                                self._tainted_vars[target.id] = node.lineno
                                self._validated_vars.add(target.id)
            self._check_llm_source(call, node.targets)
        elif isinstance(node.value, ast.Attribute) or isinstance(node.value, ast.Subscript):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    value_name = self._get_value_name(node.value)
                    if value_name and value_name in self._tainted_vars:
                        self._tainted_vars[target.id] = node.lineno
        self.generic_visit(node)

    def _get_value_name(self, node: ast.expr) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return self._get_value_name(node.value)
        if isinstance(node, ast.Subscript):
            return self._get_value_name(node.value)
        return None

    def visit_Call(self, node: ast.Call) -> None:
        call_name = self._get_call_name(node)
        if call_name in VALIDATION_FUNCTIONS:
            for arg in node.args:
                arg_name = self._get_value_name(arg)
                if arg_name and arg_name in self._tainted_vars:
                    self._validated_vars.add(arg_name)
                if arg_name and arg_name in self._validated_vars:
                    pass
            for target in getattr(node, 'targets', []):
                pass
            self.generic_visit(node)
            return

        sink_type = self._match_sink(call_name)
        if sink_type:
            for arg in node.args:
                if self._is_tainted(arg):
                    arg_name = self._get_value_name(arg)
                    validated = arg_name is not None and arg_name in self._validated_vars
                    self.flows.append(
                        TaintFlow(
                            source=self._find_source(arg),
                            sink=call_name,
                            file_path=self.file_path,
                            line_number=node.lineno,
                            sink_type=sink_type,
                            validated=validated,
                            severity="low" if validated else "high",
                        )
                    )
            for kw in node.keywords:
                if kw.arg in ("query", "command", "sql", "url", "data") and self._is_tainted(kw.value):
                    arg_name = self._get_value_name(kw.value)
                    validated = arg_name is not None and arg_name in self._validated_vars
                    self.flows.append(
                        TaintFlow(
                            source=self._find_source(kw.value),
                            sink=call_name,
                            file_path=self.file_path,
                            line_number=node.lineno,
                            sink_type=sink_type,
                            validated=validated,
                            severity="low" if validated else "high",
                        )
                    )
        self.generic_visit(node)

    def _match_sink(self, name: str) -> str | None:
        if name in SENSITIVE_SINKS:
            return SENSITIVE_SINKS[name]
        for pattern, sink_type in SENSITIVE_SINKS.items():
            if pattern.startswith(".") and name.endswith(pattern):
                return sink_type
        return None

    def _check_llm_source(
        self, call: ast.Call, targets: list[ast.expr]
    ) -> None:
        name = self._get_call_name(call)
        if any(src in name for src in LLM_OUTPUT_SOURCES):
            for target in targets:
                if isinstance(target, ast.Name):
                    self._tainted_vars[target.id] = call.lineno

    def _is_tainted(self, node: ast.expr) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self._tainted_vars
        if isinstance(node, ast.Subscript):
            return self._is_tainted(node.value)
        if isinstance(node, ast.Attribute):
            return self._is_tainted(node.value)
        return False

    def _find_source(self, node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return self._find_source(node.value) + "." + node.attr
        if isinstance(node, ast.Subscript):
            return self._find_source(node.value) + "[...]"
        return ast.dump(node)[:50]

    def _get_call_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return self._get_attr_chain(node.func)
        return ""

    def _get_attr_chain(self, node: ast.Attribute) -> str:
        parts = []
        current = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))
