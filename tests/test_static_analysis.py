import tempfile
from pathlib import Path

import pytest

from sentrix.static_analysis.taint_tracker import TaintTracker


class TestTaintTracker:
    @pytest.fixture
    def tracker(self):
        return TaintTracker()

    def _write_temp_py(self, content: str) -> str:
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        )
        tmp.write(content)
        tmp.close()
        return tmp.name

    def test_detects_llm_output_to_shell(self, tracker):
        code = """
response = model.generate("user query")
result = response.content
import os
os.system(result)
"""
        path = self._write_temp_py(code)
        result = tracker.scan_file(path)
        assert len(result.flaws) >= 1
        assert any(
            "os.system" in flaw.sink or "system" in flaw.sink
            for flaw in result.flaws
        )

    def test_detects_llm_output_to_file_write(self, tracker):
        code = """
response = model.generate("prompt")
user_content = response.content
result = open("output.txt", "w").write(user_content)
"""
        path = self._write_temp_py(code)
        result = tracker.scan_file(path)
        assert len(result.flaws) >= 1

    def test_clean_code_no_flaws(self, tracker):
        code = """
def greet(name: str) -> str:
    return f"Hello, {name}!"

def main():
    print(greet("World"))
"""
        path = self._write_temp_py(code)
        result = tracker.scan_file(path)
        assert len(result.flaws) == 0

    def test_syntax_error_returns_error(self, tracker):
        path = self._write_temp_py("this is not valid python @@@")
        result = tracker.scan_file(path)
        assert len(result.errors) >= 1

    def test_detects_db_query_injection(self, tracker):
        code = """
response = client.generate("prompt")
query = response.content
cursor.execute(query)
"""
        path = self._write_temp_py(code)
        result = tracker.scan_file(path)
        assert len(result.flaws) >= 1

    def test_validated_flow_marked_low_severity(self, tracker):
        code = """
response = model.generate("user query")
raw = response.content
safe = sanitize_input(raw)
os.system(safe)
"""
        path = self._write_temp_py(code)
        result = tracker.scan_file(path)
        assert len(result.flaws) >= 1
        assert result.flaws[0].validated
        assert result.flaws[0].severity == "low"

    def test_unvalidated_flow_marked_high_severity(self, tracker):
        code = """
response = model.generate("user query")
result = response.content
os.system(result)
"""
        path = self._write_temp_py(code)
        result = tracker.scan_file(path)
        assert len(result.flaws) >= 1
        assert not result.flaws[0].validated
        assert result.flaws[0].severity == "high"
