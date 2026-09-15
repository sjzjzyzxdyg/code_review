from pathlib import Path

import pytest

from app.tools.cppcheck_tool import CppcheckTool

_SAMPLE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<results version="2">
  <errors>
    <error id="nullPointer" severity="error" msg="Null pointer dereference" verbose="Null pointer dereference">
      <location file="src/main.cpp" line="42" column="5"/>
    </error>
    <error id="variableScope" severity="style" msg="Variable scope can be reduced">
      <location file="src/main.cpp" line="10" column="1"/>
    </error>
    <error id="missingInclude" severity="information" msg="Include file not found">
    </error>
  </errors>
</results>
"""


def test_parse_xml_extracts_findings_and_drops_locationless_entries() -> None:
    tool = CppcheckTool()

    findings = tool._parse_xml(_SAMPLE_XML)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "nullPointer"
    assert findings[0]["severity"] == "error"
    assert findings[0]["file_path"] == "src/main.cpp"
    assert findings[0]["line"] == 42
    assert findings[0]["column"] == 5


def test_parse_xml_suppresses_noise_ids() -> None:
    tool = CppcheckTool()

    findings = tool._parse_xml(_SAMPLE_XML)

    assert all(f["rule_id"] != "variableScope" for f in findings)


def test_parse_xml_handles_empty_and_malformed_input() -> None:
    tool = CppcheckTool()

    assert tool._parse_xml("") == []
    assert tool._parse_xml("not xml") == []


def test_run_with_empty_target_files_skips_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    tool = CppcheckTool()
    called = False

    def fake_run(*args, **kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr("subprocess.run", fake_run)

    findings = tool.run(Path("/some/project"), target_files=[])

    assert findings == []
    assert called is False


def test_run_with_target_files_passes_explicit_files_not_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tool = CppcheckTool()
    captured_command: list[str] = []

    class FakeResult:
        stderr = ""

    def fake_run(command, **kwargs):
        captured_command.extend(command)
        return FakeResult()

    monkeypatch.setattr("subprocess.run", fake_run)
    changed = tmp_path / "changed.cpp"

    tool.run(tmp_path, target_files=[changed])

    assert str(changed) in captured_command
    assert str(tmp_path) not in captured_command
