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
