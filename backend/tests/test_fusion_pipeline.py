"""Tests for the dual-path pipeline: CWE mapping, function index, semantic
audit slicing/parsing, fusion routing, and the end-to-end review stage."""

import json
from pathlib import Path

import pytest

from app.agents.semantic_audit_agent import SemanticAuditAgent
from app.core import cwe
from app.core.db import Database
from app.schemas.review import ReviewTaskCreate
from app.services import review_service as review_service_module
from app.services.fusion import fuse
from app.services.issue_service import issue_service
from app.services.report_service import report_service
from app.services.suppression_service import suppression_service
from app.tools.code_index import CodeIndex, parse_functions
from eval.sanitize import sanitize_source

# ── CWE mapping ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize("finding, expected", [
    ({"tool": "cppcheck", "rule_id": "doubleFree"}, "CWE-415"),
    ({"tool": "cppcheck", "rule_id": "cstyleCast"}, None),
    ({"tool": "clang", "rule_id": "clang-analyzer", "message": "Attempt to free released memory [unix.Malloc]"}, "CWE-415"),
    ({"tool": "clang", "rule_id": "clang-analyzer", "message": "Potential leak of memory pointed to by 'p' [unix.Malloc]"}, "CWE-401"),
    ({"tool": "clang", "rule_id": "clang-analyzer", "message": "Value stored is never read [deadcode.DeadStores]"}, None),
    ({"tool": "clang-cross-file", "rule_id": "cross-div-zero"}, "CWE-369"),
    ({"tool": "llm-semantic", "rule_id": "llm-cwe-121", "cwe": "cwe_121"}, "CWE-121"),
])
def test_classify(finding, expected) -> None:
    assert cwe.classify(finding) == expected


def test_categories_group_related_cwes() -> None:
    assert cwe.category("CWE-415") == cwe.category("CWE-762") == "memory-free"
    assert cwe.category("CWE-121") == cwe.category("CWE-787") == "bounds"
    assert cwe.category("CWE-9999") is None


# ── Function index ───────────────────────────────────────────────────────────

_A = """\
namespace case_one {
void sink(int data);          /* prototype, not a definition */
void source()
{
    const char *s = "not a brace {";
    int data = read_input();  // {
    sink(data);
}
}
"""
_B = """\
namespace case_one {
void sink(int data)
{
    int buf[10];
    buf[data] = 1;
}
}
static void helper(void) { }
void sink(int data) { helper(); }
"""


def _two_file_project(tmp_path: Path) -> Path:
    (tmp_path / "a.cpp").write_text(_A)
    (tmp_path / "b.cpp").write_text(_B)
    (tmp_path / "c.cpp").write_text("void sink(int d)\n{\n    int x = 10 / d;\n}\n")
    return tmp_path


def test_parse_functions_skips_prototypes_and_ignores_braces_in_literals(tmp_path: Path) -> None:
    functions = parse_functions(tmp_path / "a.cpp", _A)
    assert [(f.name, f.start, f.end) for f in functions] == [("source", 3, 8)]
    assert functions[0].calls == {"read_input", "sink"}
    assert functions[0].namespace == "case_one"


def test_callers_resolve_across_files_by_namespace(tmp_path: Path) -> None:
    index = CodeIndex.build(_two_file_project(tmp_path))
    sink_b = next(f for f in index.functions if f.file.name == "b.cpp" and f.name == "sink" and f.namespace == "case_one" and f.start == 2)
    assert [c.name for c in index.callers(sink_b)] == ["source"]
    # c.cpp's unrelated sink() is not linked to a.cpp's call (namespace mismatch
    # is resolved in favour of the same namespace).
    sink_c = next(f for f in index.functions if f.file.name == "c.cpp")
    assert index.callers(sink_c) == []


# ── Semantic audit ───────────────────────────────────────────────────────────


def test_semantic_units_include_cross_file_callers(tmp_path: Path) -> None:
    root = _two_file_project(tmp_path)
    agent = SemanticAuditAgent()
    units = agent.build_units(CodeIndex.build(root))
    text, names = agent.render(units[0], root)
    assert "=== FILE: a.cpp ===" in text and "=== FILE: b.cpp ===" in text
    assert "buf[data] = 1;" in text and "sink(data);" in text
    assert set(names) >= {"a.cpp", "b.cpp"}


def test_semantic_parse_rejects_hallucinated_locations(tmp_path: Path) -> None:
    root = _two_file_project(tmp_path)
    agent = SemanticAuditAgent()
    unit = agent.build_units(CodeIndex.build(root))[0]
    _, names = agent.render(unit, root)
    content = "```json\n" + json.dumps([
        {"file": "b.cpp", "line": 5, "cwe": "CWE-121", "severity": "high", "confidence": 0.9, "message": "idx"},
        {"file": "b.cpp", "line": 500, "cwe": "CWE-121", "severity": "high", "message": "line not shown"},
        {"file": "zzz_CWE121_51b.c", "line": 5, "cwe": "CWE-121", "message": "file not shown"},
        {"file": "b.cpp", "line": 5, "cwe": "not a cwe", "message": "no cwe"},
    ]) + "\n```"
    findings = agent.parse(content, unit, names)
    assert [(Path(f["file_path"]).name, f["line"], f["cwe"], f["severity"]) for f in findings] == [
        ("b.cpp", 5, "CWE-121", "error"),
    ]


# ── Fusion ───────────────────────────────────────────────────────────────────


def _f(tool, line, file="x.c", **extra):
    base = {"tool": tool, "file_path": file, "line": line, "severity": "error", "message": tool}
    return {**base, **extra}


def test_fusion_routes() -> None:
    findings = [
        _f("cppcheck", 10, rule_id="doubleFree"),                          # consensus with the LLM finding below
        _f("llm-semantic", 12, rule_id="llm-cwe-415", cwe="CWE-415"),
        _f("cppcheck", 40, rule_id="nullPointer"),                          # static only
        _f("llm-semantic", 70, rule_id="llm-cwe-369", cwe="CWE-369"),       # LLM only
        _f("cppcheck", 90, rule_id="cstyleCast", severity="style"),         # quality
        _f("cppcheck", 11, rule_id="nullPointer", file="other.c"),          # different file: separate
    ]
    result = fuse(findings, max_reviews=2)
    routes = {(c.file_key, min(c.lines)): c.route for c in result.clusters}
    assert routes[("x.c", 10)] == "consensus"
    assert sorted(r for k, r in routes.items() if k != ("x.c", 10)) == ["review", "review", "unreviewed"]
    assert [f["rule_id"] for f in result.quality] == ["cstyleCast"]
    consensus = next(c for c in result.clusters if c.route == "consensus")
    assert consensus.cwe == "CWE-415" and len(consensus.members) == 2


def test_fusion_without_llm_keeps_everything_unreviewed() -> None:
    result = fuse([_f("cppcheck", 1, rule_id="doubleFree"), _f("cppcheck", 50, rule_id="memleak")], max_reviews=10,
                  review_enabled=False)
    assert [c.route for c in result.clusters] == ["unreviewed", "unreviewed"]


# ── Pipeline ─────────────────────────────────────────────────────────────────


class _FakeProject:
    def __init__(self, local_path: str) -> None:
        self.id = "proj-1"
        self.local_path = local_path


class _FakeProjectService:
    def __init__(self, project: _FakeProject) -> None:
        self._project = project

    def get_project(self, project_id: str) -> _FakeProject:
        return self._project

    def resolve_project_path(self, project_id: str, scan_scope: str = ".") -> Path:
        return Path(self._project.local_path)


def test_pipeline_consensus_review_and_budget_overflow(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    scan_dir = tmp_path / "project"
    scan_dir.mkdir()
    src = scan_dir / "main.c"
    src.write_text("void f(char *p)\n{\n" + "    free(p);\n" * 60 + "}\n")

    db = Database(tmp_path / "test.db")
    service = review_service_module.ReviewService(db=db)
    monkeypatch.setattr(review_service_module, "project_service", _FakeProjectService(_FakeProject(str(scan_dir))))
    for svc in (issue_service, report_service, suppression_service):
        monkeypatch.setattr(svc, "_db", db)
    monkeypatch.setattr(review_service_module.settings, "reports_dir", tmp_path / "reports")
    monkeypatch.setattr(review_service_module, "llm_available", lambda: True)

    static = [
        _f("cppcheck", 3, file=str(src), rule_id="doubleFree"),     # + LLM at line 4 → consensus
        _f("cppcheck", 20, file=str(src), rule_id="memleak"),        # static only → review (rejected)
        _f("cppcheck", 40, file=str(src), rule_id="nullPointer"),    # static only → over budget
        _f("cppcheck", 55, file=str(src), rule_id="cstyleCast", severity="style"),
    ]
    monkeypatch.setattr(service.cppcheck_tool, "run", lambda *a, **k: static)
    for tool in (service.clang_analyzer_tool, service.clang_custom_checker, service.cross_file_checker):
        monkeypatch.setattr(tool, "run", lambda *a, **k: [])
    monkeypatch.setattr(service.semantic_audit_agent, "run", lambda *a, **k: [
        _f("llm-semantic", 4, file=str(src), rule_id="llm-cwe-415", cwe="CWE-415", confidence=0.9),
    ])
    reviewed: list[dict] = []

    def fake_review(context):
        reviewed.append(context["finding"])
        return {"is_valid": False, "risk_level": "low", "issue_type": "memleak", "description": "d",
                "reason": "freed by caller", "fix_suggestion": "none", "confidence": 0.8}

    monkeypatch.setattr(service.llm_review_agent, "review", fake_review)

    task = service.create_task(ReviewTaskCreate(project_id="proj-1", rule_config={"max_llm_reviews": 1}))
    assert service.run_task(task.id).status == "completed"

    issues = {i.line: i for i in issue_service.list_issues(task_id=task.id)}
    assert issues[3].review_route == "consensus" and issues[3].is_valid and issues[3].cwe == "CWE-415"
    assert sorted(issues[3].sources) == ["cppcheck:doubleFree", "llm-semantic:llm-cwe-415"]
    assert issues[3].code_snippet  # context is attached for security issues
    # Budget of 1: exactly one single-path cluster reviewed (errors sort first; memleak/nullPointer tie → first).
    assert len(reviewed) == 1 and reviewed[0]["origin"] == "static analysis"
    routes = {line: issue.review_route for line, issue in issues.items()}
    assert sorted(routes[line] for line in (20, 40)) == ["review", "unreviewed"]
    reviewed_line = 20 if routes[20] == "review" else 40
    assert issues[reviewed_line].is_valid is False                     # rejected by the reviewer
    other = 40 if reviewed_line == 20 else 20
    assert issues[other].is_valid is True                             # over budget: kept, not dropped
    assert issues[55].review_route == "quality" and issues[55].risk_level == "low"


# ── Sanitizer ────────────────────────────────────────────────────────────────


def test_sanitize_removes_labels_but_keeps_lines() -> None:
    original = (
        "#ifndef OMITBAD\n"
        "void CWE415_Double_Free__x_51b_badSink(char * data)\n"
        "{\n"
        "    /* POTENTIAL FLAW: Possibly freeing memory twice */\n"
        "    free(data);\n"
        "    printLine(\"Calling bad()...\");\n"
        "}\n"
        "#endif /* OMITBAD */\n"
    )
    cleaned = sanitize_source(original)
    assert len(cleaned.splitlines()) == len(original.splitlines())
    for leak in ("bad", "Bad", "FLAW", "CWE", "OMIT"):
        assert leak not in cleaned
    assert "free(data);" in cleaned
    assert sanitize_source(original) == cleaned  # deterministic → consistent across files


def test_semantic_audit_run_end_to_end_with_fake_model(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from app.agents import semantic_audit_agent as module

    root = _two_file_project(tmp_path)
    monkeypatch.setattr(module, "llm_available", lambda: True)
    prompts: list[str] = []

    def fake_call(self, payload):
        prompt = payload["messages"][-1]["content"]
        prompts.append(prompt)
        answer = [{"file": "b.cpp", "line": 5, "cwe": "CWE-787", "severity": "high", "message": "tainted index"}]
        return {"choices": [{"message": {"content": json.dumps(answer if "buf[data]" in prompt else [])}}]}

    monkeypatch.setattr(module.SemanticAuditAgent, "_call_api", fake_call)
    findings = SemanticAuditAgent().run(root)
    assert prompts, "the model was never called"
    assert [(Path(f["file_path"]).name, f["line"], f["tool"]) for f in findings] == [("b.cpp", 5, "llm-semantic")]


def test_review_agent_stops_at_context_budget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from app.agents import llm_review_agent as module

    src = tmp_path / "big.c"
    src.write_text("\n".join(f"int v{i} = {i}; /* {'x' * 90} */" for i in range(400)))
    calls = {"tools": 0, "verdict": 0}

    def fake_call(self, payload):
        if "response_format" in payload:
            calls["verdict"] += 1
            return {"choices": [{"message": {"content": json.dumps({
                "is_valid": True, "risk_level": "high", "issue_type": "x", "description": "d",
                "reason": "r", "fix_suggestion": "f", "confidence": 0.7})}}]}
        calls["tools"] += 1
        # Always ask to read 80 more lines: would run all 5 turns without a budget.
        args = json.dumps({"file_path": str(src), "start_line": 1, "end_line": 80})
        return {"choices": [{"message": {"content": None, "tool_calls": [
            {"id": f"c{calls['tools']}-{i}", "type": "function",
             "function": {"name": "read_code_snippet", "arguments": args}} for i in range(3)]}}]}

    monkeypatch.setattr(module.LLMReviewAgent, "_call_api", fake_call)
    monkeypatch.setattr(module.settings, "llm_enabled", True)
    monkeypatch.setattr(module.settings, "llm_api_key", "k")
    verdict = module.LLMReviewAgent().review({"finding": {"file_path": str(src), "line": 3}, "scan_root": str(tmp_path)})
    assert verdict["is_valid"] is True
    assert calls["tools"] < 5 and calls["verdict"] == 1


def test_graph_runs_static_and_llm_paths_concurrently(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import threading
    import time

    scan_dir = tmp_path / "project"
    scan_dir.mkdir()
    (scan_dir / "main.c").write_text("int main(void) { return 0; }\n")
    db = Database(tmp_path / "test.db")
    service = review_service_module.ReviewService(db=db)
    monkeypatch.setattr(review_service_module, "project_service", _FakeProjectService(_FakeProject(str(scan_dir))))
    for svc in (issue_service, report_service, suppression_service):
        monkeypatch.setattr(svc, "_db", db)
    monkeypatch.setattr(review_service_module.settings, "reports_dir", tmp_path / "reports")

    # Both branches block until the other has started: only possible if the
    # graph really runs them at the same time.
    started = {"static": threading.Event(), "llm": threading.Event()}

    def detector(me, other):
        def run(*a, **k):
            started[me].set()
            assert started[other].wait(timeout=5), f"{other} branch never started while {me} was running"
            return []
        return run

    monkeypatch.setattr(service.cppcheck_tool, "run", detector("static", "llm"))
    monkeypatch.setattr(service.semantic_audit_agent, "run", detector("llm", "static"))
    for tool in (service.clang_analyzer_tool, service.clang_custom_checker, service.cross_file_checker):
        monkeypatch.setattr(tool, "run", lambda *a, **k: [])

    task = service.create_task(ReviewTaskCreate(project_id="proj-1"))
    begin = time.monotonic()
    assert service.run_task(task.id).status == "completed"
    assert time.monotonic() - begin < 5


def test_graph_shape() -> None:
    graph = review_service_module.ReviewService(db=Database(Path(":memory:")))._graph.get_graph()
    edges = {(e.source, e.target) for e in graph.edges}
    assert {("prepare", "static_detect"), ("prepare", "llm_detect"),
            ("static_detect", "fuse"), ("llm_detect", "fuse"),
            ("fuse", "review"), ("fuse", "build_issues"), ("review", "build_issues")} <= edges


def test_model_json_with_c_escapes_is_repaired_not_dropped() -> None:
    from app.core.llm_client import loads_lenient, parse_json_array, repair_json_escapes

    # qwen-flash quoting C code: '\0' is not a valid JSON escape.
    raw = '[{"file": "a.c", "line": 5, "cwe": "CWE-121", "message": "writes \'\\0\' past end; C:\\\\x"}]'
    findings = parse_json_array(raw)
    assert len(findings) == 1 and findings[0]["line"] == 5
    assert findings[0]["message"] == "writes '\\0' past end; C:\\x"
    valid = '{"a": "t\\t q\\" u\\u0041 b\\\\x"}'
    assert repair_json_escapes(valid) == valid
    assert loads_lenient(valid) == json.loads(valid)
