"""LangGraph orchestration of one review task.

                 ┌──────────────┐
         START ─►│   prepare    │  paths, include dirs, incremental-cppcheck plan
                 └──┬────────┬──┘
          (parallel)│        │
       ┌────────────▼─┐   ┌──▼───────────┐
       │ static_detect│   │  llm_detect  │  static tools ‖ LLM semantic audit
       └────────────┬─┘   └──┬───────────┘
                    └───┬────┘   (join: waits for both branches)
                 ┌──────▼───────┐
                 │     fuse     │  suppression → CWE mapping → clustering → routes
                 └──┬────────┬──┘
     single-path    │        │ nothing to review
     clusters exist │        │
                 ┌──▼─────┐  │
                 │ review │  │  tool-using agent verifies single-path clusters
                 └──┬─────┘  │
                 ┌──▼────────▼──┐
                 │ build_issues │  verdicts + context → issues, persisted
                 └──────┬───────┘
                 ┌──────▼───────┐
                 │    report    │ ─► END
                 └──────────────┘

Every node is a thin wrapper over a ReviewService method, so the graph owns
control flow (fan-out, join, conditional routing) and ReviewService owns the
work. ``build_review_graph(service).get_graph().draw_mermaid()`` renders the
compiled graph.
"""

from __future__ import annotations

import operator
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, TypedDict

from langgraph.graph import END, START, StateGraph

from app.core.config import settings
from app.services.fusion import FusionResult, fuse

if TYPE_CHECKING:
    from app.services.review_service import ReviewService

STATIC_DETECTORS = ("cppcheck", "clang", "clang_custom", "cross_file")
LLM_DETECTORS = ("semantic_audit", "taint_flow", "semantic_rules")


class ReviewState(TypedDict, total=False):
    # Inputs
    task_id: str
    project_id: str
    scan_scope: str
    rule_config: dict[str, Any]
    # prepare
    scan_path: Path
    include_paths: list[Path]
    cppcheck_plan: dict[str, Any]
    # detection. Both branches append to `findings` concurrently, so the
    # channel needs a reducer that concatenates instead of overwriting.
    findings: Annotated[list[dict], operator.add]
    rule_issues: Annotated[list[Any], operator.add]
    # fuse / review / build
    fusion: FusionResult
    review_results: dict[int, dict]
    issues: list[Any]


def build_review_graph(service: "ReviewService"):
    def prepare(state: ReviewState) -> dict:
        return service.prepare_scan(state["project_id"], state["scan_scope"], state["rule_config"])

    def static_detect(state: ReviewState) -> dict:
        plan = state["cppcheck_plan"]
        findings, _, fresh_cppcheck = service._run_detectors(
            STATIC_DETECTORS, state["scan_path"], state["rule_config"], state["task_id"],
            state["include_paths"], cppcheck_target_files=plan.get("target_files"),
        )
        service.save_cppcheck_cache(state["project_id"], state["scan_path"], plan, fresh_cppcheck)
        return {"findings": findings + plan.get("cached_findings", [])}

    def llm_detect(state: ReviewState) -> dict:
        findings, rule_issues, _ = service._run_detectors(
            LLM_DETECTORS, state["scan_path"], state["rule_config"], state["task_id"], state["include_paths"],
        )
        return {"findings": findings, "rule_issues": rule_issues}

    def fuse_node(state: ReviewState) -> dict:
        findings = service._filter_suppressed(state["findings"], state["project_id"], state["scan_path"])
        max_reviews = int(state["rule_config"].get("max_llm_reviews", settings.llm_max_reviews))
        return {"fusion": fuse(findings, max_reviews=max_reviews, review_enabled=service._llm_available())}

    def route_after_fuse(state: ReviewState) -> str:
        return "review" if state["fusion"].by_route("review") else "build_issues"

    def review(state: ReviewState) -> dict:
        service._update_task(state["task_id"], status="llm_reviewing")
        return {"review_results": service._review_clusters(state["fusion"].by_route("review"), state["scan_path"])}

    def build_issues(state: ReviewState) -> dict:
        service._update_task(state["task_id"], status="result_validating")
        issues = service._build_issues(
            state["task_id"], state["fusion"], state.get("review_results") or {},
            state.get("rule_issues") or [], state["scan_path"],
        )
        service.persist_issues(state["task_id"], issues)
        return {"issues": issues}

    def report(state: ReviewState) -> dict:
        service._update_task(state["task_id"], status="report_generating")
        service.generate_report(state["task_id"], state["issues"])
        return {}

    graph = StateGraph(ReviewState)
    graph.add_node("prepare", prepare)
    graph.add_node("static_detect", static_detect)
    graph.add_node("llm_detect", llm_detect)
    graph.add_node("fuse", fuse_node)
    graph.add_node("review", review)
    graph.add_node("build_issues", build_issues)
    graph.add_node("report", report)

    graph.add_edge(START, "prepare")
    graph.add_edge("prepare", "static_detect")
    graph.add_edge("prepare", "llm_detect")
    graph.add_edge(["static_detect", "llm_detect"], "fuse")
    graph.add_conditional_edges("fuse", route_after_fuse, {"review": "review", "build_issues": "build_issues"})
    graph.add_edge("review", "build_issues")
    graph.add_edge("build_issues", "report")
    graph.add_edge("report", END)
    return graph.compile()
