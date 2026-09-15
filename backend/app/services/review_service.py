import concurrent.futures
import logging
import threading
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from fastapi import HTTPException, status

from app.agents.llm_review_agent import LLMReviewAgent
from app.agents.report_generation_agent import ReportGenerationAgent
from app.agents.result_validation_agent import ResultValidationAgent
from app.core.db import Database, get_db
from app.schemas.issue import ReviewIssueRead
from app.schemas.review import ReviewTaskCreate, ReviewTaskRead
from app.services.issue_service import issue_service
from app.services.project_service import project_service
from app.services.report_service import report_service
from app.agents.taint_flow_agent import TaintFlowAgent
from app.tools.clang_analyzer_tool import ClangAnalyzerTool
from app.tools.clang_custom_checker import ClangCustomCheckerTool
from app.tools.cross_file_checker import CrossFileChecker
from app.tools.cppcheck_tool import CppcheckTool, StaticAnalysisToolUnavailable

logger = logging.getLogger(__name__)

_PARALLEL_WORKERS = 4   # keep DeepSeek concurrent connections low to avoid SSL drops
_DETECT_WORKERS   = 5   # cppcheck + clang + clang_custom + cross_file + taint_flow
_MAX_LLM_FINDINGS = 40  # cap before LLM review to prevent timeout

# Lower value → reviewed first when over the cap
_SEVERITY_PRIORITY: dict[str, int] = {
    "error": 0, "warning": 1,
    "style": 2, "performance": 3, "portability": 3, "information": 4,
}
_RISK_RANK: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}

_IN_PROGRESS_STATUSES = {
    "static_analyzing", "llm_reviewing", "result_validating", "report_generating",
}


class ReviewService:
    def __init__(self, db: Database | None = None) -> None:
        self._db = db or get_db()
        self._run_lock = threading.Lock()
        self.cppcheck_tool          = CppcheckTool()
        self.clang_analyzer_tool    = ClangAnalyzerTool()
        self.clang_custom_checker   = ClangCustomCheckerTool()
        self.cross_file_checker     = CrossFileChecker()
        self.taint_flow_agent       = TaintFlowAgent()
        self.llm_review_agent       = LLMReviewAgent()
        self.result_validation_agent = ResultValidationAgent()
        self.report_generation_agent = ReportGenerationAgent()

    def create_task(self, payload: ReviewTaskCreate) -> ReviewTaskRead:
        project_service.get_project(payload.project_id)
        now = datetime.utcnow()
        task = ReviewTaskRead(
            id=str(uuid4()),
            project_id=payload.project_id,
            status="created",
            scan_scope=payload.scan_scope,
            rule_config=payload.rule_config,
            created_at=now,
        )
        return self._save(task)

    def list_tasks(self) -> list[ReviewTaskRead]:
        return [ReviewTaskRead.model_validate(row) for row in self._db.list("review_tasks")]

    def get_task(self, task_id: str) -> ReviewTaskRead:
        row = self._db.get("review_tasks", task_id)
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Review task not found",
            )
        return ReviewTaskRead.model_validate(row)

    def cancel_task(self, task_id: str) -> ReviewTaskRead:
        task = self.get_task(task_id)
        cancelled = task.model_copy(
            update={
                "status": "cancelled",
                "finished_at": datetime.utcnow(),
            }
        )
        return self._save(cancelled)

    def run_task(self, task_id: str) -> ReviewTaskRead:
        with self._run_lock:
            task = self.get_task(task_id)
            if task.status == "cancelled":
                return task
            if task.status in _IN_PROGRESS_STATUSES:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Review task is already running.",
                )
            self._update_task(
                task_id,
                status="static_analyzing",
                started_at=task.started_at or datetime.utcnow(),
                error_message=None,
            )

        try:
            scan_path    = project_service.resolve_project_path(task.project_id, task.scan_scope)
            project_root = Path(project_service.get_project(task.project_id).local_path or "")
            include_paths = self._discover_include_paths(project_root, scan_path)

            # ── Phase 1: Detection (all tools in parallel) ────────────────────
            static_findings, taint_issues = self._run_detection_parallel(
                scan_path, task.rule_config, task_id, include_paths
            )

            # ── Phase 2: Prioritise + cap before LLM review ───────────────────
            static_findings = self._prioritize_findings(static_findings)

            # ── Phase 3: LLM review of static findings (parallel) ────────────
            self._update_task(task_id, status="llm_reviewing")
            review_results = self._llm_review_parallel(static_findings, scan_path)

            # ── Phase 4: Build & deduplicate issues ───────────────────────────
            self._update_task(task_id, status="result_validating")
            issues = self._build_issues(
                task_id, static_findings, review_results, taint_issues, scan_path,
            )
            issue_service.replace_task_issues(task_id, issues)

            # ── Phase 5: Report generation ────────────────────────────────────
            self._update_task(task_id, status="report_generating")
            generating_task = self.get_task(task_id)
            markdown     = self.report_generation_agent.generate_markdown(generating_task, issues)
            json_payload = self.report_generation_agent.generate_json(generating_task, issues)
            summary      = self.report_generation_agent.summarize(issues)
            report_service.create_report(task_id, markdown, json_payload, summary)

        except StaticAnalysisToolUnavailable as exc:
            # User-actionable (e.g. "install cppcheck") and safe to show as-is.
            return self._update_task(
                task_id,
                status="failed",
                error_message=str(exc),
                finished_at=datetime.utcnow(),
            )
        except Exception:
            # Don't leak internal exception details (paths, stack info) to API
            # clients; the full traceback is logged for operators.
            logger.exception("Review task %s failed unexpectedly.", task_id)
            return self._update_task(
                task_id,
                status="failed",
                error_message="Review task failed due to an internal error. Check server logs for details.",
                finished_at=datetime.utcnow(),
            )

        return self._update_task(
            task_id,
            status="completed",
            finished_at=datetime.utcnow(),
        )

    # ── Pipeline helpers ───────────────────────────────────────────────────────

    def _discover_include_paths(self, project_root: Path, scan_path: Path) -> list[Path]:
        """Return header directories in project_root that are outside scan_path."""
        if not project_root.is_dir():
            return []
        result: list[Path] = []
        for child in project_root.iterdir():
            if not child.is_dir():
                continue
            try:
                scan_path.resolve().relative_to(child.resolve())
                continue  # child is an ancestor of scan_path — skip
            except ValueError:
                pass
            if any(child.rglob("*.h")) or any(child.rglob("*.hpp")):
                result.append(child)
        return result

    def _run_detection_parallel(
        self, scan_path: Path, rule_config: dict, task_id: str,
        include_paths: list[Path] | None = None,
    ) -> tuple[list[dict], list[ReviewIssueRead]]:
        with concurrent.futures.ThreadPoolExecutor(max_workers=_DETECT_WORKERS) as pool:
            pending: dict[str, tuple[concurrent.futures.Future, bool]] = {}

            if rule_config.get("cppcheck", True):
                rule_level = str(rule_config.get("cppcheck_enable", "all"))
                rule_files = [Path(p) for p in rule_config.get("cppcheck_rule_files", [])]
                pending["cppcheck"] = (
                    pool.submit(
                        self.cppcheck_tool.run, scan_path,
                        rule_level=rule_level, rule_files=rule_files,
                        include_paths=include_paths,
                    ),
                    True,
                )

            pending["clang"]        = (pool.submit(self.clang_analyzer_tool.run, scan_path, include_paths), False)
            pending["clang_custom"] = (pool.submit(self.clang_custom_checker.run, scan_path), False)

            if rule_config.get("cross_file", False):
                pending["cross_file"] = (pool.submit(self.cross_file_checker.run, scan_path), False)

            pending["taint_flow"] = (pool.submit(self.taint_flow_agent.run, scan_path, task_id), False)

            static_findings: list[dict] = []
            taint_issues: list[ReviewIssueRead] = []

            for key, (future, fatal) in pending.items():
                try:
                    result = future.result()
                except StaticAnalysisToolUnavailable:
                    if fatal:
                        raise
                    logger.warning("Detection tool %r unavailable; skipping.", key)
                    result = []
                except Exception:
                    logger.exception("Detection tool %r failed unexpectedly; skipping.", key)
                    result = []

                if key == "taint_flow":
                    taint_issues = result or []
                else:
                    static_findings.extend(result or [])

        return static_findings, taint_issues

    def _prioritize_findings(self, findings: list[dict]) -> list[dict]:
        """Sort by severity (errors first) and cap to _MAX_LLM_FINDINGS."""
        if len(findings) <= _MAX_LLM_FINDINGS:
            return findings
        sorted_findings = sorted(
            findings,
            key=lambda f: _SEVERITY_PRIORITY.get(str(f.get("severity", "")).lower(), 99),
        )
        return sorted_findings[:_MAX_LLM_FINDINGS]

    def _llm_review_parallel(self, findings: list[dict], scan_path: Path) -> list[dict]:
        if not findings:
            return []
        scan_root = str(scan_path.resolve())
        with concurrent.futures.ThreadPoolExecutor(max_workers=_PARALLEL_WORKERS) as pool:
            futures = [
                pool.submit(self.llm_review_agent.review, {"finding": f, "scan_root": scan_root})
                for f in findings
            ]
            results: list[dict] = []
            for finding, fut in zip(findings, futures):
                try:
                    results.append(fut.result())
                except Exception:
                    # API failure: fall back to static severity rather than aborting the task
                    logger.exception("LLM review failed for finding %r; using static severity.", finding.get("rule_id"))
                    sev = str(finding.get("severity", "warning")).lower()
                    results.append({
                        "is_valid": True,
                        "risk_level": issue_service._normalize_risk_level(sev),
                        "issue_type": str(finding.get("rule_id") or "static-analysis"),
                        "description": str(finding.get("message") or "Static analysis finding"),
                        "reason": "LLM review unavailable (API error); verdict from static tool only.",
                        "fix_suggestion": "Review the highlighted code path.",
                        "confidence": 0.45,
                    })
            return results

    def _build_issues(
        self,
        task_id: str,
        static_findings: list[dict],
        review_results: list[dict],
        taint_issues: list[ReviewIssueRead],
        scan_path: Path,
    ) -> list[ReviewIssueRead]:
        issues: list[ReviewIssueRead] = []

        # Static findings reviewed by LLM
        for finding, review_result in zip(static_findings, review_results):
            validated = self.result_validation_agent.validate(review_result)
            issue = issue_service.create_from_review_result(
                task_id=task_id,
                finding=self._make_finding_relative(finding, scan_path),
                review_result=validated,
                code_snippet=None,
                ast_summary=None,
                ast_context={},
                call_chain=[],
                call_chain_graph={},
                dependencies=[],
            )
            # Floor risk level: static severity as minimum when finding is valid
            if issue.is_valid:
                issue = issue.model_copy(update={
                    "risk_level": self._floor_risk(
                        issue.risk_level, finding.get("severity", "")
                    )
                })
            issues.append(issue)

        # TaintFlow issues: already LLM-judged — skip second validation
        for taint in taint_issues:
            rel_path = self._make_finding_relative(
                {"file_path": taint.file_path}, scan_path
            )["file_path"]
            issues.append(taint.model_copy(update={"file_path": rel_path}))

        return _dedup_issues(issues)

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _update_task(self, task_id: str, **updates) -> ReviewTaskRead:
        task = self.get_task(task_id)
        updated = task.model_copy(update=updates)
        return self._save(updated)

    def _save(self, task: ReviewTaskRead) -> ReviewTaskRead:
        self._db.upsert(
            "review_tasks", task.id, task.project_id,
            task.created_at.isoformat(), task.model_dump(mode="json"),
        )
        return task

    def _make_finding_relative(self, finding: dict, scan_path: Path) -> dict:
        file_path = finding.get("file_path")
        if not file_path:
            return finding
        path = Path(str(file_path))
        try:
            relative_path = path.resolve().relative_to(scan_path.resolve())
            return {**finding, "file_path": str(relative_path).replace("\\", "/")}
        except ValueError:
            return finding

    @staticmethod
    def _floor_risk(llm_risk: str, static_severity: str) -> str:
        """Return the higher of the LLM risk and the floor implied by static severity."""
        _FLOOR_MAP = {"error": "high", "warning": "medium"}
        floor = _FLOOR_MAP.get(static_severity.lower(), "low")
        return floor if _RISK_RANK.get(floor, 0) > _RISK_RANK.get(llm_risk, 0) else llm_risk


def _dedup_issues(issues: list[ReviewIssueRead]) -> list[ReviewIssueRead]:
    """Keep one issue per (file_path, line, rule_id), preferring higher confidence."""
    seen: dict[tuple, ReviewIssueRead] = {}
    for issue in issues:
        key = (issue.file_path, issue.line, issue.rule_id)
        existing = seen.get(key)
        if existing is None or issue.confidence > existing.confidence:
            seen[key] = issue
    return list(seen.values())


review_service = ReviewService()
