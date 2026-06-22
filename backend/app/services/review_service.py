from datetime import datetime
from pathlib import Path
from uuid import uuid4

from fastapi import HTTPException, status

from app.agents.llm_review_agent import LLMReviewAgent
from app.agents.report_generation_agent import ReportGenerationAgent
from app.agents.result_validation_agent import ResultValidationAgent
from app.schemas.review import ReviewTaskCreate, ReviewTaskRead
from app.services.context_builder import context_builder
from app.services.issue_service import issue_service
from app.services.project_service import project_service
from app.services.report_service import report_service
from app.tools.clang_analyzer_tool import ClangAnalyzerTool
from app.tools.cppcheck_tool import BuiltinCppHeuristicTool, CppcheckTool, StaticAnalysisToolUnavailable


class ReviewService:
    def __init__(self) -> None:
        self._tasks: dict[str, ReviewTaskRead] = {}
        self.cppcheck_tool = CppcheckTool()
        self.builtin_cpp_tool = BuiltinCppHeuristicTool()
        self.clang_analyzer_tool = ClangAnalyzerTool()
        self.llm_review_agent = LLMReviewAgent()
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
        self._tasks[task.id] = task
        return task

    def list_tasks(self) -> list[ReviewTaskRead]:
        return list(self._tasks.values())

    def get_task(self, task_id: str) -> ReviewTaskRead:
        task = self._tasks.get(task_id)
        if task is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Review task not found",
            )
        return task

    def cancel_task(self, task_id: str) -> ReviewTaskRead:
        task = self.get_task(task_id)
        cancelled = task.model_copy(
            update={
                "status": "cancelled",
                "finished_at": datetime.utcnow(),
            }
        )
        self._tasks[task_id] = cancelled
        return cancelled

    def run_task(self, task_id: str) -> ReviewTaskRead:
        task = self.get_task(task_id)
        if task.status == "cancelled":
            return task

        self._update_task(
            task_id,
            status="static_analyzing",
            started_at=task.started_at or datetime.utcnow(),
            error_message=None,
        )

        try:
            scan_path = project_service.resolve_project_path(task.project_id, task.scan_scope)
            findings = self._run_static_analysis(scan_path, task.rule_config)

            self._update_task(task_id, status="context_building")
            contexts = [
                context_builder.build_issue_context(finding, scan_path)
                for finding in findings
            ]

            self._update_task(task_id, status="llm_reviewing")
            review_results = [
                self.llm_review_agent.review(context)
                for context in contexts
            ]

            self._update_task(task_id, status="result_validating")
            issues = []
            for finding, context, review_result in zip(findings, contexts, review_results):
                validated = self.result_validation_agent.validate(
                    review_result,
                    call_chain=context.get("call_chain", []),
                )
                issues.append(
                    issue_service.create_from_review_result(
                        task_id=task_id,
                        finding=self._make_finding_relative(finding, scan_path),
                        review_result=validated,
                        code_snippet=context.get("code_snippet"),
                        ast_summary=context.get("ast_summary"),
                        ast_context=context.get("ast_context", {}),
                        call_chain=context.get("call_chain", []),
                        call_chain_graph=context.get("call_chain_graph", {}),
                        dependencies=context.get("dependencies", []),
                    )
                )
            issue_service.replace_task_issues(task_id, issues)

            self._update_task(task_id, status="report_generating")
            generating_task = self.get_task(task_id)
            markdown = self.report_generation_agent.generate_markdown(generating_task, issues)
            json_payload = self.report_generation_agent.generate_json(generating_task, issues)
            summary = self.report_generation_agent.summarize(issues)
            report_service.create_report(task_id, markdown, json_payload, summary)
        except StaticAnalysisToolUnavailable as exc:
            return self._update_task(
                task_id,
                status="failed",
                error_message=str(exc),
                finished_at=datetime.utcnow(),
            )
        except Exception as exc:
            return self._update_task(
                task_id,
                status="failed",
                error_message=f"Review task failed: {exc}",
                finished_at=datetime.utcnow(),
            )

        return self._update_task(
            task_id,
            status="completed",
            finished_at=datetime.utcnow(),
        )

    def _update_task(self, task_id: str, **updates) -> ReviewTaskRead:
        task = self.get_task(task_id)
        updated = task.model_copy(update=updates)
        self._tasks[task_id] = updated
        return updated

    def _run_static_analysis(self, project_path: Path, rule_config: dict) -> list[dict]:
        findings: list[dict] = []
        if rule_config.get("cppcheck", True):
            rule_level = str(rule_config.get("cppcheck_enable", "all"))
            try:
                findings.extend(self.cppcheck_tool.run(project_path, rule_level=rule_level))
            except StaticAnalysisToolUnavailable:
                if rule_config.get("strict_cppcheck", False):
                    raise
                findings.extend(self.builtin_cpp_tool.run(project_path))
        if rule_config.get("clang", False):
            findings.extend(self.clang_analyzer_tool.run(project_path))
        return findings

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


review_service = ReviewService()
