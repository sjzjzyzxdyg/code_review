from datetime import datetime
from uuid import uuid4

from fastapi import HTTPException, status

from app.core.db import Database, get_db
from app.schemas.issue import ReviewIssueRead


class IssueService:
    def __init__(self, db: Database | None = None) -> None:
        self._db = db or get_db()

    def list_issues(self, task_id: str | None = None) -> list[ReviewIssueRead]:
        rows = self._db.list("issues", parent_id=task_id)
        return [ReviewIssueRead.model_validate(row) for row in rows]

    def replace_task_issues(self, task_id: str, issues: list[ReviewIssueRead]) -> None:
        rows = [
            (issue.id, issue.created_at.isoformat(), issue.model_dump(mode="json"))
            for issue in issues
        ]
        self._db.replace_children("issues", task_id, rows)

    def create_from_static_finding(
        self,
        task_id: str,
        finding: dict,
        code_snippet: str | None = None,
        ast_summary: str | None = None,
        call_chain: list[str] | None = None,
        call_chain_graph: dict | None = None,
        dependencies: list[str] | None = None,
        ast_context: dict | None = None,
    ) -> ReviewIssueRead:
        severity = str(finding.get("severity") or "medium").lower()
        risk_level = self._normalize_risk_level(severity)
        message = str(finding.get("message") or "Static analysis finding")
        rule_id = finding.get("rule_id")

        return ReviewIssueRead(
            id=str(uuid4()),
            task_id=task_id,
            tool=str(finding.get("tool") or "unknown"),
            rule_id=str(rule_id) if rule_id else None,
            file_path=str(finding.get("file_path") or ""),
            line=max(int(finding.get("line") or 1), 1),
            column=finding.get("column"),
            issue_type=str(rule_id or finding.get("issue_type") or "static-analysis"),
            risk_level=risk_level,
            description=message,
            reason=message,
            fix_suggestion="Review the highlighted code path and apply the tool recommendation.",
            confidence=0.75,
            is_valid=True,
            call_chain=call_chain or [],
            call_chain_graph=call_chain_graph or {},
            ast_summary=ast_summary,
            ast_context=ast_context or {},
            dependencies=dependencies or [],
            code_snippet=code_snippet,
            created_at=datetime.utcnow(),
        )

    def create_from_review_result(
        self,
        task_id: str,
        finding: dict,
        review_result,
        code_snippet: str | None = None,
        ast_summary: str | None = None,
        call_chain: list[str] | None = None,
        call_chain_graph: dict | None = None,
        dependencies: list[str] | None = None,
        ast_context: dict | None = None,
    ) -> ReviewIssueRead:
        rule_id = finding.get("rule_id")
        return ReviewIssueRead(
            id=str(uuid4()),
            task_id=task_id,
            tool=str(finding.get("tool") or "unknown"),
            rule_id=str(rule_id) if rule_id else None,
            file_path=str(finding.get("file_path") or ""),
            line=max(int(finding.get("line") or 1), 1),
            column=finding.get("column"),
            issue_type=review_result.issue_type,
            risk_level=review_result.risk_level,
            description=review_result.description,
            reason=review_result.reason,
            fix_suggestion=review_result.fix_suggestion,
            confidence=review_result.confidence,
            is_valid=review_result.is_valid,
            call_chain=call_chain or [],
            call_chain_graph=call_chain_graph or {},
            ast_summary=ast_summary,
            ast_context=ast_context or {},
            dependencies=dependencies or [],
            code_snippet=code_snippet,
            created_at=datetime.utcnow(),
        )

    def get_issue(self, issue_id: str) -> ReviewIssueRead:
        row = self._db.get("issues", issue_id)
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Review issue not found",
            )
        return ReviewIssueRead.model_validate(row)

    def mark_false_positive(self, issue_id: str) -> ReviewIssueRead:
        issue = self.get_issue(issue_id)
        updated = issue.model_copy(update={"is_valid": False})
        self._db.upsert(
            "issues", updated.id, updated.task_id,
            updated.created_at.isoformat(), updated.model_dump(mode="json"),
        )
        return updated

    def _normalize_risk_level(self, severity: str) -> str:
        mapping = {
            "error": "high",
            "critical": "critical",
            "warning": "medium",
            "style": "low",
            "performance": "low",
            "portability": "low",
            "information": "low",
        }
        return mapping.get(severity, "medium")


issue_service = IssueService()
