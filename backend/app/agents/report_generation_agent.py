from app.schemas.issue import ReviewIssueRead
from app.schemas.review import ReviewTaskRead


class ReportGenerationAgent:
    """Generates structured review reports."""

    def generate_markdown(self, task: ReviewTaskRead, issues: list[ReviewIssueRead]) -> str:
        counts = self._count_by_risk(issues)
        lines = [
            f"# Code Review Report",
            "",
            f"- Task ID: {task.id}",
            f"- Project ID: {task.project_id}",
            f"- Status: {task.status}",
            f"- Total Issues: {len(issues)}",
            f"- Critical: {counts['critical']}",
            f"- High: {counts['high']}",
            f"- Medium: {counts['medium']}",
            f"- Low: {counts['low']}",
            "",
            "## Issues",
            "",
        ]

        if not issues:
            lines.append("No issues were reported.")
            return "\n".join(lines)

        for index, issue in enumerate(issues, start=1):
            lines.extend(
                [
                    f"### {index}. {issue.issue_type}",
                    "",
                    f"- Risk: {issue.risk_level}",
                    f"- Tool: {issue.tool}",
                    f"- Rule: {issue.rule_id or 'N/A'}",
                    f"- Location: {issue.file_path}:{issue.line}",
                    f"- Confidence: {issue.confidence:.2f}",
                    "",
                    f"Description: {issue.description}",
                    "",
                    f"Reason: {issue.reason}",
                    "",
                    f"Fix Suggestion: {issue.fix_suggestion}",
                    "",
                ]
            )
            if issue.code_snippet:
                lines.extend(["```cpp", issue.code_snippet, "```", ""])
            if issue.ast_summary:
                lines.extend([f"AST Summary: {issue.ast_summary}", ""])
            if issue.call_chain:
                lines.extend([f"Call Chain: {' -> '.join(issue.call_chain)}", ""])
            if issue.call_chain_graph.get("edges"):
                lines.extend(
                    [
                        "Call Graph Edges:",
                        *[
                            f"- {edge.get('source')} -> {edge.get('target')}"
                            for edge in issue.call_chain_graph.get("edges", [])[:12]
                        ],
                        "",
                    ]
                )
            if issue.dependencies:
                lines.extend([f"Dependencies: {', '.join(issue.dependencies[:10])}", ""])

        return "\n".join(lines)

    def generate_json(self, task: ReviewTaskRead, issues: list[ReviewIssueRead]) -> dict:
        counts = self._count_by_risk(issues)
        return {
            "task_id": task.id,
            "project_id": task.project_id,
            "status": task.status,
            "summary": {
                "total": len(issues),
                "critical": counts["critical"],
                "high": counts["high"],
                "medium": counts["medium"],
                "low": counts["low"],
            },
            "issues": [issue.model_dump(mode="json") for issue in issues],
        }

    def summarize(self, issues: list[ReviewIssueRead]) -> str:
        counts = self._count_by_risk(issues)
        return (
            f"Found {len(issues)} issues: "
            f"{counts['critical']} critical, {counts['high']} high, "
            f"{counts['medium']} medium, {counts['low']} low."
        )

    def _count_by_risk(self, issues: list[ReviewIssueRead]) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for issue in issues:
            counts[issue.risk_level] += 1
        return counts
