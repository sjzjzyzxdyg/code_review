from pathlib import Path

from app.agents.call_chain_agent import CallChainRetrievalAgent
from app.tools.ast_parser_tool import ASTParserTool


class ContextBuilder:
    def __init__(self) -> None:
        self.ast_parser = ASTParserTool()
        self.call_chain_agent = CallChainRetrievalAgent()

    def build_issue_context(
        self,
        finding: dict,
        scan_path: Path,
        context_lines: int = 5,
    ) -> dict:
        file_path = Path(str(finding.get("file_path") or ""))
        snippet = self.read_code_snippet(file_path, int(finding.get("line") or 1), context_lines)

        ast_context = self.ast_parser.summarize(
            str(finding.get("file_path") or ""),
            int(finding.get("line") or 1),
        )
        call_chain_graph = self.call_chain_agent.retrieve_graph(finding)
        call_chain = call_chain_graph.get("chain", [])

        return {
            "finding": finding,
            "scan_path": str(scan_path),
            "code_snippet": snippet,
            "ast_summary": ast_context.get("summary"),
            "ast_context": ast_context,
            "dependencies": ast_context.get("dependencies", []),
            "call_chain": call_chain,
            "call_chain_graph": call_chain_graph,
        }

    def read_code_snippet(
        self,
        file_path: Path,
        line: int,
        context_lines: int = 5,
    ) -> str | None:
        if not file_path.exists() or not file_path.is_file():
            return None

        try:
            lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return None

        start = max(line - context_lines - 1, 0)
        end = min(line + context_lines, len(lines))
        return "\n".join(
            f"{number + 1}: {lines[number]}"
            for number in range(start, end)
        )


context_builder = ContextBuilder()
