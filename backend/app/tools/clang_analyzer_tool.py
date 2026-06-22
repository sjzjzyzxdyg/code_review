import subprocess
from pathlib import Path

from app.tools.cppcheck_tool import StaticAnalysisToolUnavailable
from app.tools.structured_tools import make_structured_tool


class ClangAnalyzerTool:
    """Adapter for Clang Static Analyzer with plist/text tolerant parsing."""

    def as_structured_tool(self):
        return make_structured_tool(
            name="clang_static_analyzer_scan",
            description="Run Clang Static Analyzer on C/C++ files and return normalized findings.",
            func=lambda project_path: self.run(Path(project_path)),
        )

    def run(self, project_path: Path) -> list[dict]:
        analyzer = self._resolve_analyzer()
        findings: list[dict] = []
        for source in self._iter_sources(project_path):
            command = [analyzer, "--analyze", str(source)]
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                encoding="utf-8",
                errors="replace",
            )
            findings.extend(self._parse_text_output(result.stderr, source))
        return findings

    def _resolve_analyzer(self) -> str:
        for candidate in ("clang", "clang-cl"):
            try:
                subprocess.run(
                    [candidate, "--version"],
                    capture_output=True,
                    text=True,
                    check=False,
                    encoding="utf-8",
                    errors="replace",
                )
                return candidate
            except FileNotFoundError:
                continue
        raise StaticAnalysisToolUnavailable(
            "Clang Static Analyzer is not installed or not available in PATH."
        )

    def _iter_sources(self, project_path: Path) -> list[Path]:
        extensions = {".c", ".cc", ".cpp", ".cxx"}
        if project_path.is_file():
            return [project_path] if project_path.suffix.lower() in extensions else []
        return [
            path
            for path in project_path.rglob("*")
            if path.is_file() and path.suffix.lower() in extensions
        ]

    def _parse_text_output(self, stderr: str, source: Path) -> list[dict]:
        findings: list[dict] = []
        for line in stderr.splitlines():
            if "warning:" not in line and "error:" not in line:
                continue
            parts = line.split(":", 4)
            if len(parts) < 5:
                continue
            try:
                line_number = int(parts[1])
                column = int(parts[2])
            except ValueError:
                line_number = 1
                column = None
            severity = "warning" if "warning:" in line else "error"
            message = parts[-1].strip()
            findings.append(
                {
                    "tool": "clang",
                    "rule_id": "clang-analyzer",
                    "severity": severity,
                    "message": message,
                    "file_path": str(source),
                    "line": line_number,
                    "column": column,
                }
            )
        return findings
