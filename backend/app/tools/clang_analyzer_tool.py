import logging
import re
import subprocess
from pathlib import Path

from app.core.config import settings
from app.tools.cppcheck_tool import StaticAnalysisToolUnavailable
from app.tools.structured_tools import make_structured_tool

logger = logging.getLogger(__name__)


class ClangAnalyzerTool:
    """Adapter for Clang Static Analyzer with plist/text tolerant parsing."""

    def as_structured_tool(self):
        return make_structured_tool(
            name="clang_static_analyzer_scan",
            description="Run Clang Static Analyzer on C/C++ files and return normalized findings.",
            func=lambda project_path: self.run(Path(project_path)),
        )

    def run(self, project_path: Path, include_paths: list[Path] | None = None) -> list[dict]:
        analyzer = self._resolve_analyzer()
        findings: list[dict] = []
        inc_flags: list[str] = []
        for inc in (include_paths or []):
            inc_flags.extend(["-I", str(inc)])
        for source in self._iter_sources(project_path):
            command = [analyzer, "--analyze", *inc_flags, str(source)]
            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    check=False,
                    encoding="utf-8",
                    errors="replace",
                    timeout=settings.tool_timeout_seconds,
                )
            except subprocess.TimeoutExpired:
                logger.warning(
                    "clang --analyze timed out after %ss on %s",
                    settings.tool_timeout_seconds, source,
                )
                continue
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
                    timeout=10,
                )
                return candidate
            except (FileNotFoundError, subprocess.TimeoutExpired):
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

    # Anchored on ":<line>:<col>: <severity>:" rather than split(":") so a
    # Windows drive letter ("C:\src\a.c:12:5: warning: ...") doesn't shift
    # every field and collapse all findings onto line 1.
    _DIAG_RE = re.compile(
        r"^(?P<file>.*?):(?P<line>\d+):(?P<col>\d+):\s*(?P<sev>(?:fatal )?error|warning):\s*(?P<msg>.*)$"
    )

    def _parse_text_output(self, stderr: str, source: Path) -> list[dict]:
        findings: list[dict] = []
        for line in stderr.splitlines():
            match = self._DIAG_RE.match(line.strip())
            if not match:
                continue
            if match.group("sev") != "warning":
                # Compiler errors (e.g. a missing header) are not analyzer
                # findings; they only mean the file couldn't be analysed.
                logger.debug("clang could not analyse %s: %s", source, match.group("msg"))
                continue
            line_number = int(match.group("line"))
            column = int(match.group("col"))
            severity = "warning"
            message = match.group("msg").strip()
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
