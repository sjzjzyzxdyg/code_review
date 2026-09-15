import logging
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

from app.core.config import settings
from app.tools.structured_tools import make_structured_tool

logger = logging.getLogger(__name__)

# Style/config IDs that generate high volumes of noise and are never
# security-relevant; suppressed both at the cppcheck command level and
# defensively filtered in the parser.
_SUPPRESS_IDS: tuple[str, ...] = (
    # Build / include noise
    "missingInclude",
    "missingIncludeSystem",
    # Pure style — not security-relevant; generate high volume of FP
    "variableScope",
    "redundantAssignment",
    "staticFunction",
    "constParameter",
    "constParameterPointer",
    "constParameterReference",
    # Performance / analysis-depth note
    "normalCheckLevelMaxBranches",
)
_SUPPRESS_IDS_SET: frozenset[str] = frozenset(_SUPPRESS_IDS)


class StaticAnalysisToolUnavailable(RuntimeError):
    pass


class CppcheckTool:
    """Adapter for cppcheck XML output."""

    def as_structured_tool(self):
        return make_structured_tool(
            name="cppcheck_scan",
            description="Run Cppcheck against a C/C++ project path and return normalized findings.",
            func=lambda project_path, rule_level="all": self.run(Path(project_path), rule_level),
        )

    def run(
        self,
        project_path: Path,
        rule_level: str = "all",
        rule_files: list[Path] | None = None,
        include_paths: list[Path] | None = None,
        target_files: list[Path] | None = None,
    ) -> list[dict]:
        """Run cppcheck against `project_path`, or against just
        `target_files` when given (used for incremental re-scans: the caller
        has already worked out which files changed since the last scan of
        this project). `target_files=[]` means "nothing changed" — skip
        invoking the tool entirely rather than running it with no target."""
        if target_files is not None and not target_files:
            return []

        command = [
            "cppcheck",
            "--enable=all" if rule_level == "all" else f"--enable={rule_level}",
            "--xml",
            "--xml-version=2",
            "--inline-suppr",
        ]
        for sid in _SUPPRESS_IDS:
            command.append(f"--suppress={sid}")
        for inc in (include_paths or []):
            command.extend(["-I", str(inc)])
        for rf in (rule_files or []):
            command.append(f"--rule-file={rf}")
        if target_files:
            command.extend(str(f) for f in target_files)
        else:
            command.append(str(project_path))

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
        except FileNotFoundError as exc:
            raise StaticAnalysisToolUnavailable(
                "Cppcheck is not installed or not available in PATH."
            ) from exc
        except subprocess.TimeoutExpired:
            logger.warning(
                "cppcheck timed out after %ss on %s", settings.tool_timeout_seconds, project_path
            )
            return []

        return self._parse_xml(result.stderr)

    def _parse_xml(self, xml_output: str) -> list[dict]:
        if not xml_output.strip():
            return []

        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError:
            return []

        findings: list[dict] = []
        errors = root.find("errors")
        if errors is None:
            return findings

        for error in errors.findall("error"):
            if error.attrib.get("id") in _SUPPRESS_IDS_SET:
                continue
            location = error.find("location")
            if location is None:
                continue

            findings.append(
                {
                    "tool": "cppcheck",
                    "rule_id": error.attrib.get("id"),
                    "severity": error.attrib.get("severity", "warning"),
                    "message": error.attrib.get("msg", ""),
                    "file_path": location.attrib.get("file", ""),
                    "line": int(location.attrib.get("line", "1")),
                    "column": int(location.attrib["column"])
                    if location.attrib.get("column")
                    else None,
                }
            )

        return findings
