import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
import re

from app.tools.structured_tools import make_structured_tool


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

    def run(self, project_path: Path, rule_level: str = "all") -> list[dict]:
        command = [
            "cppcheck",
            "--enable=all" if rule_level == "all" else f"--enable={rule_level}",
            "--xml",
            "--xml-version=2",
            "--inline-suppr",
            str(project_path),
        ]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                encoding="utf-8",
                errors="replace",
            )
        except FileNotFoundError as exc:
            raise StaticAnalysisToolUnavailable(
                "Cppcheck is not installed or not available in PATH."
            ) from exc

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


class BuiltinCppHeuristicTool:
    """Small fallback scanner used when cppcheck is unavailable locally."""

    SOURCE_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}
    RULES = (
        (
            "builtin-null-deref",
            "error",
            re.compile(r"\*\s*(?:nullptr|NULL)\b"),
            "Suspicious direct dereference of a null-like value.",
        ),
        (
            "builtin-null-check-missing",
            "error",
            re.compile(r"(?<![!=<>])\*\s*[A-Za-z_]\w*\s*(?:->|\[|\.|\))"),
            "Pointer used without a preceding null check; dereference may crash.",
        ),
        (
            "builtin-malloc-no-check",
            "error",
            re.compile(r"\b(?:malloc|calloc|realloc)\s*\("),
            "malloc/calloc/realloc return value must be checked for NULL before use.",
        ),
        (
            "builtin-div-by-var",
            "error",
            re.compile(r"/\s*(?![\d\s])[A-Za-z_]\w*\s*[;,\)\]]"),
            "Division by a variable without a preceding zero check; possible divide-by-zero.",
        ),
        (
            "builtin-double-free",
            "error",
            re.compile(r"\bfree\s*\("),
            "Call to free() detected; ensure pointer is not freed twice and is set to NULL afterwards.",
        ),
        (
            "builtin-raw-new",
            "style",
            re.compile(r"\bnew\s+[A-Za-z_][\w:<>]*"),
            "Raw allocation detected; prefer RAII containers or smart pointers.",
        ),
        (
            "builtin-unsafe-copy",
            "warning",
            re.compile(r"\b(strcpy|strcat|sprintf|gets)\s*\("),
            "Unsafe C library call detected; use a bounded alternative.",
        ),
        (
            "builtin-todo",
            "style",
            re.compile(r"\b(TODO|FIXME)\b", re.IGNORECASE),
            "TODO/FIXME marker found in reviewed code.",
        ),
    )

    def run(self, project_path: Path) -> list[dict]:
        findings: list[dict] = []
        for source in self._iter_sources(project_path):
            try:
                lines = source.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue

            for index, line in enumerate(lines, start=1):
                for rule_id, severity, pattern, message in self.RULES:
                    match = pattern.search(line)
                    if match is None:
                        continue
                    findings.append(
                        {
                            "tool": "builtin-cppcheck-fallback",
                            "rule_id": rule_id,
                            "severity": severity,
                            "message": message,
                            "file_path": str(source),
                            "line": index,
                            "column": match.start() + 1,
                        }
                    )
        return findings

    def _iter_sources(self, project_path: Path) -> list[Path]:
        if project_path.is_file():
            return [project_path] if project_path.suffix.lower() in self.SOURCE_EXTENSIONS else []
        return [
            path
            for path in project_path.rglob("*")
            if path.is_file() and path.suffix.lower() in self.SOURCE_EXTENSIONS
        ]
