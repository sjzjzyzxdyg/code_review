import re
from pathlib import Path

from app.tools.structured_tools import make_structured_tool

_RESERVED = {"if", "for", "while", "switch", "return", "sizeof", "catch", "else"}


class ASTParserTool:
    """Lightweight AST-style summarizer for C/C++ source context."""

    FUNCTION_PATTERN = re.compile(
        r"^\s*(?:[\w:*&<>\[\]\s]+)\s+([A-Za-z_]\w*)\s*\([^;]*\)\s*(?:const\s*)?\{?"
    )
    INCLUDE_PATTERN = re.compile(r"^\s*#\s*include\s+[<\"]([^>\"]+)[>\"]")
    TYPE_PATTERN = re.compile(r"^\s*(class|struct|enum)\s+([A-Za-z_]\w*)")

    def as_structured_tool(self):
        return make_structured_tool(
            name="ast_context_summary",
            description="Summarize source-level AST context around a file and line.",
            func=self.summarize,
        )

    def summarize(self, file_path: str, line: int) -> dict:
        path = Path(file_path)
        if not path.exists() or not path.is_file():
            return {
                "file_path": file_path,
                "line": line,
                "summary": "Source file is unavailable for AST summary.",
                "function": None,
                "types": [],
                "dependencies": [],
            }

        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        function = self._nearest_function(lines, line)
        types = self._nearby_types(lines, line)
        dependencies = self._dependencies(lines)
        parts = []
        if function:
            parts.append(f"inside function `{function}`")
        if types:
            parts.append("near " + ", ".join(f"{kind} `{name}`" for kind, name in types[:3]))
        if dependencies:
            parts.append(f"{len(dependencies)} include dependencies")
        summary = "; ".join(parts) if parts else "No nearby function or type declaration was detected."

        return {
            "file_path": file_path,
            "line": line,
            "summary": summary,
            "function": function,
            "types": [{"kind": kind, "name": name} for kind, name in types],
            "dependencies": dependencies,
        }

    def _nearest_function(self, lines: list[str], line: int) -> str | None:
        functions = self._parse_function_ranges(lines)
        target = line  # 1-based
        for name, start, end in functions:
            if start <= target <= end:
                return name
        # Fallback: scan upward from target line
        index = min(max(line - 1, 0), len(lines) - 1)
        for current in range(index, -1, -1):
            match = self.FUNCTION_PATTERN.match(lines[current])
            if match and match.group(1) not in _RESERVED:
                return match.group(1)
        return None

    def _parse_function_ranges(self, lines: list[str]) -> list[tuple[str, int, int]]:
        ranges: list[tuple[str, int, int]] = []
        index = 0
        while index < len(lines):
            match = self.FUNCTION_PATTERN.match(lines[index])
            if not match or match.group(1) in _RESERVED:
                index += 1
                continue
            name = match.group(1)
            start = index + 1  # 1-based
            depth = lines[index].count("{") - lines[index].count("}")
            end_index = index
            if "{" not in lines[index]:
                while end_index + 1 < len(lines) and depth <= 0:
                    end_index += 1
                    depth += lines[end_index].count("{") - lines[end_index].count("}")
            while end_index + 1 < len(lines) and depth > 0:
                end_index += 1
                depth += lines[end_index].count("{") - lines[end_index].count("}")
            ranges.append((name, start, end_index + 1))
            index = max(end_index + 1, index + 1)
        return ranges

    def _nearby_types(self, lines: list[str], line: int) -> list[tuple[str, str]]:
        start = max(line - 80, 0)
        end = min(line + 20, len(lines))
        matches: list[tuple[str, str]] = []
        for source_line in lines[start:end]:
            match = self.TYPE_PATTERN.match(source_line)
            if match:
                matches.append((match.group(1), match.group(2)))
        return matches

    def _dependencies(self, lines: list[str]) -> list[str]:
        dependencies: list[str] = []
        for source_line in lines:
            match = self.INCLUDE_PATTERN.match(source_line)
            if match:
                dependencies.append(match.group(1))
        return dependencies[:50]
