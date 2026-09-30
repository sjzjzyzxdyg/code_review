"""LLM semantic audit: the second detection path, parallel to static analysis.

Static tools pattern-match single rules and can't tell a sink fed by a
validated value from one fed by attacker input. This agent asks the LLM to
reason about data flow instead, over function-level slices of the code:

1. Index every function (app/tools/code_index.py) and pick "suspicious" ones:
   those containing a potentially dangerous operation (memory management,
   buffer/string copies, format functions, array indexing, division,
   arithmetic on variables).
2. For each suspicious function, build a slice: the function itself, its
   callers up to two levels (where arguments come from, possibly in other
   files) and the bodies of functions it calls directly.
3. Pack slices into units under a character budget, so one LLM call sees a
   coherent source→sink path without dragging in whole files.
4. Ask for a JSON list of confirmed defects with CWE, severity and the line of
   the dangerous operation. Output is validated against the files and line
   ranges actually shown; anything else is discarded as hallucination.

Findings come back as plain detector dicts (same shape as cppcheck/clang
findings), so the fusion layer can treat both paths uniformly.
"""

from __future__ import annotations

import concurrent.futures
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from app.core import cwe as cwe_map
from app.core.config import settings
from app.core.llm_client import chat_completion, llm_available, parse_json_array
from app.tools.code_index import CodeIndex, Function, blank_comments_and_strings

logger = logging.getLogger(__name__)

TOOL_NAME = "llm-semantic"

_UNIT_CHAR_BUDGET = 8_000
_MAX_FUNCTION_CHARS = 6_000
_CALLER_DEPTH = 2
_MAX_UNITS = 400
_WORKERS = 4

_SUSPICIOUS = re.compile(
    r"\b(?:malloc|calloc|realloc|alloca|free|strdup|new|delete|"
    r"memcpy|memmove|memset|strcpy|strncpy|strcat|strncat|wcscpy|wcsncpy|wcscat|wcsncat|"
    r"sprintf|snprintf|vsprintf|vsnprintf|swprintf|printf|fprintf|vprintf|vfprintf|wprintf|fwprintf|"
    r"gets|fgets|scanf|fscanf|sscanf|recv|read|getenv|atoi|strtol|rand)\b"
    r"|\w\s*\[[^\]]*[A-Za-z_][^\]]*\]"          # array index by a variable
    r"|[\w)\]]\s*[/%]=?\s*[\w(]"                 # division / modulo
    r"|\+\+|--|[\w)\]]\s*[-+*]=?\s*[\w(]"        # arithmetic on variables
    r"|->|\*\s*[A-Za-z_]\w*\s*[=;,)]"            # pointer dereference
)

_SYSTEM = (
    "You are a senior C/C++ security auditor. You review code slices for real, "
    "exploitable defects and you are careful about false positives."
)

_PROMPT = """\
Below are function-level slices of a C/C++ project. Each slice shows a function
that performs potentially dangerous operations, the functions that call it
(where its arguments come from, possibly in other files), and helpers it calls.
Line numbers are shown on the left.

Check for these defect classes:
- CWE-121/122/124/126/127/787: out-of-bounds read/write (array index, memcpy/strcpy/strcat size, loop bound, off-by-one)
- CWE-190/191: integer overflow / underflow in arithmetic on untrusted or extreme values
- CWE-369: division or modulo by a value that can be zero
- CWE-134: externally controlled format string
- CWE-401: memory leak (allocated memory never freed on some path)
- CWE-415: double free; CWE-416: use after free
- CWE-590: freeing memory not on the heap (stack, static, alloca)
- CWE-762: mismatched allocator (malloc/delete, new/free, new[]/delete)
- CWE-476/690: NULL pointer dereference, including unchecked allocation results

Rules:
1. Follow the data flow through the callers shown. A parameter is only dangerous
   if some caller can actually pass a dangerous value.
2. Code that validates the value first (bounds check, NULL check, zero check,
   overflow check, constant format string, matching allocator) is NOT a defect.
   Do not report it.
3. When one sink function is reached from several callers, judge each call path
   separately, and report the sink only if at least one path is dangerous.
4. Report the line of the dangerous operation itself (the sink), in the file
   where that line appears.
5. Only report defects you are confident about. An empty list is a fine answer.

Return ONLY a JSON array, no prose. Each element:
{{"file": "<file name exactly as in a FILE header>", "line": <int>, "cwe": "CWE-<n>",
  "severity": "high|medium|low", "confidence": <0.0-1.0>,
  "message": "<one sentence: what flows where and why it is dangerous>"}}

{code}
"""


@dataclass
class AuditUnit:
    functions: list[Function] = field(default_factory=list)
    focus: list[Function] = field(default_factory=list)

    def chars(self) -> int:
        return sum(len("\n".join(fn.code)) + 16 for fn in self.functions)


class SemanticAuditAgent:
    """Function-level LLM vulnerability audit (the 'LLM path' of detection)."""

    def run(self, project_path: Path, task_id: str | None = None) -> list[dict]:
        if not llm_available():
            return []
        index = CodeIndex.build(project_path)
        units = self.build_units(index)
        if not units:
            return []
        if len(units) > _MAX_UNITS:
            logger.warning("Semantic audit: %d units, auditing the first %d.", len(units), _MAX_UNITS)
            units = units[:_MAX_UNITS]
        findings: list[dict] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=_WORKERS) as pool:
            for future in concurrent.futures.as_completed(
                [pool.submit(self._audit_unit, unit, project_path) for unit in units]
            ):
                try:
                    findings.extend(future.result())
                except Exception:
                    logger.exception("Semantic audit failed for one unit; skipping it.")
        return findings

    # ── Slicing ──────────────────────────────────────────────────────────────

    def build_units(self, index: CodeIndex) -> list[AuditUnit]:
        suspicious = [fn for fn in index.functions if fn.name != "main" and _is_suspicious(fn)]
        units: list[AuditUnit] = []
        current = AuditUnit()
        seen_focus: set[Function] = set()
        # Visit functions so that related ones (same file, then call-graph
        # neighbours) land in the same unit and share context.
        for fn in _ordered_by_affinity(suspicious, index):
            if fn in seen_focus:
                continue
            slice_fns = self._slice(fn, index)
            merged = list(dict.fromkeys(current.functions + slice_fns))
            candidate = AuditUnit(merged, current.focus + [fn])
            if current.functions and candidate.chars() > _UNIT_CHAR_BUDGET:
                units.append(current)
                candidate = AuditUnit(list(dict.fromkeys(slice_fns)), [fn])
            current = candidate
            seen_focus.update(f for f in slice_fns if f in set(suspicious))
        if current.functions:
            units.append(current)
        return units

    def _slice(self, fn: Function, index: CodeIndex) -> list[Function]:
        chosen: list[Function] = [fn]
        frontier = [fn]
        for _ in range(_CALLER_DEPTH):
            frontier = [c for f in frontier for c in index.callers(f) if c.name != "main" and c not in chosen]
            chosen.extend(dict.fromkeys(frontier))
        chosen.extend(c for c in index.callees(fn) if c not in chosen)
        return chosen

    # ── LLM call ─────────────────────────────────────────────────────────────

    def render(self, unit: AuditUnit, root: Path) -> tuple[str, dict[str, Path]]:
        """Render a unit as numbered source grouped by file. Returns the text
        and a map of the displayed file names back to real paths."""
        by_file: dict[Path, list[Function]] = {}
        for fn in unit.functions:
            by_file.setdefault(fn.file, []).append(fn)
        names: dict[str, Path] = {}
        parts: list[str] = []
        for path in sorted(by_file):
            shown = _display_name(path, root)
            names[shown] = path
            parts.append(f"=== FILE: {shown} ===")
            previous_end = None
            for fn in sorted(by_file[path], key=lambda f: f.start):
                if previous_end is not None and fn.start > previous_end + 1:
                    parts.append("      ...")
                code = "\n".join(
                    f"{fn.start + offset:5d}| {line}" for offset, line in enumerate(fn.code)
                )
                parts.append(code[:_MAX_FUNCTION_CHARS])
                previous_end = fn.end
        return "\n".join(parts), names

    def _audit_unit(self, unit: AuditUnit, root: Path) -> list[dict]:
        code, names = self.render(unit, root)
        payload = {
            "model": settings.llm_model,
            "temperature": 0.0,
            "messages": [
                {"role": "system", "content": _SYSTEM},
                {"role": "user", "content": _PROMPT.format(code=code)},
            ],
        }
        data = self._call_api(payload)
        content = data["choices"][0]["message"].get("content") or ""
        return self.parse(content, unit, names)

    def parse(self, content: str, unit: AuditUnit, names: dict[str, Path]) -> list[dict]:
        shown_ranges: dict[Path, list[tuple[int, int]]] = {}
        for fn in unit.functions:
            shown_ranges.setdefault(fn.file, []).append((fn.start, fn.end))
        by_basename = {path.name: path for path in names.values()}
        findings: list[dict] = []
        for item in parse_json_array(content):
            if not isinstance(item, dict):
                continue
            shown = str(item.get("file") or "")
            path = names.get(shown) or by_basename.get(re.split(r"[\\/]", shown)[-1])
            try:
                line = int(item.get("line"))
            except (TypeError, ValueError):
                continue
            # Discard anything outside the code we actually showed.
            if path is None or not any(start <= line <= end for start, end in shown_ranges.get(path, [])):
                continue
            cwe = cwe_map.normalize(item.get("cwe"))
            if cwe is None:
                continue
            try:
                confidence = min(max(float(item.get("confidence", 0.7)), 0.0), 1.0)
            except (TypeError, ValueError):
                confidence = 0.7
            severity = str(item.get("severity") or "medium").lower()
            findings.append({
                "tool": TOOL_NAME,
                "rule_id": f"llm-{cwe.lower()}",
                "cwe": cwe,
                "severity": {"high": "error", "critical": "error", "low": "style"}.get(severity, "warning"),
                "message": str(item.get("message") or "")[:500],
                "file_path": str(path),
                "line": line,
                "column": None,
                "confidence": confidence,
            })
        return findings

    def _call_api(self, payload: dict) -> dict:
        return chat_completion(payload)


def _is_suspicious(fn: Function) -> bool:
    body = blank_comments_and_strings("\n".join(fn.code[1:]), keep_strings=False)
    return bool(_SUSPICIOUS.search(body))


def _ordered_by_affinity(functions: list[Function], index: CodeIndex) -> list[Function]:
    """Order functions so call-graph neighbours are adjacent: walk connected
    components of the (undirected) call graph, files in path order."""
    pending = sorted(functions, key=lambda f: (str(f.file), f.start))
    wanted = set(pending)
    ordered: list[Function] = []
    visited: set[Function] = set()
    for start in pending:
        if start in visited:
            continue
        stack = [start]
        component: list[Function] = []
        while stack:
            fn = stack.pop()
            if fn in visited:
                continue
            visited.add(fn)
            if fn in wanted:
                component.append(fn)
            stack.extend(n for n in index.callers(fn) + index.callees(fn) if n not in visited and n.name != "main")
        ordered.extend(sorted(component, key=lambda f: (str(f.file), f.start)))
    return ordered


def _display_name(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root)).replace("\\", "/")
    except ValueError:
        return path.name
