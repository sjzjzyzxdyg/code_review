"""Lightweight function index for C/C++ projects.

Parses function definitions with a comment- and string-aware brace scanner,
records which functions each one calls, and answers caller/callee queries
across files. Regex-based rather than a full parser: cheap enough to run on
every scan, and good enough to slice code into function-level units for the
LLM. (clang_ast.py stays the source of truth for the AST-based checkers.)
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

SOURCE_EXTS = {".c", ".cc", ".cpp", ".cxx"}

_SIGNATURE = re.compile(
    r"^\s*(?:[\w:*&<>,\[\]\s]+?)[\s*&]+(?P<name>[A-Za-z_][\w:~]*)\s*\((?P<params>[^;{}]*)\)\s*(?:const\s*)?(?P<brace>\{)?\s*$"
)
_NAMESPACE = re.compile(r"^\s*namespace\s+([A-Za-z_][\w:]*)")
_CALL = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_KEYWORDS = {
    "if", "for", "while", "switch", "return", "sizeof", "catch", "else", "do",
    "case", "new", "delete", "defined", "alignof", "decltype", "static_assert",
}


def blank_comments_and_strings(text: str, keep_strings: bool = False) -> str:
    """Replace comments (and optionally string/char literals) with spaces,
    preserving every newline so line numbers stay valid."""
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if ch == "/" and nxt == "/":
            while i < n and text[i] != "\n":
                out.append(" ")
                i += 1
        elif ch == "/" and nxt == "*":
            out.append("  ")
            i += 2
            while i < n and not (text[i] == "*" and i + 1 < n and text[i + 1] == "/"):
                out.append("\n" if text[i] == "\n" else " ")
                i += 1
            out.append("  ")
            i += 2
        elif ch in "\"'":
            quote = ch
            out.append(ch)
            i += 1
            while i < n and text[i] != quote and text[i] != "\n":
                if text[i] == "\\" and i + 1 < n:
                    out.append(text[i:i + 2] if keep_strings else "  ")
                    i += 2
                    continue
                out.append(text[i] if keep_strings else " ")
                i += 1
            if i < n and text[i] == quote:
                out.append(quote)
                i += 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)


@dataclass
class Function:
    name: str               # unqualified name ("bar" for "Foo::bar")
    qualified_name: str
    file: Path
    start: int              # 1-based, signature line
    end: int                # 1-based, closing brace line (inclusive)
    code: list[str]         # original source lines start..end
    calls: set[str] = field(default_factory=set)
    namespace: str | None = None

    @property
    def key(self) -> tuple[str, int]:
        return str(self.file), self.start

    def __hash__(self) -> int:
        return hash(self.key)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Function) and self.key == other.key


class CodeIndex:
    def __init__(self, functions: list[Function]) -> None:
        self.functions = functions
        self.by_name: dict[str, list[Function]] = defaultdict(list)
        for fn in functions:
            self.by_name[fn.name].append(fn)
        self._callers: dict[str, list[Function]] = defaultdict(list)
        for fn in functions:
            for callee in fn.calls:
                self._callers[callee].append(fn)

    # ── Construction ────────────────────────────────────────────────────────

    @classmethod
    def build(cls, root: Path, max_files: int = 3000) -> "CodeIndex":
        paths = [root] if root.is_file() else sorted(
            p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in SOURCE_EXTS
        )
        functions: list[Function] = []
        for path in paths[:max_files]:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            functions.extend(parse_functions(path, text))
        return cls(functions)

    # ── Queries ─────────────────────────────────────────────────────────────

    def resolve(self, caller: Function, name: str, max_candidates: int = 3) -> list[Function]:
        """Definitions a call to ``name`` from ``caller`` can reach. A same-file
        definition wins (static helpers reuse names across files); otherwise
        link across files, unless the name is so common it's ambiguous."""
        candidates = self.by_name.get(name, [])
        local = [fn for fn in candidates if fn.file == caller.file]
        if local:
            return local
        if caller.namespace:
            same_ns = [fn for fn in candidates if fn.namespace == caller.namespace]
            if same_ns:
                return same_ns
        return candidates if len(candidates) <= max_candidates else []

    def callees(self, fn: Function) -> list[Function]:
        return [target for name in sorted(fn.calls) for target in self.resolve(fn, name) if target != fn]

    def callers(self, fn: Function) -> list[Function]:
        return [
            caller for caller in self._callers.get(fn.name, [])
            if caller != fn and fn in self.resolve(caller, fn.name)
        ]

    def function_at(self, file: Path, line: int) -> Function | None:
        for fn in self.functions:
            if fn.file == file and fn.start <= line <= fn.end:
                return fn
        return None


def parse_functions(path: Path, text: str) -> list[Function]:
    raw_lines = text.splitlines()
    clean_lines = blank_comments_and_strings(text).splitlines()
    functions: list[Function] = []
    namespace: str | None = None
    i = 0
    while i < len(clean_lines):
        ns = _NAMESPACE.match(clean_lines[i])
        if ns:
            namespace = ns.group(1)
        match = _SIGNATURE.match(clean_lines[i])
        if not match or match.group("name").split("::")[-1] in _KEYWORDS:
            i += 1
            continue
        # The opening brace must be on the signature line or the next non-blank line;
        # otherwise this is a prototype / macro / something else.
        open_line = i
        if not match.group("brace"):
            j = i + 1
            while j < len(clean_lines) and not clean_lines[j].strip():
                j += 1
            if j >= len(clean_lines) or not clean_lines[j].lstrip().startswith("{"):
                i += 1
                continue
            open_line = j
        depth = 0
        end = open_line
        for end in range(open_line, len(clean_lines)):
            depth += clean_lines[end].count("{") - clean_lines[end].count("}")
            if depth <= 0 and "{" in "".join(clean_lines[open_line:end + 1]):
                break
        qualified = match.group("name")
        body = "\n".join(clean_lines[open_line:end + 1])
        calls = {c for c in _CALL.findall(body) if c not in _KEYWORDS}
        functions.append(Function(
            name=qualified.split("::")[-1],
            qualified_name=qualified,
            file=path,
            start=i + 1,
            end=end + 1,
            code=raw_lines[i:end + 1],
            calls=calls,
            namespace=namespace,
        ))
        i = end + 1
    return functions
