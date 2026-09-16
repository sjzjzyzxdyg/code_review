"""
LLM-based cross-file taint flow analyzer.

Groups source files that form split implementations (e.g. the Juliet Test Suite
*_51a / *_51b pattern where tainted data is produced in one file and consumed
in another) and asks an LLM to trace the data flow across them.

Why LLM instead of cppcheck/clang:
  Cross-file interprocedural taint analysis requires knowing that a value set
  in one compilation unit flows through a function-call boundary into a sink
  in another unit.  Classic static tools analyze files independently and miss
  this class of bug unless given a whole-program compilation database.  An LLM
  can read both files simultaneously and trace the flow by understanding naming
  conventions and data semantics.
"""

import concurrent.futures
import json
import logging
import re
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from app.core.config import settings
from app.schemas.issue import ReviewIssueRead

logger = logging.getLogger(__name__)

_SOURCE_EXTENSIONS: frozenset[str] = frozenset({".c", ".cc", ".cpp", ".cxx"})
_MAX_BUNDLE_CHARS = 24_000   # total chars across all files in one bundle
_MAX_FILE_CHARS   = 10_000   # per-file truncation cap

# Matches Juliet-style split suffixes: _51a, _51b, _52a, etc.
# Requires at least one digit before a single lowercase letter at end of stem.
_SPLIT_SUFFIX_RE = re.compile(r"_\d+[a-z]$")

_RULE_META: dict[str, dict] = {
    "taint-cross-file-flow": {
        "risk_level": "high",
        "confidence": 0.80,
        "fix": (
            "Validate or bound-check the value before using it as an array index, "
            "format string argument, divisor, or pointer."
        ),
    },
    "taint-unvalidated-input": {
        "risk_level": "high",
        "confidence": 0.75,
        "fix": (
            "Add input validation at the point where external data enters the program, "
            "or guard the dangerous operation with an explicit range/null check."
        ),
    },
}

_TAINT_PROMPT = """\
You are a C/C++ security vulnerability analyst.

The source files below belong to the SAME logical unit — they call each other directly.
Find ALL security vulnerabilities by checking the three patterns below.

━━ PATTERN 1 — CROSS-FILE TAINT FLOW ━━
External/untrusted data produced in one file (via recv/accept/connect socket, fscanf,
fgets, rand, getenv, argv, time, atoi, sscanf, etc.) is passed as a function argument
into ANOTHER file, where it reaches a dangerous sink WITHOUT adequate validation.
Dangerous sinks: array/buffer index write (buf[data]), format string argument
(%s/%d without literal format), integer arithmetic wrapping, pointer dereference.

━━ PATTERN 2 — INTRA-FILE TAINT FLOW ━━
Same as Pattern 1 but the untrusted source and the dangerous sink are in the same file.

━━ PATTERN 3 — MEMORY MANAGEMENT BUGS ━━
These do NOT need external input — trace pointer ownership across all files:
a) Double-free (CWE-415): a pointer freed in one function/file is passed to another
   function that also calls free()/delete/delete[] on it, OR freed twice in the same sink.
b) Mismatched allocator (CWE-762): pointer from malloc/calloc/realloc freed with
   delete/delete[], or from new/new[] freed with free() — especially across files.
c) Free of non-heap memory (CWE-590): stack array or static/global pointer passed
   across a file boundary and then freed with free()/delete/delete[].
d) Use-after-free (CWE-416): pointer freed in one file then dereferenced or re-used
   in another.

For every vulnerability found, output one JSON object:
{{
  "file_path": "<exact file path as shown in the header lines below>",
  "line":      <integer, 1-based line of the dangerous operation>,
  "rule_id":   "taint-cross-file-flow",
  "cwe":       "<e.g. CWE-121, CWE-415, CWE-762 — best match, empty string if unsure>",
  "message":   "<concise: what flows from where to what sink, why dangerous>"
}}

Use "taint-unvalidated-input" as rule_id for Pattern 2 (intra-file) findings.
Return ONLY a JSON array.  Empty array [] if nothing found.
Do NOT wrap in markdown fences.

=== SOURCE FILES ===
{files_content}
"""


class TaintFlowAgent:
    """
    Cross-file LLM taint flow analyzer.

    Groups related source files by name pattern and asks the LLM to trace
    data flow across function-call boundaries between files.
    Returns an empty list when no LLM is configured.
    """

    def run(self, project_path: Path, task_id: str) -> list[ReviewIssueRead]:
        if not (settings.llm_enabled and settings.llm_api_key):
            return []
        return self._llm_run(project_path, task_id)

    # ── Core pipeline ─────────────────────────────────────────────────────────

    def _llm_run(self, project_path: Path, task_id: str) -> list[ReviewIssueRead]:
        sources = _iter_sources(project_path)
        if not sources:
            return []
        groups = _group_files(sources)
        if not groups:
            return []
        workers = min(len(groups), 4)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(self._analyze_group, grp, task_id) for grp in groups]
            issues: list[ReviewIssueRead] = []
            for fut in concurrent.futures.as_completed(futures):
                try:
                    issues.extend(fut.result())
                except Exception:
                    # A single group's LLM call failing (timeout, malformed
                    # response, ...) previously vanished silently, making a
                    # real miss indistinguishable from "nothing to find here".
                    logger.exception("Taint-flow analysis failed for one file group; skipping it.")
        return issues

    def _analyze_group(self, files: list[Path], task_id: str) -> list[ReviewIssueRead]:
        parts: list[str] = []
        total = 0
        for f in sorted(files):
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            truncated = text[:_MAX_FILE_CHARS]
            header = f"\n--- FILE: {f} ---\n"
            budget_left = _MAX_BUNDLE_CHARS - total - len(header)
            if budget_left < 200:
                break
            if len(truncated) > budget_left:
                truncated = truncated[:budget_left]
            parts.append(header + truncated)
            total += len(header) + len(truncated)

        if not parts:
            return []

        prompt = _TAINT_PROMPT.format(files_content="\n".join(parts))
        payload = {
            "model":       settings.llm_model,
            "temperature": 0.1,
            "messages":    [{"role": "user", "content": prompt}],
        }
        data = self._call_api(payload)
        content = (data["choices"][0]["message"].get("content") or "").strip()
        findings = self._parse_findings(content, task_id)

        # Reject any finding whose file_path is not one of the files we actually sent.
        # The LLM occasionally hallucinates Juliet-style filenames from training memory.
        valid_names = {f.name for f in files}
        valid_paths = {str(f) for f in files}
        return [
            iss for iss in findings
            if Path(iss.file_path).name in valid_names or iss.file_path in valid_paths
        ]

    def _parse_findings(self, content: str, task_id: str) -> list[ReviewIssueRead]:
        # Strip markdown fences if the LLM adds them anyway
        content = re.sub(r"^```(?:json)?\s*", "", content, flags=re.MULTILINE)
        content = re.sub(r"```\s*$", "", content, flags=re.MULTILINE).strip()
        try:
            findings = json.loads(content)
        except json.JSONDecodeError:
            m = re.search(r"\[.*\]", content, re.DOTALL)
            if not m:
                return []
            try:
                findings = json.loads(m.group(0))
            except json.JSONDecodeError:
                return []
        if not isinstance(findings, list):
            return []

        issues: list[ReviewIssueRead] = []
        for f in findings:
            if not isinstance(f, dict):
                continue
            rule_id = str(f.get("rule_id") or "taint-cross-file-flow")
            if rule_id not in _RULE_META:
                rule_id = "taint-cross-file-flow"
            meta = _RULE_META[rule_id]
            line_no   = max(int(f.get("line") or 1), 1)
            file_path = str(f.get("file_path") or "")
            cwe       = str(f.get("cwe") or "")
            message   = str(f.get("message") or "")
            issues.append(ReviewIssueRead(
                id=str(uuid4()),
                task_id=task_id,
                tool="taint-flow",
                rule_id=rule_id,
                file_path=file_path,
                line=line_no,
                column=None,
                issue_type=f"taint-flow ({cwe})" if cwe else "taint-flow",
                risk_level=meta["risk_level"],
                description=message,
                reason=(
                    f"LLM cross-file taint analysis{': ' + cwe if cwe else ''} — "
                    "unvalidated external data reaches a dangerous sink."
                ),
                fix_suggestion=meta["fix"],
                confidence=meta["confidence"],
                is_valid=True,
                code_snippet=_read_snippet(Path(file_path), line_no),
                created_at=datetime.utcnow(),
            ))
        return issues

    def _call_api(self, payload: dict) -> dict:
        last_exc: Exception = RuntimeError("no attempts made")
        for attempt in range(3):
            try:
                request = urllib.request.Request(
                    url=f"{settings.llm_base_url.rstrip('/')}/chat/completions",
                    data=json.dumps(payload).encode("utf-8"),
                    headers={
                        "Authorization": f"Bearer {settings.llm_api_key}",
                        "Content-Type":  "application/json",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(request, timeout=settings.llm_timeout_seconds) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except (urllib.error.URLError, OSError) as exc:
                last_exc = exc
                if attempt < 2:
                    time.sleep(2 ** attempt)
        raise last_exc


# ── Helpers ────────────────────────────────────────────────────────────────────

def _iter_sources(project_path: Path) -> list[Path]:
    if project_path.is_file():
        return [project_path] if project_path.suffix.lower() in _SOURCE_EXTENSIONS else []
    return [
        p for p in project_path.rglob("*")
        if p.is_file() and p.suffix.lower() in _SOURCE_EXTENSIONS
    ]


def _group_files(sources: list[Path]) -> list[list[Path]]:
    """
    Group source files that form a split-implementation pair (e.g. _51a / _51b).

    Files sharing the same (parent_dir, base_stem) after stripping the trailing
    _<digits><letter> suffix are placed in one group.  Unpaired files become
    singleton groups so they are still analyzed for intra-file taint issues.
    """
    bucket: dict[tuple, list[Path]] = {}
    for p in sources:
        stripped = _SPLIT_SUFFIX_RE.sub("", p.stem)
        key = (p.parent, stripped)
        bucket.setdefault(key, []).append(p)

    pairs     = [files for files in bucket.values() if len(files) >= 2]
    grouped   = {f for grp in pairs for f in grp}
    singletons = [[p] for p in sources if p not in grouped]
    return pairs + singletons


def _read_snippet(path: Path, line_no: int, context: int = 3) -> str:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    start = max(line_no - context - 1, 0)
    end   = min(line_no + context, len(lines))
    return "\n".join(f"{i + 1:4d}: {lines[i]}" for i in range(start, end))
