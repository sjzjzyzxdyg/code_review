"""
LLM-prompt-based semantic rule checker.

Rule 1 — semantic-missing-comment
  Command-line parameter definitions must have a descriptive comment.
  Comments that exist but contain obvious English spelling errors are also
  flagged.

  Why LLM instead of regex:
    Detecting *intent* — is this definition a command-line parameter? is this
    comment missing-but-needed? is this comment word misspelled? — requires
    language understanding. Regex matches syntax, not meaning.

Rule 2 — semantic-ccid-role-unchecked
  When a component is created via create(), the role field inside the returned
  ccid (component creation ID) is NOT reliable at that moment. The correct
  value is only delivered after the role-update callback fires. Direct access
  to ccid.role / ccid->role outside that callback is a logic bug.

  Why LLM instead of regex or AST state machine:
    The bug is an ordering constraint across statements. A state machine could
    track the rough pattern, but distinguishing "inside a registered callback
    body" from "outside it" requires understanding the surrounding control
    flow and variable bindings — well within LLM capability, beyond regex.
"""

import concurrent.futures
import json
import re
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from app.core.config import settings
from app.schemas.issue import ReviewIssueRead


_SOURCE_EXTENSIONS: frozenset[str] = frozenset({".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"})

# Truncate very large files so the prompt stays within a safe token budget.
_MAX_FILE_CHARS = 12_000


# ── Rule metadata ─────────────────────────────────────────────────────────────

_RULE_META: dict[str, dict] = {
    "semantic-missing-comment": {
        "risk_level": "low",
        "confidence": 0.70,
        "fix": (
            "Add a concise comment describing each command-line parameter, "
            "or correct the spelling error in the existing comment."
        ),
    },
    "semantic-comment-spelling": {
        "risk_level": "low",
        "confidence": 0.65,
        "fix": "Fix the spelling error in the comment.",
    },
    "semantic-ccid-role-unchecked": {
        "risk_level": "high",
        "confidence": 0.85,
        "fix": (
            "Do not read ccid.role / ccid->role immediately after create(). "
            "Register a role-update callback and read the role field only "
            "inside that callback, where the value is guaranteed to be correct."
        ),
    },
}


# ── LLM prompts ───────────────────────────────────────────────────────────────
# Single combined prompt — one API call per file instead of two.

_COMBINED_SEMANTIC_PROMPT = """\
You are a senior C/C++ code quality and security reviewer.

Analyze the following source file for EXACTLY THREE kinds of issues:

ISSUE TYPE A — rule_id "semantic-missing-comment":
  Any command-line parameter definition (functions that accept argc/argv,
  option structs / arrays, getopt / argparse-style tables, or help/usage
  string constants) MUST have a comment describing the parameter or option.
  Flag every such definition that is missing a comment entirely.

ISSUE TYPE B — rule_id "semantic-comment-spelling":
  Flag any // or /* */ comment that contains an obvious English spelling error
  (e.g. "recieve" → "receive", "occured" → "occurred", "adress" → "address").
  Do NOT flag identifiers or variable names inside executable code — only
  free-text inside comments.

ISSUE TYPE C — rule_id "semantic-ccid-role-unchecked":
  In this project, components are created with a create() call that returns
  or populates a "ccid" structure (component creation ID / component context).
  The `role` field inside ccid is NOT reliable immediately after create().
  Its correct value is delivered asynchronously via a role-update callback.
  Reading ccid.role or ccid->role (or any field named `role` on a variable
  whose type or name contains "ccid", "CcId", "cc_id", "compId", "ComponentId",
  or similar) outside a registered role-update callback is a logic bug.
  Flag every place where code reads the role field without going through
  the role-update callback.

For each problem found, output one JSON object with these exact keys:
  "line"    : integer, 1-based line number of the issue
  "rule_id" : one of "semantic-missing-comment", "semantic-comment-spelling",
              "semantic-ccid-role-unchecked"
  "message" : concise English description of the specific problem

Return a JSON ARRAY of all findings (one object per finding).
If nothing is wrong, return an empty array: []
Output ONLY the JSON array — no markdown fences, no extra text.

--- SOURCE FILE: {file_path} ---
{code}
"""


# ── Public agent ──────────────────────────────────────────────────────────────

class SemanticRuleAgent:
    """
    Scan a project with LLM prompts for semantic rules that require language
    understanding beyond regex or AST state machines.

    Returns an empty list when no LLM is configured.
    """

    def run(self, project_path: Path, task_id: str) -> list[ReviewIssueRead]:
        if not (settings.llm_enabled and settings.llm_api_key):
            return []
        return self._llm_run(project_path, task_id)

    # ── LLM path ─────────────────────────────────────────────────────────────

    def _llm_run(self, project_path: Path, task_id: str) -> list[ReviewIssueRead]:
        sources = _iter_sources(project_path)
        if not sources:
            return []
        workers = min(len(sources), 6)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(self._scan_file, src, task_id) for src in sources]
            issues: list[ReviewIssueRead] = []
            for fut in concurrent.futures.as_completed(futures):
                try:
                    issues.extend(fut.result())
                except Exception:
                    pass
        return issues

    def _scan_file(self, source: Path, task_id: str) -> list[ReviewIssueRead]:
        try:
            code = source.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        if not code.strip():
            return []
        truncated = code[:_MAX_FILE_CHARS]
        src_lines = code.splitlines()
        return self._run_prompt(_COMBINED_SEMANTIC_PROMPT, source, truncated, src_lines, task_id)

    def _run_prompt(
        self,
        template: str,
        source: Path,
        code: str,
        src_lines: list[str],
        task_id: str,
    ) -> list[ReviewIssueRead]:
        prompt = template.format(file_path=str(source), code=code)
        payload = {
            "model":       settings.llm_model,
            "temperature": 0.0,
            "messages":    [{"role": "user", "content": prompt}],
        }
        data = self._call_api(payload)
        content = (data["choices"][0]["message"].get("content") or "").strip()

        try:
            findings = json.loads(content)
        except json.JSONDecodeError:
            match = re.search(r"\[.*?\]", content, re.DOTALL)
            if not match:
                return []
            findings = json.loads(match.group(0))

        if not isinstance(findings, list):
            return []

        issues: list[ReviewIssueRead] = []
        for f in findings:
            if not isinstance(f, dict):
                continue
            rule_id = str(f.get("rule_id") or "")
            meta = _RULE_META.get(rule_id)
            if meta is None:
                continue
            line_no = max(int(f.get("line") or 1), 1)
            issues.append(ReviewIssueRead(
                id=str(uuid4()),
                task_id=task_id,
                tool="semantic-llm",
                rule_id=rule_id,
                file_path=str(source),
                line=line_no,
                column=f.get("column"),
                issue_type=rule_id,
                risk_level=meta["risk_level"],
                description=str(f.get("message") or ""),
                reason=(
                    "Detected by LLM semantic analysis. The code pattern "
                    "violates the project rule enforced by this checker."
                ),
                fix_suggestion=meta["fix"],
                confidence=meta["confidence"],
                is_valid=True,
                code_snippet=_extract_snippet(src_lines, line_no),
                created_at=datetime.utcnow(),
            ))
        return issues

    def _call_api(self, payload: dict) -> dict:
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


# ── Helpers ───────────────────────────────────────────────────────────────────

def _iter_sources(project_path: Path) -> list[Path]:
    if project_path.is_file():
        return [project_path] if project_path.suffix.lower() in _SOURCE_EXTENSIONS else []
    return [
        p for p in project_path.rglob("*")
        if p.is_file() and p.suffix.lower() in _SOURCE_EXTENSIONS
    ]


def _extract_snippet(lines: list[str], line_no: int, context: int = 3) -> str:
    start = max(line_no - context - 1, 0)
    end   = min(line_no + context, len(lines))
    return "\n".join(f"{i + 1:4d}: {lines[i]}" for i in range(start, end))
