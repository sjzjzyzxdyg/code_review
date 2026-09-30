"""Juliet test-suite helpers: case grouping, ground-truth labelling, scoring.

Ground truth
------------
Every Juliet test file wraps its flawed code in ``#ifndef OMITBAD`` and its
fixed counterparts (goodG2B / goodB2G / ...) in ``#ifndef OMITGOOD``. That
gives a per-line label for free:

* a finding on a line inside an OMITBAD block is a hit on the real flaw;
* a finding inside an OMITGOOD block is a false positive (the code there is
  the *patched* version of the same flaw);
* anything else (includes, ``main``) is neutral and ignored.

Metric unit
-----------
Each test case contributes one positive unit (its bad side) and one negative
unit (its good side). A unit is "flagged" when at least one reported issue
falls inside it. Hence, over N cases:

    recall    = bad sides flagged  / N
    precision = bad sides flagged  / (bad sides flagged + good sides flagged)

Counting sides rather than raw findings keeps one noisy rule that fires ten
times from dominating the score, and makes precision meaningful: a tool that
flags every function scores recall 1.0 but precision 0.5.
"""

from __future__ import annotations

import json
import random
import re
import shutil
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

SOURCE_EXTS = {".c", ".cpp"}

# Stem → case id: strip the per-file suffix of multi-file flow variants
# ("_51a", "_54e", "_81_bad", "_82_goodG2B") down to "..._51" / "..._81".
_CASE_RE = re.compile(r"^(?P<case>.+?_(?P<flow>\d{2}))(?:[a-z]|_bad|_good\w*)?$")

# Flow variants 81-84 split classes across .h/.cpp files with virtual dispatch;
# leave them out so every case is a self-contained set of .c/.cpp files.
_EXCLUDED_FLOWS = {"81", "82", "83", "84"}

_DIRECTIVE_RE = re.compile(r"^\s*#\s*(if|ifdef|ifndef|else|elif|endif)\b\s*(\w*)")

BAD, GOOD, NEUTRAL = "bad", "good", "neutral"


# ── Case discovery ───────────────────────────────────────────────────────────

@dataclass
class JulietCase:
    case_id: str
    cwe: str
    files: list[Path] = field(default_factory=list)

    @property
    def flow(self) -> str:
        return case_key(self.files[0].stem)[1]

    @property
    def multi_file(self) -> bool:
        return len(self.files) > 1


def case_key(stem: str) -> tuple[str, str]:
    """Return (case_id, flow_variant) for a Juliet file stem."""
    match = _CASE_RE.match(stem)
    if not match:
        return stem, ""
    return match.group("case"), match.group("flow")


def cwe_of(case_id: str) -> str:
    return case_id.split("__", 1)[0]


def discover_cases(root: Path) -> dict[str, JulietCase]:
    """Group every Juliet source file under ``root`` into test cases."""
    cases: dict[str, JulietCase] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SOURCE_EXTS:
            continue
        if not path.name.startswith("CWE"):
            continue
        case_id, _ = case_key(path.stem)
        case = cases.setdefault(case_id, JulietCase(case_id=case_id, cwe=cwe_of(case_id)))
        case.files.append(path)
    return cases


# ── Ground-truth labels ──────────────────────────────────────────────────────

def label_lines(text: str) -> list[str]:
    """Label each line (index 0 = line 1) as bad / good / neutral."""
    labels: list[str] = []
    stack: list[str | None] = []
    for line in text.splitlines():
        match = _DIRECTIVE_RE.match(line)
        current = next((tag for tag in reversed(stack) if tag), NEUTRAL)
        if match:
            directive, symbol = match.groups()
            if directive == "ifndef" and symbol == "OMITBAD":
                stack.append(BAD)
            elif directive == "ifndef" and symbol == "OMITGOOD":
                stack.append(GOOD)
            elif directive in {"if", "ifdef", "ifndef"}:
                stack.append(None)
            elif directive in {"else", "elif"} and stack:
                stack[-1] = None
            elif directive == "endif" and stack:
                stack.pop()
        labels.append(current)
    return labels


class GroundTruth:
    """Maps (file name, line) → (case_id, label) for a set of Juliet cases."""

    def __init__(self, cases: Iterable[JulietCase], aliases: dict[str, str] | None = None) -> None:
        """``aliases`` maps renamed file names (see eval/sanitize.py) back to
        the original Juliet file names."""
        self.cases: dict[str, JulietCase] = {case.case_id: case for case in cases}
        self.aliases = aliases or {}
        self._labels: dict[str, tuple[str, list[str]]] = {}
        for case in self.cases.values():
            for path in case.files:
                text = path.read_text(encoding="utf-8", errors="replace")
                self._labels[path.name] = (case.case_id, label_lines(text))

    def lookup(self, file_path: str, line: int) -> tuple[str, str] | None:
        """Return (case_id, label) for a reported location, or None if the
        file isn't part of the dataset. Works for absolute, relative, POSIX
        and Windows-style paths since Juliet file names are globally unique."""
        name = re.split(r"[\\/]", str(file_path))[-1]
        entry = self._labels.get(self.aliases.get(name, name))
        if entry is None:
            return None
        case_id, labels = entry
        if 1 <= line <= len(labels):
            return case_id, labels[line - 1]
        return case_id, NEUTRAL


# ── Scoring ──────────────────────────────────────────────────────────────────

@dataclass
class Score:
    cases: int
    bad_flagged: int
    good_flagged: int
    any_flagged: int
    findings_bad: int
    findings_good: int
    findings_neutral: int
    findings_outside: int

    @property
    def recall(self) -> float:
        return self.bad_flagged / self.cases if self.cases else 0.0

    @property
    def precision(self) -> float:
        flagged = self.bad_flagged + self.good_flagged
        return self.bad_flagged / flagged if flagged else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0

    @property
    def good_fp_rate(self) -> float:
        return self.good_flagged / self.cases if self.cases else 0.0

    @property
    def loose_recall(self) -> float:
        """Share of cases with *any* finding anywhere in their files — the
        lenient 'did the tool say something about this test case' number."""
        return self.any_flagged / self.cases if self.cases else 0.0

    def as_dict(self) -> dict:
        return {
            "cases": self.cases,
            "recall": round(self.recall, 4),
            "precision": round(self.precision, 4),
            "f1": round(self.f1, 4),
            "good_fp_rate": round(self.good_fp_rate, 4),
            "loose_recall": round(self.loose_recall, 4),
            "bad_flagged": self.bad_flagged,
            "good_flagged": self.good_flagged,
            "findings": {
                "bad": self.findings_bad,
                "good": self.findings_good,
                "neutral": self.findings_neutral,
                "outside_dataset": self.findings_outside,
            },
        }


def score(truth: GroundTruth, findings: Iterable[tuple[str, int]], case_ids: Iterable[str] | None = None) -> Score:
    """Score (file_path, line) findings against ``truth``.

    ``case_ids`` restricts scoring to a subset (e.g. one CWE); findings in
    other cases are ignored rather than counted as outside the dataset.
    """
    scope = set(case_ids) if case_ids is not None else set(truth.cases)
    bad_cases: set[str] = set()
    good_cases: set[str] = set()
    any_cases: set[str] = set()
    counts = {BAD: 0, GOOD: 0, NEUTRAL: 0}
    outside = 0
    for file_path, line in findings:
        hit = truth.lookup(file_path, int(line or 1))
        if hit is None:
            outside += 1
            continue
        case_id, label = hit
        if case_id not in scope:
            continue
        counts[label] += 1
        any_cases.add(case_id)
        if label == BAD:
            bad_cases.add(case_id)
        elif label == GOOD:
            good_cases.add(case_id)
    return Score(
        cases=len(scope),
        bad_flagged=len(bad_cases),
        good_flagged=len(good_cases),
        any_flagged=len(any_cases),
        findings_bad=counts[BAD],
        findings_good=counts[GOOD],
        findings_neutral=counts[NEUTRAL],
        findings_outside=outside,
    )


def score_breakdown(truth: GroundTruth, findings: list[tuple[str, int]]) -> dict[str, dict]:
    """Per-CWE scores."""
    by_cwe: dict[str, list[str]] = defaultdict(list)
    for case in truth.cases.values():
        by_cwe[case.cwe].append(case.case_id)
    return {
        cwe: score(truth, findings, case_ids).as_dict()
        for cwe, case_ids in sorted(by_cwe.items())
    }


# ── Dataset building ─────────────────────────────────────────────────────────

def _eligible(case: JulietCase, excluded_flows: set[str]) -> bool:
    if case.flow in _EXCLUDED_FLOWS or case.flow in excluded_flows:
        return False
    if "w32" in case.case_id:  # Windows-only APIs
        return False
    return all(path.suffix.lower() in SOURCE_EXTS for path in case.files)


def select_heldout(
    juliet_testcases: Path,
    cwes: Iterable[str],
    per_cwe_multi: int = 5,
    per_cwe_single: int = 5,
    exclude_flows: Iterable[str] = ("51",),
    seed: int = 42,
) -> list[JulietCase]:
    """Deterministically sample a held-out split from a Juliet checkout.

    Flow variant 51 (the dev split) is excluded so held-out cases differ in
    *how* data flows between functions/files, not just in variable names.
    """
    excluded = set(exclude_flows)
    rng = random.Random(seed)
    chosen: list[JulietCase] = []
    for cwe in sorted(cwes):
        cwe_dir = juliet_testcases / cwe
        if not cwe_dir.is_dir():
            raise FileNotFoundError(f"{cwe_dir} not found in the Juliet checkout")
        cases = [c for c in discover_cases(cwe_dir).values() if _eligible(c, excluded)]
        multi = sorted((c for c in cases if c.multi_file), key=lambda c: c.case_id)
        single = sorted((c for c in cases if not c.multi_file), key=lambda c: c.case_id)
        chosen += rng.sample(multi, min(per_cwe_multi, len(multi)))
        chosen += rng.sample(single, min(per_cwe_single, len(single)))
    return chosen


def materialize(cases: Iterable[JulietCase], out_dir: Path) -> Path:
    """Copy cases into ``out_dir/<CWE>/<file>`` (the layout of
    samples/juliet-cross-file-subset) and write a manifest."""
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = []
    for case in cases:
        target_dir = out_dir / case.cwe
        target_dir.mkdir(exist_ok=True)
        for path in case.files:
            shutil.copy2(path, target_dir / path.name)
        manifest.append({
            "case_id": case.case_id,
            "cwe": case.cwe,
            "flow": case.flow,
            "files": sorted(p.name for p in case.files),
        })
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return out_dir
