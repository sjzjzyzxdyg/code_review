"""Fuse findings from the static path and the LLM path.

Each detector finding is first classified (app/core/cwe.py):

* no CWE → code-quality finding. Reported as low risk, never sent to the LLM.
* CWE    → security finding, which goes through fusion.

Security findings are clustered when they point at the same file, the same
vulnerability category (bounds, memory-free, null, ...) and lines within
``LINE_WINDOW`` of each other. Each cluster then gets a route:

``consensus``  both paths (static and LLM) found it. Accepted without
               spending another LLM call; the independent agreement is the
               evidence.
``review``     only one path found it. Sent to the tool-using review agent to
               confirm or reject, which is where false positives get filtered.

When there are more ``review`` clusters than the review budget allows, the
extra ones are kept as ``unreviewed`` with their detector's verdict. They are
never dropped.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.core import cwe as cwe_map

LINE_WINDOW = 3

STATIC = "static"
LLM = "llm"

_SEVERITY_RANK = {"error": 0, "warning": 1, "style": 2, "performance": 3, "portability": 3, "information": 4}


def path_of(finding: dict) -> str:
    return LLM if str(finding.get("tool") or "").startswith("llm") else STATIC


def _file_key(file_path: str) -> str:
    return re.sub(r"[\\/]+", "/", str(file_path)).lower()


@dataclass
class Cluster:
    category: str
    file_key: str
    members: list[dict] = field(default_factory=list)
    route: str = "review"

    @property
    def paths(self) -> set[str]:
        return {path_of(f) for f in self.members}

    @property
    def lines(self) -> list[int]:
        return [int(f.get("line") or 1) for f in self.members]

    @property
    def cwe(self) -> str:
        """Most common CWE among members, static tools winning ties (their
        rule-to-CWE mapping is deterministic)."""
        votes: dict[str, int] = {}
        for f in self.members:
            votes[f["cwe"]] = votes.get(f["cwe"], 0) + (2 if path_of(f) == STATIC else 1)
        return max(sorted(votes), key=lambda c: votes[c])

    @property
    def representative(self) -> dict:
        """Member used for location/rule: prefer static (precise lines), then severity."""
        return min(
            self.members,
            key=lambda f: (path_of(f) != STATIC, _SEVERITY_RANK.get(str(f.get("severity", "")).lower(), 9)),
        )

    @property
    def priority(self) -> tuple:
        return min(_SEVERITY_RANK.get(str(f.get("severity", "")).lower(), 9) for f in self.members), -len(self.members)

    @property
    def sources(self) -> list[str]:
        return sorted({f"{f.get('tool')}:{f.get('rule_id')}" for f in self.members})


@dataclass
class FusionResult:
    clusters: list[Cluster]
    quality: list[dict]

    def by_route(self, route: str) -> list[Cluster]:
        return [c for c in self.clusters if c.route == route]


def fuse(findings: list[dict], max_reviews: int, review_enabled: bool = True) -> FusionResult:
    security: list[dict] = []
    quality: list[dict] = []
    for finding in findings:
        cwe = cwe_map.classify(finding)
        category = cwe_map.category(cwe)
        if cwe and category:
            security.append({**finding, "cwe": cwe, "category": category})
        else:
            quality.append(finding)

    clusters: list[Cluster] = []
    # Sort so that merging is a single linear sweep per (file, category).
    security.sort(key=lambda f: (_file_key(f["file_path"]), f["category"], int(f.get("line") or 1)))
    for finding in security:
        key = _file_key(finding["file_path"])
        line = int(finding.get("line") or 1)
        last = clusters[-1] if clusters else None
        if (
            last is not None
            and last.file_key == key
            and last.category == finding["category"]
            and line - max(last.lines) <= LINE_WINDOW
        ):
            last.members.append(finding)
        else:
            clusters.append(Cluster(category=finding["category"], file_key=key, members=[finding]))

    single_path = []
    for cluster in clusters:
        if cluster.paths == {STATIC, LLM}:
            cluster.route = "consensus"
        else:
            single_path.append(cluster)

    if not review_enabled:
        for cluster in single_path:
            cluster.route = "unreviewed"
    else:
        single_path.sort(key=lambda c: c.priority)
        for rank, cluster in enumerate(single_path):
            cluster.route = "review" if rank < max_reviews else "unreviewed"

    return FusionResult(clusters=clusters, quality=quality)
