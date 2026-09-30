"""Run the full review pipeline on a Juliet dataset and score it.

Usage (from backend/):

    python -m eval.run_eval --dataset ../samples/juliet-heldout --tag full
    python -m eval.run_eval --dataset ../samples/juliet-heldout --no-llm --tag static
    python -m eval.run_eval --dataset ../samples/juliet-heldout \
        --detectors semantic_audit --tag llm-only

The pipeline runs exactly as it does behind the API (same ReviewService,
same stages), against a throw-away SQLite DB so evaluation never touches
storage/app.db. LLM settings come from backend/.env unless --no-llm is given.

By default the dataset is scanned as a *sanitized* copy (eval/sanitize.py):
comments, bad/good identifiers, CWE names and OMITBAD/OMITGOOD guards are
removed so no detector can read the answer key. Scores are still computed
against the original labels.

Stages scored:

  raw       every detector's output before fusion / review
  valid     issues with is_valid=True (includes code-quality findings)
  security  valid issues that carry a CWE. This is the headline number: what
            the user sees as vulnerabilities.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import tempfile
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

STATIC_DETECTORS = ("cppcheck", "clang", "clang_custom", "cross_file")
LLM_DETECTORS = ("semantic_audit", "taint_flow")
ALL_DETECTORS = STATIC_DETECTORS + LLM_DETECTORS
DEFAULT_DETECTORS = STATIC_DETECTORS + ("semantic_audit",)


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dataset", required=True, type=Path, help="Folder of Juliet cases to scan.")
    parser.add_argument(
        "--detectors", default=",".join(DEFAULT_DETECTORS),
        help=f"Comma-separated subset of {', '.join(ALL_DETECTORS)} (for ablations).",
    )
    parser.add_argument("--no-llm", action="store_true", help="Force the LLM off regardless of .env.")
    parser.add_argument("--no-review", action="store_true", help="Keep LLM detection but skip the review agent.")
    parser.add_argument("--max-reviews", type=int, default=None, help="Review budget (default: settings).")
    parser.add_argument("--no-sanitize", action="store_true", help="Scan the raw Juliet files (labels visible!).")
    parser.add_argument(
        "--static-from", type=Path, default=None,
        help="Use static findings exported by --export-static instead of running cppcheck/clang here.",
    )
    parser.add_argument("--export-static", type=Path, default=None,
                        help="Write this run's static-path findings (paths relative to the dataset) to a file.")
    parser.add_argument("--tag", default="", help="Label stored with the result (e.g. 'baseline').")
    parser.add_argument("--out", type=Path, default=Path("eval/results"), help="Where to write result JSON.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> dict:
    args = _parse_args(argv)
    dataset = args.dataset.resolve()
    if not dataset.is_dir():
        sys.exit(f"Dataset folder not found: {dataset}")
    detectors = [d.strip() for d in args.detectors.split(",") if d.strip()]
    unknown = set(detectors) - set(ALL_DETECTORS)
    if unknown:
        sys.exit(f"Unknown detector(s): {', '.join(sorted(unknown))}")

    workdir = Path(tempfile.mkdtemp(prefix="code_review_eval_"))
    # Must be set before `app` is imported: settings and the DB singleton
    # are created at import time.
    os.environ["CODE_REVIEW_DATABASE_PATH"] = str(workdir / "eval.db")
    os.environ["CODE_REVIEW_REPORTS_DIR"] = str(workdir / "reports")
    os.environ["CODE_REVIEW_STORAGE_DIR"] = str(workdir)
    if args.no_llm:
        os.environ["CODE_REVIEW_LLM_ENABLED"] = "false"

    from app.core.config import settings
    from app.core.llm_client import llm_available
    from eval.juliet import GroundTruth, discover_cases, score, score_breakdown
    from eval.sanitize import sanitize_dataset

    if not llm_available():
        # Every review call would raise and log a traceback before the
        # pipeline falls back. Expected here, so keep the output readable.
        logging.getLogger("app.services.review_service").setLevel(logging.CRITICAL)

    cases = list(discover_cases(dataset).values())
    if not cases:
        sys.exit(f"No Juliet cases found under {dataset}")
    if args.no_sanitize:
        scan_root, aliases = dataset, {}
    else:
        scan_root = workdir / "dataset"
        aliases = sanitize_dataset(cases, dataset, scan_root)
    truth = GroundTruth(cases, aliases=aliases)

    static_requested = [d for d in detectors if d in STATIC_DETECTORS]
    imported_static = None
    if args.static_from:
        imported_static = json.loads(args.static_from.read_text(encoding="utf-8"))
        if imported_static.get("sanitized") != (not args.no_sanitize):
            sys.exit("--static-from file was produced with a different --no-sanitize setting.")
    elif static_requested:
        _check_static_tools(static_requested)

    rule_config = {name: name in detectors for name in ALL_DETECTORS}
    if args.no_review:
        rule_config["max_llm_reviews"] = 0
    elif args.max_reviews is not None:
        rule_config["max_llm_reviews"] = args.max_reviews

    run = _run_pipeline(scan_root, rule_config, imported_static)

    if args.export_static:
        static = [f for f in run["raw"] if not str(f.get("tool", "")).startswith("llm")]
        args.export_static.parent.mkdir(parents=True, exist_ok=True)
        args.export_static.write_text(json.dumps({
            "dataset": dataset.name,
            "sanitized": not args.no_sanitize,
            "detectors": static_requested,
            "tool_versions": _tool_versions(),
            "findings": [{**f, "file_path": _relative(f["file_path"], scan_root)} for f in static],
        }, indent=1, ensure_ascii=False), encoding="utf-8")
        print(f"Exported {len(static)} static findings to {args.export_static}")

    def locations(items: list[dict]) -> list[tuple[str, int]]:
        return [(item["file_path"], item["line"]) for item in items]

    from app.core.cwe import classify

    raw_security = [f for f in run["raw"] if classify(f)]
    valid = [i for i in run["issues"] if i["is_valid"]]
    security = [i for i in valid if i.get("cwe")]
    rejected = [i for i in run["issues"] if not i["is_valid"] and i.get("cwe")]

    by_tool: dict[str, list[dict]] = defaultdict(list)
    for item in raw_security:
        by_tool[item["tool"]].append(item)
    by_route: dict[str, list[dict]] = defaultdict(list)
    for issue in security:
        by_route[issue.get("review_route") or "?"].append(issue)

    result = {
        "tag": args.tag,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "dataset": str(dataset),
        "sanitized": not args.no_sanitize,
        "detectors": detectors,
        "static_source": (f"imported from {args.static_from.name} ({imported_static.get('tool_versions')})"
                          if imported_static else "run locally"),
        "llm_enabled": llm_available(),
        "llm_model": settings.llm_model if llm_available() else None,
        "max_llm_reviews": rule_config.get("max_llm_reviews", settings.llm_max_reviews),
        "task_status": run["status"],
        "task_error": run["error"],
        "seconds": round(run["seconds"], 1),
        "llm_usage": run["llm_usage"],
        "scores": {
            "raw": score(truth, locations(run["raw"])).as_dict(),
            "raw_security": score(truth, locations(raw_security)).as_dict(),
            "valid": score(truth, locations(valid)).as_dict(),
            "security": score(truth, locations(security)).as_dict(),
        },
        "security_by_route": {route: score(truth, locations(items)).as_dict() for route, items in sorted(by_route.items())},
        "review_rejected": score(truth, locations(rejected)).as_dict(),
        "route_counts": dict(Counter(i.get("review_route") or "?" for i in run["issues"])),
        "raw_security_by_tool": {tool: score(truth, locations(items)).as_dict() for tool, items in sorted(by_tool.items())},
        "security_by_cwe": score_breakdown(truth, locations(security)),
    }

    args.out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    name = f"{dataset.name}_{args.tag or 'run'}_{stamp}.json"
    (args.out / name).write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    _print_summary(result, args.out / name)
    return result


def _run_pipeline(scan_root: Path, rule_config: dict, imported_static: dict | None = None) -> dict:
    from app.core.db import Database
    from app.schemas.review import ReviewTaskCreate
    from app.services import review_service as review_service_module
    from app.services.issue_service import issue_service
    from app.services.report_service import report_service
    from app.services.suppression_service import suppression_service

    db = Database(Path(os.environ["CODE_REVIEW_DATABASE_PATH"]))
    for service in (issue_service, report_service, suppression_service):
        service._db = db
    review_service_module.project_service = _DatasetProjectService(scan_root)
    service = review_service_module.ReviewService(db=db)

    raw: list[dict] = []
    raw_lock = threading.Lock()
    original_detect = service._run_detectors

    from app.services.review_graph import STATIC_DETECTORS as GRAPH_STATIC

    def recording_detect(*a, **k):
        # Called concurrently by the graph's static and LLM branches.
        if imported_static is not None and tuple(a[0]) == tuple(GRAPH_STATIC):
            findings = [
                {**f, "file_path": str(scan_root / f["file_path"])}
                for f in imported_static["findings"]
                if rule_config.get(_detector_of(f), True)
            ]
            rule_issues, fresh = [], []
        else:
            findings, rule_issues, fresh = original_detect(*a, **k)
        with raw_lock:
            raw.extend(
                {**f, "tool": str(f.get("tool") or "unknown"), "file_path": str(f.get("file_path") or ""),
                 "line": int(f.get("line") or 1)}
                for f in findings
            )
        return findings, rule_issues, fresh

    service._run_detectors = recording_detect
    usage = _instrument_llm_calls(service)

    task = service.create_task(ReviewTaskCreate(project_id="eval", rule_config=rule_config))
    started = time.monotonic()
    finished = service.run_task(task.id)
    seconds = time.monotonic() - started

    issues = [i.model_dump(mode="json") for i in issue_service.list_issues(task_id=task.id)]
    return {
        "status": finished.status,
        "error": finished.error_message,
        "seconds": seconds,
        "raw": raw,
        "issues": issues,
        "llm_usage": usage,
    }


def _instrument_llm_calls(service) -> dict:
    """Count LLM calls and token usage per agent by wrapping each `_call_api`."""
    usage: dict[str, dict[str, int]] = {}
    lock = threading.Lock()
    for name in ("semantic_audit_agent", "llm_review_agent", "taint_flow_agent"):
        agent = getattr(service, name)
        original = agent._call_api
        bucket = usage.setdefault(name, {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0})

        def wrapped(payload, _original=original, _bucket=bucket):
            data = _original(payload)
            tokens = data.get("usage") or {}
            with lock:
                _bucket["calls"] += 1
                _bucket["prompt_tokens"] += int(tokens.get("prompt_tokens") or 0)
                _bucket["completion_tokens"] += int(tokens.get("completion_tokens") or 0)
            return data

        agent._call_api = wrapped
    return usage


def _detector_of(finding: dict) -> str:
    tool = str(finding.get("tool") or "")
    return {"cppcheck": "cppcheck", "clang": "clang", "clang-cross-file": "cross_file"}.get(tool, "clang_custom")


def _relative(file_path: str, root: Path) -> str:
    try:
        return Path(file_path).resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return Path(file_path).as_posix()


def _check_static_tools(requested: list[str]) -> None:
    """Fail loudly instead of letting the pipeline skip a missing analyzer
    (clang is non-fatal there, so a missing binary would silently lower the
    static scores)."""
    import shutil

    needed = {"cppcheck": ["cppcheck"], "clang": ["clang", "clang-cl"],
              "clang_custom": ["clang", "clang-cl"], "cross_file": ["clang", "clang-cl"]}
    missing = sorted({
        names[0] for d in requested for names in [needed[d]] if not any(shutil.which(n) for n in names)
    })
    if missing:
        sys.exit(
            f"Static analyzer(s) not found on PATH: {', '.join(missing)}.\n"
            "Either install them, or reuse exported static findings:\n"
            "  python -m eval.run_eval --dataset ... --static-from eval/static_findings_<dataset>.json\n"
            "or run LLM-only configurations (--detectors semantic_audit)."
        )


def _tool_versions() -> dict:
    import subprocess

    versions = {}
    for name in ("cppcheck", "clang"):
        try:
            out = subprocess.run([name, "--version"], capture_output=True, text=True, timeout=10).stdout
            versions[name] = out.strip().splitlines()[0] if out.strip() else None
        except (OSError, subprocess.TimeoutExpired):
            versions[name] = None
    return versions


class _DatasetProjectService:
    """Stands in for ProjectService so the eval never registers a project in
    the real DB. Only the two methods ReviewService calls are needed."""

    class _Project:
        def __init__(self, path: Path) -> None:
            self.id = "eval"
            self.local_path = str(path)

    def __init__(self, dataset: Path) -> None:
        self._project = self._Project(dataset)

    def get_project(self, project_id: str):
        return self._project

    def resolve_project_path(self, project_id: str, scan_scope: str = ".") -> Path:
        return Path(self._project.local_path)


def _print_summary(result: dict, path: Path) -> None:
    print(f"\nDataset   : {result['dataset']}  (sanitized: {result['sanitized']})")
    print(f"Detectors : {', '.join(result['detectors'])}   LLM: {'on' if result['llm_enabled'] else 'off'}"
          f"   review budget: {result['max_llm_reviews']}")
    print(f"Status    : {result['task_status']}  ({result['seconds']}s)")
    if result["task_error"]:
        print(f"Error     : {result['task_error']}")
    header = f"{'':<22}{'recall':>8}{'precision':>11}{'F1':>7}{'good-FP':>9}"
    print("\n" + header)
    rows = (
        [(f"[{k}]", v) for k, v in result["scores"].items()]
        + [(f"  route:{k}", v) for k, v in result["security_by_route"].items()]
        + [("  rejected-by-review", result["review_rejected"])]
        + [(f"  raw:{k}", v) for k, v in result["raw_security_by_tool"].items()]
    )
    for label, s in rows:
        print(f"{label:<22}{s['recall']:>8.1%}{s['precision']:>11.1%}{s['f1']:>7.3f}{s['good_fp_rate']:>9.1%}")
    print(f"\nIssue routes: {result['route_counts']}")
    for agent, u in result["llm_usage"].items():
        if u["calls"]:
            print(f"LLM {agent}: {u['calls']} calls, {u['prompt_tokens']} prompt + {u['completion_tokens']} completion tokens")
    print(f"\nSaved to {path}")


if __name__ == "__main__":
    main()
