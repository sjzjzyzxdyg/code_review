"""Put every result in eval/results/ for one dataset into a single table.

    python -m eval.compare --dataset juliet-heldout

Rows are our pipeline configurations (eval/run_eval.py) and
open-code-review (eval/run_ocr.py), all scored on the `security` stage:
issues a user would read as vulnerabilities. For ocr that means comments in
category bug/security. Output is a Markdown table, ready for a README.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

ORDER = ["static-only", "taint-only", "llm-only", "dual-no-review", "dual-full", "ocr"]


def _tokens(result: dict) -> int | None:
    total = 0
    found = False
    for usage in (result.get("llm_usage") or {}).values():
        if usage.get("total_tokens") is not None:
            total += int(usage["total_tokens"] or 0)
            found = True
        elif usage.get("prompt_tokens") is not None:
            total += int(usage.get("prompt_tokens") or 0) + int(usage.get("completion_tokens") or 0)
            found = found or bool(usage.get("calls"))
    return total if found else None


def load(results_dir: Path, dataset: str) -> list[dict]:
    rows = []
    for path in sorted(results_dir.glob("*.json")):
        if path.name.endswith("_ocr-raw.json"):
            continue
        try:
            result = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if re.split(r"[\\/]", str(result.get("dataset", "")).rstrip("\\/"))[-1] != dataset or "security" not in result.get("scores", {}):
            continue
        if not result.get("sanitized", False):
            continue  # raw Juliet leaks labels; never compare those numbers
        if result.get("task_status") not in (None, "completed", "success"):
            continue  # e.g. a run that stopped because cppcheck was missing
        rows.append({
            "tag": result.get("tag") or path.stem,
            "system": result.get("system") or "ours",
            "model": result.get("llm_model") or "-",
            "timestamp": result.get("timestamp", ""),
            "security": result["scores"]["security"],
            "tokens": _tokens(result),
            "seconds": result.get("seconds"),
        })
    latest: dict[str, dict] = {}
    for row in rows:  # keep the most recent run per tag
        if row["tag"] not in latest or row["timestamp"] > latest[row["tag"]]["timestamp"]:
            latest[row["tag"]] = row
    return sorted(latest.values(), key=lambda r: (ORDER.index(r["tag"]) if r["tag"] in ORDER else 99, r["tag"]))


def main(argv: list[str] | None = None) -> str:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dataset", default="juliet-heldout")
    parser.add_argument("--results", type=Path, default=Path("eval/results"))
    args = parser.parse_args(argv)

    rows = load(args.results, args.dataset)
    lines = [
        f"Dataset: {args.dataset} ({rows[0]['security']['cases'] if rows else '?'} cases, sanitized)",
        "",
        "| Run | System | Model | Recall | Precision | F1 | Fixed code flagged | Tokens | Time (s) |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        s = r["security"]
        tokens = f"{r['tokens']:,}" if r["tokens"] is not None else "0"
        lines.append(
            f"| {r['tag']} | {r['system']} | {r['model']} | {s['recall']:.1%} | {s['precision']:.1%} | "
            f"{s['f1']:.3f} | {s['good_fp_rate']:.1%} | {tokens} | {r['seconds'] if r['seconds'] is not None else '-'} |"
        )
    table = "\n".join(lines)
    print(table)
    return table


if __name__ == "__main__":
    main()
