"""Run Alibaba's open-code-review (`ocr scan`) on a Juliet dataset and score
it exactly like our own pipeline (eval/run_eval.py).

Usage (from backend/, after `npm install -g @alibaba-group/open-code-review`):

    python -m eval.run_ocr --dataset ../samples/juliet-heldout --tag ocr

Fairness:
* Same input: the same sanitized copy our pipeline scans (no comments, no
  bad/good names, neutral file names), with the same line numbers.
* Same model: the LLM endpoint, key and model from backend/.env are passed to
  ocr through its OCR_LLM_URL / OCR_LLM_TOKEN / OCR_LLM_MODEL variables
  (OpenAI protocol). Pass --use-ocr-config to use ocr's own config instead.
* Same scoring: ground truth from OMITBAD/OMITGOOD blocks, case-side metric.
  A comment is located at its start_line.

ocr reports every kind of comment (bug, security, performance, style, ...).
The headline row counts only category bug/security, the analogue of our
`security` stage. Its style comments are scored separately under `all`.

--score-only PATH re-scores an existing ocr JSON output without running ocr
(the dataset must be the same one, sanitized the same way).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict
from datetime import datetime
from pathlib import Path

VULN_CATEGORIES = {"bug", "security"}


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dataset", required=True, type=Path)
    parser.add_argument("--tag", default="ocr")
    parser.add_argument("--ocr-bin", default="ocr", help="ocr executable (default: from PATH)")
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--timeout", type=int, default=30, help="ocr per-task timeout, minutes")
    parser.add_argument("--use-ocr-config", action="store_true",
                        help="Use ocr's own configured model instead of the one in backend/.env")
    parser.add_argument("--preview", action="store_true", help="Only check which files ocr would scan.")
    parser.add_argument("--score-only", type=Path, help="Score an existing ocr JSON output.")
    parser.add_argument("--out", type=Path, default=Path("eval/results"))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> dict | None:
    args = _parse_args(argv)
    dataset = args.dataset.resolve()
    if not dataset.is_dir():
        sys.exit(f"Dataset folder not found: {dataset}")

    from eval.juliet import GroundTruth, discover_cases, score, score_breakdown
    from eval.sanitize import sanitize_dataset

    workdir = Path(tempfile.mkdtemp(prefix="ocr_eval_"))
    repo = workdir / "dataset"
    cases = list(discover_cases(dataset).values())
    aliases = sanitize_dataset(cases, dataset, repo)
    truth = GroundTruth(cases, aliases=aliases)

    if args.score_only:
        output = json.loads(args.score_only.read_text(encoding="utf-8"))
        seconds = None
    else:
        ocr = shutil.which(args.ocr_bin)
        if not ocr:
            sys.exit("ocr not found. Install it with: npm install -g @alibaba-group/open-code-review")
        _git_init(repo)
        env = os.environ.copy()
        if not args.use_ocr_config:
            env.update(_ocr_llm_env())
        out_file = workdir / "ocr_output.json"
        command = [ocr, "scan", "--repo", str(repo), "--path", "src", "--format", "json",
                   "--output", str(out_file), "--concurrency", str(args.concurrency),
                   "--timeout", str(args.timeout), "--audience", "agent"]
        if args.preview:
            command = [ocr, "scan", "--repo", str(repo), "--path", "src", "--preview", "--format", "json"]
            subprocess.run(command, env=env, check=False)
            return None
        print("Running:", " ".join(command[1:]))
        started = datetime.now()
        proc = subprocess.run(command, env=env, check=False)
        seconds = (datetime.now() - started).total_seconds()
        if not out_file.exists():
            sys.exit(f"ocr produced no output (exit code {proc.returncode}); see its messages above.")
        output = json.loads(out_file.read_text(encoding="utf-8"))
        args.out.mkdir(parents=True, exist_ok=True)
        shutil.copy(out_file, args.out / f"{dataset.name}_{args.tag}_ocr-raw.json")  # keep for --score-only

    comments = output.get("comments") or []

    def locations(items: list[dict]) -> list[tuple[str, int]]:
        return [(c.get("path") or "", int(c.get("start_line") or 1)) for c in items]

    vuln = [c for c in comments if str(c.get("category") or "").lower() in VULN_CATEGORIES]
    by_category: dict[str, list[dict]] = defaultdict(list)
    for comment in comments:
        by_category[str(comment.get("category") or "other").lower()].append(comment)

    summary = output.get("summary") or {}
    llm = output.get("llm") or {}
    tool_calls = output.get("tool_calls") or {}
    result = {
        "tag": args.tag,
        "system": "open-code-review",
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "dataset": str(dataset),
        "sanitized": True,
        "llm_model": llm.get("model"),
        "task_status": output.get("status"),
        "seconds": round(seconds, 1) if seconds is not None else None,
        "llm_usage": {"ocr": {
            "prompt_tokens": summary.get("input_tokens"),
            "completion_tokens": summary.get("output_tokens"),
            "total_tokens": summary.get("total_tokens"),
            "files_reviewed": summary.get("files_reviewed"),
        }},
        # Failed tool calls, e.g. code_comment arguments the model wrote as
        # invalid JSON. ocr returns the error to the model, which may resubmit,
        # so these are attempts, not necessarily lost comments.
        "ocr_tool_calls": {
            "total": tool_calls.get("total"),
            "failed": tool_calls.get("failure"),
            "failed_by_tool": tool_calls.get("failure_by_tool"),
        },
        "scores": {
            "all": score(truth, locations(comments)).as_dict(),
            "security": score(truth, locations(vuln)).as_dict(),
        },
        "by_category": {cat: score(truth, locations(items)).as_dict() for cat, items in sorted(by_category.items())},
        "security_by_cwe": score_breakdown(truth, locations(vuln)),
    }

    args.out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = args.out / f"{dataset.name}_{args.tag}_{stamp}.json"
    path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"\nopen-code-review on {dataset.name}  (model: {result['llm_model']}, status: {result['task_status']})")
    print(f"{'':<22}{'recall':>8}{'precision':>11}{'F1':>7}{'good-FP':>9}")
    rows = [("[security: bug+sec]", result["scores"]["security"]), ("[all comments]", result["scores"]["all"])]
    rows += [(f"  {cat}", s) for cat, s in result["by_category"].items()]
    for label, s in rows:
        print(f"{label:<22}{s['recall']:>8.1%}{s['precision']:>11.1%}{s['f1']:>7.3f}{s['good_fp_rate']:>9.1%}")
    print(f"Tokens: {summary.get('total_tokens')}   "
          f"Tool calls: {tool_calls.get('total')} ({tool_calls.get('failure')} failed, "
          f"e.g. invalid JSON in code_comment)   Saved to {path}")
    return result


def _git_init(repo: Path) -> None:
    """ocr scan lists files with `git ls-files`, so the dataset must be a repo."""
    git = ["git", "-C", str(repo), "-c", "user.name=eval", "-c", "user.email=eval@localhost"]
    subprocess.run(git + ["init", "-q"], check=True)
    subprocess.run(git + ["add", "-A"], check=True)
    subprocess.run(git + ["commit", "-q", "-m", "dataset"], check=True)


def _ocr_llm_env() -> dict[str, str]:
    """Point ocr at the same OpenAI-compatible endpoint/model as our pipeline."""
    from app.core.config import settings

    if not (settings.llm_api_key and settings.llm_base_url and settings.llm_model):
        sys.exit("No LLM configured in backend/.env (CODE_REVIEW_LLM_*); use --use-ocr-config instead.")
    return {
        "OCR_LLM_URL": settings.llm_base_url,
        "OCR_LLM_TOKEN": settings.llm_api_key,
        "OCR_LLM_MODEL": settings.llm_model,
        "OCR_LLM_PROTOCOL": "openai",
        "OCR_USE_ANTHROPIC": "false",
    }


if __name__ == "__main__":
    main()
