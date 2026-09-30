"""Compare how much code each LLM detector sends for the same dataset.

    python -m eval.context_stats --dataset ../samples/juliet-heldout

Offline: nothing is sent to a model. It renders the exact prompts both LLM
detectors would build from the sanitized dataset and counts characters and
calls:

  taint_flow      file-level bundles: whole files (truncated at 10k chars),
                  grouped by Juliet's _NNa/_NNb naming convention
  semantic_audit  function-level slices along the call graph (suspicious
                  function + callers + callees), packed under a budget

Real token counts come from `llm_usage` in eval/run_eval.py results.
"""

from __future__ import annotations

import argparse
import tempfile
from pathlib import Path


def main(argv: list[str] | None = None) -> dict:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dataset", required=True, type=Path)
    parser.add_argument("--no-sanitize", action="store_true")
    args = parser.parse_args(argv)

    from app.agents import taint_flow_agent as taint
    from app.agents.semantic_audit_agent import _PROMPT, SemanticAuditAgent
    from app.tools.code_index import CodeIndex
    from eval.juliet import discover_cases
    from eval.sanitize import sanitize_dataset

    dataset = args.dataset.resolve()
    if args.no_sanitize:
        src = dataset
    else:
        out = Path(tempfile.mkdtemp(prefix="ctx_stats_"))
        sanitize_dataset(list(discover_cases(dataset).values()), dataset, out)
        src = out / "src"

    sources = taint._iter_sources(src)
    all_source = sum(len(p.read_text(encoding="utf-8", errors="replace")) for p in sources)

    groups = taint._group_files(sources)
    taint_chars = 0
    for group in groups:
        total = 0
        for path in sorted(group):
            text = path.read_text(encoding="utf-8", errors="replace")[: taint._MAX_FILE_CHARS]
            header = f"\n--- FILE: {path} ---\n"
            left = taint._MAX_BUNDLE_CHARS - total - len(header)
            if left < 200:
                break
            total += len(header) + len(text[:left])
        taint_chars += total + len(taint._TAINT_PROMPT)

    agent = SemanticAuditAgent()
    units = agent.build_units(CodeIndex.build(src))
    semantic_chars = sum(len(agent.render(unit, src)[0]) + len(_PROMPT) for unit in units)

    stats = {
        "source_files": len(sources),
        "source_chars": all_source,
        "taint_flow": {"calls": len(groups), "prompt_chars": taint_chars},
        "semantic_audit": {"calls": len(units), "prompt_chars": semantic_chars},
        "semantic_vs_taint_chars": round(semantic_chars / taint_chars, 3) if taint_chars else None,
    }
    print(f"Dataset: {dataset}  (sanitized: {not args.no_sanitize})")
    print(f"  {len(sources)} source files, {all_source:,} chars of code")
    print(f"  taint_flow     (file bundles)    : {len(groups):4d} calls, {taint_chars:>10,} prompt chars")
    print(f"  semantic_audit (function slices) : {len(units):4d} calls, {semantic_chars:>10,} prompt chars")
    if taint_chars:
        print(f"  → function slicing sends {1 - semantic_chars / taint_chars:.0%} fewer characters")
    return stats


if __name__ == "__main__":
    main()
