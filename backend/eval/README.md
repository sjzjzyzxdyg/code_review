# Evaluation on Juliet

Measures the whole review pipeline (same `ReviewService` the API uses) on
NIST Juliet C/C++ test cases, with a throw-away database so `storage/app.db`
is never touched.

## Datasets

| Split | Folder | Cases | Purpose |
|---|---|---|---|
| dev | `samples/juliet-cross-file-subset` | 60 (12 CWEs × 5, flow variant 51 only) | Tuning / debugging. Don't report tuned numbers from this split. |
| held-out | `samples/juliet-heldout` | 120 (12 CWEs × 5 multi-file + 5 single-file, **no flow 51**) | Headline numbers. Different data-flow shapes than dev. |

Both folders contain a `testcasesupport/` directory with Juliet's headers
(`std_testcase.h` etc.). The pipeline picks it up as an include path. Without
it, Clang can't parse any file and only reports `'std_testcase.h' file not found`.

Rebuild the held-out split (seeded, so it comes out the same every time):

```bash
git clone --depth 1 https://github.com/arichardson/juliet-test-suite-c.git
python -m eval.build_heldout --juliet juliet-test-suite-c/testcases --out ../samples/juliet-heldout
cp juliet-test-suite-c/testcasesupport/*.h ../samples/juliet-heldout/testcasesupport/
```

## Ground truth and metrics

Juliet puts the flawed code inside `#ifndef OMITBAD` and the fixed versions
(goodG2B / goodB2G / …) inside `#ifndef OMITGOOD`. So:

- finding in an **OMITBAD** block → hit on the real flaw
- finding in an **OMITGOOD** block → false positive (that code is the patched version)
- anything else (includes, `main`) → neutral, ignored

Each case has one **bad side** (positive) and one **good side** (negative). A
side counts as flagged if at least one finding lands in it.

- **recall** = bad sides flagged / cases
- **precision** = bad sides flagged / (bad sides flagged + good sides flagged)
- **F1**, **good-FP** (share of cases whose fixed code got flagged)
- **loose**: cases with any finding anywhere in their files. This is lenient
  and not comparable with the other numbers; it's only there for reference.

### No answer key for the detectors

Juliet source spells out its own labels: `/* POTENTIAL FLAW */` and
`/* FIX */` comments, function names like `badSink` and `goodG2BSink`, CWE
names in file and namespace names, and the `OMITBAD`/`OMITGOOD` guards. An
LLM that reads those is grading itself from the label.

So by default the pipeline scans a **sanitized copy** (`eval/sanitize.py`)
with all of that removed: comments are blanked, leaky identifiers are
renamed to stable numeric aliases, the guards get neutral names, and files
are renamed and flattened. Line numbers are preserved, so the original
labels still score it. `--no-sanitize` scans the raw files. Don't report
numbers from that mode.

### Stages

- `raw`: all detector output (including style findings)
- `raw_security`: detector output that maps to a CWE
- `valid`: issues with `is_valid=True` (includes code-quality findings)
- `security`: valid issues with a CWE, i.e. what the user sees as a
  vulnerability. **This is the headline number.**

`security` is also broken down by the fusion route that decided each issue:

- `consensus`: static and LLM paths agree
- `review`: confirmed by the review agent
- `unreviewed`: over the review budget, kept as detected

`rejected-by-review` scores what the agent threw away. High precision on the
bad side there means it rejected real bugs; mostly good-side hits means it
removed false positives.

## Running

From `backend/`:

```bash
# full pipeline, LLM settings from .env
python -m eval.run_eval --dataset ../samples/juliet-heldout --tag full

# static tools only, LLM off
python -m eval.run_eval --dataset ../samples/juliet-heldout --no-llm --tag static

# ablations (run each on the held-out split)
python -m eval.run_eval --dataset ../samples/juliet-heldout --no-llm --tag static-only
python -m eval.run_eval --dataset ../samples/juliet-heldout --detectors semantic_audit --no-review --tag llm-only
python -m eval.run_eval --dataset ../samples/juliet-heldout --no-review --tag dual-no-review
python -m eval.run_eval --dataset ../samples/juliet-heldout --max-reviews 200 --tag dual-full
```

### Static findings without installing analyzers

cppcheck and clang give the same output for the same input, and the
sanitized dataset is identical on every machine. So the static path can
run once, wherever the tools are installed, and be reused:

```bash
# on a machine with cppcheck + clang (done: eval/static_findings_juliet-heldout.json,
# cppcheck 2.13 / clang 18, Linux)
python -m eval.run_eval --dataset ../samples/juliet-heldout --no-llm --tag static-only \
    --export-static eval/static_findings_juliet-heldout.json

# anywhere else, e.g. Windows without cppcheck/LLVM/MSVC headers
python -m eval.run_eval --dataset ../samples/juliet-heldout --tag dual-full --max-reviews 200 \
    --static-from eval/static_findings_juliet-heldout.json
```

Without `--static-from`, a run that needs a missing analyzer stops with an
error instead of silently skipping it. (Inside the pipeline, clang is
optional, so a missing binary would otherwise just lower the static scores.)

`--max-reviews` sets how many single-path findings the review agent checks
(the default is `CODE_REVIEW_LLM_MAX_REVIEWS`, which is 40). Findings over
the budget are kept, not dropped.

Each run writes a JSON file to `eval/results/`, containing per-stage,
per-tool and per-CWE scores plus LLM call and token counts.

## Context size: function slices vs whole files

```bash
python -m eval.context_stats --dataset ../samples/juliet-heldout
```

This renders, offline, the exact prompts that both LLM detectors would send
for the sanitized dataset, then compares calls and characters. On the
held-out split:

| Detector | Unit | Calls | Prompt chars |
|---|---|---|---|
| `taint_flow` | whole files, grouped by `_NNa/_NNb` naming | 207 | 727,095 |
| `semantic_audit` | function slices along the call graph | 26 | 315,469 (**-57%**) |

`taint_flow` groups files by Juliet's file naming. On sanitized (neutrally
named) files it can't pair them any more, so every file becomes its own
call. `semantic_audit` finds cross-file partners from the call graph, so
naming doesn't matter. Measured token counts per detector are in each eval
result's `llm_usage`.


## Comparison with open-code-review

[alibaba/open-code-review](https://github.com/alibaba/open-code-review)
(`ocr`) is an LLM code-review CLI whose `ocr scan` mode reviews whole files.
`eval/run_ocr.py` runs it on the same sanitized dataset, with the same
model, and scores it the same way:

```bash
npm install -g @alibaba-group/open-code-review
python -m eval.run_ocr --dataset ../samples/juliet-heldout --tag ocr
python -m eval.compare                     # one table: all our runs + ocr
```

- **Same input.** The sanitized copy our pipeline scans, turned into a git
  repo because `ocr scan` lists files with `git ls-files`.
- **Same model.** The endpoint, key and model from `.env` are passed to ocr
  as `OCR_LLM_URL` / `OCR_LLM_TOKEN` / `OCR_LLM_MODEL` (OpenAI protocol).
  Pass `--use-ocr-config` to use ocr's own configuration instead.
- **Same scoring.** Each comment is located at its `start_line`. The headline
  row counts categories `bug` and `security`; style and other comments are
  scored separately.
- ocr's raw output is kept (`*_ocr-raw.json`), so `--score-only <file>` can
  re-score it without spending tokens again.
