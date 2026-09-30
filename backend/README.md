# AI Code Review Platform Backend

FastAPI backend skeleton for the multi-agent AI code review platform.

## Quick Start

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m uvicorn app.main:app --reload
```

Default API docs:

- Swagger UI: http://127.0.0.1:8000/docs
- Health check: http://127.0.0.1:8000/api/v1/health

## Current Capabilities

- Create local projects.
- Upload project archives. ZIP files are extracted into `storage/projects/{project_id}/source`.
- Parse project file trees.
- Create review tasks.
- Run the review pipeline, orchestrated as a LangGraph state graph
  (`services/review_graph.py`):

  ```mermaid
  graph TD;
    START([start]) --> prepare
    prepare --> static_detect
    prepare --> llm_detect
    static_detect --> fuse
    llm_detect --> fuse
    fuse -.single-path clusters.-> review
    fuse -.nothing to review.-> build_issues
    review --> build_issues
    build_issues --> report
    report --> END([end])
  ```

  `static_detect` and `llm_detect` run concurrently, and `fuse` waits for
  both. The conditional edge skips the review agent entirely when there is
  nothing to verify (e.g. the LLM is disabled).

  1. **Detection, two paths in parallel.** The static path runs Cppcheck,
     the Clang Static Analyzer, the Clang-AST custom checker and the
     cross-file checker. The LLM path runs `SemanticAuditAgent`, which audits
     function-level slices along the call graph.
  2. **Fusion** (`services/fusion.py`). Findings are mapped to CWEs; findings
     with no CWE are reported as code quality. Security findings are
     clustered by file, CWE category and nearby line. Clusters found by both
     paths are accepted (`consensus`). Clusters found by one path go to the
     review agent.
  3. **Review.** `LLMReviewAgent` verifies single-path clusters with tools
     (read code, AST context, call chain, find callers), up to
     `CODE_REVIEW_LLM_MAX_REVIEWS`. Clusters over the budget keep their
     detector verdict and are never dropped.
  4. Pydantic result validation, issue context (snippet, AST summary, call
     chain), then Markdown and JSON report generation.
- Optional detectors, enabled through `rule_config`: `cross_file` (off by
  default), `taint_flow` (the older split-file taint prompt), and
  `semantic_rules` (project-specific comment/ccid rules).
- Evaluation on Juliet with held-out split and ablations: see `eval/README.md`.
- List issues and reports by task ID.

## Useful API Calls

```text
GET  /api/v1/health
POST /api/v1/projects
POST /api/v1/projects/upload
GET  /api/v1/projects/{project_id}/tree
POST /api/v1/review-tasks
POST /api/v1/review-tasks/{task_id}/run
GET  /api/v1/issues?task_id={task_id}
GET  /api/v1/reports?task_id={task_id}
```

## Sharing this service beyond a single local user

By default this backend trusts every caller: `/projects/from-path` and
`/projects/from-files` will register any path the server process can read,
and there is no request authentication. That's fine for a single developer
running it against their own machine, but if you deploy it so more than one
person can reach it (e.g. shared on an internal network), set these first:

```powershell
# .env
CODE_REVIEW_ALLOWED_PROJECT_ROOTS=["C:\\Users\\me\\repos"]
CODE_REVIEW_API_KEY=some-long-random-string
```

- `CODE_REVIEW_ALLOWED_PROJECT_ROOTS`: JSON array of directories. Project
  registration is rejected (403) for any path outside these roots. Empty
  (default) allows any path — keep it empty only for trusted single-user use.
- `CODE_REVIEW_API_KEY`: when set, every `/api/v1` request except `/health`
  must send a matching `X-API-Key` header, or it's rejected with 401. Empty
  (default) disables auth entirely.

If you set `CODE_REVIEW_API_KEY`, also set `VITE_API_KEY` to the same value
in `frontend/.env` so the UI sends the header automatically.

## Cppcheck

The static analysis adapter calls `cppcheck` from `PATH`.

If Cppcheck is not installed, tasks using the default rule config will fail with:

```text
Cppcheck is not installed or not available in PATH.
```

For pipeline testing without Cppcheck, create a task with:

```json
{
  "project_id": "...",
  "rule_config": {
    "cppcheck": false
  }
}
```
