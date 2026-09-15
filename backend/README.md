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
- Run the review pipeline:
  - static analysis
  - issue-level context building
  - deterministic LLMReviewAgent placeholder
  - Pydantic result validation
  - Markdown and JSON report generation
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
