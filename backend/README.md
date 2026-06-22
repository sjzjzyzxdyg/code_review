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
