@echo off
setlocal
rem One-click evaluation: installs dependencies, then runs every ablation on the
rem held-out Juliet split. Output is appended to eval\results\run_log.txt.
cd /d "%~dp0"
set PYTHONIOENCODING=utf-8
set PY=.venv\Scripts\python.exe
set DATA=..\samples\juliet-heldout
set LOG=eval\results\run_log.txt

if not exist %PY% (
  echo [ERROR] Virtual environment not found at backend\.venv
  pause
  exit /b 1
)

echo [1/7] Installing dependencies (adds langgraph)...
%PY% -m pip install -q -r requirements.txt
if errorlevel 1 (
  echo [ERROR] pip install failed.
  pause
  exit /b 1
)

echo [2/7] Checking LLM configuration in .env ...
%PY% -c "from app.core.llm_client import llm_available; import sys; sys.exit(0 if llm_available() else 1)"
if errorlevel 1 (
  echo [ERROR] LLM is not configured. Set CODE_REVIEW_LLM_ENABLED=true and CODE_REVIEW_LLM_API_KEY in backend\.env
  pause
  exit /b 1
)

echo ==== run started %date% %time% ==== >> %LOG%

echo [3/7] static-only (no LLM, free) ...
%PY% -m eval.run_eval --dataset %DATA% --no-llm --tag static-only >> %LOG% 2>&1

echo [4/7] llm-only: semantic audit, no review ...
%PY% -m eval.run_eval --dataset %DATA% --detectors semantic_audit --no-review --tag llm-only >> %LOG% 2>&1

echo [5/7] taint-only: old file-level LLM detector, no review ...
%PY% -m eval.run_eval --dataset %DATA% --detectors taint_flow --no-review --tag taint-only >> %LOG% 2>&1

echo [6/7] dual-no-review: static + semantic audit, fusion without review ...
%PY% -m eval.run_eval --dataset %DATA% --no-review --tag dual-no-review >> %LOG% 2>&1

echo [7/7] dual-full: static + semantic audit + review agent (slowest) ...
%PY% -m eval.run_eval --dataset %DATA% --max-reviews 200 --tag dual-full >> %LOG% 2>&1

echo ==== run finished %date% %time% ==== >> %LOG%
echo.
echo Done. Results are in backend\eval\results\  (summary log: run_log.txt)
echo You can close this window and tell Claude it's finished.
pause
