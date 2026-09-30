@echo off
rem Double-click: opens a command window in backend\ with .venv activated.
cd /d "%~dp0"
cmd /k ".venv\Scripts\activate.bat && echo Virtual environment active. Try: python -m pytest -q"
