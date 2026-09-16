"""Shared clang AST dumping + caching for the AST-based checkers.

clang_custom_checker.py and cross_file_checker.py each need a JSON AST per
source file to run their own independent analysis pass. Without sharing,
every scan re-parses (and re-dumps — 100+ MB per file thanks to
transitively-included Windows SDK / MSVC headers) each file once per
checker. Run concurrently, as they are during a normal scan, that's two
full passes competing for CPU over the same files at once — enough to blow
through the per-file dump timeout and silently drop files from cross-file
analysis under real scan conditions (observed directly: cross_file_checker
found 34 real cross-file bugs in a 120-file test set run alone, but ~0 when
run at the same time as clang_custom_checker in a real scan).

This module makes both tools share one dump per (file, include-args) pair
within a scan: whichever tool asks for a given file's AST first actually
runs clang; anyone else asking for the same file+args waits for that result
instead of redoing the work.
"""

from __future__ import annotations

import json
import subprocess
import threading

_TIMEOUT_SECONDS = 60

_cache_lock = threading.Lock()
_cache: dict[tuple[str, tuple[str, ...]], dict | None] = {}
_key_locks: dict[tuple[str, tuple[str, ...]], threading.Lock] = {}


def dump_ast(clang_bin: str, source_arg: str, extra_args: tuple[str, ...] = ()) -> dict | None:
    """Return the (header-content-stripped) JSON AST for `source_arg`.

    `source_arg` is the exact string passed to clang on the command line —
    callers should use the same form (e.g. always `str(path)`) so identical
    files produce identical cache keys.
    """
    key = (source_arg, extra_args)
    with _cache_lock:
        if key in _cache:
            return _cache[key]
        key_lock = _key_locks.setdefault(key, threading.Lock())

    with key_lock:
        with _cache_lock:
            if key in _cache:
                return _cache[key]
        ast = _run_dump(clang_bin, source_arg, extra_args)
        with _cache_lock:
            _cache[key] = ast
        return ast


def clear_cache() -> None:
    """Drop every cached AST. Call once at the start of each scan so a
    changed file (or a different project reusing the same file path) never
    serves a stale dump from an earlier scan."""
    with _cache_lock:
        _cache.clear()
        _key_locks.clear()


def _run_dump(clang_bin: str, source_arg: str, extra_args: tuple[str, ...]) -> dict | None:
    try:
        result = subprocess.run(
            [clang_bin, "-Xclang", "-ast-dump=json", "-fsyntax-only", "-w",
             *extra_args, source_arg],
            capture_output=True, text=True, check=False,
            encoding="utf-8", errors="replace", timeout=_TIMEOUT_SECONDS,
        )
        stdout = result.stdout.strip()
        if not stdout:
            return None
        return _drop_included_header_decls(json.loads(stdout), source_arg)
    except (json.JSONDecodeError, subprocess.TimeoutExpired, OSError):
        return None


def _drop_included_header_decls(ast: dict, source_arg: str) -> dict:
    """Discard top-level decls that came from an #included header rather
    than `source_arg` itself — see this module's docstring for why. Each
    top-level node's "loc"/"file" is only present when the file changes
    from the previous node (clang's own JSON convention), so track the
    running "current file" while scanning in source order.
    """
    inner = ast.get("inner")
    if not isinstance(inner, list):
        return ast
    kept = []
    current_file = None
    for node in inner:
        file_ = (node.get("loc") or {}).get("file")
        if file_:
            current_file = file_
        if current_file == source_arg:
            kept.append(node)
    ast["inner"] = kept
    return ast
