"""Shared OpenAI-compatible chat-completions client for the LLM agents."""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request

from app.core.config import settings


def llm_available() -> bool:
    return bool(settings.llm_enabled and settings.llm_api_key)


def chat_completion(payload: dict, retries: int = 3) -> dict:
    """POST to /chat/completions with exponential backoff on network errors."""
    last_exc: Exception = RuntimeError("no attempts made")
    for attempt in range(retries):
        try:
            request = urllib.request.Request(
                url=f"{settings.llm_base_url.rstrip('/')}/chat/completions",
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Authorization": f"Bearer {settings.llm_api_key}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=settings.llm_timeout_seconds) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, OSError) as exc:
            last_exc = exc
            if attempt < retries - 1:
                time.sleep(2 ** attempt)
    raise last_exc


# A valid escape is consumed as a whole pair, so the second backslash of an
# escaped backslash ("\\\\x") is never mistaken for the start of "\\x".
_ESCAPE = re.compile(r'\\(["\\/bfnrt]|u[0-9a-fA-F]{4})?')


def repair_json_escapes(text: str) -> str:
    """Double backslashes that don't start a valid JSON escape. Models quoting
    C code often emit '\\0' or '\\x41' inside JSON strings, which json.loads
    rejects ("invalid \\escape"), silently dropping the whole answer."""
    return _ESCAPE.sub(lambda m: m.group(0) if m.group(1) else "\\\\", text)


def loads_lenient(text: str):
    """json.loads, retrying once with invalid escapes repaired."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return json.loads(repair_json_escapes(text))


def parse_json_array(content: str) -> list:
    """Extract a JSON array from model output, tolerating markdown fences and
    surrounding prose. Returns [] when nothing parseable is found."""
    text = re.sub(r"```(?:json)?", "", content or "").strip()
    for candidate in (text, *(m.group(0) for m in re.finditer(r"\[.*\]", text, re.DOTALL))):
        try:
            parsed = loads_lenient(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, list):
            return parsed
        if isinstance(parsed, dict):
            for value in parsed.values():  # {"findings": [...]}
                if isinstance(value, list):
                    return value
    return []
