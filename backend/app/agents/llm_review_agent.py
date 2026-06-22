import json
import urllib.error
import urllib.request

from app.core.config import settings


_RULE_RISK_MAP: dict[str, tuple[str, float]] = {
    # cppcheck rules
    "nullPointer":              ("critical", 0.90),
    "nullPointerRedundantCheck":("critical", 0.88),
    "doubleFree":               ("critical", 0.90),
    "memleak":                  ("high",     0.85),
    "memleakOnRealloc":         ("high",     0.83),
    "bufferAccessOutOfBounds":  ("high",     0.87),
    "arrayIndexOutOfBounds":    ("high",     0.87),
    "zerodiv":                  ("high",     0.85),
    "uninitvar":                ("high",     0.80),
    "uninitdata":               ("high",     0.78),
    "resourceLeak":             ("high",     0.82),
    "useAfterFree":             ("critical", 0.92),
    "invalidPointerCast":       ("high",     0.80),
    # builtin fallback rules
    "builtin-null-deref":        ("critical", 0.88),
    "builtin-null-check-missing":("high",     0.75),
    "builtin-malloc-no-check":   ("high",     0.80),
    "builtin-div-by-var":        ("high",     0.82),
    "builtin-double-free":       ("critical", 0.85),
    "builtin-unsafe-copy":       ("high",     0.83),
    "builtin-raw-new":           ("low",      0.40),
    "builtin-todo":              ("low",      0.30),
}

_SEVERITY_RISK_MAP: dict[str, str] = {
    "error":       "high",
    "critical":    "critical",
    "warning":     "medium",
    "style":       "low",
    "performance": "low",
    "portability": "low",
    "information": "low",
}


class LLMReviewAgent:
    """Performs LLM-style reasoning over a candidate issue context.

    Uses an OpenAI-compatible chat completions endpoint when configured, and
    keeps a deterministic local fallback for offline development.
    """

    def review(self, context: dict) -> dict:
        if settings.llm_enabled and settings.llm_api_key:
            try:
                return self._review_with_openai_compatible_api(context)
            except (OSError, urllib.error.URLError, json.JSONDecodeError, KeyError, TypeError):
                return self._fallback_review(context)
        return self._fallback_review(context)

    def _review_with_openai_compatible_api(self, context: dict) -> dict:
        payload = {
            "model": settings.llm_model,
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a senior C/C++ code review agent. Return only JSON with keys: "
                        "is_valid, risk_level, issue_type, description, reason, fix_suggestion, confidence. "
                        "risk_level must be one of low, medium, high, critical. confidence is 0 to 1."
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(self._compact_context(context), ensure_ascii=False),
                },
            ],
        }
        request = urllib.request.Request(
            url=f"{settings.llm_base_url.rstrip('/')}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {settings.llm_api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=settings.llm_timeout_seconds) as response:
            data = json.loads(response.read().decode("utf-8"))
        content = data["choices"][0]["message"]["content"]
        parsed = json.loads(content)
        return parsed if isinstance(parsed, dict) else self._fallback_review(context)

    def _compact_context(self, context: dict) -> dict:
        snippet = context.get("code_snippet") or ""
        return {
            "finding": context.get("finding", {}),
            "code_snippet": snippet[:6000],
            "ast_summary": context.get("ast_summary"),
            "ast_context": context.get("ast_context"),
            "call_chain": context.get("call_chain", []),
            "dependencies": (context.get("dependencies") or [])[:30],
        }

    def _fallback_review(self, context: dict) -> dict:
        finding = context.get("finding", {})
        rule_id = str(finding.get("rule_id") or "static-analysis")
        message = finding.get("message") or "Static analysis finding"
        severity = str(finding.get("severity") or "warning").lower()

        risk_level, confidence = _RULE_RISK_MAP.get(
            rule_id,
            (_SEVERITY_RISK_MAP.get(severity, "medium"), 0.65),
        )

        return {
            "is_valid": True,
            "risk_level": risk_level,
            "issue_type": rule_id,
            "description": message,
            "reason": (
                "Static analysis reported this issue. "
                "The finding was reviewed with the surrounding code context, "
                f"AST summary: {context.get('ast_summary') or 'unavailable'}."
            ),
            "fix_suggestion": self._suggestion_for_rule(rule_id, message),
            "confidence": confidence,
        }

    def _risk_from_severity(self, severity: str) -> str:
        return _SEVERITY_RISK_MAP.get(severity, "medium")

    def _suggestion_for_rule(self, rule_id: str, message: str) -> str:
        rule = rule_id.lower()
        if "null" in rule:
            return "Add a null check before dereferencing the pointer and make the non-null invariant explicit."
        if "leak" in rule or "mem" in rule:
            return "Ensure allocated resources are released on every return path, preferably with RAII."
        if "bounds" in rule or "array" in rule:
            return "Validate indexes and buffer lengths before reading or writing memory."
        return f"Review the reported code path and address the analyzer warning: {message}"
