import json
import logging
import time
import urllib.error
import urllib.request
from pathlib import Path

from app.core.config import settings
from app.tools.ast_parser_tool import ASTParserTool
from app.agents.call_chain_agent import CallChainRetrievalAgent

logger = logging.getLogger(__name__)


# ── Agent constants ────────────────────────────────────────────────────────────

_MAX_TURNS = 5

_AGENT_SYSTEM = (
    "You are a senior C/C++ security code reviewer. "
    "You have tools to read source files, get AST context, and trace call chains. "
    "When given a static-analysis finding, use your tools to examine the relevant code "
    "before drawing conclusions. Investigate whether the issue is a real vulnerability, "
    "a false positive, or a code-quality concern. "
    "When finished, output ONLY a JSON object with these keys: "
    "is_valid (bool), risk_level (one of: low, medium, high, critical), "
    "issue_type (str), description (str), reason (str), "
    "fix_suggestion (str), confidence (float 0-1). "
    "Do not wrap the JSON in markdown fences."
)

_TOOL_SCHEMAS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "read_code_snippet",
            "description": (
                "Read lines of a source file around a location. "
                "Use this to see the actual code before making a judgment."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Absolute path to the source file.",
                    },
                    "start_line": {
                        "type": "integer",
                        "description": "First line to read (1-based, inclusive).",
                    },
                    "end_line": {
                        "type": "integer",
                        "description": "Last line to read (1-based, inclusive). Max 80 lines per call.",
                    },
                },
                "required": ["file_path", "start_line", "end_line"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_ast_context",
            "description": (
                "Get AST-level context at a specific file/line: "
                "enclosing function name, nearby type declarations, and include dependencies."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string"},
                    "line": {"type": "integer", "description": "Line number (1-based)."},
                },
                "required": ["file_path", "line"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_call_chain",
            "description": (
                "Trace the function call chain from the function that contains the given line. "
                "Returns the chain of function names and a call-graph with edges."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string"},
                    "line": {"type": "integer"},
                },
                "required": ["file_path", "line"],
            },
        },
    },
]


class LLMReviewAgent:
    """Agent-style C/C++ security reviewer using a ReAct loop.

    Requires a configured LLM (llm_enabled=True and llm_api_key set).
    Raises RuntimeError if called without a valid configuration.
    """

    def __init__(self) -> None:
        self._ast_tool = ASTParserTool()
        self._call_chain_agent = CallChainRetrievalAgent()

    def review(self, context: dict) -> dict:
        if not (settings.llm_enabled and settings.llm_api_key):
            raise RuntimeError("LLM is not configured; set llm_api_key to use the review agent.")
        return self._agent_review(context)

    # ── Agent loop ────────────────────────────────────────────────────────────

    def _agent_review(self, context: dict) -> dict:
        finding = context.get("finding", {})
        root = self._resolve_root(context.get("scan_root"))
        messages: list[dict] = [
            {"role": "system", "content": _AGENT_SYSTEM},
            {"role": "user",   "content": self._agent_prompt(finding)},
        ]

        for turn in range(_MAX_TURNS):
            payload: dict = {
                "model":       settings.llm_model,
                "temperature": 0.1,
                "messages":    messages,
                "tools":       _TOOL_SCHEMAS,
            }
            data = self._call_api(payload)
            msg = data["choices"][0]["message"]
            tool_calls: list[dict] = msg.get("tool_calls") or []

            if not tool_calls:
                # LLM finished tool-use; get the final JSON verdict explicitly.
                messages.append(msg)
                return self._extract_json_verdict(messages, context)

            # Execute every tool call the LLM requested and feed results back.
            messages.append(msg)
            for tc in tool_calls:
                args = json.loads(tc["function"]["arguments"])
                result = self._execute_tool(tc["function"]["name"], args, root)
                messages.append({
                    "role":         "tool",
                    "tool_call_id": tc["id"],
                    "content":      json.dumps(result, ensure_ascii=False)[:8000],
                })

        # Max turns reached — request verdict explicitly.
        return self._extract_json_verdict(messages, context)

    def _extract_json_verdict(self, messages: list[dict], context: dict) -> dict:
        """Ask the LLM to emit a final JSON verdict given the conversation so far."""
        messages = messages + [{
            "role":    "user",
            "content": (
                "Based on your investigation, output ONLY a JSON object with keys: "
                "is_valid, risk_level, issue_type, description, reason, fix_suggestion, confidence. "
                "No markdown, no extra text."
            ),
        }]
        payload = {
            "model":             settings.llm_model,
            "temperature":       0.1,
            "response_format":   {"type": "json_object"},
            "messages":          messages,
        }
        data = self._call_api(payload)
        content = data["choices"][0]["message"].get("content") or "{}"
        parsed = json.loads(content)
        if isinstance(parsed, dict) and "is_valid" in parsed:
            return parsed
        raise ValueError(f"LLM returned an unexpected verdict structure: {parsed!r}")

    def _agent_prompt(self, finding: dict) -> str:
        return (
            f"Static-analysis finding to review:\n"
            f"  File    : {finding.get('file_path')}\n"
            f"  Line    : {finding.get('line')}\n"
            f"  Rule    : {finding.get('rule_id')}\n"
            f"  Severity: {finding.get('severity')}\n"
            f"  Message : {finding.get('message')}\n\n"
            "Use your tools to read the code at this location and investigate "
            "whether this is a genuine security issue. "
            "When satisfied, output your JSON verdict."
        )

    # ── Tool dispatch ─────────────────────────────────────────────────────────

    _FILE_PATH_TOOLS = {"read_code_snippet", "get_ast_context", "get_call_chain"}

    def _resolve_root(self, scan_root: str | None) -> Path | None:
        if not scan_root:
            return None
        try:
            return Path(scan_root).resolve()
        except OSError:
            return None

    def _validate_path(self, file_path: str, root: Path | None) -> Path | None:
        """Resolve file_path and confirm it stays within root.

        The LLM chooses file_path itself based on scanned source content, which
        may contain attacker-controlled text (prompt injection). Without this
        check a crafted finding could make the agent read arbitrary files on
        the host (e.g. SSH keys, .env) and leak their contents into the report.
        """
        if not file_path or root is None:
            return None
        try:
            resolved = Path(file_path).resolve()
            resolved.relative_to(root)
        except (OSError, ValueError):
            return None
        return resolved

    def _execute_tool(self, name: str, args: dict, root: Path | None = None) -> dict:
        file_path = args.get("file_path", "")
        if name in self._FILE_PATH_TOOLS:
            safe_path = self._validate_path(file_path, root)
            if safe_path is None:
                logger.warning(
                    "Blocked tool call %r: file_path %r is outside the scanned project", name, file_path,
                )
                return {"error": "Access denied: file_path is outside the scanned project directory."}
            file_path = str(safe_path)

        if name == "read_code_snippet":
            return self._read_snippet(
                file_path,
                int(args.get("start_line", 1)),
                int(args.get("end_line", 1)),
            )
        if name == "get_ast_context":
            return self._ast_tool.summarize(file_path, int(args.get("line", 1)))
        if name == "get_call_chain":
            finding = {"file_path": file_path, "line": int(args.get("line", 1))}
            return self._call_chain_agent.retrieve_graph(finding)
        return {"error": f"Unknown tool: {name}"}

    def _read_snippet(self, file_path: str, start: int, end: int) -> dict:
        path = Path(file_path)
        if not path.exists() or not path.is_file():
            return {"error": f"File not found: {file_path}"}
        try:
            src = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            return {"error": str(exc)}
        end = min(end, start + 79)  # cap to 80 lines per call
        snippet = "\n".join(
            f"{i + 1:4d}: {line}"
            for i, line in enumerate(src[max(start - 1, 0):end])
        )
        return {"file_path": file_path, "start_line": start, "end_line": end, "code": snippet}

    # ── HTTP helper ───────────────────────────────────────────────────────────

    def _call_api(self, payload: dict) -> dict:
        last_exc: Exception = RuntimeError("no attempts made")
        for attempt in range(3):
            try:
                request = urllib.request.Request(
                    url=f"{settings.llm_base_url.rstrip('/')}/chat/completions",
                    data=json.dumps(payload).encode("utf-8"),
                    headers={
                        "Authorization": f"Bearer {settings.llm_api_key}",
                        "Content-Type":  "application/json",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(request, timeout=settings.llm_timeout_seconds) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except (urllib.error.URLError, OSError) as exc:
                last_exc = exc
                if attempt < 2:
                    time.sleep(2 ** attempt)
        raise last_exc

