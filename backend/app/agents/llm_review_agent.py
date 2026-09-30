import json
import logging
import threading
from pathlib import Path

from app.core.config import settings
from app.core.llm_client import chat_completion, loads_lenient
from app.tools.ast_parser_tool import ASTParserTool
from app.tools.code_index import CodeIndex
from app.agents.call_chain_agent import CallChainRetrievalAgent

logger = logging.getLogger(__name__)


# ── Agent constants ────────────────────────────────────────────────────────────

_MAX_TURNS = 5
_MAX_TOOL_RESULT_CHARS = 8000
# Cumulative budget for one review conversation. Per-result limits alone let
# five turns of several tool calls each grow without bound; once the history
# passes this size the agent must give its verdict with what it has.
_MAX_CONTEXT_CHARS = 32_000
_MAX_CALLERS = 6

_AGENT_SYSTEM = (
    "You are a senior C/C++ security code reviewer. "
    "You have tools to read source files, get AST context, trace call chains and find callers. "
    "You are given a candidate defect reported by one detector and must decide whether it is real. "
    "Use your tools to examine the code before concluding: read the flagged function, then use "
    "find_callers to see what values actually reach it. A sink that is only ever reached with "
    "validated or safe values is a false positive (is_valid=false). "
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
            "name": "find_callers",
            "description": (
                "List the functions (in any file of the project) that call the given function, "
                "with their source code, so you can see which arguments are passed in."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "function_name": {"type": "string", "description": "Name of the called function."},
                },
                "required": ["function_name"],
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
        self._index_lock = threading.Lock()
        self._indexes: dict[Path, CodeIndex] = {}

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
                try:
                    args = loads_lenient(tc["function"].get("arguments") or "{}")
                    result = self._execute_tool(tc["function"]["name"], args, root)
                except (json.JSONDecodeError, TypeError, ValueError) as exc:
                    result = {"error": f"Invalid tool arguments: {exc}"}
                messages.append({
                    "role":         "tool",
                    "tool_call_id": tc["id"],
                    "content":      _bounded_json(result),
                })

            if _history_chars(messages) > _MAX_CONTEXT_CHARS:
                logger.info("Review context budget reached after %d turns; requesting verdict.", turn + 1)
                break

        # Turn or context budget reached — request verdict explicitly.
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
        parsed = loads_lenient(content)
        if isinstance(parsed, dict) and "is_valid" in parsed:
            return parsed
        raise ValueError(f"LLM returned an unexpected verdict structure: {parsed!r}")

    def _agent_prompt(self, finding: dict) -> str:
        return (
            f"Candidate defect reported by {finding.get('origin') or 'static analysis'}:\n"
            f"  File    : {finding.get('file_path')}\n"
            f"  Line    : {finding.get('line')}\n"
            f"  CWE     : {finding.get('cwe') or 'unknown'}\n"
            f"  Rule    : {finding.get('rule_id')}\n"
            f"  Severity: {finding.get('severity')}\n"
            f"  Message : {finding.get('message')}\n\n"
            "Only one detector reported this, so it may be a false positive. "
            "Read the code, check the callers, and decide. "
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
        if name == "find_callers":
            return self._find_callers(str(args.get("function_name") or ""), root)
        return {"error": f"Unknown tool: {name}"}

    def _index_for(self, root: Path) -> CodeIndex:
        # One index per scanned project, shared by all concurrent reviews.
        with self._index_lock:
            if root not in self._indexes:
                self._indexes[root] = CodeIndex.build(root)
            return self._indexes[root]

    def _find_callers(self, function_name: str, root: Path | None) -> dict:
        if root is None or not function_name:
            return {"error": "function_name and a scanned project are required."}
        index = self._index_for(root)
        targets = index.by_name.get(function_name.split("::")[-1], [])
        callers = list(dict.fromkeys(c for t in targets for c in index.callers(t)))[:_MAX_CALLERS]
        return {
            "function": function_name,
            "callers": [
                {
                    "name": c.qualified_name,
                    "file_path": str(c.file),
                    "start_line": c.start,
                    "code": "\n".join(f"{c.start + i:4d}: {line}" for i, line in enumerate(c.code[:60])),
                }
                for c in callers
            ],
        }

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
        return chat_completion(payload)


def _history_chars(messages: list[dict]) -> int:
    total = 0
    for message in messages:
        total += len(message.get("content") or "")
        for call in message.get("tool_calls") or []:
            total += len(call.get("function", {}).get("arguments") or "")
    return total


def _bounded_json(result: dict) -> str:
    """Serialize a tool result under the size limit without cutting the JSON
    in half: shrink the bulky text fields first, then fall back to a summary."""
    text = json.dumps(result, ensure_ascii=False)
    if len(text) <= _MAX_TOOL_RESULT_CHARS:
        return text
    shrunk = json.loads(text)
    for key in ("code", "nodes", "edges", "callers", "dependencies"):
        if key in shrunk:
            value = shrunk[key]
            if isinstance(value, str):
                shrunk[key] = value[: _MAX_TOOL_RESULT_CHARS // 2] + "\n... (truncated)"
            elif isinstance(value, list):
                shrunk[key] = value[: max(1, len(value) // 2)]
            text = json.dumps(shrunk, ensure_ascii=False)
            if len(text) <= _MAX_TOOL_RESULT_CHARS:
                return text
    return json.dumps({"truncated": True, "preview": text[: _MAX_TOOL_RESULT_CHARS - 100]}, ensure_ascii=False)
