import re
from pathlib import Path


class CallChainRetrievalAgent:
    """Retrieves local function call chains related to a candidate issue."""

    FUNCTION_PATTERN = re.compile(
        r"^\s*(?:[\w:*&<>\[\]\s]+)\s+([A-Za-z_]\w*)\s*\([^;]*\)\s*(?:const\s*)?\{?"
    )
    CALL_PATTERN = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
    RESERVED = {"if", "for", "while", "switch", "return", "sizeof", "catch"}

    def retrieve(self, finding: dict, max_depth: int = 3) -> list[str]:
        graph = self.retrieve_graph(finding, max_depth=max_depth)
        return graph.get("chain", [])

    def retrieve_graph(self, finding: dict, max_depth: int = 3) -> dict:
        file_path = Path(str(finding.get("file_path") or ""))
        line = int(finding.get("line") or 1)
        if not file_path.exists() or not file_path.is_file():
            return {"nodes": [], "edges": [], "entry": None, "chain": []}

        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
        functions = self._parse_functions(lines)

        for related in self._related_files(file_path):
            try:
                extra_lines = related.read_text(encoding="utf-8", errors="replace").splitlines()
                functions.extend(self._parse_functions(extra_lines))
            except OSError:
                pass

        current = self._function_at_line(functions, line)
        if current is None:
            return {"nodes": [], "edges": [], "entry": None, "chain": []}

        graph = {
            name: [call for call in self._calls_in_body(body) if call != name]
            for name, _, _, body in functions
        }
        chain = [current]
        visited = {current}
        cursor = current
        for _ in range(max_depth):
            next_call = next((call for call in graph.get(cursor, []) if call in graph and call not in visited), None)
            if next_call is None:
                break
            chain.append(next_call)
            visited.add(next_call)
            cursor = next_call

        node_names = set(chain)
        edge_pairs: set[tuple[str, str]] = set()
        for name in chain:
            for call in graph.get(name, []):
                if call in graph:
                    node_names.add(call)
                    edge_pairs.add((name, call))

        return {
            "entry": current,
            "chain": chain,
            "nodes": [
                {
                    "id": name,
                    "name": name,
                    "in_chain": name in chain,
                }
                for name in sorted(node_names, key=lambda item: (item not in chain, item))
            ],
            "edges": [
                {"source": source, "target": target}
                for source, target in sorted(edge_pairs)
            ],
        }

    def _parse_functions(self, lines: list[str]) -> list[tuple[str, int, int, list[str]]]:
        functions: list[tuple[str, int, int, list[str]]] = []
        index = 0
        while index < len(lines):
            match = self.FUNCTION_PATTERN.match(lines[index])
            if not match or match.group(1) in self.RESERVED:
                index += 1
                continue

            name = match.group(1)
            start = index + 1
            brace_depth = lines[index].count("{") - lines[index].count("}")
            end_index = index
            if "{" in lines[index] and brace_depth <= 0:
                body = lines[index : end_index + 1]
                functions.append((name, start, end_index + 1, body))
                index += 1
                continue
            while end_index + 1 < len(lines) and brace_depth <= 0:
                end_index += 1
                brace_depth += lines[end_index].count("{") - lines[end_index].count("}")
                if brace_depth > 0:
                    break
            while end_index + 1 < len(lines) and brace_depth > 0:
                end_index += 1
                brace_depth += lines[end_index].count("{") - lines[end_index].count("}")
            body = lines[index : end_index + 1]
            functions.append((name, start, end_index + 1, body))
            index = max(end_index + 1, index + 1)
        return functions

    def _function_at_line(self, functions: list[tuple[str, int, int, list[str]]], line: int) -> str | None:
        for name, start, end, _ in functions:
            if start <= line <= end:
                return name
        return None

    def _calls_in_body(self, body: list[str]) -> list[str]:
        calls: list[str] = []
        for source_line in body:
            for match in self.CALL_PATTERN.findall(source_line):
                if match not in self.RESERVED and match not in calls:
                    calls.append(match)
        return calls

    def _related_files(self, file_path: Path, max_files: int = 6) -> list[Path]:
        suffix = file_path.suffix.lower()
        c_extensions = {".c", ".cc", ".cpp", ".cxx"}
        if suffix not in c_extensions:
            return []
        stem = file_path.stem
        # Strip trailing variant marker like _82a → _82, or _01 → base name
        base = re.sub(r"[_-][a-z]$", "", stem)
        siblings = [
            p for p in file_path.parent.glob(f"{base}*")
            if p != file_path and p.suffix.lower() in c_extensions
        ]
        return siblings[:max_files]
