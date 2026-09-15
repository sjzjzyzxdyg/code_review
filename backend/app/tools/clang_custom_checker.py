"""
Custom intra-procedural AND cross-file state-machine checkers using ``clang -ast-dump=json``.

Why Clang AST instead of Cppcheck regex rules
----------------------------------------------
Both rules require knowing the *history* of a variable across multiple statements.
Regex sees one line at a time; Cppcheck has no knowledge of project-specific
allocator APIs.  Clang's JSON AST gives a full, ordered view of every statement.

Checker 1 — OCMAllocatorMismatchChecker  (FOS coding standard §2)
  Tracks which allocator created each pointer, reports any call to the wrong free.

  Example violation (intra):
    void *buf = OCM_MALLOC(size);
    free(buf);                       // ERROR — must use OCM_FREE(buf)

  Example violation (cross-file):
    // file_a.c
    void *buf = OCM_MALLOC(size);
    helper(buf);                     // passes OCM-owned ptr to another file
    // file_b.c
    void helper(void *p) { free(p); } // ERROR — wrong free function

Checker 2 — RBTreeLifecycleChecker  (FOS coding standard §5)
  Tracks nodes inserted into a red-black / AVL tree; reports free without prior
  UDS_RB_DELETE / AVL_DELETE.

  Example violation (intra):
    UDS_RB_INSERT(&g_tree, &node->rb_node);
    OCM_FREE(node);                  // ERROR — delete from tree first

  Example violation (cross-file):
    // file_a.c
    UDS_RB_INSERT(&g_tree, &node->rb_node);
    cleanup(node);
    // file_b.c
    void cleanup(Node *n) { OCM_FREE(n); } // ERROR — tree not cleaned up

Cross-file algorithm (two-pass):
  Pass 1 – analyse each file independently to extract _CustomFuncFacts (how a
            function handles its parameters) and _CustomCallSite (variable states
            at each outgoing call).
  Pass 2 – for every call whose callee is in a *different* file, apply rules.
"""

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from app.tools.cppcheck_tool import StaticAnalysisToolUnavailable


# ── Domain constants ──────────────────────────────────────────────────────────

_ALLOC_TO_FREE: dict[str, str] = {
    "OCM_MALLOC":  "OCM_FREE",
    "FMEM_MALLOC": "FMEM_FREE",
    "malloc":      "free",
    "calloc":      "free",
    "realloc":     "free",
}

_ALL_FREE_FUNCS:    frozenset[str] = frozenset({"free", "OCM_FREE", "FMEM_FREE"})
_TREE_INSERT_FUNCS: frozenset[str] = frozenset({"UDS_RB_INSERT", "AVL_INSERT"})
_TREE_DELETE_FUNCS: frozenset[str] = frozenset({"UDS_RB_DELETE", "AVL_DELETE"})
_SOURCE_EXTENSIONS: frozenset[str] = frozenset({".c", ".cc", ".cpp", ".cxx"})
_CONTAINER_KINDS:   frozenset[str] = frozenset({
    "NamespaceDecl", "LinkageSpecDecl", "ExternCDecl", "TranslationUnitDecl",
})


# ── Cross-file data structures ────────────────────────────────────────────────

@dataclass
class _CustomFuncFacts:
    """Callee-side facts: what a function does to its parameters."""
    name:   str
    file:   Path
    line:   int
    params: list[str]

    # OCM: param → (free_func, line_of_free)
    freed_params: dict[str, tuple[str, int]] = field(default_factory=dict)

    # RBTree: param freed while still in-tree → line of the free call
    tree_freed_params: dict[str, int] = field(default_factory=dict)


@dataclass
class _CustomCallSite:
    """Caller-side variable state snapshot at an outgoing call."""
    caller_file: Path
    callee_name: str
    args:        list[str | None]
    line:        int

    alloc_vars:   dict[str, str] = field(default_factory=dict)  # var → alloc_func
    in_tree_vars: set[str]       = field(default_factory=set)   # vars currently in-tree


# ── Public tool ───────────────────────────────────────────────────────────────

class ClangCustomCheckerTool:
    """
    Run OCMAllocatorMismatchChecker and RBTreeLifecycleChecker at two scopes:

    • Intra-procedural: within a single function body.
    • Cross-file: variable allocated/inserted in caller, wrong free/lifecycle
      operation in a callee defined in a different file.
    """

    def run(self, project_path: Path) -> list[dict]:
        clang    = _resolve_clang()
        findings: list[dict] = []
        sources  = _iter_sources(project_path)

        # Collect ASTs once; reuse for both intra- and cross-file passes.
        all_asts: dict[Path, dict] = {}
        for source in sources:
            ast = _dump_ast(clang, source)
            if ast is None:
                continue
            all_asts[source] = ast

            # ── Intra-procedural: per function body ───────────────────────
            for fn_stmts in _extract_function_stmts(ast):
                findings.extend(OCMAllocatorMismatchChecker().check(fn_stmts, source))
                findings.extend(RBTreeLifecycleChecker().check(fn_stmts, source))

        # ── Cross-file interprocedural: two-pass ──────────────────────────
        if len(all_asts) >= 2:
            findings.extend(_cross_file_check(all_asts))

        return findings


# ── Intra-procedural checkers ─────────────────────────────────────────────────

class OCMAllocatorMismatchChecker:
    """
    Intra-procedural state machine:

      state[var] = (alloc_func, correct_free_func, alloc_line)

    Transition rules:
      OCM_MALLOC(…) → var  :  state[var] = ("OCM_MALLOC", "OCM_FREE", line)
      free(var)             :  if state[var].correct_free != "free"  → REPORT
      OCM_FREE(var)         :  if state[var].correct_free != "OCM_FREE" → REPORT
    """

    def check(self, stmts: list[dict], source: Path) -> list[dict]:
        findings: list[dict] = []
        owned: dict[str, tuple[str, str, int]] = {}

        for stmt in stmts:
            if stmt["event"] == "alloc":
                alloc_func = stmt["alloc_func"]
                owned[stmt["var"]] = (alloc_func, _ALLOC_TO_FREE[alloc_func], stmt["line"])

            elif stmt["event"] == "call" and stmt["callee"] in _ALL_FREE_FUNCS:
                for arg in stmt["args"]:
                    if arg not in owned:
                        continue
                    alloc_func, correct_free, alloc_line = owned.pop(arg)
                    if stmt["callee"] != correct_free:
                        findings.append({
                            "tool": "clang-custom",
                            "rule_id": "custom-allocator-mismatch",
                            "severity": "error",
                            "message": (
                                f"'{arg}' allocated with {alloc_func}() at line {alloc_line} "
                                f"but freed with {stmt['callee']}(); "
                                f"use {correct_free}() instead."
                            ),
                            "file_path": str(source),
                            "line": stmt["line"],
                            "column": stmt.get("col"),
                        })

        return findings


class RBTreeLifecycleChecker:
    """
    Intra-procedural state machine:

      tree_state[var] = "inserted" | "deleted"

    Transition rules:
      UDS_RB_INSERT(…, var) :  tree_state[var] = "inserted"
      UDS_RB_DELETE(…, var) :  tree_state[var] = "deleted"
      OCM_FREE(var)         :  if tree_state[var] == "inserted"  → REPORT
    """

    def check(self, stmts: list[dict], source: Path) -> list[dict]:
        findings: list[dict] = []
        tree_state: dict[str, str] = {}

        for stmt in stmts:
            if stmt["event"] != "call":
                continue
            callee = stmt["callee"]
            args   = stmt["args"]

            if callee in _TREE_INSERT_FUNCS:
                node_var = _last_named_arg(args)
                if node_var:
                    tree_state[node_var] = "inserted"

            elif callee in _TREE_DELETE_FUNCS:
                node_var = _last_named_arg(args)
                if node_var and node_var in tree_state:
                    tree_state[node_var] = "deleted"

            elif callee in _ALL_FREE_FUNCS:
                for arg in args:
                    if arg != "?" and tree_state.get(arg) == "inserted":
                        findings.append({
                            "tool": "clang-custom",
                            "rule_id": "custom-rbtree-free-before-delete",
                            "severity": "error",
                            "message": (
                                f"'{arg}' is still inserted in a tree but memory is freed "
                                f"without calling UDS_RB_DELETE/AVL_DELETE first; "
                                f"dangling tree node will corrupt the tree."
                            ),
                            "file_path": str(source),
                            "line": stmt["line"],
                            "column": stmt.get("col"),
                        })

        return findings


# ── Cross-file analysis ───────────────────────────────────────────────────────

def _cross_file_check(all_asts: dict[Path, dict]) -> list[dict]:
    all_func_facts: dict[str, _CustomFuncFacts] = {}
    all_call_sites: list[_CustomCallSite] = []

    for src, ast in all_asts.items():
        facts_list, sites = _analyse_file_custom(src, ast)
        for facts in facts_list:
            all_func_facts[facts.name] = facts
        all_call_sites.extend(sites)

    findings: list[dict] = []
    for site in all_call_sites:
        callee = all_func_facts.get(site.callee_name)
        if callee is None or callee.file == site.caller_file:
            continue
        findings.extend(_rule_cross_alloc_mismatch(site, callee))
        findings.extend(_rule_cross_rbtree_free(site, callee))

    return findings


def _analyse_file_custom(
    src: Path, ast_root: dict
) -> tuple[list[_CustomFuncFacts], list[_CustomCallSite]]:
    func_facts: list[_CustomFuncFacts] = []
    call_sites: list[_CustomCallSite]  = []
    _collect_custom_funcs(src, ast_root.get("inner", []), func_facts, call_sites)
    return func_facts, call_sites


def _collect_custom_funcs(
    src: Path,
    nodes: list,
    func_facts: list[_CustomFuncFacts],
    call_sites: list[_CustomCallSite],
) -> None:
    for node in nodes:
        if not isinstance(node, dict):
            continue
        kind = node.get("kind", "")
        if kind in _CONTAINER_KINDS:
            _collect_custom_funcs(src, node.get("inner", []), func_facts, call_sites)
            continue
        if kind not in ("FunctionDecl", "CXXMethodDecl"):
            continue
        loc_file = _loc_file(node)
        if loc_file and not _paths_match(loc_file, src):
            continue
        body = _find_compound_body(node)
        if body is None:
            continue

        params = _extract_params(node)
        facts  = _CustomFuncFacts(
            name=node.get("name", "?"),
            file=src,
            line=_node_line(node),
            params=params,
        )

        analyser = _CustomBodyAnalyser(params, src)
        analyser.walk(body)

        facts.freed_params      = analyser.freed_params
        facts.tree_freed_params = analyser.tree_freed_params

        func_facts.append(facts)
        call_sites.extend(analyser.call_sites)


class _CustomBodyAnalyser:
    """
    Single-pass AST walker that simultaneously tracks:

    Caller-side state (snapshot at each outgoing call → _CustomCallSite):
      alloc_state[var]  = alloc_func   — var was allocated with this function
      tree_state[var]   = "inserted"   — var is currently in a tree

    Callee-side facts (what this function does to its own params → _CustomFuncFacts):
      freed_params[param]       = (free_func, line)
      tree_freed_params[param]  = line   — param freed while still in-tree
    """

    def __init__(self, params: list[str], src: Path) -> None:
        self.params = set(params)
        self.src    = src

        self.alloc_state: dict[str, str] = {}   # var → alloc_func
        self.tree_state:  dict[str, str] = {}   # var → "inserted" | "deleted"

        self.freed_params:      dict[str, tuple[str, int]] = {}
        self.tree_freed_params: dict[str, int]             = {}

        self.call_sites: list[_CustomCallSite] = []

    def walk(self, node: dict) -> None:
        if not isinstance(node, dict):
            return
        kind = node.get("kind", "")

        if kind == "VarDecl":
            self._on_vardecl(node)

        elif kind == "BinaryOperator" and node.get("opcode") == "=":
            self._on_assign(node)

        elif kind == "CallExpr":
            self._on_call(node)

        elif kind == "CXXDeleteExpr":
            inner     = node.get("inner", [])
            free_func = "delete[]" if node.get("isArray") else "delete"
            if inner:
                name = _decl_ref_name(inner[0])
                if name:
                    self._handle_free(name, free_func, _node_line(node))
            for ch in inner:
                self.walk(ch)

        else:
            for ch in node.get("inner", []):
                self.walk(ch)

    # ── Event handlers ────────────────────────────────────────────────────────

    def _on_vardecl(self, node: dict) -> None:
        name = node.get("name")
        init = node.get("inner", [])
        if name:
            alloc = _find_alloc_in_children(init)
            if alloc:
                self.alloc_state[name] = alloc
                return  # don't recurse: avoid double-counting the inner CallExpr
        for ch in init:
            self.walk(ch)

    def _on_assign(self, node: dict) -> None:
        inner = node.get("inner", [])
        if len(inner) == 2:
            lhs  = _decl_ref_name(inner[0])
            alloc = _find_alloc_in_children([inner[1]])
            if lhs and alloc:
                self.alloc_state[lhs] = alloc
                return  # don't recurse: avoid double-counting
        for ch in inner:
            self.walk(ch)

    def _on_call(self, node: dict) -> None:
        callee = _callee_name(node)
        if not callee:
            return
        line  = _node_line(node)
        inner = node.get("inner", [])
        args  = [_decl_ref_name(a) for a in inner[1:]]

        if callee in _TREE_INSERT_FUNCS:
            node_var = _last_named_arg(args)
            if node_var:
                self.tree_state[node_var] = "inserted"
            return

        if callee in _TREE_DELETE_FUNCS:
            node_var = _last_named_arg(args)
            if node_var:
                self.tree_state[node_var] = "deleted"
            return

        if callee in _ALL_FREE_FUNCS:
            for arg in args:
                if arg:
                    self._handle_free(arg, callee, line)
            return

        if callee in _ALLOC_TO_FREE:
            return  # alloc call: handled by _on_vardecl / _on_assign

        # Outgoing call to another function: snapshot current state.
        self.call_sites.append(_CustomCallSite(
            caller_file = self.src,
            callee_name = callee,
            args        = args,
            line        = line,
            alloc_vars  = dict(self.alloc_state),
            in_tree_vars = {v for v, s in self.tree_state.items() if s == "inserted"},
        ))

    def _handle_free(self, var: str, free_func: str, line: int) -> None:
        if var in self.params:
            self.freed_params[var] = (free_func, line)
            if self.tree_state.get(var) == "inserted":
                self.tree_freed_params[var] = line
        self.alloc_state.pop(var, None)


# ── Cross-file rules ──────────────────────────────────────────────────────────

def _rule_cross_alloc_mismatch(
    site: _CustomCallSite, callee: _CustomFuncFacts
) -> list[dict]:
    """Allocated in caller with X, freed in callee with wrong Y."""
    out = []
    for i, arg in enumerate(site.args):
        if arg is None or arg not in site.alloc_vars:
            continue
        if i >= len(callee.params):
            continue
        param = callee.params[i]
        if param not in callee.freed_params:
            continue
        alloc_func             = site.alloc_vars[arg]
        free_func, free_line   = callee.freed_params[param]
        expected_free          = _ALLOC_TO_FREE.get(alloc_func)
        if expected_free and free_func != expected_free:
            out.append({
                "tool":        "clang-custom",
                "rule_id":     "custom-allocator-mismatch",
                "severity":    "error",
                "message": (
                    f"'{arg}' allocated with {alloc_func}() in "
                    f"{site.caller_file.name}:{site.line} "
                    f"but freed with {free_func}() in "
                    f"{callee.file.name}:{free_line} "
                    f"(param '{param}'); use {expected_free}() instead."
                ),
                "file_path":   str(callee.file),
                "line":        free_line,
                "column":      None,
                "cross_file":  True,
                "caller_file": str(site.caller_file),
                "caller_line": site.line,
            })
    return out


def _rule_cross_rbtree_free(
    site: _CustomCallSite, callee: _CustomFuncFacts
) -> list[dict]:
    """Variable still in-tree in caller; callee frees it without tree-delete."""
    out = []
    for i, arg in enumerate(site.args):
        if arg is None or arg not in site.in_tree_vars:
            continue
        if i >= len(callee.params):
            continue
        param = callee.params[i]
        if param not in callee.tree_freed_params:
            continue
        free_line = callee.tree_freed_params[param]
        out.append({
            "tool":        "clang-custom",
            "rule_id":     "custom-rbtree-free-before-delete",
            "severity":    "error",
            "message": (
                f"'{arg}' is still inserted in a tree "
                f"(in {site.caller_file.name}:{site.line}) "
                f"but freed in {callee.file.name}:{free_line} "
                f"(param '{param}') without calling "
                f"UDS_RB_DELETE/AVL_DELETE first."
            ),
            "file_path":   str(callee.file),
            "line":        free_line,
            "column":      None,
            "cross_file":  True,
            "caller_file": str(site.caller_file),
            "caller_line": site.line,
        })
    return out


# ── AST extraction (intra-procedural events) ──────────────────────────────────

def _extract_function_stmts(root: dict) -> list[list[dict]]:
    result: list[list[dict]] = []
    _walk_top_level(root, result)
    return result


def _walk_top_level(node: dict, result: list) -> None:
    if not isinstance(node, dict):
        return
    kind = node.get("kind", "")
    if kind in ("FunctionDecl", "CXXMethodDecl"):
        stmts: list[dict] = []
        for child in node.get("inner", []):
            _collect_stmts(child, stmts)
        if stmts:
            result.append(stmts)
        return
    for child in node.get("inner", []):
        _walk_top_level(child, result)


def _collect_stmts(node: dict, out: list) -> None:
    if not isinstance(node, dict):
        return
    kind = node.get("kind", "")

    if kind == "VarDecl":
        var_name = node.get("name")
        if var_name:
            init_children = node.get("inner", [])
            alloc_func = _find_alloc_in_children(init_children)
            if alloc_func:
                out.append({
                    "event":      "alloc",
                    "var":        var_name,
                    "alloc_func": alloc_func,
                    **_node_loc(node),
                })
                return
        for child in node.get("inner", []):
            _collect_stmts(child, out)
        return

    if kind == "BinaryOperator" and node.get("opcode") == "=":
        inner = node.get("inner", [])
        if len(inner) == 2:
            lhs_name  = _decl_ref_name(inner[0])
            alloc_func = _find_alloc_in_children([inner[1]])
            if lhs_name and alloc_func:
                out.append({
                    "event":      "alloc",
                    "var":        lhs_name,
                    "alloc_func": alloc_func,
                    **_node_loc(inner[1]),
                })
                return
        for child in inner:
            _collect_stmts(child, out)
        return

    if kind == "CallExpr":
        callee = _callee_name(node)
        if callee:
            out.append({
                "event":  "call",
                "callee": callee,
                "args":   _arg_names(node),
                **_node_loc(node),
            })
        return

    for child in node.get("inner", []):
        _collect_stmts(child, out)


# ── AST node helpers ──────────────────────────────────────────────────────────

def _find_alloc_in_children(nodes: list[dict]) -> str | None:
    for node in nodes:
        result = _find_alloc_deep(node)
        if result:
            return result
    return None


def _find_alloc_deep(node: dict) -> str | None:
    if not isinstance(node, dict):
        return None
    if node.get("kind") == "CallExpr":
        name = _callee_name(node)
        if name in _ALLOC_TO_FREE:
            return name
    for child in node.get("inner", []):
        result = _find_alloc_deep(child)
        if result:
            return result
    return None


def _callee_name(call_node: dict) -> str | None:
    inner = call_node.get("inner", [])
    return _decl_ref_name(inner[0]) if inner else None


def _arg_names(call_node: dict) -> list[str]:
    inner = call_node.get("inner", [])
    return [_decl_ref_name(a) or "?" for a in inner[1:]]


def _decl_ref_name(node: dict) -> str | None:
    if not isinstance(node, dict):
        return None
    kind = node.get("kind", "")
    if kind == "DeclRefExpr":
        return node.get("referencedDecl", {}).get("name") or node.get("name")
    if kind in (
        "ImplicitCastExpr", "CStyleCastExpr", "CXXStaticCastExpr",
        "CXXFunctionalCastExpr", "ParenExpr", "UnaryOperator",
        "MaterializeTemporaryExpr",
    ):
        for child in node.get("inner", []):
            name = _decl_ref_name(child)
            if name:
                return name
    return None


def _last_named_arg(args: list[str]) -> str | None:
    for arg in reversed(args):
        if arg and arg != "?":
            return arg
    return None


def _node_loc(node: dict) -> dict:
    loc = node.get("loc") or node.get("range", {}).get("begin", {})
    return {"line": loc.get("line", 0), "col": loc.get("col", 0)}


def _node_line(node: dict) -> int:
    loc = node.get("loc") or node.get("range", {}).get("begin", {})
    return loc.get("line", 0)


def _loc_file(node: dict) -> str | None:
    loc = node.get("loc", {})
    if "file" in loc:
        return loc["file"]
    exp = loc.get("expansionLoc", {})
    return exp.get("file")


def _paths_match(loc_file: str, src: Path) -> bool:
    lp = Path(loc_file)
    if lp.is_absolute():
        try:
            return lp.resolve() == src.resolve()
        except OSError:
            pass
    return lp.name == src.name


def _find_compound_body(func_node: dict) -> dict | None:
    for ch in func_node.get("inner", []):
        if ch.get("kind") == "CompoundStmt":
            return ch
    return None


def _extract_params(func_node: dict) -> list[str]:
    return [
        ch.get("name", "")
        for ch in func_node.get("inner", [])
        if ch.get("kind") == "ParmVarDecl" and ch.get("name")
    ]


# ── Subprocess / filesystem helpers ──────────────────────────────────────────

def _resolve_clang() -> str:
    for candidate in ("clang", "clang++", "clang-cl"):
        try:
            r = subprocess.run(
                [candidate, "--version"],
                capture_output=True,
                check=False,
                encoding="utf-8",
                errors="replace",
                timeout=10,
            )
            if r.returncode == 0:
                return candidate
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    raise StaticAnalysisToolUnavailable(
        "Clang is not installed or not available in PATH."
    )


def _dump_ast(clang: str, source: Path) -> dict | None:
    try:
        result = subprocess.run(
            [clang, "-Xclang", "-ast-dump=json", "-fsyntax-only", "-w", str(source)],
            capture_output=True,
            text=True,
            check=False,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
        stdout = result.stdout.strip()
        return json.loads(stdout) if stdout else None
    except (json.JSONDecodeError, subprocess.TimeoutExpired, OSError):
        return None


def _iter_sources(project_path: Path) -> list[Path]:
    if project_path.is_file():
        return [project_path] if project_path.suffix.lower() in _SOURCE_EXTENSIONS else []
    return [
        p for p in project_path.rglob("*")
        if p.is_file() and p.suffix.lower() in _SOURCE_EXTENSIONS
    ]
