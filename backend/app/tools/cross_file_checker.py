"""
Cross-file (interprocedural) static analysis using ``clang -ast-dump=json``.

Two-pass algorithm
------------------
Pass 1 – analyse each source file independently to extract:
  • _FuncFacts  – what a function does to/with each of its parameters
  • _CallSite   – what variable states exist at each outgoing call

Pass 2 – for every call whose callee is defined in a *different* file, apply
cross-file rules:

  CWE476  cross-null-deref        NULL passed → dereferenced without guard
  CWE690  cross-null-from-alloc   unchecked malloc → dereferenced/used without guard
  CWE762  cross-alloc-mismatch    malloc+delete[], new+free, etc.
  CWE415  cross-double-free       free() in caller → free() again in callee
  CWE401  cross-mem-leak          malloc in caller → callee never frees
  CWE590  cross-free-nonheap      stack/alloca ptr → freed in callee
  CWE369  cross-div-zero          zero/tainted var → divided-by without check
  CWE121  cross-buf-overflow      large/tainted index → array subscript, partial check only
  CWE122  cross-buf-overflow      (heap variant, same rule)
  CWE190  cross-int-overflow      large value → arithmetic without overflow check
  CWE191  cross-int-underflow     tiny/min value → arithmetic without underflow check
  CWE134  cross-format-string     tainted input → printf format-string argument
"""

import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from app.tools import clang_ast

from app.tools.cppcheck_tool import StaticAnalysisToolUnavailable


# ── Domain constants ──────────────────────────────────────────────────────────

_SOURCE_EXTENSIONS = frozenset({".c", ".cc", ".cpp", ".cxx"})

_ALLOC_TO_FREE: dict[str, str] = {
    "malloc":      "free",
    "calloc":      "free",
    "realloc":     "free",
    "OCM_MALLOC":  "OCM_FREE",
    "FMEM_MALLOC": "FMEM_FREE",
    "new":         "delete",
    "new[]":       "delete[]",
}
_ALL_ALLOC_FUNCS = frozenset({"malloc", "calloc", "realloc", "OCM_MALLOC", "FMEM_MALLOC"})
_ALL_FREE_FUNCS  = frozenset({"free", "OCM_FREE", "FMEM_FREE"})

# External input sources that produce "tainted" (potentially dangerous) values

# fgets(buf, n, stream) → buf (arg 0) is tainted
_TAINTED_ARG0_FUNCS = frozenset({
    "fgets", "gets", "getline",
})
# fscanf(stream, fmt, &var, ...) → vars from arg 2 onwards are tainted
_TAINTED_SCANF_FUNCS = frozenset({
    "scanf", "fscanf", "sscanf", "wscanf", "fwscanf",
})
# recv(sock, buf, len, flags) → buf (arg 1) is tainted; uses ALL names in buf expr
_RECV_WRITE_FUNCS = frozenset({
    "recv", "recvfrom", "read", "fread",
})
# RAND32/rand – value-returning taint (the returned value may be 0 or anything)
_TAINTED_INPLACE_FUNCS = frozenset({
    "RAND32", "rand",
    "atoi", "atol", "atof", "strtol", "strtof", "strtod",
})

# Functions that dereference a pointer argument (for CWE690 callee detection)
_UNSAFE_PTR_FUNCS = frozenset({
    "strcpy", "strncpy", "strcat", "strncat", "strlen",
    "strcmp", "strncmp", "memcpy", "memmove", "memset", "memcmp",
    "sprintf", "snprintf", "sscanf",
    "wcscpy", "wcsncpy", "wcscat", "wcsncat", "wcslen",
    "printLine", "printIntLine", "printLongLine", "printFloatLine",
    "printDoubleLine", "printHexCharLine", "printUnsignedLine",
    "printBytesLine", "printStructLine", "printShortLine",
})

# printf-family: format-string argument position (0-indexed, after implicit args)
_PRINTF_FORMAT_POS: dict[str, int] = {
    "printf": 0, "wprintf": 0, "vprintf": 0,
    "fprintf": 1, "fwprintf": 1, "vfprintf": 1,
    "sprintf": 1, "swprintf": 1, "vsprintf": 1,
    "snprintf": 2, "vsnprintf": 2,
    "_snprintf": 2, "_vsnprintf": 2,
}

# Stack / alloca allocation sources (NOT heap)
_STACK_ALLOC_FUNCS = frozenset({"alloca", "_alloca", "_malloca", "ALLOCA"})


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class _FuncFacts:
    """Facts about a function's body relevant to interprocedural checking."""
    name:   str
    file:   Path
    line:   int
    params: list[str]

    # CWE476 / CWE690 – null-pointer
    null_checked_params: set[str] = field(default_factory=set)
    dereffed_params:     set[str] = field(default_factory=set)

    # CWE762 / CWE415 / CWE401 / CWE590 – memory management
    freed_params:  dict[str, str] = field(default_factory=dict)  # param → free_func
    freed_lines:   dict[str, int] = field(default_factory=dict)  # param → line

    # CWE369 – divide-by-zero
    div_params:          set[str] = field(default_factory=set)   # params used as divisor
    zero_checked_params: set[str] = field(default_factory=set)   # params zero-checked before div

    # CWE121 / CWE122 – buffer overflow via index
    array_index_params:       set[str] = field(default_factory=set)
    upper_bound_checked_params: set[str] = field(default_factory=set)

    # CWE190 / CWE191 – integer overflow / underflow
    arith_params:            set[str] = field(default_factory=set)  # in +/-/* operations
    overflow_checked_params: set[str] = field(default_factory=set)  # checked < MAX before arith
    underflow_checked_params: set[str] = field(default_factory=set) # checked > MIN before arith

    # CWE134 – uncontrolled format string
    format_str_params: set[str] = field(default_factory=set)


@dataclass
class _CallSite:
    """One outgoing call, annotated with known variable states at that point."""
    caller_file: Path
    callee_name: str
    args:        list[str | None]
    line:        int

    # CWE476 – explicit NULL vars
    null_vars:  set[str]       = field(default_factory=set)

    # CWE762 – heap-allocated vars and their allocator
    alloc_vars: dict[str, str] = field(default_factory=dict)

    # CWE690 – heap-allocated vars NOT yet null-checked
    unchecked_alloc_vars: set[str] = field(default_factory=set)

    # CWE415 – locally freed vars (freed before this call)
    freed_vars: set[str] = field(default_factory=set)

    # CWE590 – vars holding a stack / alloca address
    stack_vars: set[str] = field(default_factory=set)

    # CWE369 – vars that could be zero (literal 0 or tainted from external)
    zero_vars: set[str] = field(default_factory=set)

    # CWE121/122 – vars that might be large (literal >= threshold or tainted)
    large_index_vars: set[str] = field(default_factory=set)

    # CWE190 – vars near integer MAX (literal >= threshold or tainted)
    max_int_vars: set[str] = field(default_factory=set)

    # CWE191 – vars near integer MIN (negative literal or tainted)
    min_int_vars: set[str] = field(default_factory=set)

    # CWE134 – vars holding external / tainted string data
    tainted_vars: set[str] = field(default_factory=set)


# ── Public tool ───────────────────────────────────────────────────────────────

class CrossFileChecker:
    """Interprocedural checker: detects bugs whose source and sink span two files."""

    def run(self, project_path: Path, include_paths: list[Path] | None = None) -> list[dict]:
        clang_bin = _resolve_clang()
        sources   = _iter_sources(project_path)
        if len(sources) < 2:
            return []

        inc_flags = tuple(f"-I{p}" for p in (include_paths or []))

        # ── Pass 1 ────────────────────────────────────────────────────────────
        all_func_facts: dict[str, _FuncFacts] = {}
        all_call_sites: list[_CallSite]       = []

        for src in sources:
            # dump_ast is shared with clang_custom_checker's own AST-based
            # pass — see clang_ast.py for why that sharing matters — so both
            # checkers must request the same include flags for the same file
            # to actually get a cache hit instead of a redundant clang call.
            ast = clang_ast.dump_ast(clang_bin, str(src), inc_flags)
            if ast is None:
                continue
            facts_list, sites = _analyse_file(src, ast)
            for facts in facts_list:
                all_func_facts[facts.name] = facts
            all_call_sites.extend(sites)

        # ── Pass 2 ────────────────────────────────────────────────────────────
        findings: list[dict] = []
        for site in all_call_sites:
            callee = all_func_facts.get(site.callee_name)
            if callee is None or callee.file == site.caller_file:
                continue
            findings.extend(_rule_null_deref(site, callee))
            findings.extend(_rule_null_from_alloc(site, callee))
            findings.extend(_rule_alloc_mismatch(site, callee))
            findings.extend(_rule_double_free(site, callee))
            findings.extend(_rule_mem_leak(site, callee))
            findings.extend(_rule_free_nonheap(site, callee))
            findings.extend(_rule_div_zero(site, callee))
            findings.extend(_rule_buf_overflow(site, callee))
            findings.extend(_rule_int_overflow(site, callee))
            findings.extend(_rule_int_underflow(site, callee))
            findings.extend(_rule_format_string(site, callee))

        return findings


# ── Cross-file rules ──────────────────────────────────────────────────────────

def _finding(site: _CallSite, callee: _FuncFacts,
             rule_id: str, arg: str, param: str, detail: str) -> dict:
    return {
        "tool":        "clang-cross-file",
        "rule_id":     rule_id,
        "severity":    "error",
        "message":     (
            f"[{rule_id}] '{arg}' in {site.caller_file.name}:{site.line} "
            f"passed to '{callee.name}()' in {callee.file.name}:{callee.line} "
            f"(param '{param}'): {detail}"
        ),
        "file_path":   str(callee.file),
        "line":        callee.line,
        "column":      None,
        "cross_file":  True,
        "caller_file": str(site.caller_file),
        "caller_line": site.line,
    }


def _rule_null_deref(site: _CallSite, callee: _FuncFacts) -> list[dict]:
    """CWE476: NULL passed → dereferenced without null guard."""
    out = []
    for i, arg in enumerate(site.args):
        if arg is None or arg not in site.null_vars:
            continue
        if i >= len(callee.params):
            continue
        param = callee.params[i]
        if param in callee.dereffed_params and param not in callee.null_checked_params:
            out.append(_finding(site, callee, "cross-null-deref", arg, param,
                                f"set to NULL in caller, dereferenced in callee without null check."))
    return out


def _rule_null_from_alloc(site: _CallSite, callee: _FuncFacts) -> list[dict]:
    """CWE690: malloc return not null-checked in caller → dereferenced in callee without check."""
    out = []
    for i, arg in enumerate(site.args):
        if arg is None or arg not in site.unchecked_alloc_vars:
            continue
        if i >= len(callee.params):
            continue
        param = callee.params[i]
        if param in callee.dereffed_params and param not in callee.null_checked_params:
            out.append(_finding(site, callee, "cross-null-from-alloc", arg, param,
                                f"malloc() return not null-checked in caller; "
                                f"callee dereferences without guard."))
    return out


def _rule_alloc_mismatch(site: _CallSite, callee: _FuncFacts) -> list[dict]:
    """CWE762: allocated with X, freed with wrong Y."""
    out = []
    for i, arg in enumerate(site.args):
        if arg is None or arg not in site.alloc_vars:
            continue
        if i >= len(callee.params):
            continue
        param         = callee.params[i]
        alloc_func    = site.alloc_vars[arg]
        expected_free = _ALLOC_TO_FREE.get(alloc_func)
        actual_free   = callee.freed_params.get(param)
        if actual_free and expected_free and actual_free != expected_free:
            free_line = callee.freed_lines.get(param, callee.line)
            out.append({
                **_finding(site, callee, "cross-alloc-mismatch", arg, param,
                           f"allocated with {alloc_func}() but freed with {actual_free}() "
                           f"(expected {expected_free}())."),
                "line": free_line,
            })
    return out


def _rule_double_free(site: _CallSite, callee: _FuncFacts) -> list[dict]:
    """CWE415: var freed in caller, then freed again by callee."""
    out = []
    for i, arg in enumerate(site.args):
        if arg is None or arg not in site.freed_vars:
            continue
        if i >= len(callee.params):
            continue
        param = callee.params[i]
        if param in callee.freed_params:
            free_line = callee.freed_lines.get(param, callee.line)
            out.append({
                **_finding(site, callee, "cross-double-free", arg, param,
                           f"already freed in caller with {callee.freed_params[param]}(); "
                           f"callee frees it again."),
                "line": free_line,
            })
    return out


def _rule_mem_leak(site: _CallSite, callee: _FuncFacts) -> list[dict]:
    """CWE401: heap-allocated in caller, callee takes ownership but never frees."""
    out = []
    for i, arg in enumerate(site.args):
        if arg is None or arg not in site.alloc_vars:
            continue
        if i >= len(callee.params):
            continue
        param = callee.params[i]
        if param not in callee.freed_params:
            out.append(_finding(site, callee, "cross-mem-leak", arg, param,
                                f"heap-allocated with {site.alloc_vars[arg]}() in caller; "
                                f"callee never frees parameter '{param}'."))
    return out


def _rule_free_nonheap(site: _CallSite, callee: _FuncFacts) -> list[dict]:
    """CWE590: stack / alloca pointer freed in callee."""
    out = []
    for i, arg in enumerate(site.args):
        if arg is None or arg not in site.stack_vars:
            continue
        if i >= len(callee.params):
            continue
        param = callee.params[i]
        if param in callee.freed_params:
            free_line = callee.freed_lines.get(param, callee.line)
            out.append({
                **_finding(site, callee, "cross-free-nonheap", arg, param,
                           f"stack/alloca pointer freed with {callee.freed_params[param]}() "
                           f"in callee — undefined behaviour."),
                "line": free_line,
            })
    return out


def _rule_div_zero(site: _CallSite, callee: _FuncFacts) -> list[dict]:
    """CWE369: potentially-zero var used as divisor in callee without zero check."""
    out = []
    for i, arg in enumerate(site.args):
        if arg is None or arg not in site.zero_vars:
            continue
        if i >= len(callee.params):
            continue
        param = callee.params[i]
        if param in callee.div_params and param not in callee.zero_checked_params:
            out.append(_finding(site, callee, "cross-div-zero", arg, param,
                                f"value may be zero; callee divides by '{param}' "
                                f"without a zero check."))
    return out


def _rule_buf_overflow(site: _CallSite, callee: _FuncFacts) -> list[dict]:
    """CWE121/CWE122: large/tainted index used in callee's array without upper-bound check."""
    out = []
    suspect = site.large_index_vars | site.tainted_vars
    for i, arg in enumerate(site.args):
        if arg is None or arg not in suspect:
            continue
        if i >= len(callee.params):
            continue
        param = callee.params[i]
        if param in callee.array_index_params and param not in callee.upper_bound_checked_params:
            out.append(_finding(site, callee, "cross-buf-overflow", arg, param,
                                f"potentially out-of-bounds index '{arg}'; callee accesses "
                                f"array[{param}] without an upper-bound check."))
    return out


def _rule_int_overflow(site: _CallSite, callee: _FuncFacts) -> list[dict]:
    """CWE190: near-MAX or tainted value used in unchecked arithmetic in callee."""
    out = []
    suspect = site.max_int_vars | site.tainted_vars
    for i, arg in enumerate(site.args):
        if arg is None or arg not in suspect:
            continue
        if i >= len(callee.params):
            continue
        param = callee.params[i]
        if param in callee.arith_params and param not in callee.overflow_checked_params:
            out.append(_finding(site, callee, "cross-int-overflow", arg, param,
                                f"value may be near integer MAX; callee performs arithmetic "
                                f"on '{param}' without an overflow check."))
    return out


def _rule_int_underflow(site: _CallSite, callee: _FuncFacts) -> list[dict]:
    """CWE191: near-MIN or tainted value used in unchecked arithmetic in callee."""
    out = []
    suspect = site.min_int_vars | site.tainted_vars
    for i, arg in enumerate(site.args):
        if arg is None or arg not in suspect:
            continue
        if i >= len(callee.params):
            continue
        param = callee.params[i]
        if param in callee.arith_params and param not in callee.underflow_checked_params:
            out.append(_finding(site, callee, "cross-int-underflow", arg, param,
                                f"value may be near integer MIN; callee performs arithmetic "
                                f"on '{param}' without an underflow check."))
    return out


def _rule_format_string(site: _CallSite, callee: _FuncFacts) -> list[dict]:
    """CWE134: tainted string used as printf format string in callee."""
    out = []
    for i, arg in enumerate(site.args):
        if arg is None or arg not in site.tainted_vars:
            continue
        if i >= len(callee.params):
            continue
        param = callee.params[i]
        if param in callee.format_str_params:
            out.append(_finding(site, callee, "cross-format-string", arg, param,
                                f"tainted string '{arg}' used as format argument "
                                f"to printf-family in callee."))
    return out


# ── Pass 1: per-file analysis ─────────────────────────────────────────────────

def _analyse_file(
    src: Path, ast_root: dict
) -> tuple[list[_FuncFacts], list[_CallSite]]:
    func_facts: list[_FuncFacts] = []
    call_sites: list[_CallSite]  = []
    _collect_funcs(src, ast_root.get("inner", []), func_facts, call_sites)
    return func_facts, call_sites


_CONTAINER_KINDS = frozenset({
    "NamespaceDecl", "LinkageSpecDecl", "ExternCDecl", "TranslationUnitDecl",
})


def _collect_funcs(src, nodes, func_facts, call_sites):
    for node in nodes:
        if not isinstance(node, dict):
            continue
        kind = node.get("kind", "")
        if kind in _CONTAINER_KINDS:
            _collect_funcs(src, node.get("inner", []), func_facts, call_sites)
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
        facts  = _FuncFacts(
            name=node.get("name", "?"), file=src,
            line=_node_line(node), params=params,
        )

        analyser = _FuncBodyAnalyser(params, src)
        analyser.walk(body)

        facts.null_checked_params        = analyser.null_checked
        facts.dereffed_params            = analyser.dereffed
        facts.freed_params               = {v: fc for v, (fc, _) in analyser.freed.items()}
        facts.freed_lines                = {v: ln for v, (_, ln) in analyser.freed.items()}
        facts.div_params                 = analyser.div_params
        facts.zero_checked_params        = analyser.zero_checked
        facts.array_index_params         = analyser.array_index_params
        facts.upper_bound_checked_params = analyser.upper_bound_checked
        facts.arith_params               = analyser.arith_params
        facts.overflow_checked_params    = analyser.overflow_checked
        facts.underflow_checked_params   = analyser.underflow_checked
        facts.format_str_params          = analyser.format_str_params

        func_facts.append(facts)
        call_sites.extend(analyser.call_sites)


# ── Intra-procedural body analyser ────────────────────────────────────────────

class _FuncBodyAnalyser:
    """
    Sequential single-pass AST walker for one function body.

    Tracks caller-side variable states (for _CallSite) and callee-side
    vulnerability patterns (for _FuncFacts).
    """

    def __init__(self, params: list[str], src: Path) -> None:
        self.params     = set(params)
        self.src        = src

        # ── Caller-side variable state (snapshot at each call site) ──────────
        # Each dict maps var-name → state string
        self.var_state: dict[str, str | None] = {}
        # "null"       = explicitly set to NULL
        # <alloc_func> = allocated with malloc/calloc/etc.
        # None         = unknown / reassigned to something else

        self.zero_state:  dict[str, str] = {}
        # "zero"     = last concrete assignment is literal 0 / 0.0
        # "nonzero"  = last concrete assignment is a non-zero literal
        # "tainted"  = last assignment is from a function call or external input
        # (absent)   = never assigned in this scope

        self.freed_local:  set[str] = set()   # locally freed non-param vars
        self.stack_local:  set[str] = set()   # vars pointing to stack memory
        self.large_ints:   set[str] = set()   # vars with large literal values
        self.max_ints:     set[str] = set()   # vars assigned near-MAX values
        self.min_ints:     set[str] = set()   # vars assigned near-MIN / negative values
        self.tainted:      set[str] = set()   # vars from external input
        self.unchecked_alloc: set[str] = set()  # alloc'd but not yet null-checked

        # ── Callee-side facts (what this function does to parameters) ────────
        self.null_checked:   set[str]             = set()
        self.dereffed:       set[str]             = set()
        self.freed: dict[str, tuple[str, int]]    = {}

        self.div_params:          set[str] = set()
        self.zero_checked:        set[str] = set()
        self.array_index_params:  set[str] = set()
        self.upper_bound_checked: set[str] = set()
        self.arith_params:        set[str] = set()
        self.overflow_checked:    set[str] = set()
        self.underflow_checked:   set[str] = set()
        self.format_str_params:   set[str] = set()

        self.call_sites: list[_CallSite] = []

    # ── Walker ────────────────────────────────────────────────────────────────

    def walk(self, node: dict) -> None:
        if not isinstance(node, dict):
            return
        kind = node.get("kind", "")

        if kind == "VarDecl":
            self._on_vardecl(node)

        elif kind == "BinaryOperator":
            if node.get("opcode") == "=":
                self._on_assign(node)
            elif node.get("opcode") in ("/", "%"):
                self._on_div(node)
            elif node.get("opcode") in ("+", "-", "*"):
                self._on_arith(node)
            else:
                for ch in node.get("inner", []):
                    self.walk(ch)

        elif kind == "IfStmt":
            self._on_if(node)

        elif kind == "WhileStmt":
            self._on_while(node)

        elif kind == "CallExpr":
            self._on_call(node)

        elif kind == "UnaryOperator" and node.get("opcode") == "*":
            self._on_deref_unary(node)

        elif kind == "MemberExpr" and node.get("isArrow"):
            inner = node.get("inner", [])
            if inner:
                name = _decl_ref_name(inner[0])
                if name and name in self.params:
                    self.dereffed.add(name)

        elif kind == "ArraySubscriptExpr":
            self._on_array_subscript(node)

        elif kind == "CXXDeleteExpr":
            is_array  = node.get("isArray", False)
            free_func = "delete[]" if is_array else "delete"
            inner = node.get("inner", [])
            if inner:
                name = _decl_ref_name(inner[0])
                if name:
                    if name in self.params:
                        self.freed[name] = (free_func, _node_line(node))
                    else:
                        self.freed_local.add(name)
            for ch in inner:
                self.walk(ch)

        else:
            for ch in node.get("inner", []):
                self.walk(ch)

    # ── Event handlers ────────────────────────────────────────────────────────

    def _on_vardecl(self, node: dict) -> None:
        name = node.get("name")
        if not name:
            for ch in node.get("inner", []):
                self.walk(ch)
            return
        init_nodes = node.get("inner", [])

        # Pointer / heap state
        if _is_null_init(init_nodes):
            self.var_state[name] = "null"
        else:
            alloc = _find_alloc_call(init_nodes)
            if alloc:
                self.var_state[name] = alloc
                self.unchecked_alloc.add(name)
            else:
                self.var_state[name] = None

        # Stack detection
        if _is_stack_ptr(init_nodes):
            self.stack_local.add(name)

        # Zero / numeric state
        lit = _literal_value(init_nodes)
        if lit is not None:
            self._update_zero_state(name, lit)
            self._update_int_category(name, lit)
        elif _is_tainted_init(init_nodes):
            self.zero_state[name]  = "tainted"
            self.tainted.add(name)
            self.large_ints.add(name)
            self.max_ints.add(name)
            self.min_ints.add(name)

        for ch in init_nodes:
            self.walk(ch)

    def _on_assign(self, node: dict) -> None:
        inner = node.get("inner", [])
        if len(inner) < 2:
            return
        lhs_name = _decl_ref_name(inner[0])
        rhs      = [inner[1]]

        if not lhs_name:
            for ch in inner:
                self.walk(ch)
            return

        # -- Pointer state --
        if _is_null_init(rhs):
            self.var_state[lhs_name] = "null"
            self.unchecked_alloc.discard(lhs_name)
        else:
            alloc = _find_alloc_call(rhs)
            if alloc:
                self.var_state[lhs_name] = alloc
                self.unchecked_alloc.add(lhs_name)
            elif _is_stack_ptr(rhs):
                self.var_state[lhs_name] = None
                self.stack_local.add(lhs_name)
                self.unchecked_alloc.discard(lhs_name)
            else:
                self.var_state[lhs_name] = None
                self.unchecked_alloc.discard(lhs_name)

        # -- Zero / numeric state --
        lit = _literal_value(rhs)
        if lit is not None:
            self._update_zero_state(lhs_name, lit)
            self._update_int_category(lhs_name, lit)
            self.tainted.discard(lhs_name)
        elif _is_tainted_init(rhs):
            self.zero_state[lhs_name]  = "tainted"
            self.tainted.add(lhs_name)
            self.large_ints.add(lhs_name)
            self.max_ints.add(lhs_name)
            self.min_ints.add(lhs_name)
        else:
            # Unknown expression: conservatively mark as potentially zero / tainted
            self.zero_state[lhs_name] = "tainted"
            self.tainted.discard(lhs_name)   # unknown ≠ external input

        for ch in inner:
            self.walk(ch)

    def _update_zero_state(self, name: str, value: float) -> None:
        if value == 0.0:
            self.zero_state[name] = "zero"
        else:
            self.zero_state[name] = "nonzero"
            self.large_ints.discard(name)
            self.max_ints.discard(name)
            self.min_ints.discard(name)
            self.tainted.discard(name)

    def _update_int_category(self, name: str, value: float) -> None:
        # Detect near-MAX: large positive values (heuristic threshold)
        if value >= 100:
            self.large_ints.add(name)
            self.max_ints.add(name)
        elif value < 0:
            self.min_ints.add(name)
        else:
            self.large_ints.discard(name)
            self.max_ints.discard(name)
            self.min_ints.discard(name)

    def _on_if(self, node: dict) -> None:
        inner = node.get("inner", [])
        if not inner:
            return
        cond = inner[0]

        # Null checks (for CWE476/690)
        for v in _null_check_vars(cond):
            if v in self.params:
                self.null_checked.add(v)
            self.unchecked_alloc.discard(v)  # caller null-checked this alloc

        # Zero checks (for CWE369 callee)
        for v in _zero_check_vars(cond):
            if v in self.params:
                self.zero_checked.add(v)

        # Bounds checks (for CWE121/122 callee)
        lower, upper = _bounds_check_vars(cond)
        for v in upper:
            if v in self.params:
                if v in self.array_index_params:
                    self.upper_bound_checked.add(v)

        # Overflow / underflow checks (for CWE190/191 callee)
        for v in _overflow_check_vars(cond):
            if v in self.params:
                self.overflow_checked.add(v)
        for v in _underflow_check_vars(cond):
            if v in self.params:
                self.underflow_checked.add(v)

        for ch in inner[1:]:
            self.walk(ch)

    def _on_while(self, node: dict) -> None:
        inner = node.get("inner", [])
        if not inner:
            return
        cond = inner[0]
        for v in _null_check_vars(cond):
            if v in self.params:
                self.null_checked.add(v)
        for v in _zero_check_vars(cond):
            if v in self.params:
                self.zero_checked.add(v)
        for ch in inner[1:]:
            self.walk(ch)

    def _on_div(self, node: dict) -> None:
        """Handle BinaryOperator '/' or '%'  → callee-side: divisor param detection."""
        inner = node.get("inner", [])
        if len(inner) >= 2:
            divisor_name = _decl_ref_name(inner[1])
            if divisor_name and divisor_name in self.params:
                self.div_params.add(divisor_name)
        for ch in inner:
            self.walk(ch)

    def _on_arith(self, node: dict) -> None:
        """Handle BinaryOperator '+'/'-'/'*'  → callee-side: arithmetic param detection."""
        inner = node.get("inner", [])
        for ch in inner:
            n = _decl_ref_name(ch)
            if n and n in self.params:
                self.arith_params.add(n)
            self.walk(ch)

    def _on_array_subscript(self, node: dict) -> None:
        """Handle arr[index]  → callee-side: array index param detection."""
        inner = node.get("inner", [])
        if len(inner) >= 2:
            idx_name = _decl_ref_name(inner[1])
            if idx_name and idx_name in self.params:
                self.array_index_params.add(idx_name)
        # Also: arr[param] where arr itself is a param (ptr dereference)
        if inner:
            arr_name = _decl_ref_name(inner[0])
            if arr_name and arr_name in self.params:
                self.dereffed.add(arr_name)
        for ch in inner:
            self.walk(ch)

    def _on_call(self, node: dict) -> None:
        callee = _callee_name(node)
        if not callee:
            return
        line  = _node_line(node)
        inner = node.get("inner", [])
        args  = _arg_names(node)

        # Scan arguments for embedded dereferences
        for arg_node in inner[1:]:
            self._find_derefs(arg_node)

        # CWE415: track locally freed non-param variables
        if callee in _ALL_FREE_FUNCS:
            for arg in args:
                if arg:
                    if arg in self.params:
                        self.freed[arg] = (callee, line)
                    else:
                        self.freed_local.add(arg)
            return

        if callee in _STACK_ALLOC_FUNCS:
            # alloca result – caller handles assignment separately via _on_assign
            return

        # CWE690: unsafe pointer functions on params → treat as dereference
        if callee in _UNSAFE_PTR_FUNCS:
            for arg in args:
                if arg and arg in self.params:
                    self.dereffed.add(arg)

        # CWE134: detect format-string param position in callee
        fmt_pos = _PRINTF_FORMAT_POS.get(callee)
        if fmt_pos is not None and fmt_pos < len(args):
            fmt_arg = args[fmt_pos]
            if fmt_arg and fmt_arg in self.params:
                self.format_str_params.add(fmt_arg)

        # CWE134 / CWE369 / CWE121: tainted input: certain functions write into args
        if callee in _TAINTED_ARG0_FUNCS and args:
            # fgets(buf, n, stream) → buf is tainted
            if args[0]:
                self._mark_tainted(args[0])

        if callee in _TAINTED_SCANF_FUNCS:
            # fscanf(stream, fmt, &var, ...) → vars from arg 2 are tainted
            for arg in args[2:]:
                if arg:
                    self._mark_tainted(arg)

        if callee in _RECV_WRITE_FUNCS:
            # recv(sock, buf, len, flags) → buf arg (position 1) is tainted
            # buf may be a pointer-arithmetic expr like (char*)(data + offset),
            # so extract ALL referenced variable names from the raw AST arg node.
            if len(inner) > 2:
                buf_arg_node = inner[2]  # inner[0]=callee, inner[1]=arg0, inner[2]=arg1
                for name in _all_decl_ref_names(buf_arg_node):
                    self._mark_tainted(name)

        if callee in _TAINTED_INPLACE_FUNCS:
            # RAND32()/rand() — result returned via assignment, handled elsewhere.
            # But if any arg is passed by pointer to random-like functions, taint it.
            for arg in args:
                if arg:
                    self._mark_tainted(arg)

        if callee in _ALL_ALLOC_FUNCS:
            return

        # Record outgoing call site snapshot
        self.call_sites.append(_CallSite(
            caller_file  = self.src,
            callee_name  = callee,
            args         = args,
            line         = line,
            null_vars    = {v for v, s in self.var_state.items() if s == "null"},
            alloc_vars   = {v: s for v, s in self.var_state.items()
                            if s and s != "null"},
            unchecked_alloc_vars = set(self.unchecked_alloc),
            freed_vars   = set(self.freed_local),
            stack_vars   = set(self.stack_local),
            zero_vars    = {v for v, s in self.zero_state.items()
                            if s in ("zero", "tainted")},
            large_index_vars = set(self.large_ints),
            max_int_vars = set(self.max_ints),
            min_int_vars = set(self.min_ints),
            tainted_vars = set(self.tainted),
        ))

    def _mark_tainted(self, name: str) -> None:
        self.tainted.add(name)
        self.zero_state[name]  = "tainted"
        self.large_ints.add(name)
        self.max_ints.add(name)
        self.min_ints.add(name)

    def _on_deref_unary(self, node: dict) -> None:
        inner = node.get("inner", [])
        if inner:
            name = _decl_ref_name(inner[0])
            if name and name in self.params:
                self.dereffed.add(name)

    def _find_derefs(self, node: dict) -> None:
        if not isinstance(node, dict):
            return
        kind  = node.get("kind", "")
        inner = node.get("inner", [])

        if kind == "UnaryOperator" and node.get("opcode") == "*":
            name = _decl_ref_name(inner[0]) if inner else None
            if name and name in self.params:
                self.dereffed.add(name)
            for ch in inner:
                self._find_derefs(ch)

        elif kind == "MemberExpr" and node.get("isArrow"):
            name = _decl_ref_name(inner[0]) if inner else None
            if name and name in self.params:
                self.dereffed.add(name)

        elif kind == "ArraySubscriptExpr":
            name = _decl_ref_name(inner[0]) if inner else None
            if name and name in self.params:
                self.dereffed.add(name)
            for ch in inner:
                self._find_derefs(ch)

        else:
            for ch in inner:
                self._find_derefs(ch)


# ── AST predicate helpers ─────────────────────────────────────────────────────

def _is_null_init(nodes: list[dict]) -> bool:
    return any(_is_null_node(n) for n in nodes)


def _is_null_node(node: dict) -> bool:
    if not isinstance(node, dict):
        return False
    kind = node.get("kind", "")
    if kind == "CXXNullPtrLiteralExpr":
        return True
    if kind == "ImplicitCastExpr" and node.get("castKind") == "NullToPointer":
        return True
    if kind in ("ImplicitCastExpr", "CStyleCastExpr", "ParenExpr"):
        return any(_is_null_node(ch) for ch in node.get("inner", []))
    return False


def _is_stack_ptr(nodes: list[dict]) -> bool:
    """True if the expression decays a local array or takes address of a local."""
    def _check(n: dict) -> bool:
        if not isinstance(n, dict):
            return False
        kind = n.get("kind", "")
        if kind == "ImplicitCastExpr" and n.get("castKind") == "ArrayToPointerDecay":
            return True
        if kind == "UnaryOperator" and n.get("opcode") == "&":
            return True
        return any(_check(ch) for ch in n.get("inner", []))
    return any(_check(n) for n in nodes)


def _literal_value(nodes: list[dict]) -> float | None:
    """Extract numeric value if the expression subtree is a single literal."""
    def _get(n: dict) -> float | None:
        if not isinstance(n, dict):
            return None
        kind = n.get("kind", "")
        if kind == "IntegerLiteral":
            try:
                return float(n["value"])
            except (KeyError, ValueError):
                return None
        if kind == "FloatingLiteral":
            try:
                return float(n["value"])
            except (KeyError, ValueError):
                return None
        if kind in ("ImplicitCastExpr", "CStyleCastExpr", "ParenExpr",
                    "CXXStaticCastExpr", "CXXFunctionalCastExpr"):
            for ch in n.get("inner", []):
                v = _get(ch)
                if v is not None:
                    return v
        if kind == "UnaryOperator" and n.get("opcode") == "-":
            for ch in n.get("inner", []):
                v = _get(ch)
                if v is not None:
                    return -v
        return None
    for n in nodes:
        v = _get(n)
        if v is not None:
            return v
    return None


def _is_tainted_init(nodes: list[dict]) -> bool:
    """True if the RHS calls a known random/external-input function that returns a value."""
    _all_taint = _TAINTED_INPLACE_FUNCS | _TAINTED_ARG0_FUNCS | _TAINTED_SCANF_FUNCS
    def _check(n: dict) -> bool:
        if not isinstance(n, dict):
            return False
        if n.get("kind") == "CallExpr":
            name = _callee_name(n)
            if name and name in _all_taint:
                return True
        return any(_check(ch) for ch in n.get("inner", []))
    return any(_check(n) for n in nodes)


def _find_alloc_call(nodes: list[dict]) -> str | None:
    for n in nodes:
        r = _find_alloc_deep(n)
        if r:
            return r
    return None


def _find_alloc_deep(node: dict) -> str | None:
    if not isinstance(node, dict):
        return None
    kind = node.get("kind", "")
    if kind == "CallExpr":
        name = _callee_name(node)
        if name in _ALL_ALLOC_FUNCS:
            return name
    elif kind == "CXXNewExpr":
        return "new[]" if node.get("isArray") else "new"
    for ch in node.get("inner", []):
        r = _find_alloc_deep(ch)
        if r:
            return r
    return None


def _null_check_vars(node: dict) -> set[str]:
    """Vars null-tested in a condition: x != NULL, !x, if(x)."""
    if not isinstance(node, dict):
        return set()
    kind   = node.get("kind", "")
    result: set[str] = set()

    if kind == "BinaryOperator":
        opcode = node.get("opcode", "")
        inner  = node.get("inner", [])
        if opcode in ("!=", "==") and len(inner) == 2:
            lhs, rhs = inner
            if _is_null_node(rhs):
                name = _decl_ref_name(lhs)
                if name:
                    result.add(name)
            elif _is_null_node(lhs):
                name = _decl_ref_name(rhs)
                if name:
                    result.add(name)
        for ch in inner:
            result |= _null_check_vars(ch)

    elif kind == "UnaryOperator" and node.get("opcode") == "!":
        inner = node.get("inner", [])
        if inner:
            name = _decl_ref_name(inner[0])
            if name:
                result.add(name)

    elif kind in ("ImplicitCastExpr", "ParenExpr"):
        inner = node.get("inner", [])
        if inner:
            name = _decl_ref_name(inner[0])
            if name:
                result.add(name)
        for ch in inner:
            result |= _null_check_vars(ch)

    elif kind in ("BinaryConditionalOperator", "ConditionalOperator"):
        for ch in node.get("inner", []):
            result |= _null_check_vars(ch)

    return result


def _zero_check_vars(node: dict) -> set[str]:
    """Vars zero-tested in a condition: x != 0, x > 0, fabs(x) > eps."""
    if not isinstance(node, dict):
        return set()
    kind   = node.get("kind", "")
    result: set[str] = set()

    if kind == "BinaryOperator":
        opcode = node.get("opcode", "")
        inner  = node.get("inner", [])
        if opcode in ("!=", "==", ">", "<", ">=", "<=") and len(inner) == 2:
            lhs, rhs = inner
            if _literal_value([rhs]) == 0.0:
                name = _decl_ref_name(lhs)
                if name:
                    result.add(name)
                # Also check if lhs is fabs(param)
                result |= _extract_fabs_arg(lhs)
            elif _literal_value([lhs]) == 0.0:
                name = _decl_ref_name(rhs)
                if name:
                    result.add(name)
        for ch in inner:
            result |= _zero_check_vars(ch)

    elif kind in ("ImplicitCastExpr", "ParenExpr"):
        for ch in node.get("inner", []):
            result |= _zero_check_vars(ch)

    return result


def _extract_fabs_arg(node: dict) -> set[str]:
    """If node is fabs(x)/fabsf(x)/abs(x) → return {x}."""
    if not isinstance(node, dict):
        return set()
    if node.get("kind") == "CallExpr":
        name = _callee_name(node)
        if name in ("fabs", "fabsf", "fabsl", "abs"):
            inner = node.get("inner", [])
            if len(inner) >= 2:
                arg_name = _decl_ref_name(inner[1])
                if arg_name:
                    return {arg_name}
    for ch in node.get("inner", []):
        r = _extract_fabs_arg(ch)
        if r:
            return r
    return set()


def _bounds_check_vars(node: dict) -> tuple[set[str], set[str]]:
    """
    Parse an if-condition for array-index bounds checks.
    Returns (lower_checked, upper_checked) sets of var names.
    lower = param >= 0
    upper = param < N  (upper bound)
    """
    lower: set[str] = set()
    upper: set[str] = set()
    _collect_bounds(node, lower, upper)
    return lower, upper


def _collect_bounds(node: dict, lower: set[str], upper: set[str]) -> None:
    if not isinstance(node, dict):
        return
    kind = node.get("kind", "")
    inner = node.get("inner", [])

    if kind == "BinaryOperator":
        opcode = node.get("opcode", "")
        if opcode == "&&":
            for ch in inner:
                _collect_bounds(ch, lower, upper)
        elif opcode in (">=", ">") and len(inner) == 2:
            # param >= 0  or  param > -1
            lhs_name = _decl_ref_name(inner[0])
            rhs_val  = _literal_value([inner[1]])
            if lhs_name and rhs_val is not None and rhs_val <= 0:
                lower.add(lhs_name)
        elif opcode in ("<", "<=") and len(inner) == 2:
            # param < N  (upper bound check)
            lhs_name = _decl_ref_name(inner[0])
            if lhs_name:
                upper.add(lhs_name)
            # Also handle: N > param
            rhs_name = _decl_ref_name(inner[1])
            if rhs_name:
                upper.add(rhs_name)
    else:
        for ch in inner:
            _collect_bounds(ch, lower, upper)


def _overflow_check_vars(node: dict) -> set[str]:
    """Params checked for overflow: param < MAX or MAX > param."""
    result: set[str] = set()
    _collect_overflow_checks(node, result, "overflow")
    return result


def _underflow_check_vars(node: dict) -> set[str]:
    """Params checked for underflow: param > MIN or MIN < param."""
    result: set[str] = set()
    _collect_overflow_checks(node, result, "underflow")
    return result


_COMPARISON_OPS = frozenset({"<", "<=", ">", ">="})
_ABS_FUNCS      = frozenset({"abs", "fabs", "fabsf", "llabs", "labs"})


def _abs_arg_names(node: dict) -> set[str]:
    """Return param names that are the direct argument to an abs/fabs call in *node*."""
    result: set[str] = set()
    if not isinstance(node, dict):
        return result
    kind = node.get("kind", "")
    if kind in ("ImplicitCastExpr", "CStyleCastExpr"):
        return _abs_arg_names(node.get("inner", [{}])[0])
    if kind == "CallExpr":
        inner = node.get("inner", [])
        callee_node = inner[0] if inner else {}
        callee_nm   = _decl_ref_name(callee_node)
        if not callee_nm:
            # callee might be wrapped in ImplicitCastExpr
            for sub in callee_node.get("inner", []):
                callee_nm = _decl_ref_name(sub) or callee_nm
        if callee_nm in _ABS_FUNCS and len(inner) >= 2:
            result |= _all_decl_ref_names(inner[1])
    for ch in node.get("inner", []):
        result |= _abs_arg_names(ch)
    return result


def _collect_overflow_checks(node: dict, result: set[str], kind_: str) -> None:
    if not isinstance(node, dict):
        return
    kind  = node.get("kind", "")
    inner = node.get("inner", [])

    if kind == "BinaryOperator":
        opcode = node.get("opcode", "")
        if opcode == "&&":
            for ch in inner:
                _collect_overflow_checks(ch, result, kind_)
            return

        if opcode in _COMPARISON_OPS and len(inner) == 2:
            lhs_val  = _literal_value([inner[0]])
            rhs_val  = _literal_value([inner[1]])
            lhs_name = _decl_ref_name(inner[0])
            rhs_name = _decl_ref_name(inner[1])

            if kind_ == "overflow":
                # Simple: param < BIG_NUMBER  or  BIG_NUMBER > param
                if opcode == "<" and rhs_val is not None and rhs_val >= 100 and lhs_name:
                    result.add(lhs_name)
                elif opcode == ">" and lhs_val is not None and lhs_val >= 100 and rhs_name:
                    result.add(rhs_name)
                # General upper-bound: any < or <= operator involving param anywhere.
                # Handles e.g. abs(param) <= sqrt(CHAR_MAX) where param is wrapped.
                # Only upper-bound ops: `data > 0` is a lower-bound guard, not overflow check.
                elif opcode in ("<", "<="):
                    for operand in inner:
                        for name in _all_decl_ref_names(operand):
                            result.add(name)
            else:  # underflow
                # Simple: param > SMALL_NEGATIVE  or  SMALL_NEGATIVE < param
                if opcode == ">" and rhs_val is not None and rhs_val <= 0 and lhs_name:
                    result.add(lhs_name)
                elif opcode == "<" and lhs_val is not None and lhs_val <= 0 and rhs_name:
                    result.add(rhs_name)
                # abs(param) <= N  — absolute-value bound checks both directions.
                elif opcode in ("<", "<="):
                    abs_names = _abs_arg_names(inner[0]) | _abs_arg_names(inner[1])
                    result |= abs_names
                # General lower-bound: any > or >= operator involving param.
                elif opcode in (">", ">="):
                    for operand in inner:
                        for name in _all_decl_ref_names(operand):
                            result.add(name)

        for ch in inner:
            _collect_overflow_checks(ch, result, kind_)
    else:
        for ch in inner:
            _collect_overflow_checks(ch, result, kind_)


# ── AST structural helpers ────────────────────────────────────────────────────

def _extract_params(func_node: dict) -> list[str]:
    return [
        ch.get("name", "")
        for ch in func_node.get("inner", [])
        if ch.get("kind") == "ParmVarDecl" and ch.get("name")
    ]


def _find_compound_body(func_node: dict) -> dict | None:
    for ch in func_node.get("inner", []):
        if ch.get("kind") == "CompoundStmt":
            return ch
    return None


def _loc_file(node: dict) -> str | None:
    loc = node.get("loc", {})
    if "file" in loc:
        return loc["file"]
    exp = loc.get("expansionLoc", {})
    if "file" in exp:
        return exp["file"]
    return None


def _paths_match(loc_file: str, src: Path) -> bool:
    lp = Path(loc_file)
    if lp.is_absolute():
        try:
            return lp.resolve() == src.resolve()
        except OSError:
            pass
    return lp.name == src.name


def _node_line(node: dict) -> int:
    loc = node.get("loc") or node.get("range", {}).get("begin", {})
    return loc.get("line", 0)


def _callee_name(call_node: dict) -> str | None:
    inner = call_node.get("inner", [])
    return _decl_ref_name(inner[0]) if inner else None


def _arg_names(call_node: dict) -> list[str | None]:
    inner = call_node.get("inner", [])
    return [_decl_ref_name(a) for a in inner[1:]]


def _all_decl_ref_names(node: dict) -> set[str]:
    """Return ALL variable names referenced anywhere in the AST subtree."""
    if not isinstance(node, dict):
        return set()
    result: set[str] = set()
    if node.get("kind") == "DeclRefExpr":
        name = _decl_ref_name(node)
        if name:
            result.add(name)
    else:
        for ch in node.get("inner", []):
            result |= _all_decl_ref_names(ch)
    return result


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
        for ch in node.get("inner", []):
            name = _decl_ref_name(ch)
            if name:
                return name
    return None


# ── Subprocess / filesystem ───────────────────────────────────────────────────

def _resolve_clang() -> str:
    import platform, os
    candidates: list[str] = ["clang", "clang++", "clang-cl"]
    if platform.system() == "Windows":
        llvm_bin = Path(os.environ.get("LLVM_DIR", r"C:\Program Files\LLVM")) / "bin"
        candidates = [
            str(llvm_bin / "clang++.exe"),
            str(llvm_bin / "clang.exe"),
            str(llvm_bin / "clang-cl.exe"),
        ] + candidates
    for candidate in candidates:
        try:
            r = subprocess.run(
                [candidate, "--version"],
                capture_output=True, check=False,
                encoding="utf-8", errors="replace",
                timeout=10,
            )
            if r.returncode == 0:
                return candidate
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    raise StaticAnalysisToolUnavailable(
        "Clang is not installed or not available in PATH. "
        "On Windows, install LLVM from https://releases.llvm.org/ or set LLVM_DIR."
    )


def _iter_sources(project_path: Path) -> list[Path]:
    if project_path.is_file():
        return (
            [project_path]
            if project_path.suffix.lower() in _SOURCE_EXTENSIONS
            else []
        )
    return [
        p for p in project_path.rglob("*")
        if p.is_file() and p.suffix.lower() in _SOURCE_EXTENSIONS
    ]
