"""Map detector rule IDs to CWE numbers and coarse vulnerability categories.

Detectors disagree on exact CWE numbers for the same bug (cppcheck says
"doubleFree", clang says "unix.Malloc: Attempt to free released memory",
an LLM might say CWE-415 or CWE-416). Fusion therefore aligns findings on a
*category* (memory-free, null, bounds, ...) rather than on the exact CWE.

Rules that map to no CWE are code-quality findings (style, dead stores,
casts). They are still reported, but never counted as vulnerabilities and
never sent to the LLM for review.
"""

from __future__ import annotations

import re

# CWE → fusion category.
_CATEGORY_OF_CWE: dict[str, str] = {}
for _category, _cwes in {
    "bounds": (119, 120, 121, 122, 124, 125, 126, 127, 129, 131, 193, 787, 788, 805, 806),
    "integer": (190, 191, 680),
    "div-zero": (369,),
    "format-string": (134,),
    "leak": (401, 772, 775),
    "memory-free": (415, 416, 590, 761, 762, 763, 562),
    "null": (476, 690),
    "uninit": (457, 908),
}.items():
    for _cwe in _cwes:
        _CATEGORY_OF_CWE[f"CWE-{_cwe}"] = _category

_CPPCHECK: dict[str, str] = {
    "nullPointer": "CWE-476", "nullPointerRedundantCheck": "CWE-476", "ctunullpointer": "CWE-476",
    "nullPointerArithmetic": "CWE-476",
    "doubleFree": "CWE-415", "deallocDealloc": "CWE-415",
    "deallocuse": "CWE-416", "useAfterFree": "CWE-416", "invalidLifetime": "CWE-562",
    "memleak": "CWE-401", "memleakOnRealloc": "CWE-401", "leakReturnValNotUsed": "CWE-401",
    "resourceLeak": "CWE-775", "leakNoVarFunctionCall": "CWE-401",
    "mismatchAllocDealloc": "CWE-762",
    "autovarInvalidDeallocation": "CWE-590", "invalidFree": "CWE-590",
    "arrayIndexOutOfBounds": "CWE-787", "arrayIndexOutOfBoundsCond": "CWE-787",
    "bufferAccessOutOfBounds": "CWE-787", "outOfBounds": "CWE-787", "negativeIndex": "CWE-787",
    "ctuArrayIndex": "CWE-787", "pointerOutOfBounds": "CWE-787", "arrayIndexThenCheck": "CWE-129",
    "insecureCmdLineArgs": "CWE-120", "bufferNotZeroTerminated": "CWE-170",
    "zerodiv": "CWE-369", "zerodivcond": "CWE-369",
    "integerOverflow": "CWE-190", "integerOverflowCond": "CWE-190",
    "uninitvar": "CWE-457", "uninitdata": "CWE-457",
}

_CROSS_FILE: dict[str, str] = {
    "cross-buf-overflow": "CWE-787", "cross-div-zero": "CWE-369", "cross-double-free": "CWE-415",
    "cross-format-string": "CWE-134", "cross-int-overflow": "CWE-190",
    "cross-int-underflow": "CWE-191", "cross-mem-leak": "CWE-401",
    "cross-null-deref": "CWE-476", "cross-null-from-alloc": "CWE-690",
}

# clang checker → CWE, refined by message where one checker covers several bugs.
_CLANG_CHECKER: dict[str, str] = {
    "core.NullDereference": "CWE-476", "core.DivideZero": "CWE-369",
    "unix.MismatchedDeallocator": "CWE-762", "cplusplus.NewDeleteLeaks": "CWE-401",
    "cplusplus.PlacementNew": "CWE-787", "unix.MallocSizeof": "CWE-131",
    "security.ArrayBound": "CWE-787", "alpha.security.ArrayBoundV2": "CWE-787",
    "alpha.security.ArrayBound": "CWE-787", "core.uninitialized.Assign": "CWE-457",
    "core.uninitialized.Branch": "CWE-457", "core.CallAndMessage": "CWE-457",
    "unix.cstring.BadSizeArg": "CWE-131", "alpha.unix.cstring.OutOfBounds": "CWE-787",
    "-Wformat-security": "CWE-134", "-Wformat-nonliteral": "CWE-134",
}
_MEMORY_MESSAGES: tuple[tuple[str, str], ...] = (
    (r"free released memory|released memory twice|double free|double delete", "CWE-415"),
    (r"after it is (freed|released)|use of memory after", "CWE-416"),
    (r"address of the local|not allocated by malloc|non-heap|address of a|static variable"
     r"|should not be deallocated|not memory allocated", "CWE-590"),
    (r"leak", "CWE-401"),
    (r"deallocat.*(allocated by|mismatch)|should be deallocated by", "CWE-762"),
)
_CLANG_TAG = re.compile(r"\[([\w.\-]+)\]\s*$")
_CWE_TEXT = re.compile(r"CWE[-_ ]?(\d+)", re.IGNORECASE)


def normalize(cwe: str | None) -> str | None:
    """'cwe_415', 'CWE 415', '415' → 'CWE-415'."""
    if not cwe:
        return None
    match = _CWE_TEXT.search(str(cwe)) or re.fullmatch(r"\s*(\d+)\s*", str(cwe))
    return f"CWE-{int(match.group(1))}" if match else None


def category(cwe: str | None) -> str | None:
    return _CATEGORY_OF_CWE.get(normalize(cwe) or "")


def classify(finding: dict) -> str | None:
    """Return the CWE for a detector finding, or None for code-quality findings."""
    explicit = normalize(finding.get("cwe"))
    if explicit:
        return explicit
    tool = str(finding.get("tool") or "")
    rule = str(finding.get("rule_id") or "")
    message = str(finding.get("message") or "")
    if tool == "cppcheck":
        return _CPPCHECK.get(rule)
    if rule in _CROSS_FILE:
        return _CROSS_FILE[rule]
    if tool == "clang":
        tag = _CLANG_TAG.search(message)
        checker = tag.group(1) if tag else rule
        if checker in ("unix.Malloc", "cplusplus.NewDelete"):
            lowered = message.lower()
            return next((cwe for pattern, cwe in _MEMORY_MESSAGES if re.search(pattern, lowered)), None)
        return _CLANG_CHECKER.get(checker)
    return normalize(message) if tool.startswith("llm") else None
