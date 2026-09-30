"""Strip Juliet's built-in answer key before a model sees the code.

Juliet source gives the ground truth away in plain text:

* comments such as ``/* POTENTIAL FLAW: ... */`` and ``/* FIX: ... */``
* function / variable names: ``badSink``, ``goodG2BSink``, ``bad()``, ``goodB2G``
* file and namespace names that spell out the CWE: ``CWE415_Double_Free__...``
* the ``OMITBAD`` / ``OMITGOOD`` guards around each variant

An LLM detector that reads those is grading itself from the label. The
sanitized copy keeps behaviour and line numbers identical (so the original
OMITBAD/OMITGOOD labels still score it) but removes every one of those hints:
comments are blanked, identifiers containing bad/good/CWE are renamed to
stable hashes, the guards get neutral names, and files are renamed and
flattened into one folder.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from pathlib import Path

from app.tools.code_index import blank_comments_and_strings
from eval.juliet import JulietCase

_LEAKY_IDENT = re.compile(r"\b(?:\w*(?:[Bb]ad|[Gg]ood)\w*|\w*CWE\d+\w*)\b")
# String literals Juliet uses only in the patched variants.
_LEAKY_TEXT = {"fixedstringtest": "constinputtext", "Benign, fixed string": "Constant string"}
_GUARDS = {"OMITBAD": "SECTION_ALPHA", "OMITGOOD": "SECTION_BETA", "INCLUDEMAIN": "INCLUDEMAIN"}


def _alias(identifier: str) -> str:
    if identifier in _GUARDS:
        return _GUARDS[identifier]
    return f"fn_{int(hashlib.sha1(identifier.encode()).hexdigest(), 16) % 10**8:08d}"


def sanitize_source(text: str) -> str:
    """Blank comments and rename leaky identifiers (including inside string
    literals, e.g. printLine("Calling bad()...")), preserving line structure."""
    stripped = blank_comments_and_strings(text, keep_strings=True)
    for guard, neutral in _GUARDS.items():
        stripped = re.sub(rf"\b{guard}\b", neutral, stripped)
    for leaky, neutral in _LEAKY_TEXT.items():
        stripped = stripped.replace(leaky, neutral)
    renamed = _LEAKY_IDENT.sub(lambda m: _alias(m.group(0)), stripped)
    return "\n".join(line.rstrip() for line in renamed.split("\n"))


def sanitize_dataset(cases: list[JulietCase], dataset: Path, out_dir: Path) -> dict[str, str]:
    """Write sanitized copies of every case file into ``out_dir/src`` and copy
    ``dataset/testcasesupport`` alongside. Returns {sanitized file name:
    original file name} for scoring."""
    src = out_dir / "src"
    src.mkdir(parents=True, exist_ok=True)
    mapping: dict[str, str] = {}
    for number, case in enumerate(sorted(cases, key=lambda c: c.case_id), start=1):
        for path in sorted(case.files):
            suffix = re.search(r"_\d{2}([a-z]?)$", path.stem)
            part = suffix.group(1) if suffix and suffix.group(1) else "x"
            new_name = f"t{number:03d}{part}{path.suffix}"
            text = path.read_text(encoding="utf-8", errors="replace")
            (src / new_name).write_text(sanitize_source(text), encoding="utf-8")
            mapping[new_name] = path.name
    support = dataset / "testcasesupport"
    if support.is_dir():
        shutil.copytree(support, out_dir / "testcasesupport", dirs_exist_ok=True)
    (out_dir / "name_map.json").write_text(json.dumps(mapping, indent=2), encoding="utf-8")
    return mapping
