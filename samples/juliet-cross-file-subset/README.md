# Juliet Cross-File Test Subset

120 test cases (10 per CWE, 12 CWEs) pulled from the [Juliet Test Suite for
C/C++ v1.3](https://samate.nist.gov/SARD/test-suites/112) (NIST SARD),
via the [arichardson/juliet-test-suite-c](https://github.com/arichardson/juliet-test-suite-c)
GitHub mirror.

## Why these specific cases

Every case here is the **`51a`/`51b` flow variant**: the vulnerable
source and the sink are split across two files (`_51a` defines the
entry point and calls into `_51b`, or vice versa). This makes the set
useful specifically for exercising this project's cross-file analysis —
[`cross_file_checker.py`](../../backend/app/tools/cross_file_checker.py),
[`clang_custom_checker.py`](../../backend/app/tools/clang_custom_checker.py),
and [`taint_flow_agent.py`](../../backend/app/agents/taint_flow_agent.py) —
rather than single-file detection, which cppcheck and a plain clang
`--analyze` pass already cover well on their own.

## Coverage

| CWE | Category |
|---|---|
| CWE-121 | Stack-based buffer overflow |
| CWE-122 | Heap-based buffer overflow (C++) |
| CWE-134 | Uncontrolled format string |
| CWE-190 | Integer overflow |
| CWE-191 | Integer underflow |
| CWE-369 | Divide by zero |
| CWE-401 | Memory leak |
| CWE-415 | Double free |
| CWE-476 | NULL pointer dereference |
| CWE-590 | Free of memory not on the heap |
| CWE-690 | NULL dereference from a return value |
| CWE-762 | Mismatched memory management routines |

Every test case is known-bad by construction (that's the point of
Juliet), so a good run should surface findings in most/all of these
files. Cases the tool misses are false negatives worth investigating;
cases it flags that don't correspond to the actual CWE are false
positives.

## Using it

No zip needed — this is already a plain folder. Register it directly:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/projects/from-path \
  -H "Content-Type: application/json" \
  -d '{"path": "<absolute path to this folder>"}'
```

or in the UI: Project → Folder → paste the absolute path → Register.

## Limitations

- Only the two `a`/`b` files per case are included — not Juliet's shared
  `testcasesupport/` headers (`std_testcase.h`, `io.h`, ...). cppcheck and
  clang's `--analyze` don't need a fully resolvable include graph to find
  most of these bugs, but you'll see `#include` warnings if you try to
  actually compile these files.
- This is a hand-picked 120-file slice of the ~64,000-file full suite,
  not the whole thing. If you want broader coverage, the same mirror
  repo has every CWE and every flow variant.
