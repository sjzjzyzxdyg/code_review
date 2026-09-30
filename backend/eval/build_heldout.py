"""Build the held-out Juliet split from a Juliet checkout.

    git clone --depth 1 https://github.com/arichardson/juliet-test-suite-c.git
    python -m eval.build_heldout --juliet juliet-test-suite-c/testcases \
        --out ../samples/juliet-heldout

The same CWEs as the dev split (samples/juliet-cross-file-subset) are used,
but flow variant 51 is excluded and single-file cases are mixed in, so the
held-out split tests generalisation rather than memorised patterns. Sampling
is seeded, so every run produces the same split.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from eval.juliet import materialize, select_heldout

CWES = (
    "CWE121_Stack_Based_Buffer_Overflow",
    "CWE122_Heap_Based_Buffer_Overflow",
    "CWE134_Uncontrolled_Format_String",
    "CWE190_Integer_Overflow",
    "CWE191_Integer_Underflow",
    "CWE369_Divide_by_Zero",
    "CWE401_Memory_Leak",
    "CWE415_Double_Free",
    "CWE476_NULL_Pointer_Dereference",
    "CWE590_Free_Memory_Not_on_Heap",
    "CWE690_NULL_Deref_From_Return",
    "CWE762_Mismatched_Memory_Management_Routines",
)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--juliet", required=True, type=Path, help="Path to the checkout's testcases/ folder.")
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--multi", type=int, default=5, help="Multi-file cases per CWE.")
    parser.add_argument("--single", type=int, default=5, help="Single-file cases per CWE.")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args(argv)

    cases = select_heldout(args.juliet, CWES, args.multi, args.single, seed=args.seed)
    materialize(cases, args.out)
    files = sum(len(c.files) for c in cases)
    print(f"Wrote {len(cases)} cases ({files} files) to {args.out}")


if __name__ == "__main__":
    main()
