# Juliet Held-out Split

120 test cases (12 CWEs × 5 multi-file + 5 single-file cases, 207 files) from
the [Juliet Test Suite for C/C++ v1.3](https://samate.nist.gov/SARD/test-suites/112).
The cases were drawn with a fixed seed by `backend/eval/build_heldout.py`.
The CWEs are the same as in the dev split (`../juliet-cross-file-subset`), but
flow variant 51 is excluded. That way this split measures generalisation to
other data-flow shapes and doesn't reward rules tuned to the dev cases.

`manifest.json` lists every case. `testcasesupport/` holds Juliet's shared
headers. Scoring is explained in `backend/eval/README.md`.

**Do not tune detectors or prompts against this folder.** Once you do, it
stops being held-out.
