from pathlib import Path

from app.tools.clang_analyzer_tool import ClangAnalyzerTool
from eval.juliet import BAD, GOOD, NEUTRAL, GroundTruth, case_key, discover_cases, label_lines, score

_SINK = """\
#include "std_testcase.h"

#ifndef OMITBAD
void CWE415_x_51b_badSink(char * data)
{
    free(data);
}
#endif /* OMITBAD */

#ifndef OMITGOOD
#ifdef _WIN32
static int unused;
#endif
void CWE415_x_51b_goodG2BSink(char * data)
{
    free(data);
}
#endif /* OMITGOOD */
"""


def test_case_key_groups_multi_file_variants() -> None:
    assert case_key("CWE415_Double_Free__malloc_free_char_51a") == ("CWE415_Double_Free__malloc_free_char_51", "51")
    assert case_key("CWE401_Memory_Leak__new_int_82_goodG2B") == ("CWE401_Memory_Leak__new_int_82", "82")
    assert case_key("CWE476_NULL_Pointer_Dereference__char_01") == ("CWE476_NULL_Pointer_Dereference__char_01", "01")


def test_label_lines_tracks_nested_preprocessor_blocks() -> None:
    labels = label_lines(_SINK)
    assert labels[0] == NEUTRAL          # #include
    assert labels[5] == BAD              # free(data) in badSink
    assert labels[11] == GOOD            # nested #ifdef _WIN32 keeps the GOOD label
    assert labels[15] == GOOD            # free(data) in goodG2BSink
    assert labels[-1] == GOOD            # the closing #endif line itself


def _dataset(tmp_path: Path) -> GroundTruth:
    folder = tmp_path / "CWE415_x"
    folder.mkdir()
    (folder / "CWE415_x_51a.c").write_text("#ifndef OMITBAD\nvoid bad(){}\n#endif\n")
    (folder / "CWE415_x_51b.c").write_text(_SINK)
    (folder / "CWE415_y_01.c").write_text("#ifndef OMITBAD\nvoid bad(){}\n#endif\n#ifndef OMITGOOD\nvoid good(){}\n#endif\n")
    cases = discover_cases(tmp_path)
    assert sorted(cases) == ["CWE415_x_51", "CWE415_y_01"]
    assert len(cases["CWE415_x_51"].files) == 2
    return GroundTruth(cases.values())


def test_score_counts_sides_not_raw_findings(tmp_path: Path) -> None:
    truth = _dataset(tmp_path)
    findings = [
        (r"C:\proj\CWE415_x\CWE415_x_51b.c", 6),   # bad side, Windows path
        ("CWE415_x/CWE415_x_51b.c", 6),            # same bad side again
        ("CWE415_x/CWE415_x_51b.c", 17),           # good side → false positive
        ("CWE415_x/CWE415_x_51b.c", 1),            # neutral (include line)
        ("other/unrelated.c", 3),                  # not in the dataset
    ]
    s = score(truth, findings)
    assert s.cases == 2
    assert s.bad_flagged == 1 and s.good_flagged == 1
    assert s.recall == 0.5
    assert s.precision == 0.5
    assert (s.findings_bad, s.findings_good, s.findings_neutral, s.findings_outside) == (2, 1, 1, 1)


def test_clang_output_parses_windows_paths() -> None:
    stderr = (
        r"C:\src\CWE415_x_51b.c:6:5: warning: Attempt to free released memory [unix.Malloc]" "\n"
        r"C:\src\CWE415_x_51b.c:1:10: fatal error: 'std_testcase.h' file not found" "\n"
    )
    findings = ClangAnalyzerTool()._parse_text_output(stderr, Path(r"C:\src\CWE415_x_51b.c"))
    # The fatal "file not found" error is a compile failure, not a finding.
    assert [(f["line"], f["column"], f["severity"]) for f in findings] == [(6, 5, "warning")]
    assert findings[0]["message"] == "Attempt to free released memory [unix.Malloc]"
