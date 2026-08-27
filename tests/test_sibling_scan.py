"""Sibling-bug sweep: model-free, filesystem-light (same standard as test_units.py).

Reuses target_selector.prescore's own math, so these tests check the wiring -
same rule id grouped, self excluded, ranked by the funnel's existing prescore -
not the scoring formula itself (already covered in test_units.py).
"""
import textwrap

import pytest

from aegiscrs import sibling_scan

SAMPLE_C = textwrap.dedent("""\
    #include <string.h>

    void copy_a(const unsigned char *data, size_t len, char *out) {
        memcpy(out, data, len);
    }

    void copy_b(const unsigned char *data, size_t len, char *out) {
        memcpy(out, data, len);
    }

    int LLVMFuzzerTestOneInput(const unsigned char *d, size_t n) {
        char buf[16];
        copy_a(d, n, buf);
        return 0;
    }
    """)


@pytest.fixture
def project_dir(tmp_path):
    (tmp_path / "parser.c").write_text(SAMPLE_C)
    return tmp_path


def _finding(id_, category, function, line, cwe="CWE-120"):
    return {"id": id_, "file": "", "line": line, "function": function,
            "category": category, "cwe": cwe, "severity": "high",
            "evidence": "", "tool": "semgrep"}


def test_finds_siblings_sharing_the_same_rule(project_dir):
    confirmed = _finding("finding-000", "unchecked-length-copy", "copy_a", 4)
    confirmed["file"] = str(project_dir / "parser.c")
    sibling = _finding("finding-001", "unchecked-length-copy", "copy_b", 8)
    sibling["file"] = str(project_dir / "parser.c")
    other_rule = _finding("finding-002", "use-after-free", "copy_b", 8)
    other_rule["file"] = str(project_dir / "parser.c")

    result = sibling_scan.find_siblings(
        [confirmed, sibling, other_rule], confirmed,
        str(project_dir), "LLVMFuzzerTestOneInput")

    assert [s["finding_id"] for s in result] == ["finding-001"]
    assert result[0]["status"] == "unpatched-candidate"


def test_excludes_the_confirmed_finding_itself(project_dir):
    confirmed = _finding("finding-000", "unchecked-length-copy", "copy_a", 4)
    confirmed["file"] = str(project_dir / "parser.c")

    result = sibling_scan.find_siblings([confirmed], confirmed, str(project_dir), "LLVMFuzzerTestOneInput")
    assert result == []


def test_no_siblings_when_no_other_finding_shares_the_rule(project_dir):
    confirmed = _finding("finding-000", "unchecked-length-copy", "copy_a", 4)
    confirmed["file"] = str(project_dir / "parser.c")
    other_rule = _finding("finding-001", "use-after-free", "copy_b", 8)
    other_rule["file"] = str(project_dir / "parser.c")

    result = sibling_scan.find_siblings([confirmed, other_rule], confirmed, str(project_dir), "LLVMFuzzerTestOneInput")
    assert result == []


def test_ranks_reachable_sibling_above_unreachable_one(project_dir):
    # copy_a is reachable from the fuzz entry point; copy_b is not called by
    # anything in this fixture, so it must score lower and sort second.
    unreachable_c = textwrap.dedent("""\
        void copy_c(const unsigned char *data, size_t len, char *out) {
            memcpy(out, data, len);
        }
        """)
    (project_dir / "orphan.c").write_text(unreachable_c)

    confirmed = _finding("finding-000", "unchecked-length-copy", "LLVMFuzzerTestOneInput", 11)
    confirmed["file"] = str(project_dir / "parser.c")
    reachable_sibling = _finding("finding-001", "unchecked-length-copy", "copy_a", 4)
    reachable_sibling["file"] = str(project_dir / "parser.c")
    unreachable_sibling = _finding("finding-002", "unchecked-length-copy", "copy_c", 1)
    unreachable_sibling["file"] = str(project_dir / "orphan.c")

    result = sibling_scan.find_siblings(
        [confirmed, reachable_sibling, unreachable_sibling], confirmed,
        str(project_dir), "LLVMFuzzerTestOneInput")

    assert [s["finding_id"] for s in result] == ["finding-001", "finding-002"]
    assert result[0]["reachability"] > result[1]["reachability"]
