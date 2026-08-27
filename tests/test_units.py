"""Unit tests for the deterministic parts of the CRS.

Scope on purpose: everything here is model-free and filesystem-light. The
gate, the constraint policy, the diff builder and the crash-signature logic are
the components whose correctness the whole "we prove the fix holds" claim rests
on, so they are the ones that get tested independently of a live pipeline run.
"""
import textwrap

import pytest

from aegiscrs import (
    code_context,
    fuzzer,
    gate,
    patch_generator,
    pov_validator,
    target_selector,
    variant_mutator,
)

SAMPLE_C = textwrap.dedent("""\
    #include <string.h>

    static int helper(int x) {
        return x + 1;  /* brace in comment: } */
    }

    int parse_packet(const unsigned char *data, size_t size, char *out, size_t out_cap) {
        if (size < 1) {
            return -1;
        }
        unsigned char len = data[0];
        memcpy(out, data + 1, len);
        return (int)len;
    }

    int LLVMFuzzerTestOneInput(const unsigned char *d, size_t n) {
        char buf[16];
        parse_packet(d, n, buf, sizeof(buf));
        return 0;
    }
    """)


@pytest.fixture
def c_file(tmp_path):
    path = tmp_path / "parser.c"
    path.write_text(SAMPLE_C)
    return path


# --- code_context -------------------------------------------------------

def test_extract_function_returns_exact_span(c_file):
    fn = code_context.extract_function(str(c_file), 12)  # inside parse_packet
    assert fn["name"] == "parse_packet"
    assert fn["source"].startswith("int parse_packet(")
    assert fn["source"].rstrip().endswith("}")
    assert "memcpy" in fn["source"]
    # Must not bleed into the next function.
    assert "LLVMFuzzerTestOneInput" not in fn["source"]


def test_extract_function_ignores_braces_in_comments(c_file):
    fn = code_context.extract_function(str(c_file), 4)  # inside helper
    assert fn["name"] == "helper"
    assert fn["source"].count("\n") == 2  # signature, body, closing brace


def test_extract_function_span_round_trips(c_file):
    fn = code_context.extract_function(str(c_file), 12)
    lines = SAMPLE_C.splitlines()
    assert "\n".join(lines[fn["start_line"] - 1:fn["end_line"]]) == fn["source"]


KR_STYLE_C = textwrap.dedent("""\
    #include <string.h>

    void /* PRIVATE */
    png_handle_iCCP(int png_ptr, int info_ptr, unsigned int length)
    /* Note: split K&R-style signature, common throughout libpng */
    {
        int keyword[41];
        unsigned int read_length = sizeof(keyword);
        memcpy(keyword, &png_ptr, read_length);
        return;
    }
    """)


@pytest.fixture
def kr_style_file(tmp_path):
    path = tmp_path / "pngrutil.c"
    path.write_text(KR_STYLE_C)
    return path


def test_extract_function_handles_split_kr_signature(kr_style_file):
    # Return type on its own line, name+params on the next - neither line
    # alone looks like a signature to a single-line regex.
    fn = code_context.extract_function(str(kr_style_file), 9)  # inside the memcpy line
    assert fn["name"] == "png_handle_iCCP"
    assert fn["source"].startswith("void /* PRIVATE */")
    assert fn["source"].rstrip().endswith("}")
    assert "memcpy" in fn["source"]


def test_reachability_finds_path_from_entry(tmp_path, c_file):
    assert code_context.reachability_score(str(tmp_path), "LLVMFuzzerTestOneInput", "parse_packet") == 1.0


def test_reachability_unreachable_scores_low(tmp_path, c_file):
    assert code_context.reachability_score(str(tmp_path), "LLVMFuzzerTestOneInput", "helper") == 0.15


def test_reachability_unknown_is_not_zero(tmp_path, c_file):
    # A parser limitation must never silently discard a finding.
    assert code_context.reachability_score(str(tmp_path), "LLVMFuzzerTestOneInput", "no_such_fn") == 0.5


# --- patch_generator: diff construction ---------------------------------

def test_build_diff_produces_applyable_header():
    original = "int f(void) {\n    return 0;\n}\n"
    fixed = "int f(void) {\n    return 1;\n}"
    result = patch_generator.build_diff("src/f.c", original, 1, 3, fixed)
    assert result["ok"]
    assert result["diff"].startswith("--- a/src/f.c\n+++ b/src/f.c\n")
    assert "-    return 0;" in result["diff"]
    assert "+    return 1;" in result["diff"]


def test_build_diff_rejects_unchanged_function():
    original = "int f(void) {\n    return 0;\n}\n"
    result = patch_generator.build_diff("src/f.c", original, 1, 3, original.rstrip("\n"))
    assert not result["ok"]
    assert "unchanged" in result["reason"]


def test_build_diff_preserves_surrounding_lines():
    original = "int a(void) { return 1; }\nint b(void) {\n    return 2;\n}\nint c(void) { return 3; }\n"
    result = patch_generator.build_diff("x.c", original, 2, 4, "int b(void) {\n    return 9;\n}")
    assert "int a(void)" not in result["diff"].replace(" int a(void) { return 1; }", "")
    assert "+    return 9;" in result["diff"]


# --- patch_generator: constraint policy ---------------------------------

def _diff_touching(path, added=1):
    body = "".join(f"+line{i}\n" for i in range(added))
    return f"--- a/{path}\n+++ b/{path}\n@@ -1,1 +1,{added} @@\n{body}"


def test_constraints_accept_small_in_scope_diff():
    result = patch_generator.validate_constraints(_diff_touching("src/parser.c"), ["tests/"])
    assert result["ok"]
    assert result["touched_files"] == ["src/parser.c"]


def test_constraints_reject_forbidden_path():
    result = patch_generator.validate_constraints(_diff_touching("tests/test_basic.c"), ["tests/"])
    assert not result["ok"]
    assert any("forbidden" in r for r in result["reasons"])


def test_constraints_reject_oversized_diff():
    result = patch_generator.validate_constraints(_diff_touching("src/p.c", added=25), [])
    assert not result["ok"]
    assert any("exceeds cap" in r for r in result["reasons"])


def test_constraints_fail_closed_on_unparseable_diff():
    # No ---/+++ headers at all: the policy check cannot see what was touched,
    # so it must reject rather than wave the patch through.
    result = patch_generator.validate_constraints("+something\n-else\n", ["tests/"])
    assert not result["ok"]
    assert any("failing closed" in r for r in result["reasons"])


def test_constraints_handle_diff_without_ab_prefix():
    diff = "--- src/parser.c\n+++ src/parser.c\n@@ -1 +1 @@\n+x\n"
    result = patch_generator.validate_constraints(diff, ["src/"])
    assert not result["ok"]
    assert any("forbidden" in r for r in result["reasons"])


def test_constraints_reject_empty_diff():
    result = patch_generator.validate_constraints("", [])
    assert not result["ok"]


# --- gate ---------------------------------------------------------------

APPLIED = {"applied": True, "build": {"success": True}}
GOOD_REGRESSION = {
    "pov_reproduces_on_vulnerable": True,
    "pov_reproduces_on_patched": False,
    "existing_tests": {"success": True},
}
OK_CONSTRAINTS = {"ok": True, "reasons": []}
GENERALIZES = {"generalizes": True}


def test_gate_accepts_only_when_every_condition_holds():
    result = gate.accept_patch(APPLIED, GOOD_REGRESSION, OK_CONSTRAINTS, GENERALIZES)
    assert result["accepted"]
    assert result["reasons"] == []


@pytest.mark.parametrize("mutation,expected", [
    ({"pov_reproduces_on_patched": True}, "still reproduces"),
    ({"pov_reproduces_on_vulnerable": False}, "invalid baseline"),
    ({"existing_tests": {"success": False}}, "regression tests failed"),
])
def test_gate_rejects_on_each_regression_failure(mutation, expected):
    regression = {**GOOD_REGRESSION, **mutation}
    result = gate.accept_patch(APPLIED, regression, OK_CONSTRAINTS, GENERALIZES)
    assert not result["accepted"]
    assert any(expected in r for r in result["reasons"])


def test_gate_rejects_non_generalizing_patch():
    result = gate.accept_patch(APPLIED, GOOD_REGRESSION, OK_CONSTRAINTS, {"generalizes": False})
    assert not result["accepted"]
    assert any("does not generalize" in r for r in result["reasons"])


def test_gate_rejects_failed_build():
    result = gate.accept_patch({"applied": True, "build": {"success": False}},
                               GOOD_REGRESSION, OK_CONSTRAINTS, GENERALIZES)
    assert not result["accepted"]
    assert any("failed to build" in r for r in result["reasons"])


def test_gate_short_circuits_when_patch_did_not_apply():
    result = gate.accept_patch({"applied": False, "build": None}, {}, OK_CONSTRAINTS, None)
    assert not result["accepted"]
    assert result["reasons"] == ["patch did not apply"]


def test_gate_reports_constraint_violations():
    result = gate.accept_patch({"applied": False, "build": None}, {},
                               {"ok": False, "reasons": ["patch touches forbidden path: tests/x"]}, None)
    assert not result["accepted"]
    assert "patch touches forbidden path: tests/x" in result["reasons"]


def test_gate_never_accepts_on_empty_regression_evidence():
    # Absence of evidence must not read as evidence of a passing patch.
    result = gate.accept_patch(APPLIED, {}, OK_CONSTRAINTS, None)
    assert not result["accepted"]


# --- crash signature ----------------------------------------------------

ASAN_TEMPLATE = """==%d==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x%x
WRITE of size 200 at 0x%x thread T0
    #0 0x%x in parse_packet /src/vulnerable/parser.c:12
    #1 0x%x in LLVMFuzzerTestOneInput /src/harness.c:6
"""


def test_crash_signature_is_stable_across_aslr():
    a = ASAN_TEMPLATE % (101, 0x7ffd1000, 0x7ffd1000, 0x4a1000, 0x4a2000)
    b = ASAN_TEMPLATE % (202, 0x7ffe9000, 0x7ffe9000, 0x5b1000, 0x5b2000)
    assert pov_validator._crash_signature(a) == pov_validator._crash_signature(b)


def test_crash_signature_differs_for_different_bugs():
    a = ASAN_TEMPLATE % (101, 0x7ffd1000, 0x7ffd1000, 0x4a1000, 0x4a2000)
    b = a.replace("stack-buffer-overflow", "heap-use-after-free")
    assert pov_validator._crash_signature(a) != pov_validator._crash_signature(b)


def test_crash_signature_differs_for_different_stacks():
    a = ASAN_TEMPLATE % (101, 0x7ffd1000, 0x7ffd1000, 0x4a1000, 0x4a2000)
    b = a.replace("parse_packet", "decode_header")
    assert pov_validator._crash_signature(a) != pov_validator._crash_signature(b)


# --- variant mutator ----------------------------------------------------

def test_variants_include_llm_boundaries_and_generic_mutations():
    pov = bytes([200, 1, 2, 3])
    variants = variant_mutator.generate_variants(pov, {"offset": 0, "boundary_values": [15, 16, 17]}, count=6)
    assert len(variants) == 6
    sources = {v["source"] for v in variants}
    assert sources == {"llm-hypothesis", "generic-mutation"}
    assert bytes([15, 1, 2, 3]) in [v["bytes"] for v in variants]


def test_variants_survive_useless_llm_hypothesis():
    # Even with nothing from the model, deterministic mutations still run (11.11 tier 2).
    variants = variant_mutator.generate_variants(b"\x10abc", {"offset": 0, "boundary_values": []}, count=4)
    assert variants
    assert all(v["source"] == "generic-mutation" for v in variants)


def test_variants_handle_offset_past_end():
    variants = variant_mutator.generate_variants(b"\x01", {"offset": 99, "boundary_values": [1, 2]}, count=4)
    assert all(v["source"] == "generic-mutation" for v in variants)


# --- fuzzer: seed corpus (BUILD-BRIEF Phase 3) ---------------------------

def test_seed_corpus_copies_files(tmp_path):
    seed_dir = tmp_path / "seeds"
    seed_dir.mkdir()
    (seed_dir / "a.png").write_bytes(b"a")
    (seed_dir / "b.png").write_bytes(b"b")
    corpus_dir = tmp_path / "corpus"
    count = fuzzer.seed_corpus(str(corpus_dir), str(seed_dir))
    assert count == 2
    assert sorted(p.name for p in corpus_dir.iterdir()) == ["a.png", "b.png"]


def test_seed_corpus_missing_dir_is_not_an_error(tmp_path):
    corpus_dir = tmp_path / "corpus"
    assert fuzzer.seed_corpus(str(corpus_dir), None) == 0
    assert fuzzer.seed_corpus(str(corpus_dir), str(tmp_path / "nope")) == 0


# --- ranking ------------------------------------------------------------

def test_impact_ordering_favours_memory_corruption():
    assert target_selector.impact_from_cwe("CWE-787") > target_selector.impact_from_cwe("CWE-401")
    assert target_selector.impact_from_cwe("CWE-unknown") == 0.4


def test_priority_penalises_cost_and_rewards_confidence():
    cheap = target_selector.priority(0.9, 1.0, 1.0, 0.5)
    costly = target_selector.priority(0.9, 1.0, 1.0, 3.0)
    assert cheap > costly
    assert target_selector.priority(0.9, 1.0, 1.0, 1.0) > target_selector.priority(0.3, 1.0, 1.0, 1.0)


def test_unreachable_finding_ranks_below_reachable_one():
    reachable = target_selector.priority(0.9, 1.0, 0.85, 1.0)
    unreachable = target_selector.priority(0.9, 0.15, 1.0, 1.0)
    assert reachable > unreachable


@pytest.mark.parametrize("confidence,expected", [
    (0.1, "discard"), (0.39, "discard"), (0.4, "fuzz"),
    (0.75, "fuzz"), (0.76, "direct_pov"), (0.99, "direct_pov"),
])
def test_route_thresholds(confidence, expected):
    assert target_selector.route(confidence) == expected
