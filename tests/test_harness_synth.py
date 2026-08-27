"""Unit tests for fuzz harness synthesis (BUILD-BRIEF Phase 4).

candidate-finding and coverage validation are both model-free and covered
here without a compiler or model. The end-to-end synthesize() loop (drafting
via llm_client, real compile, real libFuzzer run) needs clang/libFuzzer and
is exercised manually against the real libpng target, not in this suite.
"""
import textwrap
from unittest.mock import patch

from aegiscrs import harness_synth

PLAIN_HEADER = textwrap.dedent("""\
    #ifndef PARSER_H
    #define PARSER_H
    #include <stddef.h>
    int parse_packet(const unsigned char *data, size_t size, char *out, size_t out_cap);
    void not_a_candidate(int x, int y);
    #endif
    """)

EXPORT_MACRO_HEADER = textwrap.dedent("""\
    PNG_EXPORT(3, int, png_sig_cmp, (png_const_bytep sig, size_t start,
        size_t num_to_check));
    PNG_EXPORT(9, void, png_set_sig_bytes, (png_structrp png_ptr, int num_bytes));
    """)


def test_finds_plain_buffer_length_prototype(tmp_path):
    header = tmp_path / "parser.h"
    header.write_text(PLAIN_HEADER)
    candidates = harness_synth.find_candidate_entries([str(header)])
    names = [c["name"] for c in candidates]
    assert "parse_packet" in names
    assert "not_a_candidate" not in names  # no buffer+length shape


def test_finds_export_macro_style_declaration(tmp_path):
    header = tmp_path / "png.h"
    header.write_text(EXPORT_MACRO_HEADER)
    candidates = harness_synth.find_candidate_entries([str(header)])
    names = [c["name"] for c in candidates]
    assert "png_sig_cmp" in names
    assert "png_set_sig_bytes" not in names  # no buffer+length shape


def test_find_candidates_missing_file_is_not_an_error(tmp_path):
    assert harness_synth.find_candidate_entries([str(tmp_path / "nope.h")]) == []


def _fake_libfuzzer_output(final_cov: int) -> str:
    return (
        f"#2\tINITED cov: 3 ft: 3 corp: 1/1b exec/s: 0 rss: 32Mb\n"
        f"#161\tNEW    cov: {final_cov} ft: {final_cov} corp: 2/5b exec/s: 0 rss: 33Mb\n"
        f"stat::number_of_executed_units: 3099\n"
    )


def test_validate_harness_ok_above_threshold(tmp_path, monkeypatch):
    fake = tmp_path / "fake_binary"
    fake.write_text("")

    class FakeResult:
        stdout = _fake_libfuzzer_output(154)
        stderr = ""

    with patch("aegiscrs.harness_synth.sandbox.run", return_value=FakeResult()):
        result = harness_synth.validate_harness(str(fake), min_coverage=20)
    assert result["ok"]
    assert result["coverage"] == 154


def test_validate_harness_rejects_below_threshold(tmp_path):
    fake = tmp_path / "fake_binary"
    fake.write_text("")

    class FakeResult:
        stdout = _fake_libfuzzer_output(4)
        stderr = ""

    with patch("aegiscrs.harness_synth.sandbox.run", return_value=FakeResult()):
        result = harness_synth.validate_harness(str(fake), min_coverage=20)
    assert not result["ok"]
    assert result["coverage"] == 4


def test_validate_harness_no_coverage_lines_is_zero(tmp_path):
    fake = tmp_path / "fake_binary"
    fake.write_text("")

    class FakeResult:
        stdout = "some crash before any stats were printed\n"
        stderr = ""

    with patch("aegiscrs.harness_synth.sandbox.run", return_value=FakeResult()):
        result = harness_synth.validate_harness(str(fake), min_coverage=20)
    assert not result["ok"]
    assert result["coverage"] == 0


def test_synthesize_retries_on_compile_failure_then_succeeds(tmp_path, monkeypatch):
    harness_path = tmp_path / "harness.cc"
    calls = {"n": 0}

    def fake_draft_harness(candidate, includes, previous_error=None):
        calls["n"] += 1
        return f"// attempt {calls['n']}, previous_error={previous_error!r}\n"

    def fake_build_target(snapshot_dir, build_command, isolation=None):
        # First attempt fails to compile, second succeeds.
        return {"success": calls["n"] >= 2, "stderr": "fake compile error" if calls["n"] < 2 else ""}

    def fake_validate_harness(binary_path, isolation=None, timeout_seconds=8, min_coverage=20):
        return {"coverage": 50, "ok": True}

    with patch("aegiscrs.harness_synth.llm_client.draft_harness", side_effect=fake_draft_harness), \
         patch("aegiscrs.harness_synth.builder_sidecar.build_target", side_effect=fake_build_target), \
         patch("aegiscrs.harness_synth.validate_harness", side_effect=fake_validate_harness):
        result = harness_synth.synthesize(
            snapshot_dir=str(tmp_path), header_paths=[], harness_source_path=str(harness_path),
            build_command="fake", harness_binary_path=str(tmp_path / "bin"))

    assert result["ok"]
    assert result["attempts"] == 2
    assert calls["n"] == 2


def test_synthesize_gives_up_after_max_attempts(tmp_path):
    harness_path = tmp_path / "harness.cc"

    def always_fails(snapshot_dir, build_command, isolation=None):
        return {"success": False, "stderr": "still broken"}

    with patch("aegiscrs.harness_synth.llm_client.draft_harness", return_value="// nope\n"), \
         patch("aegiscrs.harness_synth.builder_sidecar.build_target", side_effect=always_fails):
        result = harness_synth.synthesize(
            snapshot_dir=str(tmp_path), header_paths=[], harness_source_path=str(harness_path),
            build_command="fake", harness_binary_path=str(tmp_path / "bin"), max_attempts=3)

    assert not result["ok"]
    assert result["attempts"] == 3
