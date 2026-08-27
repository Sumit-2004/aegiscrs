"""End-to-end check of the model-output -> applied-patch path.

This is the highest-risk seam in the CRS: the model returns a function, the
harness turns it into a unified diff, and `git apply` has to accept it. It runs
against the real demo target and needs no compiler and no model, so it can
guard the path on any machine.
"""
import shutil
import subprocess
from pathlib import Path

import pytest

from aegiscrs import builder_sidecar, code_context, llm_client, patch_generator

DEMO_TARGET = Path(__file__).resolve().parent.parent / "demo_target"
PARSER_C = DEMO_TARGET / "vulnerable" / "parser.c"


def _git_available() -> bool:
    try:
        return subprocess.run(["git", "--version"], capture_output=True).returncode == 0
    except OSError:
        return False


requires_git = pytest.mark.skipif(not _git_available(), reason="git not available")


@pytest.fixture
def workspace(tmp_path):
    dest = tmp_path / "target"
    shutil.copytree(DEMO_TARGET, dest)
    return dest


def _build_demo_diff() -> dict:
    fn = code_context.extract_function(str(PARSER_C), 11)
    assert fn is not None and fn["name"] == "parse_packet"
    fix = llm_client.draft_function_fix(
        {"id": "finding-000", "cwe": "CWE-787", "function": "parse_packet"},
        fn["source"], "AddressSanitizer: stack-buffer-overflow")
    return patch_generator.build_diff(
        "vulnerable/parser.c", PARSER_C.read_text(),
        fn["start_line"], fn["end_line"], fix["function_source"])


def test_demo_diff_is_minimal_and_in_policy():
    diff = _build_demo_diff()
    assert diff["ok"], diff["reason"]
    result = patch_generator.validate_constraints(
        diff["diff"], ["tests/", "build.sh", "harness.c"])
    assert result["ok"], result["reasons"]
    assert result["touched_files"] == ["vulnerable/parser.c"]


@requires_git
def test_generated_diff_applies_cleanly(workspace):
    diff = _build_demo_diff()
    result = builder_sidecar.apply_patch_build(
        str(workspace), diff["diff"], build_command="true")
    assert result["applied"], result["apply_stderr"]


@requires_git
def test_applied_patch_adds_guard_without_removing_functionality(workspace):
    diff = _build_demo_diff()
    builder_sidecar.apply_patch_build(str(workspace), diff["diff"], build_command="true")
    patched = (workspace / "vulnerable" / "parser.c").read_text()

    assert "out_cap" in patched, "capacity guard missing from patched source"
    # The cheap way to 'fix' a crash is to delete the operation that crashes.
    # A patch that does that must never look like a success here.
    assert "memcpy(out, data + 1, len);" in patched
    assert "return (int)len;" in patched


@requires_git
def test_patch_file_is_written_with_lf_endings(workspace):
    """Path.write_text() would translate LF to CRLF on Windows and silently
    break `git apply` on every context line - regression guard for that."""
    diff = _build_demo_diff()
    builder_sidecar.apply_patch_build(str(workspace), diff["diff"], build_command="true")
    raw = (workspace / "_aegiscrs_patch.diff").read_bytes()
    assert b"\r\n" not in raw
