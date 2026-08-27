"""Unit tests for the mock branches in llm_client.py that back BUILD-BRIEF
Phase 6 (second CWE + staged rejection demo). Model-free: MOCK_LLM=1 is
already the default for the whole test suite, so these exercise the exact
code path a real pipeline run takes.
"""
import os

from aegiscrs import code_context, llm_client

UAF_SOURCE = code_context.extract_function(
    "uaf_target/vulnerable/session.c", 25)["source"]


def test_uaf_general_fix_resets_pointer_to_null():
    fix = llm_client.draft_function_fix(
        {"id": "x", "cwe": "CWE-416", "function": "process_session"},
        UAF_SOURCE, "AddressSanitizer: heap-use-after-free")
    assert "s = NULL;" in fix["function_source"]
    assert "BUG: s is left dangling" not in fix["function_source"]


def test_uaf_overfit_mode_special_cases_exact_pov_bytes(monkeypatch):
    monkeypatch.setenv("MOCK_LLM_OVERFIT", "1")
    pov = bytes([0x00, 0x01, 0x00])
    fix = llm_client.draft_function_fix(
        {"id": "x", "cwe": "CWE-416", "function": "process_session"},
        UAF_SOURCE, "AddressSanitizer: heap-use-after-free", pov_bytes=pov)
    # Root cause is untouched - the real bug is still there...
    assert "BUG: s is left dangling" in fix["function_source"]
    # ...but the exact reported input is special-cased away.
    assert "size == 3" in fix["function_source"]
    assert "data[0] == 0" in fix["function_source"]
    assert "data[1] == 1" in fix["function_source"]
    assert "data[2] == 0" in fix["function_source"]


def test_uaf_overfit_guard_is_specific_to_the_pov_it_was_given(monkeypatch):
    # A different PoV must produce a different (still exact-match) guard -
    # this isn't a fixed hardcoded string, it's derived from pov_bytes.
    monkeypatch.setenv("MOCK_LLM_OVERFIT", "1")
    fix_a = llm_client.draft_function_fix(
        {"id": "x", "cwe": "CWE-416"}, UAF_SOURCE, "", pov_bytes=bytes([0, 1, 0]))
    fix_b = llm_client.draft_function_fix(
        {"id": "x", "cwe": "CWE-416"}, UAF_SOURCE, "", pov_bytes=bytes([1, 0, 1, 0]))
    assert fix_a["function_source"] != fix_b["function_source"]
    assert "size == 4" in fix_b["function_source"]


def test_uaf_overfit_without_pov_bytes_falls_back_to_general_fix():
    # MOCK_LLM_OVERFIT set but no pov_bytes given - must not crash, and must
    # not silently produce a no-op guard either.
    os.environ.pop("MOCK_LLM_OVERFIT", None)
    fix = llm_client.draft_function_fix(
        {"id": "x", "cwe": "CWE-416"}, UAF_SOURCE, "", pov_bytes=None)
    assert "s = NULL;" in fix["function_source"]
