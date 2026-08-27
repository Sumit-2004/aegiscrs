"""Patch assembly and constraint enforcement (plan §11.8).

Key design decision: the model never writes a unified diff. Small quantized
models are unreliable at hunk headers and exact context lines, so an
apply-failure rate that has nothing to do with whether the fix was *correct*
would dominate the results. Instead the model returns a whole corrected
function, and build_diff() computes the diff deterministically with difflib —
so a patch that fails to apply is now a genuine bug, not a formatting artifact.
"""
import difflib
import re

_FILE_HEADER = re.compile(r"^(?:---|\+\+\+) (?:[ab]/)?(\S+)", re.MULTILINE)


def build_diff(rel_path: str, original_text: str, start_line: int, end_line: int,
               new_function_source: str) -> dict:
    """Splice a replacement function into the file and emit a unified diff.

    start_line/end_line are 1-indexed and inclusive, as returned by
    code_context.extract_function.
    """
    original_lines = original_text.splitlines()
    replacement_lines = new_function_source.rstrip("\n").splitlines()
    patched_lines = (original_lines[:start_line - 1]
                     + replacement_lines
                     + original_lines[end_line:])

    if patched_lines == original_lines:
        return {"ok": False, "diff": "", "reason": "model returned the function unchanged"}

    diff = "".join(difflib.unified_diff(
        [line + "\n" for line in original_lines],
        [line + "\n" for line in patched_lines],
        fromfile=f"a/{rel_path}",
        tofile=f"b/{rel_path}",
        n=3,
    ))
    return {"ok": True, "diff": diff, "reason": ""}


def validate_constraints(diff_text: str, forbidden_paths: list[str], max_lines: int = 20) -> dict:
    """Fail-closed policy check: anything unparseable is a rejection, never a pass."""
    reasons = []

    changed_lines = [
        line for line in diff_text.splitlines()
        if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))
    ]
    if not changed_lines:
        reasons.append("diff contains no changed lines")
    if len(changed_lines) > max_lines:
        reasons.append(f"diff touches {len(changed_lines)} lines, exceeds cap of {max_lines}")

    touched_files = {path for path in _FILE_HEADER.findall(diff_text) if path != "/dev/null"}
    if diff_text.strip() and not touched_files:
        # A security gate that cannot read its input must reject, not wave it through.
        reasons.append("could not parse any file path from the diff (failing closed)")

    for touched in sorted(touched_files):
        for forbidden in forbidden_paths:
            if touched.startswith(forbidden.rstrip("/")):
                reasons.append(f"patch touches forbidden path: {touched}")

    return {"ok": len(reasons) == 0, "reasons": reasons, "touched_files": sorted(touched_files)}
