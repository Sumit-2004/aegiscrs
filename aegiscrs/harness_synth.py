"""Fuzz harness synthesis (BUILD-BRIEF Phase 4, the top differentiator).

Real defense code rarely ships an LLVMFuzzerTestOneInput. This module lets
AegisCRS write one itself: the model drafts candidate C source, but whether
that source is any good is never the model's call - the compiler judges by
building it, and a short libFuzzer run judges by whether it actually reaches
into the target (gains coverage) rather than compiling to a no-op. Both
checks are real subprocess results, same as everywhere else in the CRS.
"""
import os
import re
from pathlib import Path

from . import builder_sidecar, llm_client, sandbox

MAX_ATTEMPTS = 3

# Two header-declaration shapes: a plain prototype, and the
# `SOMETHING_EXPORT(ordinal, type, name, (args))` macro table style some
# libraries (libpng among them) use instead of a plain declaration for their
# public API. Both are treated as candidates the same way.
_PLAIN_PROTO = re.compile(r"(?<!\w)([A-Za-z_][\w\s\*]*?)\s+(\w+)\s*\(([^;{}]*)\)\s*;")
_EXPORT_MACRO = re.compile(
    r"\b\w*EXPORTA?\s*\(\s*\d+\s*,\s*([\w\s\*]+?)\s*,\s*(\w+)\s*,\s*\(([^;{}]*)\)\s*\)\s*;")
_BUFFER_PARAM = re.compile(
    r"(?:const\s+)?(?:unsigned\s+)?char\s*\*|png_const_bytep|png_bytep|u?int8_t\s*\*", re.IGNORECASE)
_LEN_PARAM = re.compile(r"\bsize_t\b")
_COV_STAT = re.compile(r"\bcov:\s*(\d+)")


def find_candidate_entries(header_paths: list[str]) -> list[dict]:
    """Scan headers for functions shaped like parse(buffer, length, ...) -
    the common 'hand me bytes, I parse them' signature fuzz targets need.
    Heuristic and over-approximate by design, same spirit as code_context.py:
    a wrong guess just gives the model a less useful hint, it doesn't block
    anything downstream.
    """
    candidates = []
    for header in header_paths:
        try:
            text = Path(header).read_text()
        except OSError:
            continue
        for regex in (_EXPORT_MACRO, _PLAIN_PROTO):
            for m in regex.finditer(text):
                return_type, name, params = m.group(1).strip(), m.group(2), m.group(3).strip()
                if _BUFFER_PARAM.search(params) and _LEN_PARAM.search(params):
                    candidates.append({
                        "name": name, "return_type": return_type,
                        "params": params, "header": str(header),
                    })
    return candidates


def validate_harness(harness_binary_path: str, isolation: dict | None = None,
                     timeout_seconds: int = 8, min_coverage: int = 20) -> dict:
    """The runtime half of 'the compiler judges': does the harness actually
    execute into the target library, or does it just parse its arguments and
    return? A harness that compiles but always bails out early would
    otherwise look identical to a working one from the build result alone.
    """
    result = sandbox.run(
        [harness_binary_path, f"-max_total_time={timeout_seconds}", "-print_final_stats=1"],
        cwd=os.path.dirname(harness_binary_path) or ".",
        timeout=timeout_seconds + 30, isolation=isolation)
    combined = (result.stdout or "") + (result.stderr or "")
    matches = _COV_STAT.findall(combined)
    coverage = int(matches[-1]) if matches else 0
    return {"coverage": coverage, "ok": coverage >= min_coverage}


def synthesize(snapshot_dir: str, header_paths: list[str], harness_source_path: str,
              build_command: str, harness_binary_path: str,
              isolation: dict | None = None, max_attempts: int = MAX_ATTEMPTS,
              validate_timeout_seconds: int = 8, min_coverage: int = 20) -> dict:
    """Draft -> compile -> validate, retrying with the specific failure on
    each miss, then hand off a working binary to the normal pipeline."""
    candidates = find_candidate_entries(header_paths)
    candidate = candidates[0] if candidates else {
        "name": "unknown", "return_type": "", "params": "", "header": ""}
    includes = [Path(h).name for h in header_paths]

    previous_error = None
    attempts = []
    build_result = None
    for attempt in range(1, max_attempts + 1):
        harness_src = llm_client.draft_harness(candidate, includes, previous_error)
        Path(harness_source_path).write_text(harness_src)
        build_result = builder_sidecar.build_target(snapshot_dir, build_command, isolation)

        record = {"attempt": attempt, "candidate": candidate["name"], "build_success": build_result["success"]}
        if not build_result["success"]:
            previous_error = f"compile failed:\n{build_result['stderr'][-1000:]}"
            record["error"] = previous_error
            attempts.append(record)
            continue

        coverage_result = validate_harness(
            harness_binary_path, isolation, validate_timeout_seconds, min_coverage)
        record["coverage"] = coverage_result["coverage"]
        record["coverage_ok"] = coverage_result["ok"]
        attempts.append(record)
        if coverage_result["ok"]:
            return {
                "ok": True, "attempts": len(attempts), "attempt_log": attempts,
                "candidate": candidate, "build": build_result,
                "coverage": coverage_result["coverage"],
            }
        previous_error = (
            f"the harness compiled but only reached coverage={coverage_result['coverage']} "
            f"(need >= {min_coverage}) - it likely returns before really calling into the "
            "target library, or the entry point it calls isn't the right one"
        )

    return {
        "ok": False, "attempts": len(attempts), "attempt_log": attempts,
        "candidate": candidate, "build": build_result, "coverage": 0,
    }
