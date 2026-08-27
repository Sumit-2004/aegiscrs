"""Bounded retry decision logic for patch drafting (BUILD-BRIEF Phase 2).

Model-free by design: given the outcome of one attempt, decide whether a
retry is warranted and what went wrong. The "did it work" verdict always
comes from a real build_diff/apply/build/PoV result, never the model's own
opinion of its patch - the retry loop asks the model to try again, it never
asks the model whether it succeeded.
"""

MAX_ATTEMPTS = 3


def classify_failure(diff_result: dict, apply_result: dict | None,
                     pov_still_crashes: bool | None) -> str | None:
    """None means the attempt succeeded so far. Otherwise a short, model-facing
    description of what specifically needs fixing on the next attempt."""
    if not diff_result.get("ok"):
        return f"the function was rejected: {diff_result.get('reason', 'unknown reason')}"
    if apply_result is None:
        return None
    if not apply_result.get("applied"):
        stderr = (apply_result.get("apply_stderr") or "").strip()[:500]
        return f"the patch failed to apply: {stderr}" if stderr else "the patch failed to apply"
    build = apply_result.get("build") or {}
    if not build.get("success"):
        stderr = (build.get("stderr") or "").strip()[:500]
        return f"the patched target failed to build: {stderr}" if stderr else "the patched target failed to build"
    if pov_still_crashes:
        return "the original proof-of-vulnerability input still crashes the patched binary"
    return None


def should_retry(attempt_number: int, failure_reason: str | None, max_attempts: int = MAX_ATTEMPTS) -> bool:
    return failure_reason is not None and attempt_number < max_attempts
