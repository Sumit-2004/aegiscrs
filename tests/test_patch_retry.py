"""Unit tests for the bounded retry decision logic (BUILD-BRIEF Phase 2).

Model-free on purpose: classify_failure/should_retry only ever look at real
diff/apply/build/PoV results, so they can be verified without a live model.
"""
from aegiscrs import patch_retry

DIFF_OK = {"ok": True, "diff": "--- a/f.c\n+++ b/f.c\n", "reason": ""}
DIFF_UNCHANGED = {"ok": False, "diff": "", "reason": "model returned the function unchanged"}
APPLIED_BUILT = {"applied": True, "build": {"success": True}}
APPLY_FAILED = {"applied": False, "apply_stderr": "patch does not apply", "build": None}
BUILD_FAILED = {"applied": True, "build": {"success": False, "stderr": "undefined reference to foo"}}


def test_classify_failure_none_when_everything_succeeds():
    assert patch_retry.classify_failure(DIFF_OK, APPLIED_BUILT, False) is None


def test_classify_failure_reports_unchanged_diff():
    reason = patch_retry.classify_failure(DIFF_UNCHANGED, None, None)
    assert reason is not None and "unchanged" in reason


def test_classify_failure_reports_apply_failure():
    reason = patch_retry.classify_failure(DIFF_OK, APPLY_FAILED, None)
    assert reason is not None and "failed to apply" in reason


def test_classify_failure_reports_build_failure():
    reason = patch_retry.classify_failure(DIFF_OK, BUILD_FAILED, None)
    assert reason is not None and "failed to build" in reason


def test_classify_failure_reports_pov_still_crashing():
    reason = patch_retry.classify_failure(DIFF_OK, APPLIED_BUILT, True)
    assert reason is not None and "still crashes" in reason


def test_classify_failure_none_when_diff_ok_and_nothing_built_yet():
    # apply_result=None means "haven't gotten that far yet", not a failure.
    assert patch_retry.classify_failure(DIFF_OK, None, None) is None


def test_should_retry_true_below_cap_with_a_failure():
    assert patch_retry.should_retry(1, "some failure", max_attempts=3)
    assert patch_retry.should_retry(2, "some failure", max_attempts=3)


def test_should_retry_false_at_cap():
    assert not patch_retry.should_retry(3, "some failure", max_attempts=3)


def test_should_retry_false_on_success():
    assert not patch_retry.should_retry(1, None, max_attempts=3)
