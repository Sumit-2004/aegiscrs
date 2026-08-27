def accept_patch(apply_result: dict, regression_result: dict, constraint_result: dict,
                 robustness_result: dict | None = None) -> dict:
    """plan section 12: deterministic AND gate. No model judgment involved.

    Every failure path is a rejection with a preserved reason - there is no
    branch here that accepts on partial evidence.
    """
    reasons = []

    if not constraint_result.get("ok"):
        reasons.extend(constraint_result.get("reasons", []))

    if not apply_result.get("applied"):
        reasons.append("patch did not apply")
        # Regression checks never ran, so reporting them as failures would be
        # misleading noise in the evidence bundle. The rejection already stands.
        return {"accepted": False, "reasons": reasons}

    build = apply_result.get("build") or {}
    if not build.get("success"):
        reasons.append("patched target failed to build")

    if not regression_result.get("pov_reproduces_on_vulnerable"):
        reasons.append("original PoV did not reproduce on vulnerable binary (invalid baseline)")
    if regression_result.get("pov_reproduces_on_patched"):
        reasons.append("PoV still reproduces on patched binary")
    if not regression_result.get("existing_tests", {}).get("success"):
        reasons.append("existing regression tests failed")

    if robustness_result is not None and not robustness_result.get("generalizes", True):
        reasons.append("patch does not generalize: an adversarial variant PoV reproduces "
                       "on the patched binary (section 11.11)")

    return {"accepted": len(reasons) == 0, "reasons": reasons}
