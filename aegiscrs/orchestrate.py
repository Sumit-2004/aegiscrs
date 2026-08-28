import json
import sys
import time
from pathlib import Path

import yaml

from . import (
    builder_sidecar,
    code_context,
    controller,
    evidence,
    fuzzer,
    gate,
    harness_synth,
    llm_client,
    patch_generator,
    patch_retry,
    patch_robustness,
    pov_validator,
    regression,
    sandbox,
    sibling_scan,
    signal_extractor,
    static_analysis,
    target_selector,
)


def load_target(config_path: str) -> dict:
    return yaml.safe_load(Path(config_path).read_text())


def _rel_to(snapshot_dir: str, file_path: str) -> str:
    try:
        return Path(file_path).resolve().relative_to(Path(snapshot_dir).resolve()).as_posix()
    except ValueError:
        return Path(file_path).name


def run(config_path: str):
    cfg = load_target(config_path)
    base_dir = Path(config_path).resolve().parent
    repo_path = (base_dir / cfg["repo_path"]).resolve()
    work_root = (base_dir / "crs_scratch").resolve()
    work_root.mkdir(parents=True, exist_ok=True)

    # One isolation decision, applied to every subprocess that touches target code (plan section 15).
    isolation = sandbox.docker_isolation(cfg.get("isolation"), str(work_root))

    ctrl = controller.Controller(db_path=str(base_dir / "aegiscrs_state.db"))
    campaign_id = ctrl.start_campaign(cfg["name"])
    timings = {}
    t0 = time.time()
    print(f"[controller] campaign {campaign_id} started for target '{cfg['name']}'")
    mode = f"docker/{isolation['image']}" if isolation else "none (host subprocess)"
    print(f"[controller] isolation={mode}")

    # --- Vulnerable workspace: built once, never patched. Stays the regression baseline. ---
    vuln_snap = builder_sidecar.prepare(str(repo_path), str(work_root))
    ctrl.log(campaign_id, "intake", vuln_snap)
    vuln_dir = vuln_snap["snapshot_dir"]

    synth_result = None
    if cfg.get("synthesize_harness"):
        # BUILD-BRIEF Phase 4: no harness shipped with the target (or one is
        # being deliberately ignored) - AegisCRS writes its own before doing
        # anything else. The harness source is cleared first so a successful
        # build genuinely proves synthesis happened, not that the original
        # file was left alone.
        t = time.time()
        harness_source_path = str(Path(vuln_dir) / cfg["harness_source_path"])
        Path(harness_source_path).write_text("/* cleared: no harness provided - AegisCRS must synthesize one */\n")
        header_paths = [str(Path(vuln_dir) / h) for h in cfg.get("candidate_headers", [])]
        print(f"[harness-synth] no harness at {cfg['harness_source_path']} - synthesizing one")
        synth_result = harness_synth.synthesize(
            snapshot_dir=vuln_dir, header_paths=header_paths,
            harness_source_path=harness_source_path, build_command=cfg["build_command"],
            harness_binary_path=str(Path(vuln_dir) / cfg["harness_binary"]), isolation=isolation)
        timings["harness_synth_seconds"] = round(time.time() - t, 2)
        ctrl.log(campaign_id, "harness_synth", {
            "ok": synth_result["ok"], "attempts": synth_result["attempts"],
            "candidate": synth_result["candidate"].get("name"), "coverage": synth_result["coverage"]})
        print(f"[harness-synth] ok={synth_result['ok']} attempts={synth_result['attempts']} "
              f"candidate={synth_result['candidate'].get('name')} coverage={synth_result['coverage']} "
              f"in {timings['harness_synth_seconds']}s")
        if not synth_result["ok"]:
            ctrl.set_status(campaign_id, "harness_synthesis_failed")
            return
        build_result = synth_result["build"]
    else:
        build_result = builder_sidecar.build_target(vuln_dir, cfg["build_command"], isolation)

    ctrl.log(campaign_id, "intake", {"build": build_result})
    print(f"[intake] vulnerable snapshot at {vuln_dir} build_success={build_result['success']}")
    if not build_result["success"]:
        ctrl.set_status(campaign_id, "failed_build")
        print(build_result["stderr"])
        return
    vulnerable_binary = str(Path(vuln_dir) / cfg["harness_binary"])
    timings["build_seconds"] = round(time.time() - t0, 2)

    # --- Static analysis ---
    t = time.time()
    findings = static_analysis.run_semgrep(
        vuln_dir,
        cfg.get("static_analysis_paths", []),
        use_registry=cfg.get("semgrep_use_registry", False),
    )
    timings["static_analysis_seconds"] = round(time.time() - t, 2)
    ctrl.log(campaign_id, "static_analysis", {"count": len(findings)})
    print(f"[static-analysis] {len(findings)} finding(s) in {timings['static_analysis_seconds']}s")
    if not findings:
        print("[static-analysis] no findings - nothing to triage")
        ctrl.set_status(campaign_id, "no_findings")
        return

    # --- Ranking funnel (11.5): cheap score for all, LLM triage only for the top few ---
    t = time.time()
    entry_point = cfg.get("fuzz_entry_point", "LLVMFuzzerTestOneInput")
    candidates = target_selector.rank(findings, vuln_dir, entry_point, cfg.get("triage_top_n", 3))
    print(f"[ranker] prescored {len(findings)} finding(s), triaging top {len(candidates)}:")
    for c in candidates:
        f = c["finding"]
        print(f"          {f['id']} {f['cwe']:<12} {f.get('function', '?'):<16} "
              f"impact={c['impact']:.2f} reach={c['reachability']:.2f} "
              f"cost={c['cost']:.2f} prescore={c['prescore']:.2f}")

    trail = []
    injection_signals = []
    for c in candidates:
        raw_source = c["function"]["source"] if c["function"] else ""
        sanitized = signal_extractor.sanitize_source(raw_source)
        if sanitized["stripped"]:
            print(f"[signal-extractor] {c['finding']['id']}: redacted {len(sanitized['stripped'])} "
                  f"span(s) before this reached the model - see injection-signals.json")
            injection_signals.append({"finding_id": c["finding"]["id"], "stage": "triage",
                                      "stripped": sanitized["stripped"]})
        triage = llm_client.triage(c["finding"], sanitized["skeleton"])
        c["triage"] = triage
        c["confidence"] = float(triage.get("confidence", 0.0))
        c["priority"] = target_selector.priority(
            c["confidence"], c["reachability"], c["impact"], c["cost"])
        c["route"] = target_selector.route(c["confidence"])
        trail.append({
            "finding_id": c["finding"]["id"], "cwe": c["finding"]["cwe"],
            "impact": c["impact"], "reachability": c["reachability"], "cost": c["cost"],
            "confidence": c["confidence"], "priority": c["priority"], "route": c["route"],
        })
        print(f"[llm] {c['finding']['id']} confidence={c['confidence']:.2f} "
              f"priority={c['priority']:.2f} route={c['route']}")

    ctrl.log(campaign_id, "ranking", {"trail": trail})
    if injection_signals:
        ctrl.log(campaign_id, "signal_extractor", {"count": len(injection_signals)})
    timings["triage_seconds"] = round(time.time() - t, 2)

    survivors = [c for c in candidates if c["route"] != "discard"]
    if not survivors:
        ctrl.set_status(campaign_id, "discarded_low_confidence")
        print("[funnel] all candidates discarded: confidence below threshold")
        return

    # --- Confirm dynamically: try candidates in priority order, falling back to
    # the next one if fuzzing can't reproduce it. A cheap prescore heuristic can
    # rank a hardened call above the real bug (an unconditionally-reachable
    # false positive scoring higher than a real bug gated behind a branch), so
    # the funnel shouldn't give up on the whole campaign after one miss.
    ordered = sorted(survivors, key=lambda c: c["priority"], reverse=True)
    finding = function = selected = fuzz_result = confirmation = pov_path = None
    fuzz_seconds_total = 0.0
    for candidate in ordered:
        cand_finding = candidate["finding"]
        cand_function = candidate["function"]
        if cand_function is None:
            print(f"[funnel] {cand_finding['id']}: no enclosing function context - skipping")
            continue
        print(f"[funnel] trying {cand_finding['id']} (priority={candidate['priority']:.2f})")
        if candidate["route"] == "direct_pov":
            # A standalone direct-PoV-without-fuzzing generator is roadmap (plan section 10),
            # not built for the MVP - high-confidence findings still go through the
            # same timeboxed fuzz-confirm path below rather than being skipped.
            print("[funnel] high confidence, but direct-PoV path isn't built yet - routing to fuzz-confirm anyway")

        t = time.time()
        corpus_dir = str(work_root / f"{campaign_id}_{cand_finding['id']}_corpus")
        artifact_prefix = str(work_root / f"{campaign_id}_{cand_finding['id']}_crash_")
        seed_dir = cfg.get("seed_corpus")
        if seed_dir:
            seeded = fuzzer.seed_corpus(corpus_dir, str((base_dir / seed_dir).resolve()))
            print(f"[fuzzer] seeded corpus with {seeded} file(s) from {seed_dir}")
        cand_fuzz_result = fuzzer.run_campaign(
            vulnerable_binary, corpus_dir, cfg.get("fuzz_timeout_seconds", 60),
            artifact_prefix, isolation)
        elapsed = time.time() - t
        fuzz_seconds_total += elapsed
        ctrl.log(campaign_id, "fuzzer", {
            "finding_id": cand_finding["id"], "found_crash": cand_fuzz_result["found_crash"],
            "crashes": cand_fuzz_result["crashes"]})
        print(f"[fuzzer] {cand_finding['id']} found_crash={cand_fuzz_result['found_crash']} "
              f"in {round(elapsed, 2)}s")
        if not cand_fuzz_result["found_crash"]:
            continue

        cand_pov_path = cand_fuzz_result["crashes"][0]
        cand_confirmation = pov_validator.confirm(vulnerable_binary, cand_pov_path, isolation=isolation)
        ctrl.log(campaign_id, "pov_validator", {
            "finding_id": cand_finding["id"], "confirmed": cand_confirmation["confirmed"],
            "signature": cand_confirmation["signature"]})
        print(f"[pov-validator] {cand_finding['id']} confirmed={cand_confirmation['confirmed']} "
              f"signature={cand_confirmation['signature']}")
        if not cand_confirmation["confirmed"]:
            continue

        # Attribution check: every candidate's fuzz campaign runs the SAME harness
        # binary from the SAME seed corpus, so a crash found while "confirming"
        # candidate X can genuinely be a different bug entirely - the seed corpus
        # doesn't know which candidate it's supposedly testing. Resolve the crash's
        # backtrace (offline, via addr2line - sandbox.py disables ASan's own
        # in-process symbolizer, see its docstring) and re-attribute to whichever
        # finding's function the crash actually occurred in, if that's not the one
        # this campaign was nominally run for. Patching the wrong function is worse
        # than useless: it fixes nothing and burns a full retry budget finding that out.
        crash_report = cand_confirmation["runs"][0]["stderr"]
        resolved_frames = pov_validator.resolve_frames(crash_report)
        if cand_function and cand_function["name"] not in resolved_frames:
            rematch = next((f for f in findings
                            if f["id"] != cand_finding["id"] and f.get("function") in resolved_frames),
                           None)
            if rematch is not None:
                print(f"[funnel] crash backtrace ({', '.join(resolved_frames[:3])}) doesn't match "
                      f"{cand_finding['id']}'s function '{cand_function['name']}' - "
                      f"re-attributing to {rematch['id']} ({rematch['function']})")
                cand_finding = rematch
                cand_function = code_context.extract_function(rematch["file"], rematch["line"])

        finding, function, selected = cand_finding, cand_function, candidate
        fuzz_result, confirmation, pov_path = cand_fuzz_result, cand_confirmation, cand_pov_path
        break

    timings["fuzz_seconds"] = round(fuzz_seconds_total, 2)
    if finding is None:
        ctrl.set_status(campaign_id, "no_crash_found")
        print("[funnel] no candidate's crash could be confirmed - campaign ends here")
        return

    # --- Sibling-bug sweep: same rule id, elsewhere in the codebase. Reuses the
    # findings and prescore already computed for ranking - no new Semgrep run,
    # no model call. A confirmed bug on a legacy C codebase is rarely unique.
    t = time.time()
    sibling_findings = sibling_scan.find_siblings(findings, finding, vuln_dir, entry_point)
    timings["sibling_scan_seconds"] = round(time.time() - t, 2)
    ctrl.log(campaign_id, "sibling_scan", {"count": len(sibling_findings)})
    print(f"[sibling-scan] {len(sibling_findings)} other finding(s) share rule "
          f"'{finding['category']}' in {timings['sibling_scan_seconds']}s")
    for s in sibling_findings[:5]:
        print(f"          {s['finding_id']} {s['file']}:{s['line']} {s['function']:<16} "
              f"prescore={s['prescore']:.2f}")

    # --- Patch: model returns a function; bounded retry on build/apply/PoV failure
    # (BUILD-BRIEF Phase 2). The model is re-prompted with the specific failure text;
    # whether an attempt succeeded is always decided by a real diff/build/PoV result.
    t = time.time()
    crash_report = confirmation["runs"][0]["stderr"]
    rel_path = _rel_to(vuln_dir, finding["file"])
    original_text = Path(finding["file"]).read_text()

    # The model only ever sees the sanitized skeleton; build_diff below always
    # splices against original_text, so a stripped comment never leaks into the
    # actual patch - only into what the model was allowed to read.
    patch_sanitized = signal_extractor.sanitize_source(function["source"])
    if patch_sanitized["stripped"]:
        print(f"[signal-extractor] {finding['id']}: redacted {len(patch_sanitized['stripped'])} "
              f"span(s) before patch drafting - see injection-signals.json")
        injection_signals.append({"finding_id": finding["id"], "stage": "patch_drafting",
                                  "stripped": patch_sanitized["stripped"]})
    function_source_for_model = patch_sanitized["skeleton"]

    previous_attempt = None
    attempts_log = []
    fix = {}
    diff_result = {"ok": False, "diff": "", "reason": "no attempt made"}
    apply_result = None
    patch_dir = None
    patched_binary = None
    constraint_result = None

    pov_bytes = Path(pov_path).read_bytes()

    for attempt in range(1, patch_retry.MAX_ATTEMPTS + 1):
        fix = llm_client.draft_function_fix(
            finding, function_source_for_model, crash_report,
            attempt=attempt, previous_attempt=previous_attempt, pov_bytes=pov_bytes)
        diff_result = patch_generator.build_diff(
            rel_path, original_text, function["start_line"], function["end_line"],
            fix["function_source"])

        apply_result = None
        patch_dir = None
        patched_binary = None
        pov_still_crashes = None
        constraint_violation = False

        if diff_result["ok"]:
            constraint_result = patch_generator.validate_constraints(
                diff_result["diff"], cfg.get("forbidden_patch_paths", []))
            if not constraint_result["ok"]:
                # Not a retryable condition (BUILD-BRIEF Phase 2 scope): a policy
                # violation is a hard reject, never something to re-prompt the model on.
                constraint_violation = True
            else:
                patch_snap = builder_sidecar.prepare(str(repo_path), str(work_root))
                patch_dir = patch_snap["snapshot_dir"]
                apply_result = builder_sidecar.apply_patch_build(
                    patch_dir, diff_result["diff"], cfg["build_command"], isolation)
                patched_binary = str(Path(patch_dir) / cfg["harness_binary"])
                if apply_result["applied"] and (apply_result.get("build") or {}).get("success"):
                    pov_still_crashes = pov_validator.reproduces(patched_binary, pov_path, isolation)

        failure_reason = None if constraint_violation else patch_retry.classify_failure(
            diff_result, apply_result, pov_still_crashes)
        attempt_record = {
            "attempt": attempt, "diff_ok": diff_result["ok"],
            "constraint_violation": constraint_violation,
            "applied": (apply_result or {}).get("applied"),
            "build_success": ((apply_result or {}).get("build") or {}).get("success"),
            "pov_still_crashes": pov_still_crashes, "failure_reason": failure_reason,
        }
        attempts_log.append(attempt_record)
        ctrl.log(campaign_id, "patch_attempt", attempt_record)
        print(f"[patch] attempt {attempt}/{patch_retry.MAX_ATTEMPTS}: "
              f"{'ok' if failure_reason is None and not constraint_violation else failure_reason or 'constraint violation'}")

        if constraint_violation or failure_reason is None:
            break
        if not patch_retry.should_retry(attempt, failure_reason):
            break
        previous_attempt = {"function_source": fix["function_source"], "failure_reason": failure_reason}

    timings["patch_seconds"] = round(time.time() - t, 2)
    ctrl.log(campaign_id, "patch_generator", {
        "ok": diff_result["ok"], "reason": diff_result["reason"], "attempts": len(attempts_log),
        "explanation": fix.get("explanation", "")[:500]})
    print(f"[patch] diff_built={diff_result['ok']} after {len(attempts_log)} attempt(s) "
          f"({len(diff_result['diff'].splitlines())} lines) {diff_result['reason']}")

    if not diff_result["ok"]:
        ctrl.set_status(campaign_id, "patch_not_generated")
        return
    patch_diff = diff_result["diff"]

    print(f"[patch] constraints ok={constraint_result['ok']} "
          f"files={constraint_result['touched_files']} reasons={constraint_result['reasons']}")

    # A constraint violation, or every retry exhausted without a clean apply+build,
    # is a hard reject: skip regression (there is nothing valid to regress against)
    # and write the evidence bundle straight from what the attempts show.
    build_ok = (apply_result or {}).get("applied") and (apply_result.get("build") or {}).get("success")
    if not constraint_result["ok"] or not build_ok:
        gate_result = gate.accept_patch(apply_result or {"applied": False, "build": None},
                                        {}, constraint_result)
        ctrl.log(campaign_id, "gate", gate_result)
        print(f"[gate] accepted=False (rejected pre-regression) reasons={gate_result['reasons']}")
        timings["total_seconds"] = round(time.time() - t0, 2)
        bundle_dir = evidence.write_bundle(
            output_dir=str(base_dir / "evidence"), campaign_id=campaign_id, finding=finding,
            pov_path=pov_path, vulnerable_binary=vulnerable_binary, patched_binary=patched_binary or "",
            diff_text=patch_diff, regression_result={}, gate_result=gate_result,
            robustness_result=None, decision_trail=trail, timings=timings, patch_attempts=attempts_log,
            harness_synth_result=synth_result, injection_signals=injection_signals,
            sibling_findings=sibling_findings)
        ctrl.set_status(campaign_id, "rejected")
        print(f"[evidence] bundle written to {bundle_dir}")
        return

    robustness_result = None
    if apply_result["applied"] and (apply_result.get("build") or {}).get("success"):
        t = time.time()
        robustness_result = patch_robustness.check(
            patched_binary=patched_binary, finding=finding, patch_diff=patch_diff,
            original_pov_path=pov_path,
            work_dir=str(work_root / f"{campaign_id}_robustness"), isolation=isolation)
        timings["robustness_seconds"] = round(time.time() - t, 2)
        ctrl.log(campaign_id, "patch_robustness", {
            "generalizes": robustness_result["generalizes"],
            "variants_tested": len(robustness_result["variants"]),
        })
        print(f"[robustness] generalizes={robustness_result['generalizes']} "
              f"variants_tested={len(robustness_result['variants'])} "
              f"fuzz_reseed_ran={robustness_result['fuzz_reseed'] is not None}")

    regression_result = regression.run_sequence(
        vulnerable_binary=vulnerable_binary, patched_binary=patched_binary, pov_path=pov_path,
        test_command=cfg["test_command"], snapshot_dir=patch_dir, isolation=isolation)
    ctrl.log(campaign_id, "regression", regression_result)
    summary = {k: (v if not isinstance(v, dict) else v.get("success"))
               for k, v in regression_result.items()}
    print(f"[regression] {json.dumps(summary)}")

    gate_result = gate.accept_patch(apply_result, regression_result, constraint_result, robustness_result)
    ctrl.log(campaign_id, "gate", gate_result)
    print(f"[gate] accepted={gate_result['accepted']} reasons={gate_result['reasons']}")

    timings["total_seconds"] = round(time.time() - t0, 2)
    bundle_dir = evidence.write_bundle(
        output_dir=str(base_dir / "evidence"), campaign_id=campaign_id, finding=finding,
        pov_path=pov_path, vulnerable_binary=vulnerable_binary, patched_binary=patched_binary,
        diff_text=patch_diff, regression_result=regression_result, gate_result=gate_result,
        robustness_result=robustness_result, decision_trail=trail, timings=timings,
        patch_attempts=attempts_log, harness_synth_result=synth_result,
        injection_signals=injection_signals, sibling_findings=sibling_findings)
    ctrl.set_status(campaign_id, "accepted" if gate_result["accepted"] else "rejected")
    print(f"[evidence] bundle written to {bundle_dir}")
    print(f"[timing] {json.dumps(timings)}")


if __name__ == "__main__":
    default_config = Path(__file__).resolve().parent.parent / "config" / "target.example.yaml"
    run(sys.argv[1] if len(sys.argv) > 1 else str(default_config))
