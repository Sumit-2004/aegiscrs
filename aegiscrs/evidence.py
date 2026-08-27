import hashlib
import json
import shutil
import subprocess
from pathlib import Path


def _sha256_file(path: str) -> str:
    if not path:
        return ""
    p = Path(path)
    if not p.exists():
        return ""
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _tool_versions() -> dict:
    """Recorded so a reviewer can reproduce the run (plan section 15)."""
    versions = {}
    for name, argv in (("clang", ["clang", "--version"]),
                       ("semgrep", ["semgrep", "--version"]),
                       ("git", ["git", "--version"])):
        try:
            out = subprocess.run(argv, capture_output=True, text=True, timeout=20)
            versions[name] = out.stdout.strip().splitlines()[0] if out.stdout.strip() else "unknown"
        except (OSError, subprocess.SubprocessError, IndexError):
            versions[name] = "unavailable"
    return versions


def write_bundle(output_dir: str, campaign_id: str, finding: dict, pov_path: str,
                 vulnerable_binary: str, patched_binary: str, diff_text: str,
                 regression_result: dict, gate_result: dict,
                 robustness_result: dict | None = None,
                 decision_trail: list | None = None,
                 timings: dict | None = None,
                 patch_attempts: list | None = None,
                 harness_synth_result: dict | None = None,
                 injection_signals: list | None = None,
                 sibling_findings: list | None = None) -> str:
    """plan section 16: evidence bundle - the artifact that turns an LLM suggestion
    into a reproducible engineering result."""
    out = Path(output_dir) / campaign_id
    out.mkdir(parents=True, exist_ok=True)

    (out / "static-finding.json").write_text(json.dumps(finding, indent=2))
    (out / "patch.diff").write_text(diff_text, newline="")
    if pov_path and Path(pov_path).exists():
        shutil.copy(pov_path, out / "pov-input.bin")
    (out / "regression.log").write_text(json.dumps(regression_result, indent=2))
    (out / "decision.json").write_text(json.dumps(gate_result, indent=2))
    (out / "tool-versions.txt").write_text(
        "\n".join(f"{k}: {v}" for k, v in _tool_versions().items()) + "\n")
    if robustness_result is not None:
        (out / "variant-povs.json").write_text(json.dumps(robustness_result, indent=2))
    if decision_trail is not None:
        # Why this candidate and not the others - the funnel's audit trail (11.5).
        (out / "decision-trail.json").write_text(json.dumps(decision_trail, indent=2))
    if timings is not None:
        (out / "timings.json").write_text(json.dumps(timings, indent=2))
    if patch_attempts is not None:
        # Every drafting attempt, success or not - the bounded retry loop's audit trail (BUILD-BRIEF Phase 2).
        (out / "patch-attempts.json").write_text(json.dumps(patch_attempts, indent=2))
    if harness_synth_result is not None:
        # No harness shipped with the target - proof AegisCRS built its own,
        # including every failed attempt (BUILD-BRIEF Phase 4).
        (out / "harness-synthesis.json").write_text(json.dumps(harness_synth_result, indent=2))
    if injection_signals is not None:
        # Exactly what was redacted from source before the model ever saw it,
        # and why (BUILD-BRIEF Phase 5). Empty list is still written - "we
        # checked and found nothing" is different from "we never checked".
        (out / "injection-signals.json").write_text(json.dumps(injection_signals, indent=2))
    if sibling_findings is not None:
        # Other findings sharing the confirmed bug's rule id, ranked and left
        # unpatched - "we checked and found none" is different from "we never
        # checked" (same reasoning as injection-signals.json above).
        (out / "sibling-findings.json").write_text(json.dumps(sibling_findings, indent=2))

    manifest = {
        "campaign_id": campaign_id,
        "finding_id": finding.get("id"),
        "cwe": finding.get("cwe"),
        "vulnerable_build_sha256": _sha256_file(vulnerable_binary),
        "patched_build_sha256": _sha256_file(patched_binary),
        "pov_sha256": _sha256_file(pov_path),
        "patch_sha256": hashlib.sha256(diff_text.encode()).hexdigest(),
        "accepted": gate_result.get("accepted"),
        "rejection_reasons": gate_result.get("reasons", []),
        "sibling_findings_count": len(sibling_findings) if sibling_findings is not None else None,
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2))
    return str(out)
