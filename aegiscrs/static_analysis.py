import json
import subprocess
from pathlib import Path

from . import code_context

CUSTOM_RULES_DIR = Path(__file__).resolve().parent.parent / "config" / "semgrep_rules"


def run_semgrep(target_dir: str, paths: list[str], use_registry: bool = False) -> list[dict]:
    """Normalized Semgrep findings (plan §11.3).

    `--config auto` fetches rules from semgrep.dev at run time, so it is OFF by
    default: an air-gapped run (and any demo with the network cable pulled)
    would otherwise fail at the first pipeline stage. Local rule packs only
    unless a target explicitly opts in with semgrep_use_registry: true.

    `--no-git-ignore`: Semgrep's default is to scan only git-tracked files,
    treating any untracked-and-gitignored file as excluded. Every target this
    scans is a fresh, git-untracked copy under crs_scratch/ - which is itself
    gitignored - so without this flag Semgrep silently scans zero files and
    the funnel gets "no findings" instead of the real result.
    """
    scan_paths = [str(Path(target_dir) / p) for p in paths] or [target_dir]
    cmd = ["semgrep", "--config", str(CUSTOM_RULES_DIR), "--no-git-ignore"]
    if use_registry:
        cmd += ["--config", "auto"]
    cmd += ["--json", "--quiet", "--metrics=off", *scan_paths]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    try:
        raw = json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        raw = {"results": []}
    return [_normalize(r, i) for i, r in enumerate(raw.get("results", []))]


def _normalize(result: dict, idx: int) -> dict:
    path = result.get("path", "")
    start = result.get("start", {})
    extra = result.get("extra", {})
    metadata = extra.get("metadata", {})
    cwe = metadata.get("cwe")
    if isinstance(cwe, list):
        cwe = cwe[0] if cwe else None
    if isinstance(cwe, str) and ":" in cwe:
        cwe = cwe.split(":")[0].strip()   # "CWE-787: Out-of-bounds Write" -> "CWE-787"

    function = code_context.extract_function(path, start.get("line", 0))
    return {
        "id": f"finding-{idx:03d}",
        "file": path,
        "line": start.get("line", 0),
        "function": function["name"] if function else "unknown",
        "category": result.get("check_id", "unknown"),
        "cwe": cwe or "CWE-unknown",
        "severity": extra.get("severity", "medium").lower(),
        "evidence": extra.get("message", ""),
        "tool": "semgrep",
    }
