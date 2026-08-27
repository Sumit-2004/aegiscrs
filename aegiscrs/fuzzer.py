import glob
import os
import shutil

from . import sandbox


def seed_corpus(corpus_dir: str, seed_dir: str | None) -> int:
    """Copy starting inputs into the corpus dir (BUILD-BRIEF Phase 3).

    Some targets reject structurally-invalid input before ever reaching the
    interesting code (libpng bails at the header on garbage), so a blind
    campaign with an empty corpus may never get past the first few bytes.
    Returns how many seed files were copied; 0/missing seed_dir is not an
    error - plenty of targets fuzz fine from nothing.
    """
    if not seed_dir or not os.path.isdir(seed_dir):
        return 0
    os.makedirs(corpus_dir, exist_ok=True)
    count = 0
    for name in sorted(os.listdir(seed_dir)):
        src = os.path.join(seed_dir, name)
        if os.path.isfile(src):
            shutil.copy(src, os.path.join(corpus_dir, name))
            count += 1
    return count


def run_campaign(harness_binary: str, corpus_dir: str, timeout_seconds: int,
                 artifact_prefix: str, isolation: dict | None = None) -> dict:
    """Timeboxed libFuzzer+ASan/UBSan campaign (plan §11.6)."""
    os.makedirs(corpus_dir, exist_ok=True)
    cmd = [harness_binary, f"-max_total_time={timeout_seconds}",
           f"-artifact_prefix={artifact_prefix}", corpus_dir]
    result = sandbox.run(cmd, cwd=os.path.dirname(harness_binary) or ".",
                         timeout=timeout_seconds + 30, isolation=isolation)
    crashes = sorted(glob.glob(f"{artifact_prefix}*"))
    return {
        "returncode": result.returncode,
        "stderr_tail": result.stderr[-4000:],
        "crashes": crashes,
        "found_crash": len(crashes) > 0,
    }
