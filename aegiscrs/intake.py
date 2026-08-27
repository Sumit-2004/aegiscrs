import hashlib
import shutil
import time
from pathlib import Path

from . import sandbox


def snapshot_source(repo_path: str, dest_root: str) -> dict:
    """Immutable source snapshot (plan §11.2). Excludes .git — git apply doesn't need it."""
    repo_path = Path(repo_path).resolve()
    dest_root = Path(dest_root)
    dest_root.mkdir(parents=True, exist_ok=True)
    snapshot_id = hashlib.sha256(f"{repo_path}-{time.time()!r}".encode()).hexdigest()[:16]
    snapshot_dir = dest_root / snapshot_id
    shutil.copytree(repo_path, snapshot_dir, ignore=shutil.ignore_patterns(".git"))
    return {"snapshot_id": snapshot_id, "snapshot_dir": str(snapshot_dir), "source": str(repo_path)}


def run_build(command: str, cwd: str, timeout: int = 300, isolation: dict | None = None) -> dict:
    """Runs an operator-supplied build/test command (plan §11.2 build manifest).

    Routed through sandbox.run so container isolation is a config decision, not
    a per-call-site one.
    """
    result = sandbox.run(command, cwd=cwd, timeout=timeout, isolation=isolation, shell=True)
    return {
        "command": command,
        "returncode": result.returncode,
        "stdout": result.stdout[-4000:],
        "stderr": result.stderr[-4000:],
        "success": result.returncode == 0,
    }
