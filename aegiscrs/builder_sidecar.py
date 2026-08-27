from pathlib import Path

from . import intake, pov_validator, sandbox


def prepare(repo_path: str, work_root: str) -> dict:
    return intake.snapshot_source(repo_path, work_root)


def build_target(snapshot_dir: str, build_command: str, isolation: dict | None = None) -> dict:
    return intake.run_build(build_command, snapshot_dir, isolation=isolation)


def apply_patch_build(snapshot_dir: str, diff_text: str, build_command: str,
                      isolation: dict | None = None) -> dict:
    """plan §11.9: apply-patch-build. git apply works without .git present (no --index)."""
    patch_file = Path(snapshot_dir) / "_aegiscrs_patch.diff"
    # newline="" is load-bearing: the default translates LF to CRLF on
    # Windows, which corrupts every context line and makes `git apply`
    # reject an otherwise valid patch.
    patch_file.write_text(diff_text, newline="")
    apply_result = sandbox.run(["git", "apply", "--whitespace=fix", patch_file.name],
                               cwd=snapshot_dir, timeout=60, isolation=isolation)
    if apply_result.returncode != 0:
        return {"applied": False, "apply_stderr": apply_result.stderr, "build": None}
    return {"applied": True, "apply_stderr": "",
            "build": build_target(snapshot_dir, build_command, isolation)}


def run_pov(binary_path: str, pov_path: str, isolation: dict | None = None) -> dict:
    return pov_validator.confirm(binary_path, pov_path, isolation=isolation)


def run_test(snapshot_dir: str, test_command: str, isolation: dict | None = None) -> dict:
    return intake.run_build(test_command, snapshot_dir, isolation=isolation)
