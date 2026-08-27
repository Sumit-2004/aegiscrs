from . import intake, pov_validator


def run_sequence(vulnerable_binary: str, patched_binary: str, pov_path: str,
                 test_command: str, snapshot_dir: str, isolation: dict | None = None) -> dict:
    """plan §11.10, steps 1-3. Sanitizer checking is implicit: both binaries are built
    with ASan, so the PoV-reproduction check *is* the sanitizer check here."""
    return {
        "pov_reproduces_on_vulnerable": pov_validator.reproduces(vulnerable_binary, pov_path, isolation),
        "pov_reproduces_on_patched": pov_validator.reproduces(patched_binary, pov_path, isolation),
        "existing_tests": intake.run_build(test_command, snapshot_dir, isolation=isolation),
    }
