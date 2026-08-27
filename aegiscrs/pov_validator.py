import hashlib
import os
import re

from . import sandbox

_ERROR_TYPE = re.compile(r"ERROR: \S+: ([\w-]+)")
_ACCESS = re.compile(r"^(READ|WRITE) of size \d+", re.MULTILINE)
_FRAME_FUNC = re.compile(r"#\d+ 0x[0-9a-f]+ in (\S+)")


def _crash_signature(stderr: str) -> str:
    # ASan/UBSan reports embed ASLR-randomized addresses that differ every run,
    # so hashing raw stderr would never dedup identical crashes. Signature is
    # built from the stable parts only: error type, access kind, and the
    # function-name sequence in the backtrace (no addresses, no file paths).
    error_type = _ERROR_TYPE.search(stderr)
    access = _ACCESS.search(stderr)
    frames = _FRAME_FUNC.findall(stderr)[:4]
    stable_text = f"{error_type.group(1) if error_type else ''}|{access.group(0) if access else ''}|{'|'.join(frames)}"
    return hashlib.sha256(stable_text.encode()).hexdigest()[:16]


def _run_once(binary_path: str, pov_path: str, isolation: dict | None = None) -> dict:
    result = sandbox.run([binary_path, pov_path], cwd=os.path.dirname(binary_path) or ".",
                         timeout=30, isolation=isolation)
    # sandbox.run's own timeout handling returns returncode=None when the
    # process never exited on its own - see its docstring. A real sanitizer
    # report is still fully flushed to the captured output by the time that
    # happens, so treat a timeout containing one as the crash it is, rather
    # than losing the reproduction to what looks like a plain hang.
    timed_out = result.returncode is None
    crashed = bool(_ERROR_TYPE.search(result.stderr)) if timed_out else result.returncode != 0
    signature = _crash_signature(result.stderr) if crashed else None
    return {"crashed": crashed, "returncode": result.returncode,
            "stderr": result.stderr[-4000:], "signature": signature, "timed_out": timed_out}


def confirm(binary_path: str, pov_path: str, required_reps: int = 2,
            isolation: dict | None = None) -> dict:
    """plan §11.7: require N identical reproductions (same crash signature) before confirming."""
    runs = [_run_once(binary_path, pov_path, isolation) for _ in range(required_reps)]
    signatures = {r["signature"] for r in runs if r["crashed"]}
    confirmed = len(signatures) == 1 and all(r["crashed"] for r in runs)
    return {"confirmed": confirmed, "runs": runs,
            "signature": next(iter(signatures)) if signatures else None}


def reproduces(binary_path: str, pov_path: str, isolation: dict | None = None) -> bool:
    return _run_once(binary_path, pov_path, isolation)["crashed"]
