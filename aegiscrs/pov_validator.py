import hashlib
import os
import re
import subprocess

from . import sandbox

_ERROR_TYPE = re.compile(r"ERROR: \S+: ([\w-]+)")
_ACCESS = re.compile(r"^(READ|WRITE) of size \d+", re.MULTILINE)
# sandbox.py runs with ASAN_OPTIONS=symbolize=0 by default (its own in-process
# symbolizer shells out to llvm-symbolizer, which deadlocks on this toolchain) - so
# frames come back as "binary+0xOFFSET", not "in function_name". The offset is
# still perfectly stable across runs (only the ASLR base address varies, never the
# file-relative offset for a PIE binary), which is what dedup actually needs.
_FRAME_OFFSET = re.compile(r"#\d+ 0x[0-9a-f]+\s+\(([^()+]+)\+(0x[0-9a-f]+)\)")


def _crash_signature(stderr: str) -> str:
    # ASan/UBSan reports embed ASLR-randomized addresses that differ every run,
    # so hashing raw stderr would never dedup identical crashes. Signature is
    # built from the stable parts only: error type, access kind, and the
    # binary+offset sequence in the backtrace (no ASLR-varying base addresses).
    error_type = _ERROR_TYPE.search(stderr)
    access = _ACCESS.search(stderr)
    frames = _FRAME_OFFSET.findall(stderr)[:4]
    frame_text = "|".join(f"{binary}:{offset}" for binary, offset in frames)
    stable_text = f"{error_type.group(1) if error_type else ''}|{access.group(0) if access else ''}|{frame_text}"
    return hashlib.sha256(stable_text.encode()).hexdigest()[:16]


def resolve_frames(stderr: str, limit: int = 6) -> list[str]:
    """Resolve the unsymbolized backtrace to function names via addr2line, run
    offline and separately from crash capture itself - decouples "did it crash,
    with what stable signature" (never blocked on a symbolizer) from "what
    function is this," which is only needed for candidate attribution and can
    tolerate addr2line being slow, missing, or occasionally wrong.
    """
    names = []
    for binary, offset in _FRAME_OFFSET.findall(stderr)[:limit]:
        try:
            out = subprocess.run(["addr2line", "-f", "-e", binary, offset],
                                 capture_output=True, text=True, timeout=5)
            names.append(out.stdout.splitlines()[0].strip() if out.stdout else "?")
        except (OSError, subprocess.SubprocessError):
            names.append("?")
    return names


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
    # Keep the FRONT 4000 chars, not the last: unlike a plain traceback, an ASan
    # report's useful content (error header + backtrace) is at the top, and the
    # tail is a fixed-size shadow-byte legend that's identical across every crash
    # and tells you nothing about this one. The last-4000 slice was silently
    # discarding the two frames that matter (the crash site and its caller) on any
    # report over ~4KB, starving both the model's patch prompt and backtrace-based
    # candidate attribution of the one thing they actually needed.
    return {"crashed": crashed, "returncode": result.returncode,
            "stderr": result.stderr[:4000], "signature": signature, "timed_out": timed_out}


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
