"""Single execution chokepoint for every subprocess the CRS runs (plan §15).

Everything that executes target code — builds, tests, the fuzzer, PoV replays —
goes through run() so isolation is one decision in one place instead of a
property each call site has to remember. With isolation=None the behaviour is
identical to a plain subprocess.run (the default, and what the local demo uses).

Docker mode mounts `mount_root` at the *same absolute path* inside the
container, so snapshot dirs, corpus dirs and PoV paths need no rewriting: a
path that works on the host works unchanged inside the sandbox.
"""
import os
import subprocess


def _env_with_asan_defaults() -> dict:
    """Leak-only reports would otherwise dominate: a target that leaks on any
    'incomplete' sequence (e.g. this repo's own uaf_target - open without a
    matching close) gets flagged by LeakSanitizer far more easily than the
    memory-corruption bug actually being hunted for, so fuzzing/replay runs
    never even reach it. Respects an operator's explicit choice if one is
    already set. Same policy docker/Dockerfile.build already bakes in at the
    image level for the container path.
    """
    env = os.environ.copy()
    existing = env.get("ASAN_OPTIONS", "")
    if "detect_leaks=" not in existing:
        env["ASAN_OPTIONS"] = f"{existing}:detect_leaks=0" if existing else "detect_leaks=0"
    return env


def docker_isolation(cfg: dict | None, mount_root: str) -> dict | None:
    """Build an isolation spec from the target config's `isolation:` block."""
    if not cfg or cfg.get("mode", "none") == "none":
        return None
    return {
        "mode": "docker",
        "image": cfg.get("image", "aegiscrs-build"),
        "network": cfg.get("network", "none"),
        "cpus": cfg.get("cpus"),
        "memory": cfg.get("memory"),
        "mount_root": mount_root,
    }


def _docker_prefix(isolation: dict, cwd: str, env: dict) -> list[str]:
    root = isolation["mount_root"]
    argv = ["docker", "run", "--rm", f"--network={isolation.get('network', 'none')}",
            "-v", f"{root}:{root}", "-w", cwd, "-e", f"ASAN_OPTIONS={env['ASAN_OPTIONS']}"]
    if isolation.get("cpus"):
        argv.append(f"--cpus={isolation['cpus']}")
    if isolation.get("memory"):
        argv.append(f"--memory={isolation['memory']}")
    argv.append(isolation["image"])
    return argv


def run(command, cwd: str, timeout: int, isolation: dict | None = None,
        shell: bool = False) -> subprocess.CompletedProcess:
    """command: a shell string (shell=True) or an argv list (shell=False)."""
    env = _env_with_asan_defaults()
    if isolation is None:
        return subprocess.run(command, shell=shell, cwd=cwd, capture_output=True,
                              text=True, timeout=timeout, env=env)

    inner = ["bash", "-lc", command] if shell else list(command)
    argv = _docker_prefix(isolation, cwd, env) + inner
    # shell=False always: the container's bash handles shell syntax, the host's never does.
    return subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=timeout)
