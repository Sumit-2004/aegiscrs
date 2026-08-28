"""OS-wide target auto-discovery (roadmap item, sits *above* the core CRS).

Every real target this project has run (zlib_target, libpng_target,
libpng16_target, uaf_target) needed the same three things hand-assembled by a
person: a source tree, a build command, and (for harness_synth.py) a header
list. orchestrate.run() itself never cared how those three things were
produced - it only needs a target-*.yaml pointing at them. This module
automates that assembly step for a Debian-lineage OS (BOSS/Maya/Ubuntu all
qualify, same dpkg/apt tooling): walk installed library packages, pull
matching source via `apt-get source`, detect a buildable shape, and emit a
target-*.yaml ready to hand to `python -m aegiscrs.orchestrate`.

This deliberately does not try to solve arbitrary upstream build systems
generically - that is an unsolved problem industry-wide (it is most of what
OSS-Fuzz integration effort per project actually is). Instead it generalizes
the one build shape validated by hand on all four real targets this project
already shipped: compile every top-level .c file directly against clang with
ASan+libFuzzer, no configure/cmake/autotools step. That covers flat,
dependency-light C libraries - which is what most base-OS libraries actually
are - and fails loudly (a normal `failed_build` gate outcome, exactly like
any hand-assembled target that doesn't compile, not a silent skip) on
anything needing a generated config header (e.g. libpng's pnglibconf.h,
still hand-solved in libpng16_target) or external link flags this heuristic
doesn't know about.

Discovery and campaign execution stay two separate steps, same as every
hand-assembled target: this module only ever writes files, it never calls
orchestrate.run() itself.
"""
import re
import subprocess
from pathlib import Path

import yaml

_LIB_PACKAGE = re.compile(r"^lib[a-z0-9][a-z0-9.+-]*$")
_SKIP_SUFFIXES = ("-dev", "-dbg", "-dbgsym", "-doc", "-common", "-data", "-bin")
_MAIN_FN = re.compile(r"\bint\s+main\s*\(")
_PP_IF = re.compile(r"^\s*#\s*(if|ifdef|ifndef)\b")
_PP_ENDIF = re.compile(r"^\s*#\s*endif\b")
_EXCLUDE_DIR_HINTS = ("test", "tests", "example", "examples", "doc", "docs",
                      "contrib", "debian", ".pc")


def _has_unguarded_main(text: str) -> bool:
    """True if main() is defined outside any #ifdef/#if block. A bare regex
    on 'int main(' over-excludes real libraries: zlib's crc32.c and
    inflate.c both carry a dead, #ifdef-guarded main() for a build-time
    codegen/debug utility (MAKECRCH / MAKEFIXED) that is never compiled in
    a normal build - naively excluding on sight would have thrown out
    inflate.c itself, the file with this project's own CVE-2022-37434
    target. This does a light nesting-depth scan instead: only a main()
    seen at #if depth 0 counts as a real collision risk.
    """
    depth = 0
    for line in text.splitlines():
        if _PP_IF.match(line):
            depth += 1
        elif _PP_ENDIF.match(line):
            depth = max(0, depth - 1)
        elif depth == 0 and _MAIN_FN.search(line):
            return True
    return False


def list_installed_libraries(dpkg_output: str) -> list[dict]:
    """Parse `dpkg -l` text output for installed ('ii') packages shaped like
    a C library. Skips -dev/-dbg/-doc/-common/-data/-bin metapackages: those
    carry headers, symbols, or docs but no library source of their own to
    fetch and scan.

    Known limitation: this is a naming-convention heuristic (packages
    starting with 'lib'), not a check of what a package actually ships. A
    real minority of Debian-lineage libraries predate that convention and
    won't match - zlib1g itself is the prototypical example, ironic given
    it's this project's own zlib_target. A stricter version would confirm
    via `dpkg -L <pkg> | grep '\\.so'`, at the cost of one subprocess call
    per installed package; left as a documented gap rather than done here.
    """
    packages = []
    for line in dpkg_output.splitlines():
        parts = line.split(None, 3)
        if len(parts) < 3 or parts[0] != "ii":
            continue
        name = parts[1].split(":")[0]  # strip multiarch ":amd64" suffix
        if not _LIB_PACKAGE.match(name) or name.endswith(_SKIP_SUFFIXES):
            continue
        packages.append({"name": name, "version": parts[2]})
    return packages


def query_installed_libraries() -> list[dict]:
    out = subprocess.run(["dpkg", "-l"], capture_output=True, text=True, timeout=30)
    return list_installed_libraries(out.stdout)


def fetch_source(package: str, dest_dir: str, timeout: int = 300) -> dict:
    """`apt-get source` the package's exact installed-version source into
    dest_dir. Requires deb-src lines enabled for the OS's repos - if none
    are configured this fails with apt's own error text, surfaced verbatim
    (e.g. "You must put some 'deb-src' URIs in your sources.list") rather
    than guessed at, same "let the real tool's own failure be the signal"
    approach as every subprocess call elsewhere in this project.
    """
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(["apt-get", "source", "--download-only", package],
                            cwd=dest, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        return {"ok": False, "src_dir": None, "stderr": result.stderr or result.stdout}

    dsc_files = list(dest.glob("*.dsc"))
    if not dsc_files:
        return {"ok": False, "src_dir": None, "stderr": "apt-get source produced no .dsc file"}

    extracted_before = {p for p in dest.iterdir() if p.is_dir()}
    extract = subprocess.run(["dpkg-source", "-x", dsc_files[0].name],
                             cwd=dest, capture_output=True, text=True, timeout=timeout)
    if extract.returncode != 0:
        return {"ok": False, "src_dir": None, "stderr": extract.stderr}

    new_dirs = [p for p in dest.iterdir() if p.is_dir() and p not in extracted_before]
    if not new_dirs:
        return {"ok": False, "src_dir": None, "stderr": "dpkg-source produced no source directory"}
    return {"ok": True, "src_dir": str(new_dirs[0]), "stderr": ""}


def _is_excluded(rel_parts: tuple[str, ...]) -> bool:
    return any(hint in part.lower() for part in rel_parts for hint in _EXCLUDE_DIR_HINTS)


def discover_c_sources(src_dir: str, limit: int = 200) -> list[str]:
    """Every .c file outside test/example/doc/debian-packaging dirs, minus
    any file already defining its own main() - that would collide with
    libFuzzer's own main() once linked into the harness binary.
    """
    root = Path(src_dir)
    found = []
    for path in sorted(root.rglob("*.c")):
        rel = path.relative_to(root)
        if _is_excluded(rel.parts[:-1]):
            continue
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        if _has_unguarded_main(text):
            continue
        found.append(str(rel))
        if len(found) >= limit:
            break
    return found


def discover_headers(src_dir: str, limit: int = 50) -> list[str]:
    """Public-looking headers only (top 3 path components), same exclusions
    as discover_c_sources. harness_synth.py only needs enough headers to
    find a parse(buffer, length)-shaped entry point, not every internal one.
    """
    root = Path(src_dir)
    found = []
    for path in sorted(root.rglob("*.h")):
        rel = path.relative_to(root)
        if len(rel.parts) > 3 or _is_excluded(rel.parts[:-1]):
            continue
        found.append(str(rel))
        if len(found) >= limit:
            break
    return found


def write_build_script(sources: list[str], harness_source_path: str, out_path: str) -> None:
    """The one build shape validated by hand on zlib_target, libpng_target,
    libpng16_target, and uaf_target: compile the harness plus every
    discovered source file directly with clang, ASan+libFuzzer, no
    configure/cmake step.
    """
    srcs = " \\\n    ".join(sources)
    script = (
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        'cd "$(dirname "$0")"\n\n'
        # -D_GNU_SOURCE: modern clang defaults to a C standard where an
        # undeclared POSIX call (read/write/close/etc., common in real
        # libraries that shell out to raw file descriptors) is a hard error,
        # not just a warning - this is what actually broke the first real
        # smoke test of this generator (zlib's gzread.c/gzwrite.c). Same
        # fix generalizes to any similarly-shaped library, not a zlib-only patch.
        "clang -g -O1 -fsanitize=address,fuzzer -D_GNU_SOURCE -I. \\\n"
        f"    {harness_source_path} \\\n"
        f"    {srcs} \\\n"
        "    -o fuzz_harness\n"
    )
    Path(out_path).write_text(script)
    Path(out_path).chmod(0o755)


def write_target_config(package: str, repo_path: str, sources: list[str], headers: list[str],
                        out_path: str, harness_source_path: str) -> dict:
    """Emit a target-*.yaml in the exact shape every hand-written one in
    config/ already uses - orchestrate.run() cannot tell an auto-discovered
    target from a hand-assembled one, by design. synthesize_harness is
    always on here: unlike the four curated targets, nobody has hand-picked
    a specific vulnerable entry point for an auto-discovered package, so
    harness_synth.py's already-proven draft/compile/coverage loop (see
    target-libpng-synth.yaml) is what has to find one.
    """
    cfg = {
        "name": f"os-discovered-{package}",
        "repo_path": repo_path,
        "build_command": "bash build.sh",
        "test_command": "true",
        "harness_binary": "fuzz_harness",
        "synthesize_harness": True,
        "harness_source_path": harness_source_path,
        "candidate_headers": headers,
        "fuzz_entry_point": "LLVMFuzzerTestOneInput",
        "sanitizers": ["address", "fuzzer"],
        "fuzz_timeout_seconds": 60,
        "static_analysis_paths": sources,
        "semgrep_use_registry": False,
        "triage_top_n": 20,
        "forbidden_patch_paths": ["build.sh", harness_source_path],
        "isolation": {"mode": "none", "image": "aegiscrs-build", "network": "none",
                     "cpus": "4", "memory": "8g"},
    }
    header = (
        f"# Auto-discovered by aegiscrs.os_discovery from installed package '{package}'.\n"
        "# Heuristic build/source list, not hand-verified like the other target-*.yaml\n"
        "# files in this directory - run it and read the [intake]/build_success line\n"
        "# before trusting any result. See os_discovery.py's module docstring for\n"
        "# exactly what this heuristic can and can't build.\n"
    )
    Path(out_path).write_text(header + yaml.safe_dump(cfg, sort_keys=False))
    return cfg


def discover_target(package: str, work_root: str, config_out_dir: str) -> dict:
    """Fetch source, detect .c/.h files, write build.sh + target-*.yaml for
    one package. Every failure path returns a status string plus the real
    tool output that caused it - the point is an honest per-package manifest
    row, not a silent skip.
    """
    src_root = Path(work_root) / package
    fetch = fetch_source(package, str(src_root))
    if not fetch["ok"]:
        return {"package": package, "status": "no_source", "detail": fetch["stderr"].strip()}

    src_dir = fetch["src_dir"]
    harness_source_path = "fuzz_harness_autogen.c"
    sources = [s for s in discover_c_sources(src_dir) if s != harness_source_path]
    headers = discover_headers(src_dir)
    if not sources:
        return {"package": package, "status": "no_c_sources", "detail": src_dir}

    Path(src_dir, harness_source_path).write_text(
        "/* cleared: no harness provided - AegisCRS must synthesize one */\n")
    write_build_script(sources, harness_source_path, str(Path(src_dir) / "build.sh"))

    Path(config_out_dir).mkdir(parents=True, exist_ok=True)
    config_path = Path(config_out_dir) / f"target-os-{package}.yaml"
    write_target_config(package, src_dir, sources, headers, str(config_path), harness_source_path)
    return {"package": package, "status": "config_written", "config_path": str(config_path),
            "src_dir": src_dir, "num_sources": len(sources), "num_headers": len(headers)}


def discover_os(work_root: str, config_out_dir: str, dpkg_output: str | None = None,
               limit: int | None = None) -> list[dict]:
    """Top-level driver: enumerate installed library packages, attempt
    discovery on each (up to `limit`), return one manifest row per package -
    including every failure - so a run always shows exactly how many of the
    OS's libraries actually became runnable targets, and exactly why the
    rest didn't, rather than only reporting successes.
    """
    packages = (list_installed_libraries(dpkg_output) if dpkg_output is not None
               else query_installed_libraries())
    if limit is not None:
        packages = packages[:limit]
    Path(config_out_dir).mkdir(parents=True, exist_ok=True)
    return [discover_target(p["name"], work_root, config_out_dir) for p in packages]


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--limit", type=int, default=None,
                    help="only attempt the first N installed library packages")
    ap.add_argument("--work-root", default="crs_scratch/os_discovery")
    ap.add_argument("--out-dir", default="config/discovered")
    args = ap.parse_args()

    manifest = discover_os(args.work_root, args.out_dir, limit=args.limit)
    ok = [m for m in manifest if m["status"] == "config_written"]
    print(f"\n{len(ok)}/{len(manifest)} installed library package(s) became runnable targets\n")
    for m in manifest:
        if m["status"] == "config_written":
            print(f"  OK    {m['package']:<30} {m['num_sources']} source file(s) -> {m['config_path']}")
        else:
            print(f"  SKIP  {m['package']:<30} {m['status']}: {m['detail'][:80]}")
    if ok:
        print(f"\nNext: eyeball a config, then run it exactly like any other target, e.g.\n"
              f"  .venv/bin/python -m aegiscrs.orchestrate {ok[0]['config_path']}")
