"""Interactive front door for AegisCRS.

`python -m aegiscrs.cli` opens a menu so a user doesn't have to already know
which module or config file to reach for. No new scanning logic lives here -
every option below routes to functionality already implemented and tested in
os_discovery.py; this file is only the menu and input handling. Discovery and
campaign execution stay separate steps here too: this always stops after
writing target-*.yaml file(s) and tells you the next command to run, it never
calls orchestrate.run() itself.
"""
from . import os_discovery

_KERNEL_SCAN_EXPLANATION = """\
Not implemented - and deliberately so, not a placeholder waiting to be filled in.

Everything else in this menu compiles a library into an ordinary userspace
process and fuzzes it directly with ASan+libFuzzer. A kernel module or
syscall path can't be isolated that way: there is no single userspace
binary to link a harness into, a crash there is a kernel panic or a KASAN
report from a running/virtualized kernel, not a subprocess exit code, and
"the compiler judges" only gets you a build, not proof of reachability
without either a kernel-aware coverage guide (syzkaller-style, driven by
kcov) or a hypervisor-level harness. That's a materially different harness
model, sanitizer, and evidence format from every other stage in this
project - not an extension of os_discovery.py's current design, a separate
build.

Stated here as a scoped boundary rather than silently left out."""


def _prompt(text: str) -> str:
    return input(text).strip()


def _print_manifest(manifest: list[dict], label_key: str) -> None:
    ok = [m for m in manifest if m["status"] == "config_written"]
    print(f"\n{len(ok)}/{len(manifest)} target(s) became runnable\n")
    for m in manifest:
        label = m.get(label_key, "?")
        kind = f" ({m['kind']})" if "kind" in m else ""
        if m["status"] == "config_written":
            print(f"  OK    {label}{kind}: {m['num_sources']} source file(s) -> {m['config_path']}")
        else:
            print(f"  SKIP  {label}{kind}: {m['status']} - {str(m.get('detail', ''))[:80]}")
    if ok:
        print(f"\nNext: eyeball a config, then run it exactly like any other target, e.g.\n"
              f"  .venv/bin/python -m aegiscrs.orchestrate {ok[0]['config_path']}")


def run_menu() -> None:
    print("AegisCRS - what do you want to scan?\n")
    print("  1) Full OS scan - installed user-mode libraries and services")
    print("  2) Kernel-level services/libraries")
    print("  3) A specific library from a GitHub (or other git) URL")
    choice = _prompt("\n> ")

    if choice == "1":
        limit_raw = _prompt("Limit to first N discovered packages (blank = no limit): ")
        limit = int(limit_raw) if limit_raw else None
        manifest = os_discovery.discover_os(
            "crs_scratch/os_discovery", "config/discovered", limit=limit)
        _print_manifest(manifest, label_key="package")
    elif choice == "2":
        print(f"\n{_KERNEL_SCAN_EXPLANATION}\n")
    elif choice == "3":
        url = _prompt("git URL: ")
        result = os_discovery.discover_from_github(
            url, "crs_scratch/os_discovery", "config/discovered")
        _print_manifest([result], label_key="repo")
    else:
        print("Not a valid choice.")


if __name__ == "__main__":
    run_menu()
