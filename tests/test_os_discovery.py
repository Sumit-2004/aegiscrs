"""Unit tests for OS-wide target auto-discovery.

All of these are model-free and network-free, same spirit as the rest of
tests/: they exercise the parsing/heuristic logic in isolation via mocks and
tmp_path fixtures. The real end-to-end path (apt-get source against a live
system, then actually compiling the generated build.sh with clang+ASan+
libFuzzer) was verified manually against this machine's real installed
zlib1g package - see os_discovery.py's module docstring for why that can't
be a hermetic CI test (it needs deb-src enabled, network, and clang).
"""
import stat
import subprocess
import textwrap
from pathlib import Path
from unittest.mock import patch

import yaml

from aegiscrs import os_discovery

DPKG_L_SAMPLE = textwrap.dedent("""\
    Desired=Unknown/Install/Remove/Purge/Hold
    | Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend
    |/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)
    ||/ Name           Version              Architecture Description
    +++-==============-====================-============-===============
    ii  libpng16-16:amd64 1.6.39-2           amd64        PNG library
    ii  libpng-dev     1.6.39-2             amd64        PNG library (dev)
    ii  libcurl4:amd64 8.5.0-2ubuntu10      amd64        URL transfer library
    ii  libcurl4-dev   8.5.0-2ubuntu10      amd64        headers for libcurl4
    rc  libold1        0.1-1                amd64        removed-but-configs
    ii  bash           5.2.21-2ubuntu4      amd64        not a library
    ii  libc-bin       2.39-0ubuntu8        amd64        GLIBC utility programs
    """)


def test_list_installed_libraries_filters_and_normalizes():
    libs = os_discovery.list_installed_libraries(DPKG_L_SAMPLE)
    names = {p["name"] for p in libs}
    assert names == {"libpng16-16", "libcurl4"}
    assert {"name": "libcurl4", "version": "8.5.0-2ubuntu10"} in libs


def test_list_installed_libraries_ignores_non_installed_status():
    assert not any(p["name"] == "libold1"
                   for p in os_discovery.list_installed_libraries(DPKG_L_SAMPLE))


def test_discover_c_sources_excludes_test_and_debian_dirs(tmp_path):
    (tmp_path / "foo.c").write_text("int foo(void) { return 1; }\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_foo.c").write_text("int main(void) { return 0; }\n")
    (tmp_path / "debian").mkdir()
    (tmp_path / "debian" / "rules.c").write_text("int x;\n")

    sources = os_discovery.discover_c_sources(str(tmp_path))
    assert sources == ["foo.c"]


def test_discover_c_sources_excludes_unguarded_main(tmp_path):
    (tmp_path / "haslib.c").write_text("void lib_fn(void) {}\n")
    (tmp_path / "hasmain.c").write_text("int main(void) { return 0; }\n")

    sources = os_discovery.discover_c_sources(str(tmp_path))
    assert sources == ["haslib.c"]


def test_discover_c_sources_keeps_ifdef_guarded_main():
    # Real shape from zlib's crc32.c / inflate.c: a main() only compiled
    # under a codegen/debug macro nobody defines in a normal build.
    text = textwrap.dedent("""\
        void real_api(void) {}
        #ifdef MAKECRCH
        int main(void) { return 0; }
        #endif
        """)
    assert os_discovery._has_unguarded_main(text) is False


def test_has_unguarded_main_true_at_top_level():
    assert os_discovery._has_unguarded_main("int main(void) { return 0; }\n") is True


def test_discover_headers_depth_and_exclusion_limit(tmp_path):
    (tmp_path / "pub.h").write_text("")
    deep = tmp_path / "a" / "b" / "c"
    deep.mkdir(parents=True)
    (deep / "toodeep.h").write_text("")
    (tmp_path / "doc").mkdir()
    (tmp_path / "doc" / "notes.h").write_text("")

    headers = os_discovery.discover_headers(str(tmp_path))
    assert headers == ["pub.h"]


def test_write_build_script_is_executable_and_includes_all_sources(tmp_path):
    out = tmp_path / "build.sh"
    os_discovery.write_build_script(["a.c", "b.c"], "harness.c", str(out))
    content = out.read_text()
    assert "a.c" in content and "b.c" in content and "harness.c" in content
    assert "-fsanitize=address,fuzzer" in content
    assert stat.S_IMODE(out.stat().st_mode) & stat.S_IXUSR


def test_write_target_config_matches_orchestrate_shape(tmp_path):
    out = tmp_path / "target-os-foo.yaml"
    cfg = os_discovery.write_target_config(
        "foo", "/src/foo", ["a.c"], ["a.h"], str(out), "fuzz_harness_autogen.c")

    assert cfg["repo_path"] == "/src/foo"
    assert cfg["synthesize_harness"] is True
    assert cfg["static_analysis_paths"] == ["a.c"]
    assert cfg["candidate_headers"] == ["a.h"]
    assert "build.sh" in cfg["forbidden_patch_paths"]

    # Must actually parse back as a normal target-*.yaml, same as any
    # hand-written config/target-*.yaml.
    reloaded = yaml.safe_load(out.read_text())
    assert reloaded["name"] == "os-discovered-foo"
    assert reloaded["build_command"] == "bash build.sh"


def test_fetch_source_reports_timeout_without_crashing(tmp_path):
    """A slow/huge package (e.g. lib32stdc++6, whose source is gcc-14's
    multi-hundred-MB tarball) must come back as a normal failure dict, not
    propagate subprocess.TimeoutExpired up into the caller's whole batch."""
    with patch("aegiscrs.os_discovery.subprocess.run",
              side_effect=subprocess.TimeoutExpired(cmd="apt-get", timeout=300)):
        result = os_discovery.fetch_source("lib32stdc++6", str(tmp_path / "dest"))
    assert result["ok"] is False
    assert "timed out" in result["stderr"]


def test_fetch_source_clears_stale_dest_dir_before_refetching(tmp_path):
    """work_root persists across separate discover_os()/CLI runs by design,
    so a second real fetch of a package already fetched once must not fail
    with dpkg-source's "unpack target exists" against a prior run's leftover
    download/extraction in the same dest_dir."""
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "gcc-14-14.2.0").mkdir()
    (dest / "gcc-14-14.2.0" / "stale.txt").write_text("leftover from a previous run")
    (dest / "gcc-14_14.2.0-4ubuntu2.dsc").write_text("stale dsc")

    def fake_run(cmd, cwd, capture_output, text, timeout, stdin):
        if cmd[:2] == ["apt-get", "source"]:
            (Path(cwd) / "pkg_1.0.dsc").write_text("dsc")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        if cmd[0] == "dpkg-source":
            (Path(cwd) / "pkg-1.0").mkdir()
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        raise AssertionError(f"unexpected command: {cmd}")

    with patch("aegiscrs.os_discovery.subprocess.run", side_effect=fake_run):
        result = os_discovery.fetch_source("pkg", str(dest))

    assert result["ok"] is True
    assert not (dest / "gcc-14-14.2.0").exists()


def test_discover_target_reports_no_source_without_crashing(tmp_path):
    with patch("aegiscrs.os_discovery.fetch_source",
              return_value={"ok": False, "src_dir": None, "stderr": "no deb-src configured"}):
        result = os_discovery.discover_target("foo", str(tmp_path / "work"), str(tmp_path / "cfg"))
    assert result == {"package": "foo", "status": "no_source", "detail": "no deb-src configured"}


def test_discover_target_reports_no_c_sources(tmp_path):
    src_dir = tmp_path / "empty_src"
    src_dir.mkdir()
    with patch("aegiscrs.os_discovery.fetch_source",
              return_value={"ok": True, "src_dir": str(src_dir), "stderr": ""}):
        result = os_discovery.discover_target("foo", str(tmp_path / "work"), str(tmp_path / "cfg"))
    assert result["status"] == "no_c_sources"


def test_discover_target_writes_config_on_success(tmp_path):
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "lib.c").write_text("void api(void) {}\n")
    (src_dir / "lib.h").write_text("void api(void);\n")
    cfg_dir = tmp_path / "cfg"

    with patch("aegiscrs.os_discovery.fetch_source",
              return_value={"ok": True, "src_dir": str(src_dir), "stderr": ""}):
        result = os_discovery.discover_target("foo", str(tmp_path / "work"), str(cfg_dir))

    assert result["status"] == "config_written"
    assert result["num_sources"] == 1
    assert (src_dir / "build.sh").exists()
    assert (src_dir / "fuzz_harness_autogen.c").exists()
    config_path = list(cfg_dir.glob("target-os-foo.yaml"))
    assert len(config_path) == 1


def test_discover_target_is_idempotent_on_rerun(tmp_path):
    """A second discover_target() call over a directory left by a previous
    attempt must not fold the already-written harness stub back into its
    own source list (it would double-define LLVMFuzzerTestOneInput at link
    time - the exact bug caught during manual smoke-testing)."""
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "lib.c").write_text("void api(void) {}\n")
    cfg_dir = tmp_path / "cfg"

    with patch("aegiscrs.os_discovery.fetch_source",
              return_value={"ok": True, "src_dir": str(src_dir), "stderr": ""}):
        os_discovery.discover_target("foo", str(tmp_path / "work"), str(cfg_dir))
        second = os_discovery.discover_target("foo", str(tmp_path / "work"), str(cfg_dir))

    assert second["num_sources"] == 1
    assert "fuzz_harness_autogen.c" not in yaml.safe_load(
        (cfg_dir / "target-os-foo.yaml").read_text())["static_analysis_paths"]


def test_discover_os_respects_limit_and_dpkg_output(tmp_path):
    calls = []

    def fake_discover_target(package, work_root, config_out_dir):
        calls.append(package)
        return {"package": package, "status": "config_written", "config_path": "x"}

    with patch("aegiscrs.os_discovery.discover_target", side_effect=fake_discover_target):
        manifest = os_discovery.discover_os(
            str(tmp_path / "work"), str(tmp_path / "cfg"),
            dpkg_output=DPKG_L_SAMPLE, limit=1)

    assert len(manifest) == 1
    assert len(calls) == 1


def test_discover_os_with_dpkg_output_skips_live_service_discovery():
    """Passing a canned dpkg -l blob must never shell out to the live
    system's dpkg -S / systemd unit dirs - that's the whole point of the
    canned-vs-live split (same as list_installed_libraries)."""
    with patch("aegiscrs.os_discovery.discover_target",
              return_value={"status": "no_c_sources", "detail": "x"}), \
         patch("aegiscrs.os_discovery.list_installed_services") as services_mock:
        os_discovery.discover_os("work", "cfg", dpkg_output=DPKG_L_SAMPLE)
    services_mock.assert_not_called()


def test_find_service_unit_files(tmp_path):
    unit_dir = tmp_path / "systemd"
    unit_dir.mkdir()
    (unit_dir / "sshd.service").write_text("")
    (unit_dir / "not-a-unit.txt").write_text("")

    found = os_discovery.find_service_unit_files((str(unit_dir), str(tmp_path / "missing")))
    assert found == [str(unit_dir / "sshd.service")]


def test_owning_package_parses_dpkg_dash_s():
    class FakeResult:
        returncode = 0
        stdout = "openssh-server: /lib/systemd/system/ssh.service\n"

    with patch("aegiscrs.os_discovery.subprocess.run", return_value=FakeResult()):
        assert os_discovery.owning_package("/lib/systemd/system/ssh.service") == "openssh-server"


def test_owning_package_returns_none_for_unowned_file():
    class FakeResult:
        returncode = 1
        stdout = "dpkg-query: no path found matching pattern anything\n"

    with patch("aegiscrs.os_discovery.subprocess.run", return_value=FakeResult()):
        assert os_discovery.owning_package("/etc/systemd/system/local.service") is None


def test_list_installed_services_dedupes_by_package(tmp_path):
    unit_dir = tmp_path / "systemd"
    unit_dir.mkdir()
    (unit_dir / "a.service").write_text("")
    (unit_dir / "b.service").write_text("")

    with patch("aegiscrs.os_discovery.owning_package", return_value="samepkg"):
        services = os_discovery.list_installed_services((str(unit_dir),))
    assert [s["name"] for s in services] == ["samepkg"]


def test_repo_name_from_url_variants():
    assert os_discovery.repo_name_from_url("https://github.com/madler/zlib") == "zlib"
    assert os_discovery.repo_name_from_url("https://github.com/madler/zlib.git") == "zlib"
    assert os_discovery.repo_name_from_url("https://github.com/madler/zlib/") == "zlib"


def test_fetch_git_source_refuses_existing_dest(tmp_path):
    existing = tmp_path / "already-here"
    existing.mkdir()
    result = os_discovery.fetch_git_source("https://example.com/x.git", str(existing))
    assert not result["ok"]
    assert "already exists" in result["stderr"]


def test_fetch_git_source_reports_git_failure(tmp_path):
    class FakeResult:
        returncode = 128
        stderr = "fatal: repository not found"

    with patch("aegiscrs.os_discovery.subprocess.run", return_value=FakeResult()):
        result = os_discovery.fetch_git_source("https://example.com/nope.git", str(tmp_path / "d"))
    assert not result["ok"]
    assert "not found" in result["stderr"]


def test_discover_from_github_success(tmp_path):
    src_dir = tmp_path / "cloned"
    src_dir.mkdir()
    (src_dir / "lib.c").write_text("void api(void) {}\n")

    with patch("aegiscrs.os_discovery.fetch_git_source",
              return_value={"ok": True, "src_dir": str(src_dir), "stderr": ""}):
        result = os_discovery.discover_from_github(
            "https://github.com/example/lib", str(tmp_path / "work"), str(tmp_path / "cfg"))

    assert result["status"] == "config_written"
    assert result["repo"] == "lib"
    assert result["num_sources"] == 1


def test_discover_from_github_no_source():
    with patch("aegiscrs.os_discovery.fetch_git_source",
              return_value={"ok": False, "src_dir": None, "stderr": "fatal: auth required"}):
        result = os_discovery.discover_from_github("https://example.com/x.git", "work", "cfg")
    assert result == {"repo": "x", "url": "https://example.com/x.git",
                      "status": "no_source", "detail": "fatal: auth required"}
