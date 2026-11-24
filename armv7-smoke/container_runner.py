#!/usr/bin/env python3
"""Run hash-locked imports and synthetic MCP/SMB checks inside ARMv7 QEMU container."""
import base64
import importlib
import importlib.metadata
import json
import os
import pathlib
import platform
import re
import resource
import shutil
import stat
import struct
import subprocess
import sys
import sysconfig
import tempfile
import threading
import time

MAX_LOG_BYTES = 1_000_000

def validate_site_mount(path):
    """Require the dedicated executable tmpfs to be private, owned and empty."""
    path = pathlib.Path(path)
    if path.is_symlink() or not path.is_dir():
        raise RuntimeError("ARMV7_SITE_MOUNT_INVALID")
    info = os.lstat(str(path))
    if info.st_uid != os.geteuid() or info.st_gid != os.getegid():
        raise RuntimeError("ARMV7_SITE_MOUNT_OWNER_INVALID")
    if stat.S_IMODE(info.st_mode) != 0o700:
        raise RuntimeError("ARMV7_SITE_MOUNT_MODE_INVALID")
    if next(path.iterdir(), None) is not None:
        raise RuntimeError("ARMV7_SITE_MOUNT_NOT_EMPTY")

def validate_lock_file(path):
    path = pathlib.Path(path)
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("REQUIREMENTS_LOCK_INVALID")
    data = path.read_bytes()
    if len(data) > 4096:
        raise RuntimeError("REQUIREMENTS_LOCK_INVALID")
    try:
        lines = data.decode("ascii").splitlines()
    except UnicodeDecodeError:
        raise RuntimeError("REQUIREMENTS_LOCK_INVALID")
    pattern = re.compile(r"^([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+!-]+) --hash=sha256:([0-9a-f]{64})$")
    names = []
    for line in lines:
        match = pattern.fullmatch(line)
        if match is None:
            raise RuntimeError("REQUIREMENTS_LOCK_INVALID")
        names.append(re.sub(r"[-_.]+", "-", match.group(1)).lower())
    expected = {"cffi", "cryptography", "pycparser", "pyspnego", "smbprotocol", "typing-extensions"}
    if len(lines) != 6 or len(set(names)) != 6 or set(names) != expected:
        raise RuntimeError("REQUIREMENTS_LOCK_INVENTORY_INVALID")
    return path

def build_offline_install_command(python, site, wheelhouse, lock_path):
    return [str(python), "-m", "pip", "install", "--disable-pip-version-check",
            "--no-cache-dir", "--no-index", "--require-hashes", "--only-binary=:all:",
            "--no-compile", "--target", str(site), "--find-links", str(wheelhouse),
            "-r", str(lock_path)]

def verify_results_write(results):
    results = pathlib.Path(results)
    info = os.lstat(str(results))
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.geteuid() or info.st_gid != os.getegid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise RuntimeError("RESULTS_DIRECTORY_IDENTITY_INVALID")
    fd, temporary_name = tempfile.mkstemp(prefix=".mcp-results-probe-", dir=str(results))
    temporary = pathlib.Path(temporary_name)
    committed = results / (temporary.name + ".committed")
    primary = None
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(b"ARMV7_RESULTS_WRITE_PROBE_V1\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(str(temporary), str(committed))
        if committed.read_bytes() != b"ARMV7_RESULTS_WRITE_PROBE_V1\n":
            raise RuntimeError("RESULTS_WRITE_PROBE_MISMATCH")
        committed.unlink()
    except Exception as exc:
        primary = exc
    finally:
        for path in (temporary, committed):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            except OSError as cleanup_exc:
                if primary is None:
                    primary = RuntimeError("RESULTS_WRITE_PROBE_CLEANUP_FAILED")
                else:
                    sys.stderr.write("MCP_ARMV7_CLEANUP_FAILURE phase=results_write_probe code=PROBE_FILE_REMOVE_FAILED errno=%s\n" % (cleanup_exc.errno or 0))
    if primary is not None:
        raise primary

def write_report(results, report):
    results = pathlib.Path(results)
    target = results / "runtime-report.json"
    if target.is_symlink():
        raise RuntimeError("RUNTIME_REPORT_PATH_INVALID")
    fd, temporary_name = tempfile.mkstemp(prefix=".runtime-report-", suffix=".tmp", dir=str(results))
    temporary = pathlib.Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(report, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(str(temporary), 0o600)
        os.replace(str(temporary), str(target))
    except Exception:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise

def snapshot():
    rows = {}
    for item in pathlib.Path("/proc").iterdir():
        if not item.name.isdigit():
            continue
        try:
            stat = (item / "stat").read_text(encoding="ascii")
            tail = stat[stat.rfind(")") + 2:].split()
            status = (item / "status").read_text(encoding="ascii")
            rss = next((int(line.split()[1]) for line in status.splitlines() if line.startswith("VmRSS:")), 0)
            try:
                pss = next((int(line.split()[1]) for line in (item / "smaps_rollup").read_text(encoding="ascii").splitlines() if line.startswith("Pss:")), None)
            except OSError:
                pss = None
            rows[int(item.name)] = (int(tail[1]), rss, pss)
        except (OSError, ValueError, IndexError):
            continue
    return rows

def tree_metrics(pid):
    rows = snapshot()
    members = {pid}
    changed = True
    while changed:
        changed = False
        for child, (parent, _rss, _pss) in rows.items():
            if parent in members and child not in members:
                members.add(child)
                changed = True
    rss = sum(rows[p][1] for p in members if p in rows)
    pss = [rows[p][2] for p in members if p in rows and rows[p][2] is not None]
    return rss, sum(pss) if pss else None, len(members)

def cgroup_paths():
    try:
        membership = pathlib.Path("/proc/self/cgroup").read_text(encoding="ascii").splitlines()
    except OSError:
        return None, None
    for line in membership:
        parts = line.split(":", 2)
        if len(parts) != 3:
            continue
        if not parts[1]:
            base = pathlib.Path("/sys/fs/cgroup") / parts[2].lstrip("/")
            current, peak, procs = base / "memory.current", base / "memory.peak", base / "cgroup.procs"
        elif "memory" in parts[1].split(","):
            base = pathlib.Path("/sys/fs/cgroup/memory") / parts[2].lstrip("/")
            current, peak, procs = base / "memory.usage_in_bytes", base / "memory.max_usage_in_bytes", base / "cgroup.procs"
        else:
            continue
        try:
            if str(os.getpid()) in procs.read_text(encoding="ascii").split():
                return current, peak
        except OSError:
            pass
    return None, None

def read_int(path):
    try:
        value = path.read_text(encoding="ascii").strip()
        return None if value == "max" else int(value)
    except (OSError, ValueError):
        return None

def run_measured(name, command, env, cwd, log_path, metrics):
    peak_rss = peak_pss = peak_count = sampled_cgroup = 0
    pss_complete = True
    current_path, lifetime_path = cgroup_paths()
    written = 0
    truncated = False
    with log_path.open("wb") as log:
        process = subprocess.Popen(command, cwd=str(cwd), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        def drain():
            nonlocal written, truncated
            while True:
                block = process.stdout.read(65536)
                if not block:
                    break
                remaining = max(0, MAX_LOG_BYTES - written)
                if remaining:
                    log.write(block[:remaining])
                    written += min(len(block), remaining)
                if len(block) > remaining:
                    truncated = True
            if truncated:
                log.write(b"\n[diagnostics truncated at fixed limit]\n")
        reader = threading.Thread(target=drain, daemon=True)
        reader.start()
        while process.poll() is None:
            rss, pss, count = tree_metrics(process.pid)
            peak_rss = max(peak_rss, rss)
            peak_count = max(peak_count, count)
            if pss is None:
                pss_complete = False
            else:
                peak_pss = max(peak_pss, pss)
            current = read_int(current_path) if current_path else None
            if current is not None:
                sampled_cgroup = max(sampled_cgroup, current)
            time.sleep(0.05)
        code = process.wait()
        reader.join(timeout=5)
        rss, pss, count = tree_metrics(process.pid)
        peak_rss = max(peak_rss, rss)
        peak_count = max(peak_count, count)
        if pss is None:
            pss_complete = False
        else:
            peak_pss = max(peak_pss, pss)
    metrics.append({"phase": name, "exit_code": code,
                    "process_tree_peak_rss_kib": peak_rss,
                    "process_tree_peak_pss_kib": peak_pss if pss_complete else None,
                    "peak_process_count": peak_count,
                    "container_cgroup_peak_sampled_bytes": sampled_cgroup or None,
                    "container_cgroup_lifetime_peak_bytes": read_int(lifetime_path) if lifetime_path else None,
                    "cgroup_includes_qemu_and_container_overhead": True,
                    "rss_sum_not_physical_total": True,
                    "diagnostic_log_truncated": truncated})
    return code

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheelhouse", default="/wheelhouse")
    parser.add_argument("--source", default="/private-source")
    parser.add_argument("--smoke", default="/smoke")
    parser.add_argument("--results", default="/results")
    parser.add_argument("--lock", default="/requirements.lock")
    args = parser.parse_args()
    results = pathlib.Path(args.results)
    report = {"status": "RUNNING", "target": {}, "phases": [],
              "limitations": ["QEMU RSS/PSS is not a NAS measurement.", "container cgroup includes QEMU/container overhead.", "no real SMB, tunnel, document or credential used."]}
    exit_code = 1
    current_phase = "argument_path_preflight"
    fixture = None
    primary_recorded = False
    try:
        path_args = (args.wheelhouse, args.source, args.smoke, args.results)
        resolved = []
        for value in path_args:
            candidate = pathlib.Path(value)
            if candidate.is_symlink():
                raise RuntimeError("CONTAINER_INPUT_PATH_INVALID")
            resolved.append(candidate.resolve(strict=True))
        wheels, source, smoke, results = resolved
        if not results.is_dir():
            raise RuntimeError("RESULTS_DIRECTORY_INVALID")
        current_phase = "requirements_lock_preflight"
        lock_path = validate_lock_file(args.lock)
        if sys.version_info[:2] != (3, 9) or platform.machine() != "armv7l" or struct.calcsize("P") != 4:
            current_phase = "target_preflight"
            raise RuntimeError("ARMV7_CPYTHON_TARGET_MISMATCH")
        report["target"] = {"python": sys.version.split()[0], "machine": platform.machine(),
                             "soabi": sysconfig.get_config_var("SOABI"), "pointer_bytes": struct.calcsize("P")}

        current_phase = "results_write_probe"
        verify_results_write(results)
        report["results_write_probe"] = "PASS"

        site = pathlib.Path("/opt/mcp-armv7-site")
        current_phase = "site_mount_preflight"
        validate_site_mount(site)
        env = os.environ.copy()
        env.update({"PIP_CONFIG_FILE": os.devnull, "PIP_NO_INDEX": "1",
                    "PYTHONDONTWRITEBYTECODE": "1", "PIP_NO_CACHE_DIR": "1"})
        install = build_offline_install_command(sys.executable, site, wheels, lock_path)
        current_phase = "offline_install"
        install_code = run_measured("offline_install", install, env, source,
                                    results / "offline-install.log", report["phases"])
        if install_code:
            report.update({"status": "FAIL", "failed_phase": current_phase,
                           "primary_error": {"phase": current_phase, "code": "PHASE_EXIT_NONZERO",
                                             "category": "CHILD_EXIT", "exit_code": install_code}})
            primary_recorded = True
        else:
            fixture_path = pathlib.Path("/tmp/mcp-armv7-fixture")
            current_phase = "fixture_setup"
            fixture_path.mkdir(mode=0o700)
            fixture = fixture_path
            credentials = fixture / "users"
            credentials.write_text(":fixture-user:fixture-password\n", encoding="ascii")
            credentials.chmod(0o600)
            env.update({"PYTHONPATH": os.pathsep.join((str(site), str(source), str(source / "src"))),
                        "PYTHONNOUSERSITE": "1", "MCP_ARMV7_SITE": str(site),
                        "MCP_ARMV7_FIXTURE_CREDS": str(credentials)})
            current_phase = "imports_arc4_rs256_ntlm_fixture"
            crypto_code = run_measured("imports_arc4_rs256_ntlm_fixture",
                                       [sys.executable, "-B", str(source / "tools" / "armv7_offline_bundle_smoke.py")],
                                       env, source, results / "crypto-smb-smoke.log", report["phases"])
            if crypto_code:
                report.update({"status": "FAIL", "failed_phase": current_phase,
                               "primary_error": {"phase": current_phase, "code": "PHASE_EXIT_NONZERO",
                                                 "category": "CHILD_EXIT", "exit_code": crypto_code}})
                primary_recorded = True
            else:
                suites = ["tests.test_mcp_oauth_http_adapter", "tests.test_native_service_real_gateway_e2e",
                          "tests.test_native_service_coordinator_composition", "tests.test_native_service_runtime_adapters"]
                current_phase = "real_mcp_gateway_supervisor_watchdog_tunnel_fixture"
                test_code = run_measured("real_mcp_gateway_supervisor_watchdog_tunnel_fixture",
                                         [sys.executable, "-B", "-m", "unittest", *suites, "-v"],
                                         env, source, results / "mcp-e2e-tests.log", report["phases"])
                if test_code:
                    report.update({"status": "FAIL", "failed_phase": current_phase,
                                   "primary_error": {"phase": current_phase, "code": "PHASE_EXIT_NONZERO",
                                                     "category": "CHILD_EXIT", "exit_code": test_code}})
                    primary_recorded = True
                else:
                    report["status"] = "PASS"
                    exit_code = 0
        report["runner_ru_maxrss_kib"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        report["process_memory_is_qemu_guest_view"] = True
    except Exception as exc:
        code = (str(exc) if isinstance(exc, RuntimeError) and str(exc).isupper()
                and len(str(exc)) < 100 else
                ("RESULTS_WRITE_PROBE_FAILED" if current_phase == "results_write_probe" and isinstance(exc, OSError)
                 else "PHASE_SETUP_OS_ERROR" if isinstance(exc, OSError)
                 else "CONTAINER_RUNNER_ERROR"))
        error = {"phase": current_phase, "code": code,
                 "category": "OS_ERROR" if isinstance(exc, OSError) else "RUNTIME_ERROR"}
        if isinstance(exc, OSError):
            error["errno"] = exc.errno
        report.update({"status": "FAIL", "failed_phase": current_phase, "primary_error": error})
        primary_recorded = True
    finally:
        if fixture is None:
            report.setdefault("fixture_cleanup", "NOT_CREATED")
        else:
            try:
                shutil.rmtree(str(fixture))
                report["fixture_cleanup"] = "PASS"
            except OSError as exc:
                report["fixture_cleanup"] = "INCOMPLETE"
                report["fixture_cleanup_errno"] = exc.errno
                sys.stderr.write("MCP_ARMV7_CLEANUP_FAILURE phase=fixture_cleanup code=FIXTURE_CLEANUP_FAILED errno=%s\n" % (exc.errno or 0))
                if not primary_recorded:
                    report.update({"status": "FAIL", "failed_phase": "fixture_cleanup",
                                   "primary_error": {"phase": "fixture_cleanup",
                                                     "code": "FIXTURE_CLEANUP_FAILED",
                                                     "category": "OS_ERROR", "errno": exc.errno}})
                    primary_recorded = True
                exit_code = 1
        primary = report.get("primary_error")
        if primary:
            sys.stderr.write("MCP_ARMV7_FAILURE phase=%s code=%s errno=%s exit=%s\n" % (
                primary.get("phase", "unknown"), primary.get("code", "UNKNOWN"),
                primary.get("errno", 0), primary.get("exit_code", 0)))
            exit_code = 1
        try:
            write_report(results, report)
        except OSError as exc:
            sys.stderr.write("MCP_ARMV7_REPORT_WRITE_FAILED code=REPORT_OS_ERROR errno=%s\n" % (exc.errno or 0))
            exit_code = 1
        except RuntimeError as exc:
            code = str(exc) if str(exc).isupper() and len(str(exc)) < 80 else "REPORT_WRITE_FAILED"
            sys.stderr.write("MCP_ARMV7_REPORT_WRITE_FAILED code=%s errno=0\n" % code)
            exit_code = 1
        except Exception:
            sys.stderr.write("MCP_ARMV7_REPORT_WRITE_FAILED code=REPORT_WRITE_ERROR errno=0\n")
            exit_code = 1
    return exit_code

if __name__ == "__main__":
    raise SystemExit(main())
