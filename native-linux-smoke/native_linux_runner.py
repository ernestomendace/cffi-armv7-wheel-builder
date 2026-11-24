#!/usr/bin/env python3
"""Offline install and process-real native Linux MCP lifecycle suite."""
import hashlib
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
import subprocess
import sys
import sysconfig
import tempfile
import threading
import time

MAX_LOG_BYTES = 2_000_000
EXPECTED = {"cffi":"2.0.0", "cryptography":"50.0.2", "pycparser":"2.23",
            "pyspnego":"0.12.4", "smbprotocol":"1.12.0", "typing-extensions":"4.15.0"}


def need(condition, code):
    if not condition:
        raise RuntimeError(code)


def resolve_checked_input(raw, expected_kind):
    """Reject symlinks in the supplied path before resolving any component."""
    path = pathlib.Path(raw)
    need(path.is_absolute() and ".." not in path.parts, "INPUT_PATH_INVALID")
    current = pathlib.Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        info = os.lstat(str(current))
        need(not stat.S_ISLNK(info.st_mode), "INPUT_SYMLINK_INVALID")
    resolved = path.resolve(strict=True)
    info = os.lstat(str(resolved))
    if expected_kind == "directory":
        need(stat.S_ISDIR(info.st_mode), "INPUT_PATH_TYPE_INVALID")
    else:
        need(stat.S_ISREG(info.st_mode), "INPUT_PATH_TYPE_INVALID")
    return resolved


def read_text(path):
    try:
        return pathlib.Path(path).read_text(encoding="ascii")
    except OSError:
        return ""


def validate_tmp_mount(path, mountinfo):
    path = pathlib.Path(path)
    info = os.lstat(str(path))
    need(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode), "TEST_TMP_INVALID")
    need((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) ==
         (os.getuid(), os.getgid(), 0o700), "TEST_TMP_IDENTITY_INVALID")
    found = None
    for row in mountinfo.splitlines():
        split = row.split(" - ", 1)
        if len(split) != 2: continue
        left, right = split
        fields, after = left.split(), right.split()
        if len(fields) >= 6 and len(after) >= 3:
            mountpoint = fields[4].replace("\\040", " ")
            if mountpoint == str(path):
                found = (after[0], set(fields[5].split(",")) | set(after[2].split(",")))
                break
    need(found is not None and found[0] == "tmpfs", "TEST_TMP_NOT_DEDICATED_TMPFS")
    need({"noexec", "nosuid", "nodev"}.issubset(found[1]), "TEST_TMP_MOUNT_OPTIONS_INVALID")
    need(next(path.iterdir(), None) is None, "TEST_TMP_NOT_EMPTY")


def validate_site_mount(path, mountinfo):
    path = pathlib.Path(path)
    info = os.lstat(str(path))
    need(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode), "SITE_MOUNT_INVALID")
    need((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) ==
         (os.getuid(), os.getgid(), 0o700), "SITE_MOUNT_IDENTITY_INVALID")
    row = next((line for line in mountinfo.splitlines()
                if " - " in line
                and line.split(" - ", 1)[0].split()[4].replace("\\040", " ") == str(path)), None)
    need(row is not None and " - tmpfs " in row, "SITE_NOT_DEDICATED_TMPFS")
    options = set(row.split(" - ",1)[0].split()[5].split(",")) | set(row.split(" - ",1)[1].split()[2].split(","))
    need("nosuid" in options and "nodev" in options and "noexec" not in options,
         "SITE_MOUNT_OPTIONS_INVALID")
    need(next(path.iterdir(), None) is None, "SITE_MOUNT_NOT_EMPTY")


def requirements_from_lock(lock_path, wheelhouse):
    entries = json.loads(pathlib.Path(lock_path).read_text(encoding="utf-8"))["wheels"]
    lines = []
    expected_files = set()
    normalized = set()
    for entry in entries:
        name = re.sub(r"[-_.]+", "-", entry["name"]).lower()
        need(name not in normalized and name in {re.sub(r"[-_.]+", "-", x).lower() for x in EXPECTED},
             "WHEEL_LOCK_DUPLICATE_OR_UNEXPECTED")
        normalized.add(name)
        need(entry["version"] == EXPECTED[entry["name"]] and
             re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) is not None,
             "WHEEL_LOCK_ENTRY_INVALID")
        path = pathlib.Path(wheelhouse) / entry["filename"]
        need(path.is_file() and not path.is_symlink(), "WHEEL_FILE_MISSING")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        need(digest == entry["sha256"], "WHEEL_SHA256_MISMATCH")
        expected_files.add(entry["filename"])
        lines.append("%s==%s --hash=sha256:%s" % (entry["name"], entry["version"], digest))
    need(normalized == {re.sub(r"[-_.]+", "-", x).lower() for x in EXPECTED},
         "WHEEL_LOCK_INVENTORY_INVALID")
    actual = {path.name for path in pathlib.Path(wheelhouse).iterdir() if path.is_file()}
    need(actual == expected_files, "WHEELHOUSE_INVENTORY_INVALID")
    return "\n".join(lines) + "\n"


def cgroup_memory_paths():
    for row in read_text("/proc/self/cgroup").splitlines():
        parts = row.split(":", 2)
        if len(parts) == 3 and parts[1] == "":
            base = pathlib.Path("/sys/fs/cgroup") / parts[2].lstrip("/")
            current, peak, limit = base / "memory.current", base / "memory.peak", base / "memory.max"
            if current.exists(): return current, peak, limit
    return None, None, None


def read_int(path):
    if path is None: return None
    try:
        value = pathlib.Path(path).read_text(encoding="ascii").strip()
        return None if value == "max" else int(value)
    except (OSError, ValueError):
        return None


def process_snapshot():
    rows = {}
    for path in pathlib.Path("/proc").iterdir():
        if not path.name.isdigit(): continue
        try:
            raw = (path / "stat").read_text(encoding="ascii")
            tail = raw[raw.rfind(")") + 2:].split()
            status = (path / "status").read_text(encoding="ascii")
            rss = next((int(line.split()[1]) for line in status.splitlines()
                        if line.startswith("VmRSS:")), 0)
            pss = None
            try:
                pss = next(int(line.split()[1]) for line in
                    (path / "smaps_rollup").read_text(encoding="ascii").splitlines()
                    if line.startswith("Pss:"))
            except (OSError, StopIteration, ValueError): pass
            rows[int(path.name)] = (int(tail[1]), rss, pss)
        except (OSError, ValueError, IndexError):
            continue
    return rows


def tree_memory(pid, rows):
    members = {pid}
    changed = True
    while changed:
        changed = False
        for child, (parent, _rss, _pss) in rows.items():
            if parent in members and child not in members:
                members.add(child); changed = True
    rss = sum(rows[p][1] for p in members if p in rows)
    pss_values = [rows[p][2] for p in members if p in rows and rows[p][2] is not None]
    pss_complete = len(pss_values) == len(members)
    return rss, (sum(pss_values) if pss_complete else None), len(members)


def run_measured(name, command, env, cwd, log_path, metrics, cg):
    rss_peak = pss_peak = proc_peak = 0
    pss_complete = True
    bytes_saved = bytes_received = 0
    truncated = False
    current_path, peak_path, limit_path = cg
    cgroup_sample_peak = 0
    with pathlib.Path(log_path).open("wb") as log:
        process = subprocess.Popen(command, cwd=str(cwd), env=env,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            close_fds=True, start_new_session=True)
        def drain():
            nonlocal bytes_saved, bytes_received, truncated
            while True:
                block = process.stdout.read(65536)
                if not block: break
                bytes_received += len(block)
                remain = max(0, MAX_LOG_BYTES - bytes_saved)
                if remain:
                    log.write(block[:remain]); bytes_saved += min(len(block), remain)
                if len(block) > remain: truncated = True
            if truncated: log.write(b"\n[diagnostic log capped; pipe drained to EOF]\n")
        reader = threading.Thread(target=drain, daemon=True)
        reader.start()
        deadline = time.monotonic() + 600
        try:
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    process.terminate()
                    raise RuntimeError("TEST_SUBPROCESS_TIMEOUT")
                rows = process_snapshot()
                rss, pss, count = tree_memory(process.pid, rows)
                rss_peak = max(rss_peak, rss); proc_peak = max(proc_peak, count)
                if pss is None: pss_complete = False
                else: pss_peak = max(pss_peak, pss)
                current = read_int(current_path)
                if current is not None: cgroup_sample_peak = max(cgroup_sample_peak, current)
                time.sleep(0.025)
            code = process.wait()
        finally:
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=3)
                except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=3)
            reader.join(timeout=10)
        need(not reader.is_alive(), "DIAGNOSTIC_PIPE_DRAIN_INCOMPLETE")
    metrics.append({"phase":name, "exit_code":code,
        "process_tree_peak_rss_kib_sum_not_physical_total":rss_peak,
        "process_tree_peak_pss_kib":pss_peak if pss_complete else None,
        "peak_process_count":proc_peak, "cgroup_memory_current_sample_peak_bytes":cgroup_sample_peak or None,
        "container_cgroup_memory_peak_bytes_cumulative":read_int(peak_path),
        "container_cgroup_memory_limit_bytes":read_int(limit_path),
        "cgroup_scope":"whole isolated container, includes Python image/runtime overhead",
        "log_bytes_received":bytes_received, "log_bytes_saved":bytes_saved,
        "log_truncated":truncated})
    return code


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", default="/private-source")
    parser.add_argument("--wheelhouse", default="/wheelhouse")
    parser.add_argument("--requirements", default="/requirements.lock")
    parser.add_argument("--results", default="/results")
    parser.add_argument("--harness", default="/harness")
    parser.add_argument("--site", default="/mcp-native-site")
    parser.add_argument("--tmp", default="/mcp-native-test-tmp")
    args = parser.parse_args()
    source = pathlib.Path(args.source)
    wheelhouse = pathlib.Path(args.wheelhouse)
    requirements_path = pathlib.Path(args.requirements)
    results = pathlib.Path(args.results)
    harness = pathlib.Path(args.harness)
    site, test_tmp = pathlib.Path(args.site), pathlib.Path(args.tmp)
    report = {"status":"RUNNING", "target":{}, "phases":[],
              "limitations":["Native x86-64 Linux container measurements are not NAS measurements.",
                             "No real SMB server, credential, document, or public tunnel is used.",
                             "PSS is proportional per-process accounting; RSS tree sums can double-count shared pages."]}
    code = 1
    phase = "runtime_preflight"
    fixture = None
    primary = None
    try:
        need(sys.platform.startswith("linux") and platform.machine() == "x86_64"
             and sys.version_info[:2] == (3, 9) and struct_size_ok(), "NATIVE_RUNTIME_IDENTITY_MISMATCH")
        soabi = sysconfig.get_config_var("SOABI")
        need(isinstance(soabi, str) and soabi.startswith("cpython-39-x86_64"), "NATIVE_SOABI_MISMATCH")
        report["target"] = {"python":sys.version.split()[0], "machine":platform.machine(),
                            "soabi":soabi, "uid":os.getuid(), "gid":os.getgid()}
        mountinfo = pathlib.Path("/proc/self/mountinfo").read_text(encoding="ascii")
        phase = "secure_mount_preflight"
        validate_tmp_mount(test_tmp, mountinfo); validate_site_mount(site, mountinfo)
        source = resolve_checked_input(source, "directory")
        wheelhouse = resolve_checked_input(wheelhouse, "directory")
        requirements_path = resolve_checked_input(requirements_path, "file")
        results = resolve_checked_input(results, "directory")
        harness = resolve_checked_input(harness, "directory")

        phase = "wheel_hash_preflight"
        lock = harness / "native-linux-wheel-lock.json"
        requirements = requirements_from_lock(lock, wheelhouse)
        lockfile = requirements_path
        need(lockfile.read_text(encoding="ascii") == requirements, "REQUIREMENTS_LOCK_MISMATCH")

        phase = "fixture_preparation"
        fixture = test_tmp / "native-mcp-fixture"
        fixture.mkdir(mode=0o700)
        credentials = fixture / "users"
        credentials.write_text(":fixture-user:fixture-password\n", encoding="ascii")
        credentials.chmod(0o600)
        tmp_info = os.lstat(str(test_tmp))
        need(stat.S_IMODE(tmp_info.st_mode) == 0o700 and
             (tmp_info.st_uid, tmp_info.st_gid) == (os.getuid(), os.getgid()), "TEST_TMP_CHANGED")

        env = os.environ.copy()
        env.update({"TMPDIR":str(test_tmp), "PIP_CONFIG_FILE":os.devnull,
            "PIP_NO_INDEX":"1", "PIP_NO_CACHE_DIR":"1", "PYTHONDONTWRITEBYTECODE":"1",
            "PYTHONNOUSERSITE":"1"})
        tempfile.tempdir = None
        cg = cgroup_memory_paths()
        report["container_cgroup_memory_start_bytes"] = read_int(cg[0])
        report["container_cgroup_memory_limit_bytes"] = read_int(cg[2])
        phase = "offline_wheel_install"
        install_cmd = [sys.executable,"-m","pip","install","--disable-pip-version-check",
            "--no-index","--no-cache-dir","--require-hashes","--only-binary=:all:",
            "--no-compile","--target",str(site),"--find-links",str(wheelhouse),"-r",str(lockfile)]
        if run_measured("offline_wheel_install", install_cmd, env, source,
                        results/"offline-install.log", report["phases"], cg):
            raise RuntimeError("OFFLINE_INSTALL_FAILED")
        env.update({"PYTHONPATH":os.pathsep.join((str(site),str(source),str(source/"src"))),
                    "MCP_NATIVE_SITE":str(site), "MCP_ARMV7_SITE":str(site),
                    "MCP_NATIVE_FIXTURE_CREDS":str(credentials),
                    "MCP_ARMV7_FIXTURE_CREDS":str(credentials)})
        phase = "native_import_crypto_and_synthetic_ntlm"
        if run_measured("native_import_crypto_and_synthetic_ntlm",
                [sys.executable,"-B",str(harness/"native_linux_runtime_smoke.py")],
                env,source,results/"native-runtime-smoke.log",report["phases"],cg):
            raise RuntimeError("NATIVE_RUNTIME_SMOKE_FAILED")
        phase = "native_mcp_gateway_supervisor_watchdog_cycle"
        suites = ["tests.test_mcp_oauth_http_adapter", "tests.test_native_service_real_gateway_e2e",
                  "tests.test_native_service_coordinator_composition", "tests.test_native_service_runtime_adapters"]
        test_cmd = [sys.executable,"-B","-m","unittest",*suites,"-v"]
        if run_measured("native_mcp_gateway_supervisor_watchdog_cycle",test_cmd,env,source,
                        results/"native-mcp-e2e-tests.log",report["phases"],cg):
            raise RuntimeError("NATIVE_MCP_E2E_FAILED")
        report["status"] = "PASS"
        report["test_process_network"] = "disabled by docker --network none; loopback remains available"
        report["test_execution_identity"] = "unprivileged; no capabilities; no-new-privileges; read-only root"
        code = 0
    except Exception as exc:
        reason = str(exc) if isinstance(exc, RuntimeError) and re.fullmatch(r"[A-Z0-9_]+", str(exc)) else "NATIVE_RUNNER_ERROR"
        primary = {"phase":phase,"code":reason,"class":type(exc).__name__,
                   "errno":getattr(exc, "errno", None) if isinstance(exc, OSError) else None}
        report.update({"status":"FAIL","failed_phase":phase,"primary_error":primary})
    finally:
        if fixture is not None:
            try:
                info = os.lstat(str(fixture))
                need(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
                     and info.st_uid == os.getuid() and info.st_gid == os.getgid()
                     and stat.S_IMODE(info.st_mode) == 0o700, "FIXTURE_IDENTITY_INVALID")
                shutil.rmtree(str(fixture))
                report["fixture_cleanup"] = "PASS"
            except Exception as exc:
                report["fixture_cleanup"] = "INCOMPLETE"
                report["fixture_cleanup_error_class"] = type(exc).__name__
                report["fixture_cleanup_errno"] = getattr(exc, "errno", None) if isinstance(exc, OSError) else None
                if primary is None:
                    report.update({"status":"FAIL","failed_phase":"fixture_cleanup",
                        "primary_error":{"phase":"fixture_cleanup","code":"FIXTURE_CLEANUP_FAILED",
                                          "class":type(exc).__name__,
                                          "errno":getattr(exc, "errno", None) if isinstance(exc, OSError) else None}})
                code = 1
        try:
            residuals = sorted(item.name for item in test_tmp.iterdir())
            report["test_tmp_residuals"] = residuals[:32]
            report["test_tmp_cleanup"] = "PASS" if not residuals else "INCOMPLETE"
            if residuals:
                report["status"] = "FAIL"
                if primary is None:
                    report["primary_error"] = {"phase":"test_tmp_cleanup","code":"TEST_TMP_NOT_EMPTY"}
                code = 1
        except Exception as exc:
            report["test_tmp_cleanup"] = "UNVERIFIED"
            report["test_tmp_cleanup_error_class"] = type(exc).__name__
            report["test_tmp_cleanup_errno"] = getattr(exc, "errno", None) if isinstance(exc, OSError) else None
            report["status"] = "FAIL"; code = 1
        report["container_cgroup_memory_peak_bytes"] = read_int(cgroup_memory_paths()[1])
        report["harness_process_maxrss_kib"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        report_path = results / "native-runtime-report.json"
        report_path.write_text(json.dumps(report,sort_keys=True)+"\n",encoding="ascii")
        report_path.chmod(0o600)
        print("NATIVE_LINUX_RUNTIME=" + report["status"])
        if report.get("primary_error"):
            print("NATIVE_LINUX_FAILURE phase=%s code=%s" %
                  (report["primary_error"].get("phase","unknown"), report["primary_error"].get("code","unknown")))
    return code


def struct_size_ok():
    import struct
    return struct.calcsize("P") == 8


if __name__ == "__main__":
    raise SystemExit(main())
