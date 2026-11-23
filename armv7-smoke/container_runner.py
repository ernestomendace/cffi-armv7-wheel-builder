#!/usr/bin/env python3
"""Run hash-locked imports and synthetic MCP/SMB checks inside ARMv7 QEMU container."""
import base64
import importlib
import importlib.metadata
import json
import os
import pathlib
import platform
import resource
import shutil
import struct
import subprocess
import sys
import sysconfig
import threading
import time

MAX_LOG_BYTES = 1_000_000

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
    args = parser.parse_args()
    wheels, source, smoke, results = [pathlib.Path(p).resolve(strict=True) for p in (args.wheelhouse, args.source, args.smoke, args.results)]
    report = {"status": "RUNNING", "target": {}, "phases": [],
              "limitations": ["QEMU RSS/PSS is not a NAS measurement.", "container cgroup includes QEMU/container overhead.", "no real SMB, tunnel, document or credential used."]}
    exit_code = 1
    try:
        if sys.version_info[:2] != (3, 9) or platform.machine() != "armv7l" or struct.calcsize("P") != 4:
            raise RuntimeError("ARMV7_CPYTHON_TARGET_MISMATCH")
        report["target"] = {"python": sys.version.split()[0], "machine": platform.machine(), "soabi": sysconfig.get_config_var("SOABI"), "pointer_bytes": struct.calcsize("P")}
        site = pathlib.Path("/tmp/mcp-armv7-site")
        site.mkdir(mode=0o700)
        env = os.environ.copy()
        env.update({"PIP_CONFIG_FILE": os.devnull, "PIP_NO_INDEX": "1", "PYTHONDONTWRITEBYTECODE": "1"})
        install = [sys.executable, "-m", "pip", "install", "--disable-pip-version-check", "--no-index", "--require-hashes", "--only-binary=:all:", "--no-compile", "--target", str(site), "--find-links", str(wheels), "-r", str(smoke / "requirements.lock")]
        if run_measured("offline_install", install, env, source, results / "offline-install.log", report["phases"]):
            report.update({"status": "FAIL", "failed_phase": "offline_install"})
        else:
            fixture = pathlib.Path("/tmp/mcp-armv7-fixture")
            fixture.mkdir(mode=0o700)
            credentials = fixture / "users"
            credentials.write_text(":fixture-user:fixture-password\n", encoding="ascii")
            credentials.chmod(0o600)
            env.update({"PYTHONPATH": os.pathsep.join((str(site), str(source), str(source / "src"))), "PYTHONNOUSERSITE": "1", "MCP_ARMV7_SITE": str(site), "MCP_ARMV7_FIXTURE_CREDS": str(credentials)})
            crypto_code = run_measured("imports_arc4_rs256_ntlm_fixture", [sys.executable, "-B", str(source / "tools" / "armv7_offline_bundle_smoke.py")], env, source, results / "crypto-smb-smoke.log", report["phases"])
            if crypto_code:
                report.update({"status": "FAIL", "failed_phase": "imports_arc4_rs256_ntlm_fixture"})
            else:
                suites = ["tests.test_mcp_oauth_http_adapter", "tests.test_native_service_real_gateway_e2e", "tests.test_native_service_coordinator_composition", "tests.test_native_service_runtime_adapters"]
                test_code = run_measured("real_mcp_gateway_supervisor_watchdog_tunnel_fixture", [sys.executable, "-B", "-m", "unittest", *suites, "-v"], env, source, results / "mcp-e2e-tests.log", report["phases"])
                report.update({"status": "PASS" if test_code == 0 else "FAIL"})
                if test_code:
                    report["failed_phase"] = "real_mcp_gateway_supervisor_watchdog_tunnel_fixture"
            try:
                credentials.unlink()
                fixture.rmdir()
                report["fixture_cleanup"] = "PASS"
            except OSError:
                report["fixture_cleanup"] = "INCOMPLETE"
            if report["status"] == "PASS" and report["fixture_cleanup"] == "PASS":
                exit_code = 0
        report["runner_ru_maxrss_kib"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        report["process_memory_is_qemu_guest_view"] = True
    except Exception as exc:
        report.update({"status": "FAIL", "failed_phase": "container_runner",
                       "error_code": str(exc) if str(exc).isupper() and len(str(exc)) < 100 else "CONTAINER_RUNNER_ERROR"})
    finally:
        (results / "runtime-report.json").write_text(json.dumps(report, sort_keys=True) + "\n", encoding="utf-8")
        import shutil
        shutil.rmtree("/tmp/mcp-armv7-site", ignore_errors=True)
        shutil.rmtree("/tmp/mcp-armv7-fixture", ignore_errors=True)
    return exit_code

if __name__ == "__main__":
    raise SystemExit(main())
