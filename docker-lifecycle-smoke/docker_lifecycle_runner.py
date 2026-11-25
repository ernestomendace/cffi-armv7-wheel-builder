#!/usr/bin/env python3
"""Run real Docker Engine phases A-C with the production CAS implementation."""
import argparse
import dataclasses
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

BASE_DIGEST = "sha256:03dee9ce00747bb5390e7b4ad00307b4dbc7790f7da77cc3581f93cfa99a6363"
SOCKET_ROOT = Path("/run/codex-mcp-lease")
EXPECTED_ENGINE_SOCKET = "/var/run/docker.sock"


class TrialFailure(RuntimeError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _proc_ticks(pid):
    with open("/proc/{}/stat".format(pid), "r", encoding="ascii") as stream:
        raw = stream.read(8192)
    pos = raw.rfind(")")
    if pos < 0:
        raise TrialFailure("CONTROLLER_IDENTITY_UNAVAILABLE")
    return raw[pos+2:].split()[19]


def _secure_socket_tree(run_id):
    if os.geteuid() != 0:
        raise TrialFailure("CONTROLLER_ROOT_REQUIRED")
    root_created = False
    try:
        st = os.lstat(str(SOCKET_ROOT))
        if (not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode)
                or st.st_uid != 0 or st.st_gid != 0 or stat.S_IMODE(st.st_mode) != 0o711):
            raise TrialFailure("CAS_SOCKET_ROOT_UNSAFE")
    except FileNotFoundError:
        os.mkdir(str(SOCKET_ROOT), 0o711)
        root_created = True
    run_dir = SOCKET_ROOT / run_id.replace("-", "")
    os.mkdir(str(run_dir), 0o710)
    os.chown(str(run_dir), 0, 61001)
    os.chmod(str(run_dir), 0o710)
    st = os.lstat(str(run_dir))
    if (not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode)
            or st.st_uid != 0 or st.st_gid != 61001 or stat.S_IMODE(st.st_mode) != 0o710):
        raise TrialFailure("CAS_SOCKET_RUN_DIRECTORY_UNSAFE")
    return run_dir, root_created


def _parse_proc_identity(pid, diagnostics=None):
    """Read a small, stable procfs identity snapshot; never reads cmdline/env."""
    if not isinstance(pid, int) or pid < 1:
        if diagnostics is not None:
            diagnostics.update({"proc_identity_phase": "pid_validation", "proc_identity_errno": None})
        return None
    proc = Path("/proc") / str(pid)
    phase = "proc_exe_before"
    try:
        exe_stat_before = os.stat(str(proc / "exe"))
        exe = os.readlink(str(proc / "exe"))
        phase = "proc_status"
        status = (proc / "status").read_text(encoding="ascii")
        phase = "proc_stat_before"
        stat_before = (proc / "stat").read_text(encoding="ascii")
        marker = stat_before.rfind(")")
        if marker < 0:
            return None
        fields = stat_before[marker + 2:].split()
        start_ticks = fields[19]
        uid_line = next(line for line in status.splitlines() if line.startswith("Uid:"))
        gid_line = next(line for line in status.splitlines() if line.startswith("Gid:"))
        uid_values = [int(value) for value in uid_line.split()[1:5]]
        gid_values = [int(value) for value in gid_line.split()[1:5]]
        phase = "proc_fd_inventory"
        fd_dir = proc / "fd"
        held_socket_inodes = set()
        for name in os.listdir(str(fd_dir)):
            try:
                target = os.readlink(str(fd_dir / name))
            except OSError:
                continue
            match = re.fullmatch(r"socket:\[(\d+)\]", target)
            if match:
                held_socket_inodes.add(int(match.group(1)))
        phase = "proc_stat_after"
        stat_after = (proc / "stat").read_text(encoding="ascii")
        marker_after = stat_after.rfind(")")
        phase = "proc_exe_after"
        exe_stat_after = os.stat(str(proc / "exe"))
    except OSError as exc:
        if diagnostics is not None:
            diagnostics.update({"proc_identity_phase": phase, "proc_identity_errno": exc.errno})
        return None
    except (StopIteration, ValueError, IndexError):
        if diagnostics is not None:
            diagnostics.update({"proc_identity_phase": phase, "proc_identity_errno": None})
        return None
    if (marker_after < 0 or stat_after[marker_after + 2:].split()[19] != start_ticks
            or (exe_stat_before.st_dev, exe_stat_before.st_ino)
                != (exe_stat_after.st_dev, exe_stat_after.st_ino)):
        if diagnostics is not None:
            diagnostics.update({"proc_identity_phase": "stable_readback", "proc_identity_errno": None})
        return None
    if diagnostics is not None:
        diagnostics.update({"proc_identity_phase": "verified", "proc_identity_errno": None})
    return {"pid": pid, "uid_real": uid_values[0], "uid_effective": uid_values[1],
        "gid_real": gid_values[0], "gid_effective": gid_values[1],
        "start_ticks": start_ticks, "exe_name": os.path.basename(exe), "exe_path": exe,
        "listener_fd_inodes": sorted(held_socket_inodes)}


def _systemd_unit(unit, diagnostics=None):
    try:
        proc = subprocess.run(["systemctl", "show", "--no-pager", "--property=ActiveState",
            "--property=MainPID", "--property=Listen", unit], capture_output=True,
            text=True, timeout=3, check=False, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    except OSError as exc:
        if diagnostics is not None:
            diagnostics.update({"systemd_probe_phase": unit, "systemd_probe_errno": exc.errno})
        return None
    except subprocess.TimeoutExpired:
        if diagnostics is not None:
            diagnostics.update({"systemd_probe_phase": unit, "systemd_probe_errno": None,
                "systemd_probe_timeout": True})
        return None
    if proc.returncode != 0:
        return None
    result = {}
    for line in proc.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            if key in {"ActiveState", "MainPID", "Listen"}:
                result[key] = value
    return result


def _listener_kernel_inode(path, diagnostics=None):
    try:
        lines = Path("/proc/net/unix").read_text(encoding="ascii").splitlines()[1:]
    except OSError as exc:
        if diagnostics is not None:
            diagnostics.update({"listener_check_phase": "proc_net_unix", "listener_check_errno": exc.errno})
        return None
    found = set()
    for line in lines:
        fields = line.split()
        if len(fields) < 8:
            continue
        try:
            row_inode = int(fields[6])
            flags = int(fields[3], 16)
            sock_type = int(fields[4], 16)
        except ValueError:
            continue
        if (fields[7] in {path, os.path.realpath(path)} and sock_type == 1
                and flags & 0x10000):
            found.add(row_inode)
    if len(found) == 1:
        return next(iter(found))
    return None


def _listener_owner_pids(inode, diagnostics=None):
    """Find processes holding the exact listener inode, without reading cmdline/env."""
    owners = []
    try:
        proc_ids = [name for name in os.listdir("/proc") if name.isdigit()]
    except OSError as exc:
        if diagnostics is not None:
            diagnostics.update({"listener_owner_phase": "proc_root", "listener_owner_errno": exc.errno})
        return owners
    for name in proc_ids:
        fd_dir = Path("/proc") / name / "fd"
        try:
            fds = os.listdir(str(fd_dir))
        except OSError:
            continue
        for fd in fds:
            try:
                target = os.readlink(str(fd_dir / fd))
            except OSError:
                continue
            if target == "socket:[{}]".format(inode):
                owners.append(int(name))
                break
    return sorted(set(owners))


def _engine_peer_proof(peer_pid, peer_uid, peer_gid, socket_path, socket_inode):
    """Require procfs plus the exact listening socket to identify the Engine."""
    diagnostics = {}
    peer = _parse_proc_identity(peer_pid, diagnostics)
    kernel_socket_inode = _listener_kernel_inode(socket_path, diagnostics)
    listener = kernel_socket_inode is not None
    listener_owners = (_listener_owner_pids(kernel_socket_inode, diagnostics)
        if kernel_socket_inode is not None else [])
    base = {"peer_pid_expected": None, "peer_proc_uid_effective": None,
        "peer_proc_gid_effective": None, "peer_executable_name": None,
        "peer_start_ticks": None, "socket_listener_verified": listener,
        "socket_path_inode": socket_inode, "listener_kernel_inode": kernel_socket_inode,
        "socket_listener_owner_pids": listener_owners,
        "socket_activation_verified": False, "verified": False}
    base.update(diagnostics)
    if peer is None:
        return dict(base, error_code="ENGINE_PEER_IDENTITY_UNVERIFIED")
    base.update({"peer_proc_uid_effective": peer["uid_effective"],
        "peer_proc_gid_effective": peer["gid_effective"],
        "peer_executable_name": peer["exe_name"],
        "peer_start_ticks": peer["start_ticks"]})
    if (peer["uid_effective"] != peer_uid or peer["gid_effective"] != peer_gid
            or peer_uid != 0 or peer_gid != 0 or not listener
            or kernel_socket_inode not in peer["listener_fd_inodes"]):
        return dict(base, error_code="ENGINE_PEER_IDENTITY_UNVERIFIED")
    if peer_pid > 1 and peer["exe_name"] == "dockerd":
        unit = _systemd_unit("docker.service", diagnostics)
        base.update(diagnostics)
        service_active = bool(unit and unit.get("ActiveState") in {"active", "activating"})
        try:
            main_pid = int(unit.get("MainPID", "0")) if service_active else 0
        except ValueError:
            main_pid = 0
        dockerd_owners = []
        for candidate in listener_owners:
            identity = _parse_proc_identity(candidate)
            if (identity and identity["exe_name"] == "dockerd"
                    and identity["uid_effective"] == 0 and identity["gid_effective"] == 0):
                dockerd_owners.append(candidate)
        expected_pid = main_pid if main_pid > 1 else (
            dockerd_owners[0] if len(dockerd_owners) == 1 else None)
        base["peer_pid_expected"] = expected_pid
        base["dockerd_listener_pids"] = dockerd_owners
        base["daemon_main_pid"] = main_pid or None
        if (expected_pid == peer_pid and expected_pid in dockerd_owners
                and peer_pid in listener_owners):
            return dict(base, verified=True,
                peer_kind="docker_service_main" if main_pid else "direct_dockerd")
        return dict(base, error_code="ENGINE_PEER_IDENTITY_UNVERIFIED")
    if peer_pid == 1 and peer["exe_name"] in {"systemd", "init"}:
        sock_unit = _systemd_unit("docker.socket", diagnostics)
        service_unit = _systemd_unit("docker.service", diagnostics)
        base.update(diagnostics)
        try:
            main_pid = int(service_unit.get("MainPID", "0")) if service_unit else 0
        except ValueError:
            main_pid = 0
        daemon = _parse_proc_identity(main_pid) if main_pid > 1 else None
        listen_text = sock_unit.get("Listen", "") if sock_unit else ""
        activation_ok = bool(sock_unit and sock_unit.get("ActiveState") == "active"
            and (socket_path in listen_text or os.path.realpath(socket_path) in listen_text)
            and service_unit
            and service_unit.get("ActiveState") in {"active", "activating"}
            and daemon and daemon["exe_name"] == "dockerd"
            and kernel_socket_inode in daemon["listener_fd_inodes"]
            and 1 in listener_owners and main_pid in listener_owners)
        if activation_ok:
            base["peer_pid_expected"] = 1
            base["dockerd_listener_pids"] = [main_pid]
            return dict(base, verified=True, peer_kind="verified_systemd_socket_activation",
                socket_activation_verified=True, daemon_main_pid=main_pid,
                daemon_executable_name=daemon["exe_name"])
        return dict(base, error_code="ENGINE_SOCKET_ACTIVATION_UNVERIFIED",
            daemon_main_pid=main_pid if main_pid else None,
            docker_socket_unit_active=bool(sock_unit and sock_unit.get("ActiveState") == "active"),
            docker_service_active=bool(service_unit and service_unit.get("ActiveState") == "active"))
    return dict(base, error_code="ENGINE_PEER_IDENTITY_UNVERIFIED")


def _docker_cli_socket():
    """The workflow pins DOCKER_HOST and disables context overrides explicitly."""
    if os.environ.get("DOCKER_CONTEXT"):
        raise TrialFailure("DOCKER_CLI_CONTEXT_OVERRIDE_UNEXPECTED")
    host = os.environ.get("DOCKER_HOST")
    if not isinstance(host, str) or not host.startswith("unix://"):
        raise TrialFailure("DOCKER_CLI_ENDPOINT_UNVERIFIED")
    path = host[len("unix://"):]
    if path != EXPECTED_ENGINE_SOCKET:
        raise TrialFailure("DOCKER_CLI_ENDPOINT_MISMATCH")
    return path


def _preserve_cas_for_reconciliation(temp_root, result_dir):
    source = Path(temp_root) / "lease"
    target = Path(result_dir) / "cas-recovery"
    target.mkdir(mode=0o700)
    hashes = {}
    for name in ("lease-v2.json", "lease-v2.lock"):
        path = source / name
        try:
            info = os.lstat(str(path))
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise TrialFailure("CAS_RECOVERY_FILE_UNSAFE")
        payload = path.read_bytes()
        destination = target / name
        fd = os.open(str(destination), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            try:
                destination.unlink()
            except OSError:
                pass
            raise
        if destination.read_bytes() != payload:
            raise TrialFailure("CAS_RECOVERY_READBACK_FAILED")
        hashes[name] = hashlib.sha256(payload).hexdigest()
    if not hashes:
        raise TrialFailure("CAS_RECOVERY_STATE_MISSING")
    return hashes


def run(source_root: Path, dependency_archive: Path, dependency_sha: str, image_id: str):
    report = {"schema": 1, "status": "RUNNING", "phases": {}, "cleanup": "NOT_STARTED",
              "cas": "NOT_STARTED", "container_peer_auth": "NOT_STARTED"}
    current_phase = "runner_preflight"
    if os.geteuid() != 0 or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise TrialFailure("RUNNER_PREFLIGHT_INVALID")
    source_root = source_root.resolve(strict=True)
    dependency_archive = dependency_archive.resolve(strict=True)
    source_archive = Path(os.environ["MCP_DOCKER_SOURCE_ARCHIVE"])
    source_sha = os.environ["MCP_DOCKER_SOURCE_SHA256"]
    if hashlib.sha256(source_archive.read_bytes()).hexdigest() != source_sha:
        raise TrialFailure("SOURCE_ARCHIVE_READBACK_MISMATCH")
    sys.path.insert(0, str(source_root))
    from tools.document_nas_local_service_lease_v2 import (
        LeaseRecord, SecureLeaseV2Store, _kernel_boot_id,
    )
    from tools.document_nas_docker_lease_port import (
        DockerLeaseRPCServer, SecureDockerLeasePort,
    )
    from tools.document_nas_docker_engine_v141 import DockerEngineV141
    from tools.document_nas_docker_named_volume_lifecycle import (
        APPROVED_BASE_AMD64, NamedVolumeTrialLifecycle,
    )
    if APPROVED_BASE_AMD64 != BASE_DIGEST:
        raise TrialFailure("X86_BASE_DIGEST_POLICY_MISMATCH")

    run_id = str(uuid.uuid4())
    report["run_id"] = run_id
    temp_root = tempfile.mkdtemp(prefix="codex-mcp-docker-trial-", dir="/run/lock")
    os.chmod(temp_root, 0o700)
    run_dir = None
    socket_root_created = False
    rpc = None
    rpc_thread = None
    lifecycle = None
    engine = None
    store = None
    port = None
    image = image_id
    try:
        lease_dir = Path(temp_root) / "lease"
        lease_dir.mkdir(mode=0o700)
        now = time.monotonic()
        pid, ticks, boot = os.getpid(), _proc_ticks(os.getpid()), _kernel_boot_id()
        source_digest = source_sha
        record = LeaseRecord.initial(run_id=run_id, boot_id=boot, mode="trial",
            owner_role="coordinator", owner_pid=pid, owner_start_ticks=ticks,
            contract_digest=source_digest, now=now, phase_ttl=270.0,
            run_deadline_monotonic=now+280.0)
        record = dataclasses.replace(record, coordinator_pid=pid, coordinator_start_ticks=ticks)
        store = SecureLeaseV2Store(str(lease_dir), trusted_root=temp_root,
            owner_uid=0, owner_gid=0)
        store.create(record)
        port = SecureDockerLeasePort(store, run_id=run_id, coordinator_pid=pid,
            coordinator_start_ticks=ticks, monotonic=time.monotonic)
        current_phase = "ENGINE_PREFLIGHT"
        report["phases"][current_phase] = "RUNNING"
        cli_socket = _docker_cli_socket()
        report["engine_endpoints"] = {"docker_cli_socket": cli_socket,
            "adapter_socket": cli_socket, "match": True,
            "expected_peer_uid": 0, "expected_peer_gid": 0}
        engine = DockerEngineV141(socket_path=cli_socket, expected_uid=0, expected_gid=0,
            peer_identity_verifier=_engine_peer_proof,
            expected_platform=("linux", "amd64", ""),
            expected_base_digest=BASE_DIGEST)
        daemon_version = engine.ping()
        report["engine_peer_diagnostic"] = engine.last_peer_diagnostic
        report["docker_api"] = "1.41"
        report["docker_engine_version"] = daemon_version
        report["phases"]["ENGINE_PREFLIGHT"] = "PASS"

        run_dir, socket_root_created = _secure_socket_tree(run_id)
        socket_path = run_dir / "lease.sock"
        holder = {"lifecycle": None}
        def verify_peer(peer_pid, peer_uid, peer_gid):
            current = holder["lifecycle"]
            cid = current.ids.get("gateway") if current is not None else None
            peer_proc = _parse_proc_identity(peer_pid)
            initial = {"peer_pid_observed": peer_pid, "peer_uid_observed": peer_uid,
                "peer_gid_observed": peer_gid, "peer_pid_expected_from_engine": None,
                "peer_uid_expected": 61001, "peer_gid_expected": 61001,
                "peer_executable_observed": peer_proc.get("exe_name") if peer_proc else None,
                "peer_start_ticks_observed": peer_proc.get("start_ticks") if peer_proc else None,
                "namespace_pid_match": False, "process_identity_verified": False}
            report["container_peer_observation"] = initial
            if not cid or (peer_uid, peer_gid) != (61001, 61001) or peer_proc is None:
                return False
            observed = engine.inspect_container(cid)
            if not isinstance(observed, dict):
                return False
            state, config = observed.get("State", {}), observed.get("Config", {})
            expected_pid = state.get("Pid")
            initial["peer_pid_expected_from_engine"] = expected_pid
            initial["namespace_pid_match"] = expected_pid == peer_pid
            initial["proc_uid_effective"] = peer_proc.get("uid_effective")
            initial["proc_gid_effective"] = peer_proc.get("gid_effective")
            initial["proc_executable_path"] = peer_proc.get("exe_path")
            initial["container_id_match"] = observed.get("Id") == cid
            initial["container_running"] = state.get("Running") is True
            initial["container_user"] = config.get("User")
            initial["container_image"] = config.get("Image")
            initial["container_labels_match"] = config.get("Labels") == {
                "codex.mcp.trial":"1", "codex.mcp.run":run_id, "codex.mcp.role":"gateway"}
            identity_ok = (observed.get("Id") == cid and state.get("Running") is True
                and expected_pid == peer_pid
                and (peer_proc.get("uid_effective"), peer_proc.get("gid_effective")) == (peer_uid, peer_gid)
                and os.path.basename(peer_proc.get("exe_path", "")) == "python3.9"
                and config.get("User") == "61001:61001"
                and config.get("Image") == image
                and config.get("Labels") == {"codex.mcp.trial":"1",
                    "codex.mcp.run":run_id, "codex.mcp.role":"gateway"})
            initial["process_identity_verified"] = bool(identity_ok)
            return bool(identity_ok)
        rpc = DockerLeaseRPCServer(str(socket_path), port, peer_uid=61001,
            peer_gid=61001, peer_executable="/usr/local/bin/python3.9",
            application_only=True, application_run_id=run_id,
            application_peer_verifier=verify_peer).bind()
        rpc_thread = threading.Thread(target=rpc.serve_forever, daemon=True)
        rpc_thread.start()

        lifecycle = NamedVolumeTrialLifecycle(engine=engine, lease=port, run_id=run_id,
            gateway_image_id=image, tunnel_image_id=image,
            expected_platform=("linux", "amd64", ""), expected_base_digest=BASE_DIGEST,
            cas_socket_host_path=str(socket_path), dependency_profile="x86_64-validation")
        lifecycle.approve_non_nas_validation()
        report["admission"] = "NON_NAS_X86_CI_ONLY"
        current_phase = "A_volume_init_readback"
        report["phases"][current_phase] = "RUNNING"
        lifecycle.prepare_volume()
        report["phases"][current_phase] = "PASS"
        current_phase = "B_offline_installer_import_cgroup"
        report["phases"][current_phase] = "RUNNING"
        lifecycle.install_offline_bundle(dependency_archive.read_bytes(), sha256=dependency_sha,
            source_archive=source_archive.read_bytes(), source_sha256=source_sha)
        report["phases"][current_phase] = "PASS"
        holder["lifecycle"] = lifecycle
        current_phase = "C_same_store_so_peercred_peer_pin"
        report["phases"][current_phase] = "RUNNING"
        lifecycle.start_gateway()
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline and rpc.application_success_count < 1:
            running = engine.inspect_container(lifecycle.ids["gateway"])
            if not isinstance(running, dict) or running.get("State", {}).get("Status") != "running":
                raise TrialFailure("GATEWAY_EXITED_BEFORE_CAS_READ")
            time.sleep(0.1)
        if rpc.application_success_count < 1 or rpc.application_last_operation != "read_state":
            raise TrialFailure("APPLICATION_CAS_READ_NOT_OBSERVED")
        report["phases"][current_phase] = "PASS"
        report["container_peer_auth"] = "PASS"
        report["application_cas_state"] = port.read_state(run_id)
        report["application_rpc_count"] = rpc.application_success_count
        report["phases"]["D_full_runtime"] = "NOT_EXECUTED"
        report["phases"]["E_deadline_recovery"] = "NOT_EXECUTED"
        report["status"] = "PASS_A_B_C"
        return_code = 0
    except Exception as exc:
        code = getattr(exc, "code", "DOCKER_TRIAL_UNEXPECTED")
        report["status"] = "FAIL"
        report["primary_error"] = code if re.fullmatch(r"[A-Z0-9_]+", str(code)) else "DOCKER_TRIAL_UNEXPECTED"
        report["failed_phase"] = current_phase
        diagnostics = getattr(exc, "diagnostics", None)
        if isinstance(diagnostics, dict):
            report["primary_error_diagnostics"] = diagnostics
        if engine is not None and engine.last_peer_diagnostic is not None:
            report["engine_peer_diagnostic"] = engine.last_peer_diagnostic
        return_code = 1
    finally:
        cleanup_ok = False
        if lifecycle is not None:
            try:
                lifecycle.cleanup()
                report["cleanup"] = "PASS"
                cleanup_ok = True
            except Exception as exc:
                report["cleanup"] = "FAIL"
                report["cleanup_error"] = getattr(exc, "code", "CLEANUP_UNCERTAIN")
        elif port is not None:
            report["cleanup"] = "NO_DOCKER_MUTATION"
            cleanup_ok = True
        final = None
        if store is not None:
            try:
                final = store.read()
                resources = final.docker_resources
                report["cas"] = {"phase": final.phase, "resource_state": resources.state if resources else None,
                    "pinned_roles": sorted((resources.pins or {}).keys()) if resources else [],
                    "intent_present": bool(resources and resources.intent)}
            except Exception as exc:
                report["cas"] = "FINAL_READBACK_FAILED"
                report["cas_readback_error"] = getattr(exc, "code", "CAS_FINAL_READBACK_FAILED")
        if rpc is not None:
            rpc.stop()
            rpc.close()
        if rpc_thread is not None:
            rpc_thread.join(timeout=2)
        if run_dir is not None:
            try:
                run_dir.rmdir()
            except OSError:
                report["socket_cleanup"] = "FAIL"
            else:
                report["socket_cleanup"] = "PASS"
        if socket_root_created:
            try:
                SOCKET_ROOT.rmdir()
            except OSError:
                report["socket_root_cleanup"] = "RETAINED_NONEMPTY"
            else:
                report["socket_root_cleanup"] = "PASS"
        resources_absent = lifecycle is None
        if lifecycle is not None and cleanup_ok and final is not None and engine is not None:
            try:
                current = final.docker_resources
                no_pins = current is None or not (current.pins or {})
                no_resources = (engine.inspect_volume(lifecycle.volume.name) is None
                    and all(engine.inspect_container(cid) is None for cid in lifecycle.ids.values())
                    and port.read_volume_pin(run_id) is None
                    and port.read_initializer_pin(run_id) is None
                    and port.read_installer_pin(run_id) is None
                    and all(port.read_pin(run_id, role) is None for role in ("gateway", "tunnel")))
                resources_absent = bool(no_pins and no_resources
                    and (current is None or current.state == "STOPPED"))
            except Exception:
                resources_absent = False
        report["resource_absence_verified"] = bool(resources_absent)
        preserve_state = (not resources_absent or not cleanup_ok
            or report.get("cas") == "FINAL_READBACK_FAILED"
            or report.get("socket_cleanup") == "FAIL"
            or report.get("socket_root_cleanup") == "FAIL")
        if preserve_state:
            result_dir = Path(os.environ.get("DOCKER_TRIAL_RESULTS", "/results"))
            try:
                report["cas_recovery_copy_sha256"] = _preserve_cas_for_reconciliation(
                    temp_root, result_dir)
                report["controller_state_cleanup"] = "RETAINED_FOR_RECONCILIATION"
                report["controller_state_path"] = "encrypted-report:cas-recovery"
            except Exception as exc:
                report["controller_state_cleanup"] = "PRESERVATION_FAILED"
                report["cas_recovery_error"] = getattr(exc, "code", "CAS_RECOVERY_PRESERVATION_FAILED")
        else:
            try:
                shutil.rmtree(temp_root)
            except OSError:
                report["controller_state_cleanup"] = "FAIL"
            else:
                report["controller_state_cleanup"] = "PASS"
        if (report.get("cleanup") == "FAIL" or report.get("socket_cleanup") == "FAIL"
                or report.get("controller_state_cleanup") in {"FAIL", "PRESERVATION_FAILED"}
                or not resources_absent):
            report["status"] = "FAIL_CLEANUP"
            return_code = 1
        result_dir = Path(os.environ.get("DOCKER_TRIAL_RESULTS", "/results"))
        result_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        result_path = result_dir / "docker-trial-report.json"
        result_path.write_text(json.dumps(report, sort_keys=True) + "\n", encoding="ascii")
        os.chmod(result_path, 0o600)
    print("DOCKER_TRIAL_STATUS=" + str(report["status"]))
    for name in ("A_volume_init_readback", "B_offline_installer_import_cgroup",
                 "C_same_store_so_peercred_peer_pin", "D_full_runtime", "E_deadline_recovery"):
        print("DOCKER_TRIAL_{}={}".format(name, report.get("phases", {}).get(name, "NOT_REACHED")))
    return return_code


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--dependencies", required=True)
    parser.add_argument("--dependency-sha256", required=True)
    parser.add_argument("--image-iid", required=True)
    args = parser.parse_args()
    try:
        image_id = Path(args.image_iid).read_text(encoding="ascii").strip()
        if hashlib.sha256(Path(args.dependencies).read_bytes()).hexdigest() != args.dependency_sha256:
            raise TrialFailure("DEPENDENCY_ARCHIVE_DIGEST_MISMATCH")
        return run(Path(args.source), Path(args.dependencies), args.dependency_sha256, image_id)
    except Exception as exc:
        code = getattr(exc, "code", "DOCKER_TRIAL_PREFLIGHT_FAILED")
        safe_code = str(code) if re.fullmatch(r"[A-Z0-9_]+", str(code)) else "DOCKER_TRIAL_PREFLIGHT_FAILED"
        result_dir = Path(os.environ.get("DOCKER_TRIAL_RESULTS", "/results"))
        try:
            result_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            target = result_dir / "docker-trial-report.json"
            target.write_text(json.dumps({"schema":1, "status":"FAIL",
                "failed_phase":"controller_preflight", "primary_error":safe_code},
                sort_keys=True) + "\n", encoding="ascii")
            os.chmod(target, 0o600)
        except OSError:
            pass
        print("DOCKER_TRIAL_STATUS=FAIL code=" + safe_code)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
