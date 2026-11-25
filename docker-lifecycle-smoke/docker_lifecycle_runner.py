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
import traceback
import uuid
from pathlib import Path

BASE_DIGEST = "sha256:03dee9ce00747bb5390e7b4ad00307b4dbc7790f7da77cc3581f93cfa99a6363"
SOCKET_ROOT = Path("/run/codex-mcp-lease")
EXPECTED_ENGINE_SOCKET = "/var/run/docker.sock"


class TrialFailure(RuntimeError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _safe_exception_details(exc, phase):
    """Bound diagnostics to exception type/errno and source locations only."""
    return {"phase": phase, "exception_class": type(exc).__name__[:80],
        "errno": exc.errno if isinstance(exc, OSError) and type(exc.errno) is int else None,
        "stack": [{"file": os.path.basename(frame.filename)[:80],
                   "line": int(frame.lineno), "function": frame.name[:80]}
                  for frame in traceback.extract_tb(exc.__traceback__, limit=12)]}


def _mark_phase_failed(report, phase):
    phases = report.get("phases")
    if isinstance(phases, dict) and phases.get(phase) == "RUNNING":
        phases[phase] = "FAIL"


def _nocopy_failure_is_payload_only(exc):
    """Allow only a verified sentinel-payload defect to proceed to independent A-C."""
    diagnostics = getattr(exc, "diagnostics", None)
    if (getattr(exc, "code", None) != "NOCOPY_CONTROL_PAYLOAD_EXIT_NONZERO"
            or not isinstance(diagnostics, dict)):
        return None
    stages = diagnostics.get("stages")
    cleanup = diagnostics.get("cleanup")
    container = diagnostics.get("container_diagnostic")
    allowed_codes = {"NOCOPY_CONTROL_SENTINEL_CONTENT_INVALID",
                     "NOCOPY_CONTROL_SENTINEL_IDENTITY_INVALID"}
    if (not isinstance(stages, dict)
            or stages.get("image_sentinel_preflight") != "PASS"
            or any(stages.get(key) != "PASS" for key in
                   ("create", "create_readback", "pin", "start"))
            or stages.get("sentinel_verify") != "FAIL"
            or not isinstance(cleanup, dict) or cleanup.get("status") != "PASS"
            or cleanup.get("container_absent") is not True
            or cleanup.get("pin_absent") is not True
            or cleanup.get("creation_absent") is not True
            or not isinstance(container, dict) or container.get("status") != "PASS"
            or container.get("exit_code") != 2 or container.get("oom_killed") is not False
            or container.get("application_code") not in allowed_codes
            or container.get("application_phase") != "nocopy-positive-control"):
        return None
    return {"code":container["application_code"],
            "phase":container["application_phase"], "exit_code":2,
            "pre_mount_image_sentinel":"PASS", "creation_and_pin":"PASS",
            "cleanup":"PASS"}


def _locked_source_digest():
    """Read the private source archive digest from the checked-in lock."""
    lock_path = Path(__file__).resolve().parent / "docker-lifecycle-lock.json"
    try:
        lock = json.loads(lock_path.read_text(encoding="ascii"))
        source = lock["private_source"]
        digest = source["archive_sha256"]
    except (OSError, ValueError, KeyError, TypeError):
        raise TrialFailure("SOURCE_LOCK_UNREADABLE")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise TrialFailure("SOURCE_LOCK_DIGEST_INVALID")
    return digest


def _shutdown_rpc(rpc, thread, *, stop_timeout=2.0, escalation_timeout=1.0):
    """Stop and join before closing; close is a bounded escalation only."""
    rpc.stop()
    if thread is not None:
        thread.join(timeout=stop_timeout)
        if thread.is_alive():
            rpc.close()
            thread.join(timeout=escalation_timeout)
        if thread.is_alive():
            raise TrialFailure("RPC_THREAD_DID_NOT_TERMINATE")
    rpc.close()


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


def _auxiliary_cas_volume(*, root, engine, LeaseRecord, SecureLeaseV2Store,
                          SecureDockerLeasePort, kernel_boot_id, contract_digest,
                          image_id, contexts=None, now_fn=time.monotonic):
    """Create one isolated run CAS plus one volume, recording identity before use."""
    from tools.document_nas_docker_named_volume_lifecycle import (
        VolumeSpec, validate_volume_readback,
    )
    run_id = str(uuid.uuid4())
    run_dir = Path(root) / ("aux-" + run_id.replace("-", ""))
    run_dir.mkdir(mode=0o700)
    os.chmod(run_dir, 0o700)
    now = now_fn()
    pid, ticks = os.getpid(), _proc_ticks(os.getpid())
    record = LeaseRecord.initial(run_id=run_id, boot_id=kernel_boot_id, mode="trial",
        owner_role="coordinator", owner_pid=pid, owner_start_ticks=ticks,
        contract_digest=contract_digest, now=now, phase_ttl=270.0,
        run_deadline_monotonic=now + 280.0)
    record = dataclasses.replace(record, coordinator_pid=pid, coordinator_start_ticks=ticks)
    store = SecureLeaseV2Store(str(run_dir), trusted_root=str(root), owner_uid=0, owner_gid=0)
    store.create(record)
    port = SecureDockerLeasePort(store, run_id=run_id, coordinator_pid=pid,
        coordinator_start_ticks=ticks, monotonic=now_fn)
    volume = VolumeSpec.for_run(run_id)
    context = {"run_id":run_id, "store":store, "port":port, "volume":volume,
               "image_id":image_id, "created":False, "removed":False}
    if contexts is not None:
        contexts.append(context)
    labels = dict(volume.labels)
    if port.persist_intent(volume.name, image_id, image_id, labels) is not True:
        raise TrialFailure("AUX_CAS_INTENT_FAILED")
    if engine.inspect_volume(volume.name) is not None:
        raise TrialFailure("AUX_VOLUME_COLLISION")
    if port.begin_resource_creation(run_id, "volume", name=volume.name, image_id="",
            volume_name=volume.name, driver="local", labels=labels) is not True:
        raise TrialFailure("AUX_VOLUME_CREATE_INTENT_FAILED")
    if engine.create_volume(volume) is not True:
        raise TrialFailure("AUX_VOLUME_CREATE_FAILED")
    if port.record_created_resource(run_id, "volume", volume.name) is not True:
        raise TrialFailure("AUX_VOLUME_IDENTITY_CAS_FAILED")
    actual = engine.inspect_volume(volume.name)
    if not isinstance(actual, dict) or not validate_volume_readback(volume, actual):
        raise TrialFailure("AUX_VOLUME_READBACK_FAILED")
    if not isinstance(actual.get("Mountpoint"), str) or not actual["Mountpoint"].startswith("/"):
        raise TrialFailure("AUX_VOLUME_MOUNTPOINT_INVALID")
    if port.persist_volume_pin(run_id, volume.name, volume.driver, labels) is not True:
        raise TrialFailure("AUX_VOLUME_PIN_FAILED")
    if port.read_volume_pin(run_id) != {"name":volume.name,"driver":"local","labels":labels}:
        raise TrialFailure("AUX_VOLUME_PIN_READBACK_FAILED")
    context["created"] = True
    return context


def _remove_auxiliary_volume(*, context, engine):
    from tools.document_nas_docker_named_volume_lifecycle import validate_volume_readback
    run_id, volume, port = context["run_id"], context["volume"], context["port"]
    current = engine.inspect_volume(volume.name)
    creation = port.read_creation_record(run_id, "volume")
    if port.transition(run_id, "PREPARED", "STOPPING") is not True:
        raise TrialFailure("AUX_CAS_STOPPING_FAILED")
    if current is not None:
        if (not isinstance(creation, dict)
                or creation.get("role") != "volume"
                or creation.get("run_id") != run_id
                or creation.get("name") != volume.name
                or creation.get("driver") != "local"
                or creation.get("labels") != dict(volume.labels)
                or not isinstance(current, dict) or not validate_volume_readback(volume, current)):
            raise TrialFailure("AUX_VOLUME_OWNERSHIP_UNVERIFIED")
        if creation is not None and creation.get("state") == "INTENDED":
            if port.record_created_resource(run_id, "volume", volume.name) is not True:
                raise TrialFailure("AUX_VOLUME_ID_RECOVERY_FAILED")
            creation = port.read_creation_record(run_id, "volume")
        if creation is not None and creation.get("resource_id") != volume.name:
            raise TrialFailure("AUX_VOLUME_CAS_IDENTITY_MISMATCH")
        if engine.remove_volume(volume.name) is not True:
            raise TrialFailure("AUX_VOLUME_REMOVE_FAILED")
    if engine.inspect_volume(volume.name) is not None:
        raise TrialFailure("AUX_VOLUME_REMOVE_READBACK_FAILED")
    volume_pin = port.read_volume_pin(run_id)
    if volume_pin is not None:
        if port.clear_volume_pin(run_id, volume.name) is not True:
            raise TrialFailure("AUX_VOLUME_PIN_CLEAR_FAILED")
    elif creation is not None:
        if creation.get("state") == "VERIFIED" or port.clear_unverified_creation(
                run_id, "volume", creation.get("resource_id", "")) is not True:
            raise TrialFailure("AUX_VOLUME_CREATION_CLEAR_FAILED")
    if port.read_volume_pin(run_id) is not None or port.read_creation_record(run_id, "volume") is not None:
        raise TrialFailure("AUX_VOLUME_CAS_RESIDUAL")
    if port.transition(run_id, "STOPPING", "STOPPED") is not True:
        raise TrialFailure("AUX_CAS_STOPPED_FAILED")
    if engine.inspect_volume(volume.name) is not None:
        raise TrialFailure("AUX_VOLUME_RESIDUAL")
    context["removed"] = True


def _cleanup_auxiliary_context(*, context, engine, expected_base_digest):
    """Reconcile only exact ID/name/image/run/role objects in this auxiliary CAS."""
    from tools.document_nas_docker_named_volume_lifecycle import _container_belongs_to_creation
    run_id, port = context["run_id"], context["port"]
    name = "codex-mcp-trial-install-" + run_id.replace("-", "")
    actual = engine.inspect_container_name(name)
    creation = port.read_creation_record(run_id, "installer")
    if actual is not None:
        evidence = engine.inspect_image(context["image_id"])
        if creation is not None and creation.get("state") == "INTENDED":
            if not _container_belongs_to_creation(creation, actual,
                    image_labels=evidence.config_labels,
                    expected_base_digest=expected_base_digest):
                raise TrialFailure("AUX_CONTAINER_OWNERSHIP_UNVERIFIED")
            cid = actual.get("Id")
            if not isinstance(cid, str) or port.record_created_resource(
                    run_id, "installer", cid) is not True:
                raise TrialFailure("AUX_CONTAINER_ID_RECOVERY_FAILED")
            creation = port.read_creation_record(run_id, "installer")
        if not isinstance(creation, dict) or not _container_belongs_to_creation(
                creation, actual, image_labels=evidence.config_labels,
                expected_base_digest=expected_base_digest):
            raise TrialFailure("AUX_CONTAINER_OWNERSHIP_UNVERIFIED")
        cid = actual.get("Id")
        state = actual.get("State", {}).get("Status")
        if state == "running":
            engine.stop_container(cid, 5)
            actual = engine.inspect_container(cid)
            state = actual.get("State", {}).get("Status") if isinstance(actual, dict) else None
        if state not in ("created", "exited", "dead"):
            raise TrialFailure("AUX_CONTAINER_STATE_UNCERTAIN")
        collector = getattr(engine, "collect_container_diagnostics", None)
        if callable(collector):
            collector(cid, run_id=run_id, role="installer",
                expected_name=name, image_id=context["image_id"])
        engine.remove_container(cid)
        if engine.inspect_container(cid) is not None or engine.inspect_container_name(name) is not None:
            raise TrialFailure("AUX_CONTAINER_REMOVE_READBACK_FAILED")
        pin = port.read_installer_pin(run_id)
        if pin is not None:
            if pin.get("container_id") != cid or port.clear_installer_pin(run_id, cid) is not True:
                raise TrialFailure("AUX_INSTALLER_PIN_CLEAR_FAILED")
        else:
            if creation.get("state") == "VERIFIED" or port.clear_unverified_creation(
                    run_id, "installer", cid) is not True:
                raise TrialFailure("AUX_INSTALLER_CREATION_CLEAR_FAILED")
    elif creation is not None:
        if creation.get("state") == "INTENDED":
            if port.clear_unverified_creation(run_id, "installer", "") is not True:
                raise TrialFailure("AUX_INSTALLER_INTENT_CLEAR_FAILED")
        elif creation.get("state") == "CREATED":
            if port.clear_unverified_creation(run_id, "installer", creation.get("resource_id", "")) is not True:
                raise TrialFailure("AUX_INSTALLER_ABSENCE_CLEAR_FAILED")
        else:
            raise TrialFailure("AUX_VERIFIED_INSTALLER_PIN_MISSING")
    _remove_auxiliary_volume(context=context, engine=engine)


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


def _preserve_cas_for_reconciliation(temp_root, result_dir, auxiliary_contexts=()):
    target = Path(result_dir) / "cas-recovery"
    target.mkdir(mode=0o700)
    os.chmod(target, 0o700)

    def copy_store(source, destination, *, create_directory):
        if create_directory:
            destination.mkdir(mode=0o700)
            os.chmod(destination, 0o700)
        hashes = {}
        for name in ("lease-v2.json", "lease-v2.lock"):
            path = Path(source) / name
            try:
                info = os.lstat(str(path))
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
                raise TrialFailure("CAS_RECOVERY_FILE_UNSAFE")
            payload = path.read_bytes()
            copied = destination / name
            fd = os.open(str(copied), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
            except BaseException:
                try:
                    copied.unlink()
                except OSError:
                    pass
                raise
            if copied.read_bytes() != payload:
                raise TrialFailure("CAS_RECOVERY_READBACK_FAILED")
            hashes[name] = hashlib.sha256(payload).hexdigest()
        if not hashes:
            raise TrialFailure("CAS_RECOVERY_STATE_MISSING")
        return hashes

    hashes = copy_store(Path(temp_root) / "lease", target,
                        create_directory=False)
    for index, context in enumerate(auxiliary_contexts):
        store = context.get("store") if isinstance(context, dict) else None
        source = getattr(store, "directory", None)
        if not isinstance(source, str):
            raise TrialFailure("AUX_CAS_RECOVERY_SOURCE_INVALID")
        hashes["auxiliary_{}".format(index)] = copy_store(
            source, target / "auxiliary-{:02d}".format(index), create_directory=True)
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
    source_sha = _locked_source_digest()
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
        APPROVED_BASE_AMD64, NamedVolumeTrialLifecycle, VolumeSpec,
        container_readback_checks, readback_checks_pass,
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
    rpc_thread_errors = []
    lifecycle = None
    engine = None
    store = None
    port = None
    auxiliary_contexts = []
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
            spec = current.specs.get("gateway") if current is not None else None
            evidence = current.image_evidence.get(image) if current is not None else None
            checks = (container_readback_checks(spec, observed, expected_state="running",
                expected_container_id=cid, image_labels=evidence.config_labels,
                image_env=evidence.config_env, expected_base_digest=BASE_DIGEST,
                volume_mountpoint=current.volume_mountpoint)
                if spec is not None and evidence is not None else [])
            label_check = next((item for item in checks if item.get("field") == "Config.Labels"), None)
            initial["container_labels_match"] = bool(label_check and label_check.get("result") is True)
            initial["container_config_readback"] = checks
            identity_ok = (readback_checks_pass(checks)
                and observed.get("Id") == cid and state.get("Running") is True
                and expected_pid == peer_pid
                and (peer_proc.get("uid_effective"), peer_proc.get("gid_effective")) == (peer_uid, peer_gid)
                and os.path.basename(peer_proc.get("exe_path", "")) == "python3.9"
                and config.get("User") == "61001:61001"
                and config.get("Image") == image)
            initial["process_identity_verified"] = bool(identity_ok)
            return bool(identity_ok)
        lifecycle = NamedVolumeTrialLifecycle(engine=engine, lease=port, run_id=run_id,
            gateway_image_id=image, tunnel_image_id=image,
            expected_platform=("linux", "amd64", ""), expected_base_digest=BASE_DIGEST,
            cas_socket_host_path=str(socket_path), dependency_profile="x86_64-validation")
        lifecycle.approve_non_nas_validation()
        report["admission"] = "NON_NAS_X86_CI_ONLY"
        current_phase = "A_readback_failure_cleanup_regression"
        report["phases"][current_phase] = "RUNNING"
        cleanup_context = _auxiliary_cas_volume(root=temp_root, engine=engine,
            LeaseRecord=LeaseRecord, SecureLeaseV2Store=SecureLeaseV2Store,
            SecureDockerLeasePort=SecureDockerLeasePort, kernel_boot_id=boot,
            contract_digest=source_digest, image_id=image, contexts=auxiliary_contexts)
        report["readback_cleanup_regression"] = engine.run_real_readback_cleanup_regression(
            run_id=cleanup_context["run_id"], volume=cleanup_context["volume"],
            image_id=image, lease=cleanup_context["port"])
        regression_container_name = "codex-mcp-trial-install-" + cleanup_context["run_id"].replace("-", "")
        if (engine.inspect_container_name(regression_container_name) is not None
                or cleanup_context["port"].read_creation_record(
                    cleanup_context["run_id"], "installer") is not None):
            raise TrialFailure("READBACK_REGRESSION_CONTAINER_RESIDUAL")
        _remove_auxiliary_volume(context=cleanup_context, engine=engine)
        report["readback_cleanup_regression"]["resource_cleanup_verified"] = cleanup_context["removed"]
        report["phases"][current_phase] = "PASS"

        current_phase = "A_nocopy_positive_control"
        report["phases"][current_phase] = "RUNNING"
        nocopy_context = _auxiliary_cas_volume(root=temp_root, engine=engine,
            LeaseRecord=LeaseRecord, SecureLeaseV2Store=SecureLeaseV2Store,
            SecureDockerLeasePort=SecureDockerLeasePort, kernel_boot_id=boot,
            contract_digest=source_digest, image_id=image, contexts=auxiliary_contexts)
        try:
            report["nocopy_positive_control"] = engine.run_nocopy_positive_control(
                run_id=nocopy_context["run_id"], volume=nocopy_context["volume"],
                image_id=image, lease=nocopy_context["port"])
        except Exception as exc:
            payload_failure = _nocopy_failure_is_payload_only(exc)
            if payload_failure is None:
                raise
            report["nocopy_positive_control"] = {"status":"FAIL_DIAGNOSTIC_ONLY",
                "isolated_failure":payload_failure}
            report["failed_phase"] = current_phase
            report["phases"][current_phase] = "FAIL_DIAGNOSTIC_ONLY"
            _remove_auxiliary_volume(context=nocopy_context, engine=engine)
            report["nocopy_positive_control"]["resource_cleanup_verified"] = nocopy_context["removed"]
            if not nocopy_context["removed"]:
                raise TrialFailure("NOCOPY_AUXILIARY_CLEANUP_UNVERIFIED")
        else:
            _remove_auxiliary_volume(context=nocopy_context, engine=engine)
            report["nocopy_positive_control"]["resource_cleanup_verified"] = nocopy_context["removed"]
            report["phases"][current_phase] = "PASS"

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
        # Bind and start the RPC only when phase C is ready to launch the gateway.
        rpc = DockerLeaseRPCServer(str(socket_path), port, peer_uid=61001,
            peer_gid=61001, peer_executable="/usr/local/bin/python3.9",
            application_only=True, application_run_id=run_id,
            application_peer_verifier=verify_peer).bind()
        def serve_rpc():
            try:
                rpc.serve_forever()
            except Exception as exc:
                rpc_thread_errors.append(_safe_exception_details(exc, "rpc_serve"))
        rpc_thread = threading.Thread(target=serve_rpc, daemon=True,
                                     name="docker-trial-lease-rpc")
        rpc_thread.start()
        lifecycle.start_gateway()
        deadline = time.monotonic() + 20
        while (time.monotonic() < deadline and rpc.application_success_count < 1
                and not rpc_thread_errors):
            running = engine.inspect_container(lifecycle.ids["gateway"])
            if not isinstance(running, dict) or running.get("State", {}).get("Status") != "running":
                raise TrialFailure("GATEWAY_EXITED_BEFORE_CAS_READ")
            time.sleep(0.1)
        if rpc_thread_errors:
            raise TrialFailure("RPC_SERVER_TERMINATED_BEFORE_CAS_READ")
        if rpc.application_success_count < 1 or rpc.application_last_operation != "read_state":
            raise TrialFailure("APPLICATION_CAS_READ_NOT_OBSERVED")
        report["phases"][current_phase] = "PASS"
        report["container_peer_auth"] = "PASS"
        report["application_cas_state"] = port.read_state(run_id)
        report["application_rpc_count"] = rpc.application_success_count
        report["phases"]["D_full_runtime"] = "NOT_EXECUTED"
        report["phases"]["E_deadline_recovery"] = "NOT_EXECUTED"
        if report["phases"].get("A_nocopy_positive_control") == "FAIL_DIAGNOSTIC_ONLY":
            report["status"] = "PARTIAL_A_B_C_NOCOPY_DIAGNOSTIC_FAILURE"
            return_code = 1
        else:
            report["status"] = "PASS_A_B_C"
            return_code = 0
    except Exception as exc:
        code = getattr(exc, "code", "DOCKER_TRIAL_UNEXPECTED")
        report["status"] = "FAIL"
        report["primary_error"] = code if re.fullmatch(r"[A-Z0-9_]+", str(code)) else "DOCKER_TRIAL_UNEXPECTED"
        report["failed_phase"] = current_phase
        _mark_phase_failed(report, current_phase)
        details = _safe_exception_details(exc, current_phase)
        diagnostics = getattr(exc, "diagnostics", None)
        if isinstance(diagnostics, dict):
            details.update(diagnostics)
        report["primary_error_diagnostics"] = details
        if engine is not None and engine.last_peer_diagnostic is not None:
            report["engine_peer_diagnostic"] = engine.last_peer_diagnostic
        return_code = 1
    finally:
        cleanup_ok = False
        for context in reversed(auxiliary_contexts):
            if context.get("removed"):
                continue
            try:
                _cleanup_auxiliary_context(context=context, engine=engine,
                    expected_base_digest=BASE_DIGEST)
                context["cleanup_reconciled"] = True
            except Exception as exc:
                context["cleanup_reconciled"] = False
                context["cleanup_error"] = getattr(exc, "code", "AUX_CLEANUP_UNCERTAIN")
        if lifecycle is not None:
            try:
                lifecycle.cleanup()
                report["cleanup"] = "PASS"
                cleanup_ok = True
            except Exception as exc:
                report["cleanup"] = "FAIL"
                report["cleanup_error"] = getattr(exc, "code", "CLEANUP_UNCERTAIN")
        if engine is not None:
            report["container_diagnostics"] = list(
                getattr(engine, "container_diagnostics", [])[-32:])
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
                    "creation_records": ({role:{"state":item.get("state"),
                        "resource_id":item.get("resource_id"), "name":item.get("name")}
                        for role, item in (resources.creations or {}).items()} if resources else {}),
                    "intent_present": bool(resources and resources.intent)}
            except Exception as exc:
                report["cas"] = "FINAL_READBACK_FAILED"
                report["cas_readback_error"] = getattr(exc, "code", "CAS_FINAL_READBACK_FAILED")
        if rpc is not None:
            try:
                _shutdown_rpc(rpc, rpc_thread)
                report["rpc_shutdown"] = "PASS"
            except Exception as exc:
                report["rpc_shutdown"] = "FAIL"
                report["rpc_shutdown_error"] = _safe_exception_details(exc, "rpc_shutdown")
                if report.get("status") == "PASS_A_B_C":
                    report["status"] = "FAIL_CLEANUP"
                    return_code = 1
            if rpc_thread_errors:
                report["rpc_thread_error"] = rpc_thread_errors[:4]
                report["rpc_shutdown"] = "FAIL"
                report["status"] = "FAIL_CLEANUP"
                return_code = 1
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
                no_creation_records = current is None or not (current.creations or {})
                no_resources = (engine.inspect_volume(lifecycle.volume.name) is None
                    and all(engine.inspect_container(cid) is None for cid in lifecycle.ids.values())
                    and port.read_volume_pin(run_id) is None
                    and port.read_initializer_pin(run_id) is None
                    and port.read_installer_pin(run_id) is None
                    and all(port.read_pin(run_id, role) is None for role in ("gateway", "tunnel")))
                resources_absent = bool(no_pins and no_creation_records and no_resources
                    and (current is None or current.state == "STOPPED"))
            except Exception:
                resources_absent = False
        if engine is not None:
            for context in auxiliary_contexts:
                try:
                    aux_record = context["store"].read()
                    aux_resources = aux_record.docker_resources
                    aux_clear = (
                        engine.inspect_volume(context["volume"].name) is None
                        and engine.inspect_container_name("codex-mcp-trial-install-" +
                            context["run_id"].replace("-", "")) is None
                        and aux_resources is not None and aux_resources.state == "STOPPED"
                        and not (aux_resources.pins or {})
                        and not (aux_resources.creations or {}))
                    context["reconciliation_verified"] = bool(aux_clear)
                    resources_absent = resources_absent and bool(aux_clear)
                except Exception:
                    context["reconciliation_verified"] = False
                    resources_absent = False
            report["auxiliary_resource_reconciliation"] = [
                {"status":"PASS" if item.get("reconciliation_verified") else "UNCERTAIN",
                 "removed":bool(item.get("removed"))}
                for item in auxiliary_contexts]
        report["resource_absence_verified"] = bool(resources_absent)
        preserve_state = (not resources_absent or not cleanup_ok
            or report.get("cas") == "FINAL_READBACK_FAILED"
            or report.get("socket_cleanup") == "FAIL"
            or report.get("socket_root_cleanup") == "FAIL")
        if preserve_state:
            result_dir = Path(os.environ.get("DOCKER_TRIAL_RESULTS", "/results"))
            try:
                report["cas_recovery_copy_sha256"] = _preserve_cas_for_reconciliation(
                    temp_root, result_dir, auxiliary_contexts)
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
        if (report.get("cleanup") == "FAIL" or report.get("rpc_shutdown") == "FAIL"
                or report.get("socket_cleanup") == "FAIL"
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
    for name in ("A_readback_failure_cleanup_regression", "A_nocopy_positive_control",
                 "A_volume_init_readback",
                 "B_offline_installer_import_cgroup",
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
                "failed_phase":"controller_preflight", "primary_error":safe_code,
                "primary_error_diagnostics":_safe_exception_details(exc, "controller_preflight")},
                sort_keys=True) + "\n", encoding="ascii")
            os.chmod(target, 0o600)
        except OSError:
            pass
        print("DOCKER_TRIAL_STATUS=FAIL code=" + safe_code)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
