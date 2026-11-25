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
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

BASE_DIGEST = "sha256:03dee9ce00747bb5390e7b4ad00307b4dbc7790f7da77cc3581f93cfa99a6363"
SOCKET_ROOT = Path("/run/codex-mcp-lease")


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


def run(source_root: Path, dependency_archive: Path, dependency_sha: str, image_id: str):
    report = {"schema": 1, "status": "RUNNING", "phases": {}, "cleanup": "NOT_STARTED",
              "cas": "NOT_STARTED", "container_peer_auth": "NOT_STARTED"}
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
        engine = DockerEngineV141(expected_uid=0, expected_platform=("linux", "amd64", ""),
            expected_base_digest=BASE_DIGEST)
        daemon_version = engine.ping()
        report["docker_api"] = "1.41"
        report["docker_engine_version"] = daemon_version

        run_dir, socket_root_created = _secure_socket_tree(run_id)
        socket_path = run_dir / "lease.sock"
        holder = {"lifecycle": None}
        def verify_peer(peer_pid, peer_uid, peer_gid):
            current = holder["lifecycle"]
            cid = current.ids.get("gateway") if current is not None else None
            if not cid or (peer_uid, peer_gid) != (61001, 61001):
                return False
            observed = engine.inspect_container(cid)
            if not isinstance(observed, dict):
                return False
            state, config = observed.get("State", {}), observed.get("Config", {})
            return (observed.get("Id") == cid and state.get("Running") is True
                and state.get("Pid") == peer_pid
                and config.get("User") == "61001:61001"
                and config.get("Image") == image
                and config.get("Labels") == {"codex.mcp.trial":"1",
                    "codex.mcp.run":run_id, "codex.mcp.role":"gateway"})
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
        lifecycle.prepare_volume()
        report["phases"]["A_volume_init_readback"] = "PASS"
        lifecycle.install_offline_bundle(dependency_archive.read_bytes(), sha256=dependency_sha,
            source_archive=source_archive.read_bytes(), source_sha256=source_sha)
        report["phases"]["B_offline_installer_import_cgroup"] = "PASS"
        holder["lifecycle"] = lifecycle
        lifecycle.start_gateway()
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline and rpc.application_success_count < 1:
            running = engine.inspect_container(lifecycle.ids["gateway"])
            if not isinstance(running, dict) or running.get("State", {}).get("Status") != "running":
                raise TrialFailure("GATEWAY_EXITED_BEFORE_CAS_READ")
            time.sleep(0.1)
        if rpc.application_success_count < 1 or rpc.application_last_operation != "read_state":
            raise TrialFailure("APPLICATION_CAS_READ_NOT_OBSERVED")
        report["phases"]["C_same_store_so_peercred_peer_pin"] = "PASS"
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
        report["failed_phase"] = next((name for name in ("A_volume_init_readback",
            "B_offline_installer_import_cgroup", "C_same_store_so_peercred_peer_pin")
            if name not in report["phases"]), "runner_preflight")
        return_code = 1
    finally:
        if lifecycle is not None:
            try:
                lifecycle.cleanup()
                report["cleanup"] = "PASS"
            except Exception as exc:
                report["cleanup"] = "FAIL"
                report["cleanup_error"] = getattr(exc, "code", "CLEANUP_UNCERTAIN")
        elif port is not None:
            report["cleanup"] = "NO_DOCKER_MUTATION"
        if store is not None:
            try:
                final = store.read()
                resources = final.docker_resources
                report["cas"] = {"phase": final.phase, "resource_state": resources.state if resources else None,
                    "pinned_roles": sorted((resources.pins or {}).keys()) if resources else []}
            except Exception:
                report["cas"] = "FINAL_READBACK_FAILED"
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
        try:
            shutil.rmtree(temp_root)
        except OSError:
            report["controller_state_cleanup"] = "FAIL"
        else:
            report["controller_state_cleanup"] = "PASS"
        if (report.get("cleanup") == "FAIL" or report.get("socket_cleanup") == "FAIL"
                or report.get("controller_state_cleanup") == "FAIL"):
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
