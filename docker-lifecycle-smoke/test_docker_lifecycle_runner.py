import errno
import base64
import contextlib
import io
import json
import os
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
import unittest.mock
from pathlib import Path
from types import SimpleNamespace

from docker_lifecycle_runner import (
    _mark_phase_failed, _nocopy_failure_is_payload_only, _safe_exception_details, _shutdown_rpc,
)

SOURCE_ROOT = os.environ.get("DOCKER_TRIAL_SOURCE_ROOT")
if SOURCE_ROOT and os.path.isdir(SOURCE_ROOT):
    sys.path.insert(0, SOURCE_ROOT)


class RunnerDiagnosticsTests(unittest.TestCase):
    def test_dead_controller_recovery_clears_creation_and_pin_atomically(self):
        required = os.environ.get("DOCKER_TRIAL_REQUIRE_REAL_RPC_TEST") == "1"
        if not os.path.isdir("/proc"):
            if required:
                self.fail("RECOVERY_CAS_REQUIRES_LINUX_PROCFS")
            self.skipTest("same-boot process identity recovery requires Linux")
        if not SOURCE_ROOT or not Path(SOURCE_ROOT).is_dir():
            if required:
                self.fail("RECOVERY_CAS_PRIVATE_SOURCE_MISSING")
            self.skipTest("private source archive is staged only in the Linux trial job")
        try:
            from tools.document_nas_local_service_lease_v2 import (
                SecureLeaseV2Store, _kernel_boot_id, _proc_start_ticks,
            )
        except ImportError as exc:
            if required:
                self.fail("RECOVERY_CAS_PRIVATE_IMPORT_FAILED:" + type(exc).__name__)
            self.skipTest("private CAS source not staged")
        with tempfile.TemporaryDirectory(prefix="docker-recovery-cas-") as tmp:
            root = Path(tmp)
            os.chmod(root, 0o700)
            child_script = root / "coordinator.py"
            child_script.write_text("""import dataclasses, json, os, time, uuid
from tools.document_nas_local_service_lease_v2 import LeaseRecord, SecureLeaseV2Store, _kernel_boot_id, _proc_start_ticks
from tools.document_nas_docker_lease_port import SecureDockerLeasePort
run_id=str(uuid.uuid4()); pid=os.getpid(); ticks=_proc_start_ticks(pid); boot=_kernel_boot_id(); now=time.monotonic()
image='sha256:'+'a'*64; root=os.environ['RECOVERY_TEST_ROOT']; lease_dir=os.path.join(root,'lease')
os.mkdir(lease_dir,0o700)
record=LeaseRecord.initial(run_id=run_id,boot_id=boot,mode='trial',owner_role='coordinator',owner_pid=pid,owner_start_ticks=ticks,contract_digest='b'*64,now=now,phase_ttl=270.0,run_deadline_monotonic=now+280.0)
record=dataclasses.replace(record,coordinator_pid=pid,coordinator_start_ticks=ticks)
store=SecureLeaseV2Store(lease_dir,trusted_root=root,owner_uid=os.geteuid(),owner_gid=os.getegid()); store.create(record)
port=SecureDockerLeasePort(store,run_id=run_id,coordinator_pid=pid,coordinator_start_ticks=ticks,monotonic=time.monotonic)
name='codex-mcp-trial-'+run_id.replace('-',''); labels={'codex.mcp.trial':'1','codex.mcp.run':run_id,'codex.mcp.role':'runtime'}
port.persist_intent(name,image,image,labels); port.begin_resource_creation(run_id,'volume',name=name,image_id='',volume_name=name,driver='local',labels=labels)
port.record_created_resource(run_id,'volume',name); port.persist_volume_pin(run_id,name,'local',labels)
""", encoding="utf-8")
            env = dict(os.environ)
            env["PYTHONPATH"] = SOURCE_ROOT
            env["RECOVERY_TEST_ROOT"] = str(root)
            child = subprocess.run([sys.executable, "-B", str(child_script)],
                env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=15, check=False)
            self.assertEqual(child.returncode, 0, child.stderr.decode("utf-8", "replace")[:500])
            store = SecureLeaseV2Store(str(root / "lease"), trusted_root=str(root),
                owner_uid=os.geteuid(), owner_gid=os.getegid())
            record = store.read()
            claimant_ticks = _proc_start_ticks(os.getpid())
            self.assertTrue(store.claim_docker_trial_reconciliation(record.sequence,
                run_id=record.run_id, claimant_pid=os.getpid(),
                claimant_start_ticks=claimant_ticks, now=__import__("time").monotonic(),
                current_boot_id=_kernel_boot_id()))
            current = store.read()
            self.assertEqual(current.docker_resources.state, "STOPPING")
            self.assertEqual(set(current.docker_resources.pins), {"volume"})
            self.assertEqual(set(current.docker_resources.creations), {"volume"})
            self.assertTrue(store.docker_trial_recovery_cas(current.sequence,
                run_id=record.run_id, claimant_pid=os.getpid(),
                claimant_start_ticks=claimant_ticks, now=__import__("time").monotonic(),
                clear_role="volume", verified_absent=True))
            current = store.read()
            self.assertFalse(current.docker_resources.pins)
            self.assertFalse(current.docker_resources.creations)
            self.assertIsNotNone(current.docker_resources.intent)
            self.assertTrue(store.docker_trial_recovery_cas(current.sequence,
                run_id=record.run_id, claimant_pid=os.getpid(),
                claimant_start_ticks=claimant_ticks, now=__import__("time").monotonic(),
                state="STOPPED"))
            stopped = store.read()
            self.assertEqual(stopped.docker_resources.state, "STOPPED")
            self.assertFalse(stopped.docker_resources.pins)
            self.assertFalse(stopped.docker_resources.creations)

    def test_docker_gateway_readback_normalizes_only_observed_engine_defaults(self):
        if not SOURCE_ROOT or not Path(SOURCE_ROOT).is_dir():
            if os.environ.get("DOCKER_TRIAL_REQUIRE_PRIVATE_ENTRYPOINT_TEST") == "1":
                self.fail("PRIVATE_ENTRYPOINT_TEST_SOURCE_ROOT_MISSING")
            self.skipTest("private archive is staged only in the Linux trial job")
        from tools.document_nas_docker_engine_v141 import DockerEngineV141
        from tools.document_nas_docker_named_volume_lifecycle import (
            CAS_SOCKET_TARGET, ContainerSpec, VolumeSpec, container_readback_checks,
            readback_checks_pass, restart_policy_matches,
        )

        run_id = "11111111-1111-4111-8111-111111111111"
        image_id = "sha256:" + "c" * 64
        volume = VolumeSpec.for_run(run_id)
        socket_source = "/run/codex-mcp-lease/11111111111141118111111111111111/lease.sock"
        spec = ContainerSpec.create(role="gateway", run_id=run_id, image_id=image_id,
            memory_bytes=201326592, pids_limit=64, volume_name=volume.name,
            cas_socket_host_path=socket_source)
        cid = "a" * 64
        image_labels = {"codex.mcp.base-image-digest":
            "sha256:03dee9ce00747bb5390e7b4ad00307b4dbc7790f7da77cc3581f93cfa99a6363",
            "codex.mcp.synthetic-tunnel":"true", "codex.mcp.trial-image-run":"45646177123"}
        observed = {
            "Id":cid, "Name":"/" + spec.name,
            "Config":{"Image":image_id,"User":"61001:61001",
                "Labels":{**image_labels,"codex.mcp.trial":"1","codex.mcp.run":run_id,
                    "codex.mcp.role":"gateway"},
                "Entrypoint":["python3","/opt/codex-mcp/bin/container-entrypoint.py"],
                "Cmd":["gateway","--run-id",run_id,"--config",
                    "/var/lib/codex-mcp/python/app/config/trial-gateway.json",
                    "--credential-provider-factory",
                    "docker_trial_container_entrypoint:synthetic_test_provider_factory"],
                "Env":["PYTHONDONTWRITEBYTECODE=1","MCP_SYNTHETIC_TUNNEL=1",
                    "MCP_SYNTHETIC_CREDENTIALS=1",
                    "MCP_DOCKER_TRIAL_FULL_RUNTIME=1",
                    "MCP_CAS_SOCKET_PATH=/run/codex-mcp-lease/lease.sock"]},
            "HostConfig":{"NetworkMode":"none","Privileged":False,"CapAdd":[],
                "CapDrop":["ALL"],"ReadonlyRootfs":True,
                "SecurityOpt":["no-new-privileges:true"],"Memory":201326592,
                "MemorySwap":201326592,"PidsLimit":64,
                "RestartPolicy":{"Name":"no","MaximumRetryCount":0},
                "Binds":[],"Devices":[],"PortBindings":{},"PidMode":"",
                "Mounts":[
                    {"Type":"volume","Source":volume.name,"Target":"/var/lib/codex-mcp",
                        "ReadOnly":False,"VolumeOptions":{"NoCopy":True}},
                    {"Type":"bind","Source":socket_source,
                        "Target":CAS_SOCKET_TARGET,"ReadOnly":True,
                        "BindOptions":{"Propagation":"rprivate"}}]},
            "Mounts":[
                {"Type":"volume","Name":volume.name,
                    "Source":"/var/lib/docker/volumes/"+volume.name+"/_data",
                    "Destination":"/var/lib/codex-mcp","Driver":"local","Mode":"z",
                    "RW":True,"Propagation":""},
                {"Type":"bind","Source":socket_source,"Destination":CAS_SOCKET_TARGET,
                    "Mode":"","RW":False,"Propagation":"rprivate"}],
            "State":{"Status":"created","OOMKilled":False}}
        mountpoint = observed["Mounts"][0]["Source"]
        labels = {"codex.mcp.trial":"1","codex.mcp.run":run_id,"codex.mcp.role":"gateway"}
        body = {"Image":image_id,"User":"61001:61001","Labels":labels,
            "Entrypoint":observed["Config"]["Entrypoint"],"Cmd":observed["Config"]["Cmd"],
            "Env":["PYTHONDONTWRITEBYTECODE=1","MCP_SYNTHETIC_TUNNEL=1",
                "MCP_SYNTHETIC_CREDENTIALS=1",
                "MCP_DOCKER_TRIAL_FULL_RUNTIME=1",
                "MCP_CAS_SOCKET_PATH=/run/codex-mcp-lease/lease.sock"],
            "HostConfig":{"NetworkMode":"none","SecurityOpt":["no-new-privileges:true"],
                "RestartPolicy":{"Name":"no"},
                "Mounts":[
                    {"Type":"volume","Source":volume.name,"Target":"/var/lib/codex-mcp",
                        "ReadOnly":False,"VolumeOptions":{"NoCopy":True}},
                    {"Type":"bind","Source":socket_source,
                        "Target":CAS_SOCKET_TARGET,"ReadOnly":True,
                        "BindOptions":{"Propagation":"rprivate"}}]}}

        self.assertTrue(restart_policy_matches({"Name":"no"}))
        self.assertTrue(restart_policy_matches({"Name":"no","MaximumRetryCount":0}))
        for invalid in ({"Name":"no","MaximumRetryCount":1},
                        {"Name":"always","MaximumRetryCount":0},
                        {"Name":"no","Unexpected":0},
                        {"Name":"no","MaximumRetryCount":False}):
            self.assertFalse(restart_policy_matches(invalid), invalid)

        for status in ("created", "running"):
            observed["State"]["Status"] = status
            checks = container_readback_checks(spec, observed, expected_state=status,
                expected_container_id=cid, image_labels=image_labels,
                expected_base_digest="sha256:03dee9ce00747bb5390e7b4ad00307b4dbc7790f7da77cc3581f93cfa99a6363",
                volume_mountpoint=mountpoint)
            self.assertTrue(readback_checks_pass(checks), checks)

        observed["State"]["Status"] = "created"
        ro_mode = json.loads(json.dumps(observed))
        ro_mode["Mounts"][1]["Mode"] = "ro"
        self.assertTrue(readback_checks_pass(container_readback_checks(spec, ro_mode,
            expected_state="created", expected_container_id=cid, image_labels=image_labels,
            expected_base_digest="sha256:03dee9ce00747bb5390e7b4ad00307b4dbc7790f7da77cc3581f93cfa99a6363",
            volume_mountpoint=mountpoint)))

        one_shot = DockerEngineV141._one_shot_readback_checks(spec.name, body, observed,
            cid, image_id, 201326592, 64, [], image_labels=image_labels,
            expected_base_digest="sha256:03dee9ce00747bb5390e7b4ad00307b4dbc7790f7da77cc3581f93cfa99a6363",
            volume_mountpoint=mountpoint)
        self.assertTrue(readback_checks_pass(one_shot), one_shot)
        bad_one_shot = json.loads(json.dumps(observed))
        bad_one_shot["HostConfig"]["RestartPolicy"]["MaximumRetryCount"] = 1
        rejected = DockerEngineV141._one_shot_readback_checks(spec.name, body, bad_one_shot,
            cid, image_id, 201326592, 64, [], image_labels=image_labels,
            expected_base_digest="sha256:03dee9ce00747bb5390e7b4ad00307b4dbc7790f7da77cc3581f93cfa99a6363",
            volume_mountpoint=mountpoint)
        self.assertFalse(readback_checks_pass(rejected), rejected)

        invalid_cases = []
        bad = json.loads(json.dumps(observed)); bad["HostConfig"]["RestartPolicy"]["MaximumRetryCount"] = 1
        invalid_cases.append(("restart_retry_count", bad))
        bad = json.loads(json.dumps(observed)); bad["Mounts"][1]["RW"] = True
        invalid_cases.append(("readonly_rw", bad))
        bad = json.loads(json.dumps(observed)); bad["Mounts"][1]["Mode"] = "rw,shared"
        invalid_cases.append(("readonly_mode", bad))
        bad = json.loads(json.dumps(observed)); bad["Mounts"][1]["Source"] = "/run/foreign.sock"
        invalid_cases.append(("bind_source", bad))
        bad = json.loads(json.dumps(observed)); bad["Mounts"][1]["Destination"] = "/tmp/lease.sock"
        invalid_cases.append(("bind_destination", bad))
        bad = json.loads(json.dumps(observed)); bad["Mounts"][1]["Type"] = "volume"
        invalid_cases.append(("bind_type", bad))
        bad = json.loads(json.dumps(observed)); bad["Mounts"][1]["Propagation"] = "shared"
        invalid_cases.append(("bind_propagation", bad))
        for label, bad in invalid_cases:
            with self.subTest(case=label):
                checks = container_readback_checks(spec, bad, expected_state="created",
                    expected_container_id=cid, image_labels=image_labels,
                    expected_base_digest="sha256:03dee9ce00747bb5390e7b4ad00307b4dbc7790f7da77cc3581f93cfa99a6363",
                    volume_mountpoint=mountpoint)
                self.assertFalse(readback_checks_pass(checks), label)

        tunnel_spec = ContainerSpec.create(role="tunnel", run_id=run_id,
            image_id=image_id, memory_bytes=67108864, pids_limit=32,
            gateway_id="d" * 64, volume_name=volume.name)
        tunnel = json.loads(json.dumps(observed))
        tunnel_id = "b" * 64
        tunnel["Id"] = tunnel_id
        tunnel["Name"] = "/" + tunnel_spec.name
        tunnel["Config"]["Labels"]["codex.mcp.role"] = "tunnel"
        tunnel["Config"]["Cmd"] = ["tunnel", "--run-id", run_id]
        tunnel["Config"]["Env"] = ["PYTHONDONTWRITEBYTECODE=1",
            "MCP_SYNTHETIC_TUNNEL=1", "MCP_SYNTHETIC_CREDENTIALS=1",
            "MCP_DOCKER_TRIAL_FULL_RUNTIME=1"]
        tunnel["HostConfig"]["NetworkMode"] = tunnel_spec.network_mode
        tunnel["HostConfig"]["Memory"] = tunnel_spec.memory_bytes
        tunnel["HostConfig"]["MemorySwap"] = tunnel_spec.memory_swap_bytes
        tunnel["HostConfig"]["PidsLimit"] = tunnel_spec.pids_limit
        tunnel["HostConfig"]["Mounts"] = [{"Type":"volume", "Source":volume.name,
            "Target":"/var/lib/codex-mcp", "ReadOnly":True,
            "VolumeOptions":{"NoCopy":True}}]
        tunnel["Mounts"] = [{"Type":"volume", "Name":volume.name,
            "Source":"/var/lib/docker/volumes/"+volume.name+"/_data",
            "Destination":"/var/lib/codex-mcp", "Driver":"local", "Mode":"z",
            "RW":False, "Propagation":""}]
        self.assertTrue(readback_checks_pass(container_readback_checks(tunnel_spec, tunnel,
            expected_state="created", expected_container_id=tunnel_id,
            image_labels=image_labels,
            expected_base_digest="sha256:03dee9ce00747bb5390e7b4ad00307b4dbc7790f7da77cc3581f93cfa99a6363",
            volume_mountpoint=tunnel["Mounts"][0]["Source"])),
            container_readback_checks(tunnel_spec, tunnel,
                expected_state="created", expected_container_id=tunnel_id,
                image_labels=image_labels,
                expected_base_digest="sha256:03dee9ce00747bb5390e7b4ad00307b4dbc7790f7da77cc3581f93cfa99a6363",
                volume_mountpoint=tunnel["Mounts"][0]["Source"]))

        bad_readonly = json.loads(json.dumps(tunnel))
        bad_readonly["Mounts"][0]["RW"] = True
        self.assertFalse(readback_checks_pass(container_readback_checks(tunnel_spec,
            bad_readonly, expected_state="created", expected_container_id=tunnel_id,
            image_labels=image_labels,
            expected_base_digest="sha256:03dee9ce00747bb5390e7b4ad00307b4dbc7790f7da77cc3581f93cfa99a6363",
            volume_mountpoint=bad_readonly["Mounts"][0]["Source"])))

    def test_only_sentinel_payload_failure_with_verified_cleanup_can_continue(self):
        class Failure(Exception):
            code = "NOCOPY_CONTROL_PAYLOAD_EXIT_NONZERO"
            diagnostics = {"stages":{"image_sentinel_preflight":"PASS", "create":"PASS",
                "create_readback":"PASS", "pin":"PASS", "start":"PASS",
                "sentinel_verify":"FAIL"},
                "cleanup":{"status":"PASS","container_absent":True,
                    "pin_absent":True,"creation_absent":True},
                "container_diagnostic":{"status":"PASS","exit_code":2,"oom_killed":False,
                    "application_code":"NOCOPY_CONTROL_SENTINEL_CONTENT_INVALID",
                    "application_phase":"nocopy-positive-control"}}
        result = _nocopy_failure_is_payload_only(Failure())
        self.assertEqual(result["code"], "NOCOPY_CONTROL_SENTINEL_CONTENT_INVALID")
        for key, value in (("container_absent",False), ("pin_absent",False),
                           ("creation_absent",False)):
            bad = Failure()
            bad.diagnostics["cleanup"][key] = value
            self.assertIsNone(_nocopy_failure_is_payload_only(bad))
            bad.diagnostics["cleanup"][key] = True
        bad = Failure()
        bad.diagnostics["container_diagnostic"]["application_code"] = "NOCOPY_CONTROL_VOLUME_MISSING"
        self.assertIsNone(_nocopy_failure_is_payload_only(bad))
        bad = Failure()
        bad.diagnostics["container_diagnostic"]["oom_killed"] = True
        self.assertIsNone(_nocopy_failure_is_payload_only(bad))

    def test_sentinel_diagnostic_continuation_rejects_incomplete_common_protections(self):
        class Failure(Exception):
            code = "NOCOPY_CONTROL_PAYLOAD_EXIT_NONZERO"
            diagnostics = {"stages":{"image_sentinel_preflight":"PASS", "create":"PASS",
                "create_readback":"PASS", "pin":"PASS", "start":"PASS",
                "sentinel_verify":"FAIL"},
                "cleanup":{"status":"PASS","container_absent":True,
                    "pin_absent":True,"creation_absent":True},
                "container_diagnostic":{"status":"PASS","exit_code":2,"oom_killed":False,
                    "application_code":"NOCOPY_CONTROL_SENTINEL_IDENTITY_INVALID",
                    "application_phase":"nocopy-positive-control"}}
        for stage in ("image_sentinel_preflight", "create", "create_readback", "pin", "start"):
            bad = Failure()
            bad.diagnostics = {key: dict(value) for key, value in Failure.diagnostics.items()}
            bad.diagnostics["stages"][stage] = "FAIL"
            self.assertIsNone(_nocopy_failure_is_payload_only(bad), stage)
        for field, value in (("status", "UNAVAILABLE"), ("exit_code", 0),
                             ("oom_killed", None), ("application_phase", "install"),
                             ("application_code", "ARGUMENTS_INVALID")):
            bad = Failure()
            bad.diagnostics = {key: dict(item) for key, item in Failure.diagnostics.items()}
            bad.diagnostics["container_diagnostic"][field] = value
            self.assertIsNone(_nocopy_failure_is_payload_only(bad), field)

    def test_unexpected_oserror_is_structured_bounded_and_sanitized(self):
        try:
            raise OSError(errno.EBADF, "private socket path and payload")
        except OSError as exc:
            detail = _safe_exception_details(exc, "nocopy_sentinel_verify")
        self.assertEqual(detail["phase"], "nocopy_sentinel_verify")
        self.assertEqual(detail["exception_class"], "OSError")
        self.assertEqual(detail["errno"], errno.EBADF)
        self.assertLessEqual(len(detail["stack"]), 12)
        self.assertNotIn("private socket path", repr(detail))
        self.assertTrue(all("/" not in frame["file"] for frame in detail["stack"]))

    def test_actual_adapter_sentinel_command_passes_real_entrypoint_parser(self):
        if not SOURCE_ROOT or not Path(SOURCE_ROOT).is_dir():
            if os.environ.get("DOCKER_TRIAL_REQUIRE_PRIVATE_ENTRYPOINT_TEST") == "1":
                self.fail("PRIVATE_ENTRYPOINT_TEST_SOURCE_ROOT_MISSING")
            self.skipTest("private archive is staged only in the Linux trial job")
        from tools.document_nas_docker_engine_v141 import DockerEngineV141
        from tools.document_nas_docker_named_volume_lifecycle import VolumeSpec
        from tools import docker_trial_container_entrypoint as entry
        run_id = "11111111-1111-4111-8111-111111111111"
        image_id = "sha256:" + "a" * 64
        volume = VolumeSpec.for_run(run_id)
        _name, request = DockerEngineV141.nocopy_positive_control_request(
            run_id=run_id, volume=volume, image_id=image_id,
            memory_bytes=32 * 1024 * 1024, pids_limit=8)
        self.assertEqual(request["Entrypoint"], ["python3", "/opt/codex-mcp/bin/container-entrypoint.py"])
        self.assertEqual(request["Cmd"], ["nocopy-positive-control"])
        self.assertIs(request["HostConfig"]["Mounts"][0]["VolumeOptions"]["NoCopy"], False)
        self.assertEqual(request["HostConfig"]["NetworkMode"], "none")
        with tempfile.TemporaryDirectory() as directory:
            sentinel = Path(directory) / ".codex-volume-copy-sentinel"
            sentinel.write_bytes(entry.NOCOPY_SENTINEL_BYTES)
            sentinel.chmod(0o444)
            with unittest.mock.patch.object(entry, "APP_UID", os.geteuid()), \
                 unittest.mock.patch.object(entry, "APP_GID", os.getegid()), \
                 unittest.mock.patch.object(entry, "RUNTIME", Path(directory)), \
                 unittest.mock.patch.object(entry, "NOCOPY_SENTINEL", sentinel), \
                 unittest.mock.patch.object(entry, "_mountpoint", return_value=True), \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                # Python passes Cmd as sys.argv[1:] after the image Entrypoint script.
                argv = request["Cmd"]
                result = entry.main(argv)
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(output.getvalue())["phase"], "nocopy_positive_control")

    def test_entrypoint_argparse_failure_is_structured(self):
        if not SOURCE_ROOT or not Path(SOURCE_ROOT).is_dir():
            if os.environ.get("DOCKER_TRIAL_REQUIRE_PRIVATE_ENTRYPOINT_TEST") == "1":
                self.fail("PRIVATE_ENTRYPOINT_TEST_SOURCE_ROOT_MISSING")
            self.skipTest("private archive is staged only in the Linux trial job")
        from tools import docker_trial_container_entrypoint as entry
        with contextlib.redirect_stderr(io.StringIO()) as output:
            result = entry.main(["not-a-valid-mode"])
        self.assertEqual(result, 2)
        report = json.loads(output.getvalue())
        self.assertEqual((report["component"], report["phase"], report["code"]),
                         ("container_entrypoint", "argument_parse", "ARGUMENTS_INVALID"))

    def test_real_volume_initializer_transfers_ownership_without_post_transfer_path_walk(self):
        if not SOURCE_ROOT or not Path(SOURCE_ROOT).is_dir():
            if os.environ.get("DOCKER_TRIAL_REQUIRE_PRIVATE_ENTRYPOINT_TEST") == "1":
                self.fail("PRIVATE_ENTRYPOINT_TEST_SOURCE_ROOT_MISSING")
            self.skipTest("private archive is staged only in the Linux trial job")
        from tools import docker_trial_container_entrypoint as entry
        run_id = "11111111-1111-4111-8111-111111111111"
        current_uid, current_gid = os.getuid(), os.getgid()
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory) / "volume"
            runtime.mkdir(mode=0o700)
            sentinel = runtime / entry.NOCOPY_SENTINEL.name
            events = []
            real_fchown, real_fstat, real_lstat = os.fchown, os.fstat, os.lstat

            def tracked_fchown(fd, uid, gid):
                events.append(("fchown", uid, gid))
                return real_fchown(fd, uid, gid)

            def tracked_fstat(fd):
                events.append(("fstat",))
                return real_fstat(fd)

            def tracked_lstat(path):
                events.append(("lstat", str(path)))
                return real_lstat(path)

            with unittest.mock.patch.object(entry, "RUNTIME", runtime), \
                 unittest.mock.patch.object(entry, "APP_UID", current_uid), \
                 unittest.mock.patch.object(entry, "APP_GID", current_gid), \
                 unittest.mock.patch.object(entry, "NOCOPY_SENTINEL", sentinel), \
                 unittest.mock.patch.object(entry, "_mountpoint", return_value=True), \
                 unittest.mock.patch.object(entry.os, "geteuid", return_value=0), \
                 unittest.mock.patch.object(entry.os, "fchown", side_effect=tracked_fchown), \
                 unittest.mock.patch.object(entry.os, "fstat", side_effect=tracked_fstat), \
                 unittest.mock.patch.object(entry.os, "lstat", side_effect=tracked_lstat):
                entry.initialize_volume(run_id=run_id, runtime=runtime)

            for name in ("drop", "python", "state"):
                info = (runtime / name).stat()
                self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)),
                                 (current_uid, current_gid, 0o700))
            self.assertEqual(json.loads((runtime / "state" / "volume-init-result.json").read_text()),
                {"schema": 1, "status": "PASS", "run_id": run_id,
                 "app_uid": current_uid, "app_gid": current_gid, "mode": "0700",
                 "nocopy_sentinel_absent": True})
            first_directory_transfer = next(i for i, event in enumerate(events)
                if event[0] == "fchown" and event[1:] == (current_uid, current_gid))
            self.assertTrue(any(event[0] == "fstat" for event in events[first_directory_transfer:]))
            self.assertFalse(any(event[0] == "lstat" for event in events[first_directory_transfer:]))

    def test_volume_initializer_reports_filesystem_errno_and_rolls_back_partial_transfer(self):
        if not SOURCE_ROOT or not Path(SOURCE_ROOT).is_dir():
            if os.environ.get("DOCKER_TRIAL_REQUIRE_PRIVATE_ENTRYPOINT_TEST") == "1":
                self.fail("PRIVATE_ENTRYPOINT_TEST_SOURCE_ROOT_MISSING")
            self.skipTest("private archive is staged only in the Linux trial job")
        from tools import docker_trial_container_entrypoint as entry
        run_id = "11111111-1111-4111-8111-111111111111"
        current_uid, current_gid = os.getuid(), os.getgid()
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory) / "volume"
            runtime.mkdir(mode=0o700)
            sentinel = runtime / entry.NOCOPY_SENTINEL.name
            real_fchown = os.fchown
            transfers = 0

            def fail_once_during_transfer(fd, uid, gid):
                nonlocal transfers
                if uid == current_uid and gid == current_gid:
                    transfers += 1
                    if transfers == 2:
                        raise OSError(errno.EACCES, "fixture permission failure")
                return real_fchown(fd, uid, gid)

            with unittest.mock.patch.object(entry, "RUNTIME", runtime), \
                 unittest.mock.patch.object(entry, "APP_UID", current_uid), \
                 unittest.mock.patch.object(entry, "APP_GID", current_gid), \
                 unittest.mock.patch.object(entry, "NOCOPY_SENTINEL", sentinel), \
                 unittest.mock.patch.object(entry, "_mountpoint", return_value=True), \
                 unittest.mock.patch.object(entry.os, "geteuid", return_value=0), \
                 unittest.mock.patch.object(entry.os, "fchown", side_effect=fail_once_during_transfer):
                with self.assertRaises(entry.TrialEntrypointError) as caught:
                    entry.initialize_volume(run_id=run_id, runtime=runtime)
            diagnostic = caught.exception.diagnostics["filesystem"]
            self.assertEqual(caught.exception.code, "FILESYSTEM_OPERATION_FAILED")
            self.assertEqual(diagnostic["logical_directory"], "runtime_python")
            self.assertEqual(diagnostic["operation"], "fchown")
            self.assertEqual(diagnostic["subphase"], "transfer_ownership")
            self.assertEqual(diagnostic["exception_class"], "PermissionError")
            self.assertEqual(diagnostic["errno"], errno.EACCES)
            self.assertEqual(diagnostic["effective_uid"], 0)
            self.assertIn("effective_capabilities_hex", diagnostic)
            self.assertEqual(list(runtime.iterdir()), [])

    def test_docker_log_collector_preserves_only_sanitized_filesystem_diagnostics(self):
        if not SOURCE_ROOT or not Path(SOURCE_ROOT).is_dir():
            if os.environ.get("DOCKER_TRIAL_REQUIRE_PRIVATE_ENTRYPOINT_TEST") == "1":
                self.fail("PRIVATE_ENTRYPOINT_TEST_SOURCE_ROOT_MISSING")
            self.skipTest("private archive is staged only in the Linux trial job")
        from tools.document_nas_docker_engine_v141 import _safe_application_log_records
        event = {"schema": 1, "status": "FAIL", "phase": "volume_init",
            "component": "container_entrypoint", "code": "FILESYSTEM_OPERATION_FAILED",
            "diagnostics": {"filesystem": {"logical_directory": "runtime_python",
                "operation": "fchown", "subphase": "transfer_ownership",
                "exception_class": "PermissionError", "errno": errno.EACCES,
                "effective_uid": 0, "effective_gid": 0,
                "effective_capabilities_hex": "0000000000000001",
                "observed": {"kind": "directory", "uid": 0, "gid": 0, "mode": "0700"},
                "expected": {"uid": 61001, "gid": 61001, "mode": "0700"}}}}
        good = _safe_application_log_records((json.dumps(event) + "\n").encode())[0]
        self.assertEqual(good["diagnostics"]["filesystem"]["errno"], errno.EACCES)
        self.assertEqual(good["diagnostics"]["filesystem"]["logical_directory"],
                         "runtime_python")
        self.assertNotIn("path", repr(good).lower())
        event["diagnostics"]["filesystem"]["private_path"] = "/host/private"
        rejected = _safe_application_log_records((json.dumps(event) + "\n").encode())[0]
        self.assertNotIn("diagnostics", rejected)

    def test_directory_contract_failure_reports_logical_id_and_expected_observed(self):
        if not SOURCE_ROOT or not Path(SOURCE_ROOT).is_dir():
            if os.environ.get("DOCKER_TRIAL_REQUIRE_PRIVATE_ENTRYPOINT_TEST") == "1":
                self.fail("PRIVATE_ENTRYPOINT_TEST_SOURCE_ROOT_MISSING")
            self.skipTest("private archive is staged only in the Linux trial job")
        from tools import docker_trial_container_entrypoint as entry
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory)
            missing = runtime / "drop"
            with unittest.mock.patch.object(entry, "RUNTIME", runtime):
                with self.assertRaises(entry.TrialEntrypointError) as caught:
                    entry._require_directory(missing, uid=os.getuid(), gid=os.getgid(), mode=0o700)
            diagnostic = caught.exception.diagnostics["filesystem"]
            self.assertEqual(diagnostic["logical_directory"], "runtime_drop")
            self.assertEqual(diagnostic["operation"], "lstat")
            self.assertEqual(diagnostic["errno"], errno.ENOENT)
            self.assertNotIn(str(runtime), repr(diagnostic))

    def test_initializer_failure_survives_entrypoint_and_docker_log_sanitizer(self):
        if not SOURCE_ROOT or not Path(SOURCE_ROOT).is_dir():
            if os.environ.get("DOCKER_TRIAL_REQUIRE_PRIVATE_ENTRYPOINT_TEST") == "1":
                self.fail("PRIVATE_ENTRYPOINT_TEST_SOURCE_ROOT_MISSING")
            self.skipTest("private archive is staged only in the Linux trial job")
        from tools import docker_trial_container_entrypoint as entry
        from tools.document_nas_docker_engine_v141 import _safe_application_log_records
        run_id = "11111111-1111-4111-8111-111111111111"
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory) / "volume"
            runtime.mkdir(mode=0o700)
            sentinel = runtime / entry.NOCOPY_SENTINEL.name
            real_mkdir = os.mkdir

            def fail_python_directory(name, mode=0o777, *, dir_fd=None):
                if name == "python":
                    raise OSError(errno.EACCES, "host path must not be retained")
                return real_mkdir(name, mode, dir_fd=dir_fd)

            with unittest.mock.patch.object(entry, "RUNTIME", runtime), \
                 unittest.mock.patch.object(entry, "APP_UID", os.getuid()), \
                 unittest.mock.patch.object(entry, "APP_GID", os.getgid()), \
                 unittest.mock.patch.object(entry, "NOCOPY_SENTINEL", sentinel), \
                 unittest.mock.patch.object(entry, "_mountpoint", return_value=True), \
                 unittest.mock.patch.object(entry.os, "geteuid", return_value=0), \
                 unittest.mock.patch.object(entry.os, "mkdir", side_effect=fail_python_directory), \
                 contextlib.redirect_stderr(io.StringIO()) as stderr:
                result = entry.main(["init", "--run-id", run_id])
            self.assertEqual(result, 2)
            emitted = json.loads(stderr.getvalue())
            self.assertEqual(emitted["code"], "FILESYSTEM_OPERATION_FAILED")
            records = _safe_application_log_records(stderr.getvalue().encode("utf-8"))
            fs = records[0]["diagnostics"]["filesystem"]
            self.assertEqual(fs["logical_directory"], "runtime_python")
            self.assertEqual(fs["operation"], "mkdir")
            self.assertEqual(fs["errno"], errno.EACCES)
            self.assertEqual(fs["effective_uid"], 0)
            self.assertNotIn(str(runtime), repr(records))
            self.assertEqual(list(runtime.iterdir()), [])

    def test_nocopy_raw_payload_capture_is_private_bounded_and_exact(self):
        if not SOURCE_ROOT or not Path(SOURCE_ROOT).is_dir():
            if os.environ.get("DOCKER_TRIAL_REQUIRE_PRIVATE_ENTRYPOINT_TEST") == "1":
                self.fail("PRIVATE_ENTRYPOINT_TEST_SOURCE_ROOT_MISSING")
            self.skipTest("private archive is staged only in the Linux trial job")
        from tools.document_nas_docker_engine_v141 import _bounded_nocopy_payload
        stderr = b"e" * 5000
        stdout = b"o" * 1000
        report = _bounded_nocopy_payload({"stdout":stdout, "stderr":stderr})
        kept = base64.b64decode(report["private_payload_stderr_b64"])
        kept += base64.b64decode(report["private_payload_stdout_b64"])
        self.assertEqual(len(kept), 4096)
        self.assertEqual(kept, b"e" * 4096)
        self.assertEqual(report["private_payload_bytes_observed"], 6000)
        self.assertEqual(report["private_payload_bytes_omitted"], 1904)
        self.assertNotIn("e" * 100, repr(report))

    def test_failed_phase_does_not_remain_running(self):
        report = {"phases": {"A_nocopy_positive_control": "RUNNING"}}
        _mark_phase_failed(report, "A_nocopy_positive_control")
        self.assertEqual(report["phases"]["A_nocopy_positive_control"], "FAIL")

    def test_nocopy_control_runs_only_after_main_cleanup_in_runner(self):
        source = Path(__file__).with_name("docker_lifecycle_runner.py").read_text(encoding="utf-8")
        image_preflight = source.index('current_phase = "IMAGE_SENTINEL_PREFLIGHT"')
        volume_main = source.index('current_phase = "A_volume_init_readback"')
        phase_c = source.index('current_phase = "C_same_store_so_peercred_peer_pin"')
        main_cleanup = source.index('current_phase = "MAIN_D_E_CLEANUP"')
        actual_cleanup = source.index("lifecycle.cleanup()", main_cleanup)
        positive = source.index("engine.run_nocopy_positive_control(", actual_cleanup)
        phase_d = source.index('current_phase = "D_gateway_tunnel_oauth_mcp_active_heartbeat"')
        phase_e = source.index('current_phase = "E_deadline_ordinary_stop_and_expiry_guards"')
        recovery = source.index('current_phase = "E_dead_controller_recovery_independent_lease"')
        self.assertLess(image_preflight, volume_main)
        self.assertLess(volume_main, phase_c)
        self.assertLess(phase_c, main_cleanup)
        self.assertLess(phase_d, phase_e)
        self.assertLess(phase_e, main_cleanup)
        self.assertLess(actual_cleanup, recovery)
        self.assertLess(recovery, positive)
        self.assertLess(actual_cleanup, positive)

    def test_rpc_server_stops_before_socket_close_without_thread_exception(self):
        required = os.environ.get("DOCKER_TRIAL_REQUIRE_REAL_RPC_TEST") == "1"
        if not hasattr(socket, "SO_PEERCRED"):
            if required:
                self.fail("RPC_REQUIRED_LINUX_SO_PEERCRED_UNAVAILABLE")
            self.skipTest("SO_PEERCRED and AF_UNIX lifecycle require Linux")
        if not SOURCE_ROOT or not Path(SOURCE_ROOT).is_dir():
            if required:
                self.fail("RPC_REQUIRED_PRIVATE_SOURCE_ROOT_MISSING")
            self.skipTest("private source archive not enabled for this test invocation")
        try:
            from tools.document_nas_docker_lease_port import DockerLeaseRPCServer
        except ImportError as exc:
            if required:
                self.fail("RPC_REQUIRED_PRIVATE_IMPORT_FAILED:" + type(exc).__name__)
            self.skipTest("private source archive not staged for this test invocation")
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory) / "rpc-socket-parent"
            parent.mkdir(mode=0o710)
            os.chmod(str(parent), 0o710)
            peer_uid = os.geteuid()
            peer_gid = os.getegid()
            parent_stat = os.lstat(str(parent))
            self.assertTrue(stat.S_ISDIR(parent_stat.st_mode))
            self.assertFalse(stat.S_ISLNK(parent_stat.st_mode))
            self.assertEqual(parent_stat.st_uid, peer_uid)
            self.assertEqual(parent_stat.st_gid, peer_gid)
            self.assertEqual(stat.S_IMODE(parent_stat.st_mode), 0o710)
            path = str(parent / "lease.sock")
            port = SimpleNamespace(run_id="11111111-1111-4111-8111-111111111111")
            server = DockerLeaseRPCServer(path, port,
                peer_uid=max(1, peer_uid), peer_gid=peer_gid,
                peer_executable="/usr/bin/python3").bind()
            errors = []
            def serve():
                try:
                    server.serve_forever()
                except Exception as exc:
                    errors.append(exc)
            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            _shutdown_rpc(server, thread, stop_timeout=1.0)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            self.assertFalse(os.path.exists(path))

    def test_rpc_shutdown_joins_before_close_and_escalates_only_if_needed(self):
        events = []
        class RPC:
            def stop(self): events.append("stop")
            def close(self): events.append("close")
        class Thread:
            def __init__(self): self.alive = True
            def join(self, timeout):
                events.append(("join", timeout))
                if events.count(("join", timeout)) == 1:
                    self.alive = False
            def is_alive(self): return self.alive
        _shutdown_rpc(RPC(), Thread(), stop_timeout=2.0, escalation_timeout=1.0)
        self.assertEqual(events, ["stop", ("join", 2.0), "close"])


if __name__ == "__main__":
    unittest.main()
