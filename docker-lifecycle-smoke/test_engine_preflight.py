import os
import hashlib
import tempfile
import unittest
import json
import subprocess
import sys
import time
import uuid
import dataclasses
from types import SimpleNamespace
from pathlib import Path
from unittest import mock

from docker_lifecycle_runner import (
    _docker_cli_socket, _engine_peer_proof, _listener_kernel_inode, _locked_source_digest, _parse_proc_identity,
    _preserve_cas_for_reconciliation, TrialFailure,
)


class DockerEnginePreflightTests(unittest.TestCase):
    def test_built_image_permission_check_gates_trial_and_runs_before_it(self):
        root = Path(__file__).resolve().parent.parent
        workflow = (root / ".github/workflows/docker-lifecycle-smoke.yml").read_text()
        verifier = root / "docker-lifecycle-smoke/verify_image_permissions.py"
        self.assertTrue(verifier.is_file())
        self.assertIn("id: image_permissions", workflow)
        self.assertIn("verify_image_permissions.py", workflow)
        self.assertIn("steps.image_permissions.outcome == 'success'", workflow)
        self.assertLess(workflow.index("Verify built image access for application UID"),
                        workflow.index("Run phases A-E with real Docker Engine"))

    def test_private_source_lock_matches_loader_and_runner_reaches_real_regression(self):
        root = Path(__file__).resolve().parent
        lock = json.loads((root / "docker-lifecycle-lock.json").read_text(encoding="ascii"))
        private = lock["private_source"]
        self.assertEqual(_locked_source_digest(), private["archive_sha256"])
        import prepare_docker_inputs
        self.assertEqual(private["archive_sha256"], prepare_docker_inputs.SOURCE_SHA256)
        self.assertEqual(private["archive_bytes"], prepare_docker_inputs.SOURCE_BYTES)
        self.assertEqual(private["file_count"], prepare_docker_inputs.SOURCE_FILES)
        self.assertEqual(private["max_expanded_bytes"], prepare_docker_inputs.MAX_EXPANDED)
        source = (root / "docker_lifecycle_runner.py").read_text(encoding="utf-8")
        self.assertIn("run_real_readback_cleanup_regression", source)
        self.assertIn("A_readback_failure_cleanup_regression", source)

    def test_workflow_has_no_duplicate_private_source_digest(self):
        root = Path(__file__).resolve().parent
        workflow = (root.parent / ".github" / "workflows" /
                    "docker-lifecycle-smoke.yml").read_text(encoding="utf-8")
        rpc_test = (root / "test_docker_lifecycle_runner.py").read_text(encoding="utf-8")
        runner = (root / "docker_lifecycle_runner.py").read_text(encoding="utf-8")
        self.assertNotIn("MCP_DOCKER_SOURCE_SHA256:", workflow)
        self.assertIn('DOCKER_TRIAL_REQUIRE_REAL_RPC_TEST: "1"', workflow)
        self.assertIn('self.fail("RPC_REQUIRED_PRIVATE_SOURCE_ROOT_MISSING")', rpc_test)
        self.assertIn('self.fail("RPC_REQUIRED_PRIVATE_IMPORT_FAILED:"', rpc_test)
        self.assertIn("_locked_source_digest()", runner)
        self.assertIn('"archive_sha256"', runner)
        self.assertIn('hashlib.sha256(source_archive.read_bytes()).hexdigest() != source_sha', runner)

    def test_workflow_gates_image_build_on_real_synthetic_config_validation(self):
        root = Path(__file__).resolve().parent.parent
        workflow = (root / ".github/workflows/docker-lifecycle-smoke.yml").read_text(encoding="utf-8")
        self.assertIn("Validate the exact generated synthetic gateway configuration", workflow)
        self.assertIn("validate-synthetic-config", workflow)
        self.assertIn("steps.synthetic_config.outcome == 'success'", workflow)

    def test_actual_generated_synthetic_configuration_passes_canonical_validator(self):
        source_root = os.environ.get("DOCKER_TRIAL_SOURCE_ROOT")
        if not source_root:
            self.skipTest("private source is not staged in this local test invocation")
        source_root = Path(source_root).resolve(strict=True)
        entrypoint = source_root / "tools/docker_trial_container_entrypoint.py"
        config = source_root / "config/mcp-oauth-runtime.example.json"
        result = subprocess.run([sys.executable, "-B", str(entrypoint),
            "validate-synthetic-config", "--example-config", str(config)],
            cwd=str(source_root), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False,
            env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace")[-1000:])
        summary = json.loads(result.stdout.decode("utf-8"))
        self.assertEqual(summary.get("status"), "PASS")
        self.assertEqual(summary.get("canonical_validation"), "PASS")
        self.assertIs(summary.get("canonical_resource_preserved"), True)
        self.assertIs(summary.get("fixed_smb_destination_preserved"), True)
        self.assertIs(summary.get("synthetic_oauth_endpoints"), True)

    def test_tunnel_is_created_and_pinned_after_peer_auth_before_tunnel_id_reads(self):
        source = (Path(__file__).resolve().parent / "docker_lifecycle_runner.py").read_text()
        start = source.index('current_phase = "C_same_store_so_peercred_peer_pin"')
        auth = source.index('if not gateway_probe_ok:', start)
        tunnel_start = source.index('tunnel_id = lifecycle.start_tunnel(gateway_probe=True)', auth)
        pin_readback = source.index('tunnel_pin = port.read_pin(run_id, "tunnel")', tunnel_start)
        first_id_use = source.index('lifecycle.ids["tunnel"]', pin_readback)
        self.assertLess(start, auth)
        self.assertLess(auth, tunnel_start)
        self.assertLess(tunnel_start, pin_readback)
        self.assertLess(pin_readback, first_id_use)

    def test_tunnel_volume_identity_survives_cas_intent_pin_reload_and_cleanup(self):
        source_root = os.environ.get("DOCKER_TRIAL_SOURCE_ROOT")
        if not source_root:
            self.skipTest("private source is not staged in this local test invocation")
        sys.path.insert(0, source_root)
        from tools.document_nas_local_service_lease_v2 import LeaseRecord, SecureLeaseV2Store
        from tools.document_nas_docker_lease_port import SecureDockerLeasePort

        uid, gid, pid = os.geteuid(), os.getegid(), os.getpid()
        ticks = "12345"
        executable = os.path.realpath(sys.executable)
        run_id = str(uuid.uuid4())
        suffix = run_id.replace("-", "")
        gateway_image = "sha256:" + "1" * 64
        tunnel_image = "sha256:" + "2" * 64
        gateway_id, tunnel_id = "a" * 64, "b" * 64
        now = time.monotonic()

        with tempfile.TemporaryDirectory(prefix="tunnel-volume-cas-") as temp:
            root = Path(temp); root.chmod(0o700)
            cas_dir = root / "cas"; cas_dir.mkdir(mode=0o700)
            record = LeaseRecord.initial(run_id=run_id, boot_id=str(uuid.uuid4()),
                mode="trial", owner_role="coordinator", owner_pid=pid,
                owner_start_ticks=ticks, contract_digest="c" * 64, now=now,
                phase_ttl=200.0, run_deadline_monotonic=now + 280.0)
            record = dataclasses.replace(record, coordinator_pid=pid,
                coordinator_start_ticks=ticks)
            store = SecureLeaseV2Store(str(cas_dir), trusted_root=str(root),
                owner_uid=uid, owner_gid=gid)
            store.create(record)
            port = SecureDockerLeasePort(store, run_id=run_id,
                coordinator_pid=pid, coordinator_start_ticks=ticks,
                monotonic=lambda: now, coordinator_executable=executable,
                identity_reader=lambda _pid: (uid, gid, ticks, executable))

            volume = "codex-mcp-trial-" + suffix
            runtime_labels = {"codex.mcp.trial":"1", "codex.mcp.run":run_id,
                "codex.mcp.role":"runtime"}
            self.assertTrue(port.persist_intent(volume, gateway_image, tunnel_image,
                                                runtime_labels))
            self.assertTrue(port.begin_resource_creation(run_id, "volume", name=volume,
                image_id="", volume_name=volume, driver="local", labels=runtime_labels))
            self.assertTrue(port.record_created_resource(run_id, "volume", volume))
            self.assertTrue(port.persist_volume_pin(run_id, volume, "local", runtime_labels))

            gateway_labels = {"codex.mcp.trial":"1", "codex.mcp.run":run_id,
                "codex.mcp.role":"gateway"}
            gateway_name = "codex-mcp-trial-gw-" + suffix
            self.assertTrue(port.begin_resource_creation(run_id, "gateway",
                name=gateway_name, image_id=gateway_image, volume_name=volume,
                driver="", labels=gateway_labels, network_mode="none"))
            self.assertTrue(port.record_created_resource(run_id, "gateway", gateway_id))
            self.assertTrue(port.persist_pin(run_id, "gateway", gateway_id,
                                             gateway_image, volume))

            tunnel_labels = {"codex.mcp.trial":"1", "codex.mcp.run":run_id,
                "codex.mcp.role":"tunnel"}
            tunnel_name = "codex-mcp-trial-tu-" + suffix
            with self.assertRaisesRegex(Exception, "DOCKER_CREATION_INTENT_INVALID"):
                port.begin_resource_creation(run_id, "tunnel", name=tunnel_name,
                    image_id=tunnel_image, volume_name="", driver="",
                    labels=tunnel_labels, network_mode="container:" + gateway_id)
            self.assertTrue(port.begin_resource_creation(run_id, "tunnel",
                name=tunnel_name, image_id=tunnel_image, volume_name=volume,
                driver="", labels=tunnel_labels,
                network_mode="container:" + gateway_id))
            self.assertTrue(port.record_created_resource(run_id, "tunnel", tunnel_id))
            with self.assertRaisesRegex(Exception, "DOCKER_RESOURCE_PIN_MISMATCH"):
                port.persist_pin(run_id, "tunnel", tunnel_id, tunnel_image,
                                 "codex-mcp-trial-other")
            self.assertTrue(port.persist_pin(run_id, "tunnel", tunnel_id,
                                             tunnel_image, volume))
            self.assertEqual(port.read_pin(run_id, "tunnel")["volume_name"], volume)
            self.assertEqual(port.read_creation_record(run_id, "tunnel")["volume_name"], volume)

            # Reload the actual CAS journal as a recovery process would.
            recovered_store = SecureLeaseV2Store(str(cas_dir), trusted_root=str(root),
                owner_uid=uid, owner_gid=gid)
            recovered = SecureDockerLeasePort(recovered_store, run_id=run_id,
                coordinator_pid=pid, coordinator_start_ticks=ticks,
                monotonic=lambda: now, coordinator_executable=executable,
                identity_reader=lambda _pid: (uid, gid, ticks, executable))
            self.assertEqual(recovered.read_pin(run_id, "tunnel")["volume_name"], volume)
            self.assertEqual(recovered.read_creation_record(run_id, "tunnel")["volume_name"], volume)
            self.assertTrue(recovered.transition(run_id, "PREPARED", "STOPPING"))
            self.assertTrue(recovered.clear_pin(run_id, "tunnel", tunnel_id))
            self.assertTrue(recovered.clear_pin(run_id, "gateway", gateway_id))
            self.assertTrue(recovered.clear_volume_pin(run_id, volume))
            self.assertTrue(recovered.transition(run_id, "STOPPING", "STOPPED"))
            final = recovered_store.read().docker_resources
            self.assertEqual(final.state, "STOPPED")
            self.assertEqual(final.pins, {})
            self.assertEqual(final.creations, {})

    def test_private_tunnel_entrypoint_imports_threading_for_health_server(self):
        source_root = os.environ.get("DOCKER_TRIAL_SOURCE_ROOT")
        if not source_root:
            self.skipTest("private source is not staged in this local test invocation")
        import ast
        entrypoint = Path(source_root) / "tools/docker_trial_container_entrypoint.py"
        tree = ast.parse(entrypoint.read_text(encoding="utf-8"))
        imported = {alias.name.split(".", 1)[0]
                    for node in ast.walk(tree)
                    if isinstance(node, ast.Import)
                    for alias in node.names}
        self.assertIn("threading", imported)
        self.assertTrue(any(isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "Thread"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "threading"
            for node in ast.walk(tree)))

    def test_cas_deadline_expiry_is_distinct_from_operational_stop(self):
        source = (Path(__file__).resolve().parent / "docker_lifecycle_runner.py").read_text()
        probe = source.index('current_phase = "E_cas_deadline_expiry_rejection"')
        ordinary_stop = source.index('current_phase = "E_deadline_ordinary_stop_and_expiry_guards"')
        active_helper = source.index("def _run_active_cas_deadline_boundary")
        heartbeat = source.index("port.heartbeat(run_id)", active_helper)
        call = source.index("_run_active_cas_deadline_boundary(", probe)
        self.assertLess(active_helper, heartbeat)
        self.assertLess(probe, call)
        self.assertLess(call, ordinary_stop)
        self.assertIn('"expiry_clock_injected_for_boundary_test":True', source)
        self.assertIn('"distinct_from_operational_deadline_stop"] = True', source)
        self.assertIn('"main_runtime_state_during_test"] = "ACTIVE"', source)
        self.assertIn('"cas_state_after_rejected_operation":"ACTIVE"', source)

    def test_real_secure_store_rejects_resource_mutation_after_deadline_before_stopped(self):
        source_root = os.environ.get("DOCKER_TRIAL_SOURCE_ROOT")
        if not source_root:
            self.skipTest("private source is not staged in this local test invocation")
        sys.path.insert(0, source_root)
        from tools.document_nas_local_service_lease_v2 import LeaseRecord, SecureLeaseV2Store
        from tools.document_nas_docker_lease_port import SecureDockerLeasePort
        with tempfile.TemporaryDirectory(prefix="lease-expiry-regression-") as temp:
            root = Path(temp)
            root.chmod(0o700)
            cas_dir = root / "cas"
            cas_dir.mkdir(mode=0o700)
            run_id = str(uuid.uuid4())
            now = time.monotonic()
            pid = os.getpid()
            start_ticks = "1"
            uid, gid = os.geteuid(), os.getegid()
            executable = os.path.realpath(sys.executable)
            record = LeaseRecord.initial(run_id=run_id, boot_id=str(uuid.uuid4()),
                mode="trial", owner_role="coordinator", owner_pid=pid,
                owner_start_ticks=start_ticks, contract_digest="a" * 64, now=now,
                phase_ttl=5.0, run_deadline_monotonic=now + 6.0)
            record = dataclasses.replace(record, coordinator_pid=pid,
                coordinator_start_ticks=start_ticks)
            store = SecureLeaseV2Store(str(cas_dir), trusted_root=str(root),
                owner_uid=uid, owner_gid=gid)
            store.create(record)
            clock = [now + 0.1]
            port = SecureDockerLeasePort(store, run_id=run_id,
                coordinator_pid=pid, coordinator_start_ticks=start_ticks,
                monotonic=lambda: clock[0], coordinator_executable=executable,
                identity_reader=lambda _pid: (uid, gid, start_ticks, executable))
            labels = {"codex.mcp.trial":"1", "codex.mcp.run":run_id,
                "codex.mcp.role":"runtime"}
            self.assertTrue(port.persist_intent("codex-expiry-" + run_id[:8],
                "sha256:" + "b" * 64, "sha256:" + "b" * 64, labels))
            before = store.read()
            clock[0] = before.run_deadline_monotonic + 0.01
            with self.assertRaisesRegex(Exception, "DOCKER_RESOURCE_AUTHORIZATION_FAILED"):
                port.begin_resource_creation(run_id, "volume",
                    name="codex-expiry-" + run_id[:8], image_id="",
                    volume_name="codex-expiry-" + run_id[:8], driver="local",
                    labels=labels, network_mode="")
            after = store.read()
            self.assertEqual(after.docker_resources.state, "PREPARING")
            self.assertEqual(after.sequence, before.sequence)
            self.assertTrue(port.transition(run_id, "PREPARED", "STOPPING"))
            self.assertTrue(port.transition(run_id, "STOPPING", "STOPPED"))
            self.assertEqual(port.read_state(run_id), "STOPPED")

    def test_linux_real_monotonic_cas_expiry_regression(self):
        source_root = os.environ.get("DOCKER_TRIAL_SOURCE_ROOT")
        if not source_root:
            self.skipTest("private source is not staged in this local test invocation")
        if not Path("/proc/sys/kernel/random/boot_id").is_file():
            self.skipTest("real Linux boot identity is required for this CAS regression")
        sys.path.insert(0, source_root)
        import docker_lifecycle_runner as runner
        from tools.document_nas_local_service_lease_v2 import (
            LeaseRecord, SecureLeaseV2Store, _kernel_boot_id)
        from tools.document_nas_docker_lease_port import SecureDockerLeasePort
        with tempfile.TemporaryDirectory(prefix="real-cas-expiry-") as temp:
            root = Path(temp)
            root.chmod(0o700)
            result = runner._run_real_cas_expiry_regression(root=root,
                LeaseRecord=LeaseRecord, SecureLeaseV2Store=SecureLeaseV2Store,
                SecureDockerLeasePort=SecureDockerLeasePort,
                boot_id=_kernel_boot_id(), contract_digest="c" * 64,
                image_id="sha256:" + "d" * 64)
            self.assertEqual(result.get("status"), "PASS")
            self.assertIs(result.get("run_deadline_elapsed"), True)
            self.assertIs(result.get("operation_rejected"), True)
            self.assertIs(result.get("sequence_unchanged"), True)

    def test_linux_active_cas_deadline_boundary_uses_real_secure_store(self):
        source_root = os.environ.get("DOCKER_TRIAL_SOURCE_ROOT")
        if not source_root:
            self.skipTest("private source is not staged in this local test invocation")
        if not Path("/proc/sys/kernel/random/boot_id").is_file():
            self.skipTest("real Linux boot identity is required for this CAS regression")
        sys.path.insert(0, source_root)
        import docker_lifecycle_runner as runner
        from tools.document_nas_local_service_lease_v2 import (
            LeaseRecord, SecureLeaseV2Store, _kernel_boot_id)
        from tools.document_nas_docker_lease_port import SecureDockerLeasePort
        with tempfile.TemporaryDirectory(prefix="active-cas-expiry-") as temp:
            root = Path(temp)
            root.chmod(0o700)
            result = runner._run_active_cas_deadline_boundary(root=root,
                LeaseRecord=LeaseRecord, SecureLeaseV2Store=SecureLeaseV2Store,
                SecureDockerLeasePort=SecureDockerLeasePort,
                boot_id=_kernel_boot_id(), contract_digest="e" * 64,
                image_id="sha256:" + "f" * 64)
            self.assertEqual(result.get("status"), "PASS")
            self.assertEqual(result.get("cas_state_before"), "ACTIVE")
            self.assertIs(result.get("heartbeat_rejected"), True)
            self.assertIs(result.get("sequence_unchanged"), True)
            self.assertIs(result.get("docker_resources_created"), False)

    def test_secure_store_active_cas_deadline_boundary_rejects_without_stopping(self):
        source_root = os.environ.get("DOCKER_TRIAL_SOURCE_ROOT")
        if not source_root:
            self.skipTest("private source is not staged in this local test invocation")
        sys.path.insert(0, source_root)
        import docker_lifecycle_runner as runner
        from tools.document_nas_local_service_lease_v2 import LeaseRecord, SecureLeaseV2Store
        from tools.document_nas_docker_lease_port import SecureDockerLeasePort
        with tempfile.TemporaryDirectory(prefix="active-cas-boundary-") as temp:
            root = Path(temp)
            root.chmod(0o700)
            pid, ticks = os.getpid(), "1"
            uid, gid = os.geteuid(), os.getegid()
            executable = os.path.realpath(sys.executable)
            identity_reader = lambda _pid: (uid, gid, ticks, executable)
            result = runner._run_active_cas_deadline_boundary(root=root,
                LeaseRecord=LeaseRecord, SecureLeaseV2Store=SecureLeaseV2Store,
                SecureDockerLeasePort=SecureDockerLeasePort,
                boot_id=str(uuid.uuid4()), contract_digest="9" * 64,
                image_id="sha256:" + "8" * 64,
                identity_reader=identity_reader)
            self.assertEqual(result.get("status"), "PASS")
            self.assertEqual(result.get("cas_state_before"), "ACTIVE")
            self.assertIs(result.get("heartbeat_rejected"), True)
            self.assertIs(result.get("sequence_unchanged"), True)
            self.assertEqual(result.get("final_cas_state"), "STOPPED")

    def test_synthetic_backend_and_network_are_closed_to_external_services(self):
        source_root = os.environ.get("DOCKER_TRIAL_SOURCE_ROOT")
        if not source_root:
            self.skipTest("private source is not staged in this local test invocation")
        source_root = Path(source_root).resolve(strict=True)
        fixture = (source_root / "tools/docker_trial_e2e_runtime.py").read_text()
        entrypoint = (source_root / "src/mcp_document_oauth_entrypoint.py").read_text()
        lifecycle = (source_root / "tools/document_nas_docker_named_volume_lifecycle.py").read_text()
        self.assertIn("yield PrivateSmbGateway(_ReadOnlyFixtureStore())", fixture)
        self.assertIn("if host != PRIVATE_SMB_HOST", fixture)
        self.assertIn("ProxyHandler({})", fixture)
        self.assertIn("fetch_jwks=lambda: fixture_jwks(settings), smb_factory=fixture_smb_factory", entrypoint)
        self.assertIn('network_mode="none"', lifecycle)
        self.assertIn('"container:" + gateway', lifecycle)

    def test_pinned_cli_endpoint_is_the_adapter_endpoint(self):
        with mock.patch.dict(os.environ, {"DOCKER_HOST": "unix:///var/run/docker.sock",
                "DOCKER_CONTEXT": ""}, clear=False):
            self.assertEqual(_docker_cli_socket(), "/var/run/docker.sock")

    def test_context_override_is_refused(self):
        with mock.patch.dict(os.environ, {"DOCKER_HOST": "unix:///var/run/docker.sock",
                "DOCKER_CONTEXT": "other"}, clear=False):
            with self.assertRaisesRegex(Exception, "DOCKER_CLI_CONTEXT_OVERRIDE_UNEXPECTED"):
                _docker_cli_socket()

    def test_non_unix_or_unexpected_endpoint_is_refused(self):
        for value in ("tcp://127.0.0.1:2375", "unix:///tmp/other.sock"):
            with mock.patch.dict(os.environ, {"DOCKER_HOST": value, "DOCKER_CONTEXT": ""},
                    clear=False):
                with self.assertRaises(Exception):
                    _docker_cli_socket()

    def test_identity_parser_never_claims_unavailable_procfs(self):
        # On macOS this is explicitly a platform limitation, not a Linux PASS.
        if not os.path.isdir("/proc"):
            self.assertIsNone(_parse_proc_identity(os.getpid()))
            self.skipTest("Linux procfs identity proof requires a Linux runner")
        identity = _parse_proc_identity(os.getpid())
        self.assertIsNotNone(identity)
        self.assertEqual(identity["pid"], os.getpid())
        self.assertTrue(identity["exe_name"])
        self.assertTrue(identity["start_ticks"].isdigit())

    def test_identity_proof_fails_closed_when_listener_cannot_be_verified(self):
        result = _engine_peer_proof(1, 0, 0, "/var/run/docker.sock", 99999999)
        self.assertFalse(result["verified"])
        self.assertIn(result["error_code"], {
            "ENGINE_PEER_IDENTITY_UNVERIFIED", "ENGINE_SOCKET_ACTIVATION_UNVERIFIED"})
        self.assertFalse(result["socket_activation_verified"])

    def test_observed_peer_pid_is_not_accepted_when_service_main_pid_differs(self):
        peer = {"pid": 700, "uid_effective": 0, "gid_effective": 0,
            "exe_name": "dockerd", "start_ticks": "55", "listener_fd_inodes": [123]}
        with mock.patch("docker_lifecycle_runner._parse_proc_identity", return_value=peer), \
             mock.patch("docker_lifecycle_runner._listener_kernel_inode", return_value=123), \
             mock.patch("docker_lifecycle_runner._listener_owner_pids", return_value=[700]), \
             mock.patch("docker_lifecycle_runner._systemd_unit", return_value={
                 "ActiveState": "active", "MainPID": "701"}):
            result = _engine_peer_proof(700, 0, 0, "/run/docker.sock", 123)
        self.assertFalse(result["verified"])
        self.assertEqual(result["peer_pid_expected"], 701)
        self.assertEqual(result["error_code"], "ENGINE_PEER_IDENTITY_UNVERIFIED")

    def test_pid_one_requires_verified_systemd_socket_activation(self):
        peer = {"pid": 1, "uid_effective": 0, "gid_effective": 0,
            "exe_name": "systemd", "start_ticks": "1", "listener_fd_inodes": [123]}
        daemon = {"pid": 701, "uid_effective": 0, "gid_effective": 0,
            "exe_name": "dockerd", "start_ticks": "99", "listener_fd_inodes": [123]}
        with mock.patch("docker_lifecycle_runner._parse_proc_identity", side_effect=[peer, daemon]), \
             mock.patch("docker_lifecycle_runner._listener_kernel_inode", return_value=123), \
             mock.patch("docker_lifecycle_runner._listener_owner_pids", return_value=[1, 701]), \
             mock.patch("docker_lifecycle_runner._systemd_unit", side_effect=[
                 {"ActiveState": "active", "Listen": "Stream /run/docker.sock (Stream)"},
                 {"ActiveState": "active", "MainPID": "701"}]), \
             mock.patch("docker_lifecycle_runner.os.path.realpath", return_value="/run/docker.sock"):
            result = _engine_peer_proof(1, 0, 0, "/var/run/docker.sock", 123)
        self.assertTrue(result["verified"])
        self.assertEqual(result["peer_pid_expected"], 1)
        self.assertTrue(result["socket_activation_verified"])

    def test_cas_recovery_copy_is_verified_and_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            run = root / "run"
            lease = run / "lease"
            results = run / "results"
            run.mkdir(mode=0o700)
            lease.mkdir(mode=0o700)
            results.mkdir(mode=0o700)
            journal = b"synthetic-cas-record"
            (lease / "lease-v2.json").write_bytes(journal)
            (lease / "lease-v2.lock").write_bytes(b"")
            copied = _preserve_cas_for_reconciliation(str(run), str(results))
            self.assertEqual(copied["lease-v2.json"], hashlib.sha256(journal).hexdigest())
            self.assertEqual((results / "cas-recovery" / "lease-v2.json").read_bytes(), journal)
            for item in (results / "cas-recovery").iterdir():
                self.assertEqual(item.stat().st_mode & 0o777, 0o600)

    def test_cas_recovery_copy_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            run = root / "run"
            lease = run / "lease"
            results = run / "results"
            run.mkdir(mode=0o700)
            lease.mkdir(mode=0o700)
            results.mkdir(mode=0o700)
            target = root / "outside"
            target.write_text("not-cas", encoding="ascii")
            os.symlink(target, lease / "lease-v2.json")
            with self.assertRaises(TrialFailure):
                _preserve_cas_for_reconciliation(str(run), str(results))

    def test_cas_recovery_preserves_auxiliary_authorities_separately(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            main = root / "lease"
            aux = root / "aux-lease"
            results = root / "results"
            for path in (main, aux, results):
                path.mkdir(mode=0o700)
            (main / "lease-v2.json").write_bytes(b"main-state")
            (aux / "lease-v2.json").write_bytes(b"aux-state")
            contexts = [{"store":SimpleNamespace(directory=str(aux))}]
            hashes = _preserve_cas_for_reconciliation(str(root), str(results), contexts)
            recovery = results / "cas-recovery"
            self.assertEqual((recovery / "lease-v2.json").read_bytes(), b"main-state")
            self.assertEqual((recovery / "auxiliary-00" / "lease-v2.json").read_bytes(),
                             b"aux-state")
            self.assertEqual(hashes["auxiliary_0"]["lease-v2.json"],
                             hashlib.sha256(b"aux-state").hexdigest())


if __name__ == "__main__":
    unittest.main()
