import os
import hashlib
import tempfile
import unittest
import json
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
