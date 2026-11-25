import os
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from docker_lifecycle_runner import (
    _docker_cli_socket, _engine_peer_proof, _listener_kernel_inode, _parse_proc_identity,
    _preserve_cas_for_reconciliation, TrialFailure,
)


class DockerEnginePreflightTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
