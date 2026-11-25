import errno
import os
import socket
import stat
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace

from docker_lifecycle_runner import (
    _mark_phase_failed, _nocopy_failure_is_payload_only, _safe_exception_details, _shutdown_rpc,
)

SOURCE_ROOT = os.environ.get("DOCKER_TRIAL_SOURCE_ROOT")
if SOURCE_ROOT and os.path.isdir(SOURCE_ROOT):
    sys.path.insert(0, SOURCE_ROOT)


class RunnerDiagnosticsTests(unittest.TestCase):
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

    def test_failed_phase_does_not_remain_running(self):
        report = {"phases": {"A_nocopy_positive_control": "RUNNING"}}
        _mark_phase_failed(report, "A_nocopy_positive_control")
        self.assertEqual(report["phases"]["A_nocopy_positive_control"], "FAIL")

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
