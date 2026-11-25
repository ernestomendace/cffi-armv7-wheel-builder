import errno
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace

from docker_lifecycle_runner import (
    _mark_phase_failed, _safe_exception_details, _shutdown_rpc,
)

SOURCE_ROOT = os.environ.get("DOCKER_TRIAL_SOURCE_ROOT")
if SOURCE_ROOT and os.path.isdir(SOURCE_ROOT):
    sys.path.insert(0, SOURCE_ROOT)


class RunnerDiagnosticsTests(unittest.TestCase):
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
        if not hasattr(__import__("socket"), "SO_PEERCRED"):
            self.skipTest("SO_PEERCRED and AF_UNIX lifecycle require Linux")
        try:
            from tools.document_nas_docker_lease_port import DockerLeaseRPCServer
        except ImportError:
            self.skipTest("private source archive not staged for this local test")
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "lease.sock")
            port = SimpleNamespace(run_id="11111111-1111-4111-8111-111111111111")
            server = DockerLeaseRPCServer(path, port,
                peer_uid=max(1, os.geteuid()), peer_gid=os.getegid(),
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
