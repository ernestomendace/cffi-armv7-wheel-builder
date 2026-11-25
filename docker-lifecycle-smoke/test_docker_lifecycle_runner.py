import errno
import base64
import contextlib
import io
import json
import os
import socket
import stat
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
        main_cleanup = source.index('current_phase = "MAIN_A_B_C_CLEANUP"')
        actual_cleanup = source.index("lifecycle.cleanup()", main_cleanup)
        positive = source.index("engine.run_nocopy_positive_control(", actual_cleanup)
        self.assertLess(image_preflight, volume_main)
        self.assertLess(volume_main, phase_c)
        self.assertLess(phase_c, main_cleanup)
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
