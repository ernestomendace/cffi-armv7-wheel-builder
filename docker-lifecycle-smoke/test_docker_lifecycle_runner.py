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
