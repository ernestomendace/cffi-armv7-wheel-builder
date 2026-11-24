import contextlib
import gzip
import base64
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]

def load_script(name):
    path = ROOT / "armv7-smoke" / name
    spec = importlib.util.spec_from_file_location(name.replace(".py", ""), str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

PACK = load_script("package_private_source.py")
PREP = load_script("prepare_inputs.py")
ENCRYPT = load_script("encrypt_report.py")
DECRYPT = load_script("decrypt_diagnostics.py")
RECOVER = load_script("recover_diagnostics.py")
RUNNER = load_script("container_runner.py")

def load_native_script(name):
    path = ROOT / "native-linux-smoke" / name
    spec = importlib.util.spec_from_file_location("native_" + name.replace(".py", ""), str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

NATIVE_PREP = load_native_script("prepare_native_inputs.py")
NATIVE_RUNNER = load_native_script("native_linux_runner.py")

class NativeLinuxRunnerPreflightTests(unittest.TestCase):
    def _invoke_main(self, mutation=None, mount_failure=None, fake_uid=False,
                     install_error=None, fixture_error=False):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp).resolve()
            paths = {name:root/name for name in
                     ("source", "wheelhouse", "results", "harness", "test-tmp", "site")}
            for name in ("source", "wheelhouse", "results", "harness", "test-tmp", "site"):
                paths[name].mkdir(mode=0o700)
            (paths["harness"] / "native-linux-wheel-lock.json").write_text("{}\n")
            (root / "requirements.lock").write_text("locked\n")
            if mutation:
                mutation(paths, root)
            tmp_mount = "1 0 0:1 / %s rw - tmpfs tmpfs rw,noexec,nosuid,nodev\n" % paths["test-tmp"]
            site_mount = "2 0 0:2 / %s rw - tmpfs tmpfs rw,nosuid,nodev\n" % paths["site"]
            mountinfo = tmp_mount + ("" if mount_failure == "missing-site-mount" else site_mount)
            if mount_failure == "site-mount-options":
                mountinfo = tmp_mount + "2 0 0:2 / %s rw - tmpfs tmpfs rw,nodev\n" % paths["site"]
            measured = []
            def fake_measure(name, command, env, cwd, log_path, metrics, cg):
                measured.append((name, command))
                if install_error:
                    raise install_error
                return 1
            original_read_text = pathlib.Path.read_text
            def read_text(path, *args, **kwargs):
                if str(path) == "/proc/self/mountinfo":
                    return mountinfo
                return original_read_text(path, *args, **kwargs)
            argv = ["native_linux_runner.py", "--source", str(paths["source"]),
                    "--wheelhouse", str(paths["wheelhouse"]), "--requirements", str(root/"requirements.lock"),
                    "--results", str(paths["results"]), "--harness", str(paths["harness"]),
                    "--site", str(paths["site"]), "--tmp", str(paths["test-tmp"])]
            patches = [
                mock.patch.object(NATIVE_RUNNER.sys, "platform", "linux"),
                mock.patch.object(NATIVE_RUNNER.sys, "version_info", (3, 9, 25)),
                mock.patch.object(NATIVE_RUNNER.platform, "machine", return_value="x86_64"),
                mock.patch.object(NATIVE_RUNNER.sysconfig, "get_config_var", return_value="cpython-39-x86_64-linux-gnu"),
                mock.patch.object(NATIVE_RUNNER, "struct_size_ok", return_value=True),
                mock.patch.object(NATIVE_RUNNER, "requirements_from_lock", return_value="locked\n"),
                mock.patch.object(NATIVE_RUNNER, "run_measured", side_effect=fake_measure),
                mock.patch.object(NATIVE_RUNNER, "cgroup_memory_paths", return_value=(None,None,None)),
                mock.patch.object(NATIVE_RUNNER.pathlib.Path, "read_text", new=read_text),
                mock.patch.object(NATIVE_RUNNER.sys, "argv", argv),
            ]
            if fixture_error:
                original_mkdir = pathlib.Path.mkdir
                def mkdir(path, *args, **kwargs):
                    if path == paths["test-tmp"] / "native-mcp-fixture":
                        raise OSError(28, "fixture storage full")
                    return original_mkdir(path, *args, **kwargs)
                patches.append(mock.patch.object(NATIVE_RUNNER.pathlib.Path, "mkdir", new=mkdir))
            if fake_uid:
                patches.append(mock.patch.object(NATIVE_RUNNER.os, "getuid", return_value=os.getuid()+1))
            with contextlib.ExitStack() as stack:
                for patcher in patches: stack.enter_context(patcher)
                code = NATIVE_RUNNER.main()
            report = json.loads((paths["results"] / "native-runtime-report.json").read_text())
            return code, report, measured, paths

    def test_full_main_preflight_reaches_offline_install_call_with_existing_tmpfs(self):
        code, report, measured, paths = self._invoke_main()
        self.assertEqual(code, 1)  # the fixture makes only the attempted install fail
        self.assertEqual([row[0] for row in measured], ["offline_wheel_install"])
        self.assertIn("--no-index", measured[0][1])
        self.assertEqual(report["failed_phase"], "offline_wheel_install")
        self.assertEqual(report["fixture_cleanup"], "PASS")
        self.assertEqual(report["test_tmp_cleanup"], "PASS")

    def test_oserror_errno_and_fixture_phase_are_reported_separately(self):
        code, report, measured, _paths = self._invoke_main(
            install_error=PermissionError(13, "fixture install permission denied"))
        self.assertEqual(code, 1)
        self.assertEqual(report["primary_error"]["phase"], "offline_wheel_install")
        self.assertEqual(report["primary_error"]["errno"], 13)
        self.assertEqual(report["primary_error"]["class"], "PermissionError")
        self.assertEqual(len(measured), 1)
        code, report, measured, _paths = self._invoke_main(fixture_error=True)
        self.assertEqual(code, 1)
        self.assertEqual(report["primary_error"]["phase"], "fixture_preparation")
        self.assertEqual(report["primary_error"]["errno"], 28)
        self.assertEqual(measured, [])

    def test_full_main_preflight_rejects_mount_and_path_failures_before_install(self):
        cases = [
            ("missing-site-mount", None, None, "SITE_NOT_DEDICATED_TMPFS"),
            ("site-mount-options", None, None, "SITE_MOUNT_OPTIONS_INVALID"),
            (None, lambda p,r:(p["site"] / "unexpected").write_text("x"), None, "SITE_MOUNT_NOT_EMPTY"),
            (None, lambda p,r:p["site"].chmod(0o755), None, "SITE_MOUNT_IDENTITY_INVALID"),
            (None, lambda p,r:(p["site"].rmdir(), (r/"outside-site").mkdir(),
                                p["site"].symlink_to(r/"outside-site")), None,
             "SITE_MOUNT_INVALID"),
            (None, lambda p,r:(p["source"].rmdir(), (r/"outside-source").mkdir(),
                                p["source"].symlink_to(r/"outside-source")), None,
             "INPUT_SYMLINK_INVALID"),
            (None, None, True, "TEST_TMP_IDENTITY_INVALID"),
        ]
        for mount_failure, mutation, fake_uid, expected in cases:
            with self.subTest(expected=expected):
                code, report, measured, _paths = self._invoke_main(mutation, mount_failure, fake_uid)
                self.assertEqual(code, 1)
                self.assertEqual(measured, [])
                self.assertEqual(report["primary_error"]["code"], expected)

    def test_original_input_symlink_is_rejected_before_resolution(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp).resolve()
            real = root / "real"; real.mkdir()
            link = root / "link"; link.symlink_to(real)
            with self.assertRaisesRegex(RuntimeError, "INPUT_SYMLINK_INVALID"):
                NATIVE_RUNNER.resolve_checked_input(link, "directory")

    def test_tree_pss_is_unavailable_when_any_process_value_is_missing(self):
        self.assertEqual(NATIVE_RUNNER.tree_memory(10, {10:(1,100,80), 11:(10,50,None)}),
                         (150,None,2))
        self.assertEqual(NATIVE_RUNNER.tree_memory(10, {10:(1,100,80), 11:(10,50,30)}),
                         (150,110,2))

class Armv7SmokePublicToolTests(unittest.TestCase):
    def test_native_linux_lock_is_separate_and_pins_six_x86_64_distributions(self):
        lock_path = ROOT / "native-linux-smoke" / "native-linux-wheel-lock.json"
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        rows = lock["wheels"]
        self.assertEqual(lock["runtime"]["platform"], "linux/amd64")
        self.assertIn("@sha256:", lock["runtime"]["image"])
        self.assertEqual(len(rows), 6)
        self.assertTrue(any("cp39-cp39-manylinux2014_x86_64" in row["filename"] for row in rows
                            if row["name"] == "cffi"))
        self.assertTrue(any("cp39-abi3-manylinux2014_x86_64" in row["filename"] for row in rows
                            if row["name"] == "cryptography"))
        requirements = NATIVE_PREP._requirements(lock)
        self.assertEqual(len(requirements.splitlines()), 6)
        for row in rows:
            self.assertIn("%s==%s --hash=sha256:%s" %
                          (row["name"], row["version"], row["sha256"]), requirements)
        self.assertRegex(lock["private_source"]["archive_sha256"], r"^[0-9a-f]{64}$")
        arm = json.loads((ROOT / "armv7-smoke" / "wheel-lock.json").read_text(encoding="utf-8"))
        arm_cffi = next(row for row in arm["wheels"] if row["name"] == "cryptography")
        self.assertIn("armv7l", arm_cffi["filename"])
        self.assertIn("x86_64", next(row for row in rows if row["name"] == "cryptography")["filename"])

    def test_native_workflow_is_manual_x86_linux_and_disables_test_network(self):
        path = ROOT / ".github" / "workflows" / "native-linux-mcp-smoke.yml"
        text = path.read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", text)
        self.assertIn("runs-on: ubuntu-24.04", text)
        self.assertIn("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683", text)
        self.assertIn("run_native_container.sh", text)
        for index in range(1, 9):
            self.assertIn("MCP_NATIVE_LINUX_SOURCE_B64_%02d" % index, text)
        self.assertIn("MCP_NATIVE_LINUX_DIAGNOSTIC_KEY_HEX", text)
        self.assertNotIn("MCP_ARMV7_SOURCE_B64_01", text)
        runner = (ROOT / "native-linux-smoke" / "run_native_container.sh").read_text()
        self.assertIn("--platform linux/amd64 --network none", runner)
        self.assertIn("--cap-drop ALL --security-opt no-new-privileges:true", runner)
        self.assertIn("python:3.9.25-slim-bookworm@sha256:", runner)
        self.assertNotIn("setup-qemu", text.lower())

    def test_native_private_archive_extraction_is_explicit_and_safe(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            archive_path = root / "source.tar.gz"
            entries = {
                "src/mcp_document_oauth_entrypoint.py":b"# fixture\n",
                "tools/native_service_cycle.py":b"# fixture\n",
                "tests/test_native_service_real_gateway_e2e.py":b"# fixture\n",
                "config/mcp-oauth-runtime.example.json":b"{}\n",
            }
            for index in range(43):
                entries["fixture/%02d.txt" % index] = b"synthetic\n"
            with tarfile.open(str(archive_path), "w:gz") as archive:
                for name, data in entries.items():
                    member = tarfile.TarInfo(name); member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))
            target = root / "unpacked"
            NATIVE_PREP._extract_source(archive_path.read_bytes(), target, 47)
            self.assertEqual((target / "src/mcp_document_oauth_entrypoint.py").read_bytes(), b"# fixture\n")
            self.assertEqual((target / "src/mcp_document_oauth_entrypoint.py").stat().st_mode & 0o777, 0o600)

    def test_native_private_archive_extraction_rejects_parent_escape_and_links(self):
        for entry_type in ("escape", "symlink"):
            with self.subTest(entry_type=entry_type), tempfile.TemporaryDirectory() as temp:
                root = pathlib.Path(temp)
                archive_path = root / "bad.tar.gz"
                with tarfile.open(str(archive_path), "w:gz") as archive:
                    member = tarfile.TarInfo("../outside.txt" if entry_type == "escape" else "linked.txt")
                    if entry_type == "symlink":
                        member.type = tarfile.SYMTYPE
                        member.linkname = "/etc/passwd"
                        archive.addfile(member)
                    else:
                        data = b"blocked"
                        member.size = len(data)
                        archive.addfile(member, io.BytesIO(data))
                with self.assertRaisesRegex(NATIVE_PREP.PrepareError, "SOURCE_PATH|SOURCE_NON_REGULAR"):
                    NATIVE_PREP._extract_source(archive_path.read_bytes(), root / "out", 47)

    def test_source_packaging_is_deterministic_and_0700(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            staged = root / "staged"
            staged.mkdir()
            for index in range(47):
                (staged / ("file-%02d.py" % index)).write_text("fixture %d\n" % index, encoding="ascii")
            first, second = root / "one.tar.gz", root / "two.tar.gz"
            PACK.deterministic_archive(staged, first)
            PACK.deterministic_archive(staged, second)
            self.assertEqual(hashlib.sha256(first.read_bytes()).digest(), hashlib.sha256(second.read_bytes()).digest())

    def test_source_packaging_rejects_wrong_inventory_and_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            staged = root / "staged"
            staged.mkdir()
            (staged / "one.py").write_text("x", encoding="ascii")
            with self.assertRaisesRegex(ValueError, "FILE_COUNT"):
                PACK.deterministic_archive(staged, root / "bad.tar.gz")
            outside = root / "outside.py"
            outside.write_text("x", encoding="ascii")
            for index in range(44):
                (staged / ("f%02d.py" % index)).write_text("x", encoding="ascii")
            (staged / "link.py").symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "ENTRY_TYPE"):
                PACK.deterministic_archive(staged, root / "bad-link.tar.gz")

    def test_private_source_unpack_checks_count_and_path_safety(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            archive_path = root / "fixture.tar.gz"
            with tarfile.open(str(archive_path), "w:gz") as tar:
                data = b"synthetic"
                info = tarfile.TarInfo("../outside.txt")
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            with self.assertRaisesRegex(PREP.InputError, "PATH_OR_DUPLICATE"):
                PREP._extract_source(archive_path.read_bytes(), root / "out")

    def test_source_chunk_rejects_bad_base64_and_size(self):
        old = {key: os.environ.get(key) for key in ("SOURCE_PART_%02d" % i for i in range(1, 8))}
        try:
            for index in range(1, 8):
                os.environ["SOURCE_PART_%02d" % index] = "bad!"
            with self.assertRaisesRegex(PREP.InputError, "SECRET_PART_INVALID"):
                PREP._strict_source_archive({"private_source_archive_sha256": "0" * 64})
        finally:
            for key, value in old.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def test_encrypted_report_round_trip_and_tamper_rejection(self):
        key = "12" * 32
        old = os.environ.get("MCP_DIAGNOSTIC_KEY_HEX")
        try:
            with tempfile.TemporaryDirectory() as temp:
                root = pathlib.Path(temp) / "results"
                root.mkdir(mode=0o700)
                (root / "fixture.log").write_text("SYNTHETIC_PRIVATE_DIAGNOSTIC", encoding="ascii")
                os.environ["MCP_DIAGNOSTIC_KEY_HEX"] = key
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    ENCRYPT.encrypt(str(root))
                self.assertIn("MCP_ARMV7_ENCRYPTED_DIAGNOSTICS_BEGIN", stdout.getvalue())
                envelope = root / "report.enc"
                self.assertTrue(envelope.is_file())
                decrypted = pathlib.Path(temp) / "clear.tar.gz"
                DECRYPT.decrypt(envelope, decrypted, key)
                with tarfile.open(str(decrypted), "r:gz") as tar:
                    self.assertEqual(tar.extractfile("fixture.log").read(), b"SYNTHETIC_PRIVATE_DIAGNOSTIC")
                data = bytearray(envelope.read_bytes())
                data[-1] ^= 1
                bad = pathlib.Path(temp) / "tampered.enc"
                bad.write_bytes(data)
                with self.assertRaisesRegex(ValueError, "AUTHENTICATION_FAILED"):
                    DECRYPT.decrypt(bad, pathlib.Path(temp) / "bad.tar.gz", key)
        finally:
            if old is None:
                os.environ.pop("MCP_DIAGNOSTIC_KEY_HEX", None)
            else:
                os.environ["MCP_DIAGNOSTIC_KEY_HEX"] = old

    def test_recover_requires_one_marker_pair_and_strict_base64(self):
        with self.assertRaisesRegex(ValueError, "MARKERS_INVALID"):
            RECOVER.extract("no markers")
        with self.assertRaisesRegex(Exception, "INVALID|Error"):
            RECOVER.extract("MCP_ARMV7_ENCRYPTED_DIAGNOSTICS_BEGIN\nnot-base64!\nMCP_ARMV7_ENCRYPTED_DIAGNOSTICS_END")

    def test_cffi_audit_log_marker_decoder_accepts_runner_prefix_and_hashes(self):
        data = b"synthetic cffi audit archive"
        encoded = base64.b64encode(data).decode("ascii")
        log = "2026-01-01T00:00:00Z CFFI_AUDIT_ARCHIVE_BASE64_BEGIN\n"
        log += "2026-01-01T00:00:01Z " + encoded + "\n"
        log += "2026-01-01T00:00:02Z CFFI_AUDIT_ARCHIVE_BASE64_END\n"
        self.assertEqual(PREP._decode_cffi_audit_log(log, hashlib.sha256(data).hexdigest()), data)
        with self.assertRaisesRegex(PREP.InputError, "SHA256"):
            PREP._decode_cffi_audit_log(log, "0" * 64)

    def test_container_runner_requires_private_owned_empty_exec_site_mount(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            site = root / "site"
            site.mkdir(mode=0o700)
            site.chmod(0o700)
            RUNNER.validate_site_mount(site)

            site.chmod(0o750)
            with self.assertRaisesRegex(RuntimeError, "ARMV7_SITE_MOUNT_MODE_INVALID"):
                RUNNER.validate_site_mount(site)
            site.chmod(0o700)
            (site / "unexpected").write_text("x", encoding="ascii")
            with self.assertRaisesRegex(RuntimeError, "ARMV7_SITE_MOUNT_NOT_EMPTY"):
                RUNNER.validate_site_mount(site)
            link = root / "site-link"
            link.symlink_to(site, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "ARMV7_SITE_MOUNT_INVALID"):
                RUNNER.validate_site_mount(link)

    def test_test_temp_mount_requires_private_dedicated_nonexec_tmpfs(self):
        mountinfo = ("42 1 0:55 / /mcp-armv7-test-tmp rw,nosuid,nodev,noexec - "
                     "tmpfs tmpfs rw,nosuid,nodev,noexec,size=128m")
        with tempfile.TemporaryDirectory() as temp:
            path = pathlib.Path(temp) / "private-tmp"
            path.mkdir(mode=0o700)
            path.chmod(0o700)
            RUNNER.validate_test_tmp_mount(path, mountinfo.replace(
                "/mcp-armv7-test-tmp", str(path)))
            with self.assertRaisesRegex(RuntimeError, "ARMV7_TEST_TMP_MOUNT_OPTIONS_INVALID"):
                RUNNER.validate_test_tmp_mount(
                    path, mountinfo.replace("noexec", "exec").replace(
                        "/mcp-armv7-test-tmp", str(path)))
            with self.assertRaisesRegex(RuntimeError, "ARMV7_TEST_TMP_NOT_DEDICATED_TMPFS"):
                RUNNER.validate_test_tmp_mount(
                    path, mountinfo.replace("/mcp-armv7-test-tmp", "/tmp"))
            (path / "unexpected").touch()
            with self.assertRaisesRegex(RuntimeError, "ARMV7_TEST_TMP_NOT_EMPTY"):
                RUNNER.validate_test_tmp_mount(
                    path, mountinfo.replace("/mcp-armv7-test-tmp", str(path)))

    def test_prepare_lock_generation_mount_and_pip_argument_match(self):
        lock_data = json.loads((ROOT / "armv7-smoke" / "wheel-lock.json").read_text(encoding="utf-8"))
        lines = PREP.requirements_lock_lines(lock_data)
        self.assertEqual(len(lines), 6)
        self.assertEqual(len(set(line.split("==", 1)[0] for line in lines)), 6)
        with tempfile.TemporaryDirectory() as temp:
            lock_path = pathlib.Path(temp) / "requirements.lock"
            lock_path.write_text("\n".join(lines) + "\n", encoding="ascii")
            validated = RUNNER.validate_lock_file(lock_path)
            command = RUNNER.build_offline_install_command("python3.9", "/site", "/wheelhouse", validated)
            self.assertEqual(command[command.index("-r") + 1], str(lock_path))
            self.assertEqual(command[command.index("--find-links") + 1], "/wheelhouse")
            with self.assertRaisesRegex(RuntimeError, "REQUIREMENTS_LOCK_INVALID"):
                RUNNER.validate_lock_file(pathlib.Path(temp) / "missing.lock")
            symlink = pathlib.Path(temp) / "requirements-link.lock"
            symlink.symlink_to(lock_path)
            with self.assertRaisesRegex(RuntimeError, "REQUIREMENTS_LOCK_INVALID"):
                RUNNER.validate_lock_file(symlink)
            broken = pathlib.Path(temp) / "bad.lock"
            broken.write_text("cryptography==50.0.2\n", encoding="ascii")
            with self.assertRaisesRegex(RuntimeError, "REQUIREMENTS_LOCK_INVALID"):
                RUNNER.validate_lock_file(broken)

    def test_results_write_probe_is_atomic_and_leaves_no_probe_file(self):
        with tempfile.TemporaryDirectory() as temp:
            results = pathlib.Path(temp) / "results"
            results.mkdir(mode=0o700)
            results.chmod(0o700)
            RUNNER.verify_results_write(results)
            self.assertEqual(list(results.iterdir()), [])
            results.chmod(0o500)
            with self.assertRaisesRegex(RuntimeError, "RESULTS_DIRECTORY_IDENTITY_INVALID"):
                RUNNER.verify_results_write(results)

    def test_unwritable_results_keeps_primary_phase_code_in_captured_log(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            source, wheelhouse, smoke, results = [root / name for name in
                                                  ("source", "wheelhouse", "smoke", "results")]
            for path in (source, wheelhouse, smoke, results):
                path.mkdir(mode=0o700)
                path.chmod(0o700)
            lock = root / "requirements.lock"
            lock.write_text("\n".join("%s==1.0 --hash=sha256:%s" % (name, "b" * 64)
                                       for name in ("cffi", "cryptography", "pycparser", "pyspnego",
                                                    "smbprotocol", "typing-extensions")) + "\n",
                            encoding="ascii")
            results.chmod(0o500)
            stderr = io.StringIO()
            argv = ["container_runner", "--wheelhouse", str(wheelhouse), "--source", str(source),
                    "--smoke", str(smoke), "--results", str(results), "--lock", str(lock)]
            with mock.patch.object(RUNNER.sys, "argv", argv), \
                 mock.patch.object(RUNNER.sys, "version_info", (3, 9)), \
                 mock.patch.object(RUNNER.platform, "machine", return_value="armv7l"), \
                 mock.patch.object(RUNNER.struct, "calcsize", return_value=4), \
                 mock.patch.object(RUNNER, "validate_site_mount"), \
                 contextlib.redirect_stderr(stderr):
                result = RUNNER.main()
            self.assertEqual(result, 1)
            output = stderr.getvalue()
            self.assertIn("MCP_ARMV7_FAILURE phase=results_write_probe code=RESULTS_DIRECTORY_IDENTITY_INVALID", output)
            self.assertIn("MCP_ARMV7_REPORT_WRITE_FAILED code=REPORT_OS_ERROR errno=", output)
            self.assertNotIn("Traceback", output)

    def test_run_measured_does_not_start_child_if_log_path_is_unavailable(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            marker = root / "child-started"
            code = "from pathlib import Path; Path(%r).write_text('started')" % str(marker)
            with self.assertRaises(OSError):
                RUNNER.run_measured("synthetic", [sys.executable, "-c", code],
                                    os.environ.copy(), root, root / "missing" / "phase.log", [])
            self.assertFalse(marker.exists())

    def test_container_launcher_uses_separate_private_test_tmpfs(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            run_root = root / "run"
            (run_root / "private-source").mkdir(parents=True)
            run_root.chmod(0o700)
            source = run_root / "private-source"
            source.chmod(0o700)
            for index in range(47):
                (source / ("source-%02d.py" % index)).write_text("fixture\n", encoding="ascii")
            wheelhouse = run_root / "wheelhouse"
            wheelhouse.mkdir()
            wheelhouse.chmod(0o700)
            for index in range(6):
                (wheelhouse / ("wheel-%d.whl" % index)).write_bytes(b"fixture")
            lock_data = json.loads((ROOT / "armv7-smoke" / "wheel-lock.json").read_text(encoding="utf-8"))
            lock_lines = PREP.requirements_lock_lines(lock_data)
            (run_root / "requirements.lock").write_text("\n".join(lock_lines) + "\n", encoding="ascii")
            results = run_root / "results"
            results.mkdir(mode=0o700)
            (results / "prepare-status.json").write_text(json.dumps({"status": "PASS", "wheel_count": 6,
                                                                       "private_source_file_count": 47}), encoding="ascii")
            fake_bin = root / "bin"
            fake_bin.mkdir()
            capture = root / "docker-args.txt"
            docker = fake_bin / "docker"
            script_lines = [
                "#!/usr/bin/env python3",
                "import os, pathlib, sys",
                "args = sys.argv[1:]",
                "pathlib.Path(os.environ['FAKE_DOCKER_ARGS']).write_text('\\n'.join(args), encoding='utf-8')",
                "results = next(arg[:-len(':/results:rw')] for arg in args if arg.endswith(':/results:rw'))",
                "pathlib.Path(results, 'runtime-report.json').write_text('{\\\"status\\\":\\\"PASS\\\"}\\n', encoding='utf-8')",
            ]
            docker.write_text("\n".join(script_lines) + "\n", encoding="utf-8")
            docker.chmod(0o755)
            environment = os.environ.copy()
            environment.update({"PATH": str(fake_bin) + os.pathsep + environment.get("PATH", ""),
                                "FAKE_DOCKER_ARGS": str(capture)})
            command = ["bash", str(ROOT / "armv7-smoke" / "run_container.sh"), str(run_root)]
            completed = subprocess.run(command, capture_output=True, text=True, env=environment, check=False)
            self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
            args = capture.read_text(encoding="utf-8").splitlines()
            user_index = args.index("--user")
            self.assertEqual(args[user_index + 1], "%s:%s" % (os.getuid(), os.getgid()))
            tmpfs_values = [args[i + 1] for i, value in enumerate(args[:-1]) if value == "--tmpfs"]
            self.assertIn("/tmp:rw,nosuid,nodev,noexec,size=256m", tmpfs_values)
            self.assertTrue(any(value.startswith("/opt/mcp-armv7-site:") and ",exec," in value and "mode=0700" in value for value in tmpfs_values))
            self.assertTrue(any(value.startswith("/mcp-armv7-test-tmp:")
                                and "noexec" in value and "nosuid" in value
                                and "nodev" in value and "mode=0700" in value
                                for value in tmpfs_values))
            self.assertIn("TMPDIR=/mcp-armv7-test-tmp", args)
            self.assertIn(str(run_root.resolve() / "requirements.lock") + ":/requirements.lock:ro", args)
            self.assertEqual(args[args.index("--lock") + 1], "/requirements.lock")
            validated_lock = RUNNER.validate_lock_file(run_root / "requirements.lock")
            pip_command = RUNNER.build_offline_install_command("python3.9", "/site", "/wheelhouse", "/requirements.lock")
            self.assertEqual(pip_command[pip_command.index("-r") + 1], "/requirements.lock")
            self.assertTrue((results / "runtime-report.json").is_file())

    def test_container_launcher_rejects_unexpected_results_inventory(self):
        with tempfile.TemporaryDirectory() as temp:
            run_root = pathlib.Path(temp) / "run"
            run_root.mkdir()
            run_root.chmod(0o700)
            source = run_root / "private-source"
            source.mkdir(mode=0o700)
            for index in range(47):
                (source / ("source-%02d.py" % index)).write_text("fixture\n", encoding="ascii")
            wheelhouse = run_root / "wheelhouse"
            wheelhouse.mkdir(mode=0o700)
            for index in range(6):
                (wheelhouse / ("wheel-%d.whl" % index)).write_bytes(b"fixture")
            (run_root / "requirements.lock").write_text("lock\n", encoding="ascii")
            results = run_root / "results"
            results.mkdir(mode=0o700)
            (results / "prepare-status.json").write_text(json.dumps({"status": "PASS", "wheel_count": 6,
                                                                       "private_source_file_count": 47}), encoding="ascii")
            sentinel = results / "preserve-me"
            sentinel.write_text("fixture", encoding="ascii")
            completed = subprocess.run(
                ["bash", str(ROOT / "armv7-smoke" / "run_container.sh"), str(run_root)],
                capture_output=True, text=True, env=os.environ.copy(), check=False)
            self.assertEqual(completed.returncode, 2)
            self.assertIn("RESULTS_INVENTORY_INVALID", completed.stderr)
            self.assertEqual(sentinel.read_text(encoding="ascii"), "fixture")

if __name__ == "__main__":
    unittest.main()
