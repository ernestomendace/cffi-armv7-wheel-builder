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

class Armv7SmokePublicToolTests(unittest.TestCase):
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
