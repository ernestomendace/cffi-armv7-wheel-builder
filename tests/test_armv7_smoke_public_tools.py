import contextlib
import gzip
import base64
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import tarfile
import tempfile
import unittest

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

class Armv7SmokePublicToolTests(unittest.TestCase):
    def test_source_packaging_is_deterministic_and_0700(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            staged = root / "staged"
            staged.mkdir()
            for index in range(46):
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

if __name__ == "__main__":
    unittest.main()
