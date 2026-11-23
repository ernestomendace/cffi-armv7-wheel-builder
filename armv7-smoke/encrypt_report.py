#!/usr/bin/env python3
"""Encrypt bounded local diagnostics before emitting ciphertext to public run logs."""
import argparse
import base64
import hashlib
import hmac
import os
import pathlib
import subprocess
import tarfile
import tempfile

MAX_TOTAL = 8_000_000
MAX_FILES = 24
MAGIC = b"MCPAR1\x00"

def encrypt(root):
    key_text = os.environ.pop("MCP_DIAGNOSTIC_KEY_HEX", "")
    try:
        master = bytes.fromhex(key_text)
    except ValueError:
        raise RuntimeError("DIAGNOSTIC_KEY_INVALID")
    if len(master) != 32:
        raise RuntimeError("DIAGNOSTIC_KEY_INVALID")
    root = pathlib.Path(root).resolve(strict=True)
    files = []
    total = 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise RuntimeError("DIAGNOSTIC_SYMLINK_FORBIDDEN")
        if path.is_file():
            total += path.stat().st_size
            files.append(path)
    if len(files) > MAX_FILES or total > MAX_TOTAL:
        raise RuntimeError("DIAGNOSTIC_SIZE_LIMIT")
    with tempfile.TemporaryDirectory(prefix="armv7-report-") as temp:
        temp = pathlib.Path(temp)
        plain = temp / "report.tar.gz"
        encrypted = temp / "report.openssl"
        with tarfile.open(str(plain), "w:gz") as archive:
            for path in files:
                archive.add(str(path), arcname=path.relative_to(root).as_posix(), recursive=False)
        read_fd, write_fd = os.pipe()
        try:
            process = subprocess.Popen(
                ["openssl", "enc", "-aes-256-cbc", "-salt", "-pbkdf2", "-iter", "200000",
                 "-pass", "fd:%d" % read_fd, "-in", str(plain), "-out", str(encrypted)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                pass_fds=(read_fd,))
            os.close(read_fd)
            read_fd = -1
            os.write(write_fd, key_text.encode("ascii") + b"\n")
            os.close(write_fd)
            write_fd = -1
            _stdout, _stderr = process.communicate(timeout=60)
            if process.returncode:
                raise RuntimeError("DIAGNOSTIC_ENCRYPTION_FAILED")
        finally:
            if read_fd >= 0:
                os.close(read_fd)
            if write_fd >= 0:
                os.close(write_fd)
        ciphertext = encrypted.read_bytes()
        mac_key = hmac.new(master, b"MCP-ARMV7-SMOKE-REPORT-HMAC-v1", hashlib.sha256).digest()
        tag = hmac.new(mac_key, MAGIC + ciphertext, hashlib.sha256).digest()
        envelope = MAGIC + tag + ciphertext
        if len(envelope) > 8_500_000:
            raise RuntimeError("ENCRYPTED_REPORT_SIZE_LIMIT")
    output = root / "report.enc"
    output.write_bytes(envelope)
    output.chmod(0o600)
    for path in files:
        path.unlink()
    for path in sorted(root.rglob("*"), reverse=True):
        if path.is_dir() and path != root:
            try:
                path.rmdir()
            except OSError:
                pass
    print("MCP_ARMV7_ENCRYPTED_DIAGNOSTICS_BEGIN")
    encoded = base64.b64encode(envelope).decode("ascii")
    for offset in range(0, len(encoded), 76):
        print(encoded[offset:offset + 76])
    print("MCP_ARMV7_ENCRYPTED_DIAGNOSTICS_END")
    print("MCP_ARMV7_DIAGNOSTIC_BYTES=%d" % len(envelope))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    args = parser.parse_args()
    try:
        encrypt(args.root)
    except Exception as exc:
        code = str(exc) if str(exc).isupper() and len(str(exc)) < 80 else "DIAGNOSTIC_ENCRYPTION_FAILED"
        print("MCP_ARMV7_DIAGNOSTIC_ENCRYPTION=FAIL code=%s" % code)
        raise SystemExit(1)
