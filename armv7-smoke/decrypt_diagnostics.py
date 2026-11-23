#!/usr/bin/env python3
"""Authenticate and decrypt an MCP ARMv7 smoke report into a private tar.gz file."""
import argparse
import getpass
import hashlib
import hmac
import os
import pathlib
import subprocess
import tempfile

MAGIC = b"MCPAR1\x00"

def decrypt(source, output, key_text):
    try:
        master = bytes.fromhex(key_text)
    except ValueError:
        raise ValueError("DIAGNOSTIC_KEY_INVALID")
    if len(master) != 32:
        raise ValueError("DIAGNOSTIC_KEY_INVALID")
    source = pathlib.Path(source)
    if source.is_symlink() or not source.is_file():
        raise ValueError("ENVELOPE_SOURCE_INVALID")
    data = source.read_bytes()
    if len(data) < len(MAGIC) + 32 or not data.startswith(MAGIC):
        raise ValueError("ENVELOPE_FORMAT_INVALID")
    tag = data[len(MAGIC):len(MAGIC) + 32]
    ciphertext = data[len(MAGIC) + 32:]
    mac_key = hmac.new(master, b"MCP-ARMV7-SMOKE-REPORT-HMAC-v1", hashlib.sha256).digest()
    expected = hmac.new(mac_key, MAGIC + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("ENVELOPE_AUTHENTICATION_FAILED")
    output = pathlib.Path(output)
    if output.exists() or output.is_symlink():
        raise ValueError("OUTPUT_ALREADY_EXISTS")
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    read_fd, write_fd = os.pipe()
    try:
        with tempfile.TemporaryDirectory(prefix="mcp-armv7-decrypt-") as temp:
            temp = pathlib.Path(temp)
            encrypted_payload = temp / "report.openssl"
            encrypted_payload.write_bytes(ciphertext)
            plaintext = temp / "report.tar.gz"
            process = subprocess.Popen(
                ["openssl", "enc", "-d", "-aes-256-cbc", "-salt", "-pbkdf2", "-iter", "200000",
                 "-pass", "fd:%d" % read_fd, "-in", str(encrypted_payload), "-out", str(plaintext)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                pass_fds=(read_fd,))
            os.close(read_fd)
            read_fd = -1
            os.write(write_fd, key_text.encode("ascii") + b"\n")
            os.close(write_fd)
            write_fd = -1
            _stdout, _stderr = process.communicate(timeout=60)
            if process.returncode or not plaintext.is_file():
                raise ValueError("REPORT_DECRYPTION_FAILED")
            output.write_bytes(plaintext.read_bytes())
            output.chmod(0o600)
    finally:
        if read_fd >= 0:
            os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("encrypted_report")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    secret = getpass.getpass("Diagnostic key (hex, not echoed): ")
    try:
        decrypt(args.encrypted_report, args.output, secret)
    except Exception as exc:
        code = str(exc) if str(exc).isupper() and len(str(exc)) < 80 else "REPORT_DECRYPTION_FAILED"
        raise SystemExit(code)
    print("DIAGNOSTICS_DECRYPTED_TO_PRIVATE_ARCHIVE")
