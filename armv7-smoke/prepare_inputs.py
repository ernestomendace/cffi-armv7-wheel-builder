#!/usr/bin/env python3
"""Fetch only locked wheels and restore the private source archive from Actions secrets."""
import argparse
import base64
import hashlib
import json
import os
import pathlib
import re
import subprocess
import tarfile
import tempfile
import urllib.parse
import urllib.request


REPO = "ernestomendace/cffi-armv7-wheel-builder"
MAX_SOURCE_BYTES = 1_000_000
MAX_SOURCE_FILES = 100
MAX_SOURCE_EXPANDED = 2_000_000
MAX_WHEEL_BYTES = 20_000_000


class InputError(Exception):
    pass


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def _strict_source_archive(lock):
    parts = []
    for number in range(1, 9):
        value = os.environ.get("SOURCE_PART_%02d" % number, "")
        if not value or len(value) > 40000 or not re.fullmatch(r"[A-Za-z0-9+/=]+", value):
            raise InputError("SOURCE_SECRET_PART_INVALID")
        parts.append(value)
    try:
        archive = base64.b64decode("".join(parts), validate=True)
    except (ValueError, base64.binascii.Error):
        raise InputError("SOURCE_ARCHIVE_BASE64_INVALID")
    for number in range(1, 9):
        os.environ.pop("SOURCE_PART_%02d" % number, None)
    parts.clear()
    if len(archive) > MAX_SOURCE_BYTES:
        raise InputError("SOURCE_ARCHIVE_TOO_LARGE")
    if sha256(archive) != lock["private_source_archive_sha256"]:
        raise InputError("SOURCE_ARCHIVE_SHA256_MISMATCH")
    return archive


def _extract_source(archive, destination):
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    count = 0
    expanded = 0
    with tarfile.open(fileobj=__import__("io").BytesIO(archive), mode="r:gz") as tar:
        members = tar.getmembers()
        if len(members) > MAX_SOURCE_FILES:
            raise InputError("SOURCE_MEMBER_LIMIT_EXCEEDED")
        names = set()
        for member in members:
            path = pathlib.PurePosixPath(member.name)
            if (not member.name or path.is_absolute() or ".." in path.parts
                    or "\\" in member.name or member.name in names):
                raise InputError("SOURCE_PATH_OR_DUPLICATE_INVALID")
            names.add(member.name)
            if member.isdir():
                continue
            if not member.isfile() or member.issym() or member.islnk():
                raise InputError("SOURCE_NON_REGULAR_MEMBER")
            count += 1
            expanded += member.size
            if expanded > MAX_SOURCE_EXPANDED:
                raise InputError("SOURCE_EXPANDED_LIMIT_EXCEEDED")
            output = destination.joinpath(*path.parts)
            output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            stream = tar.extractfile(member)
            if stream is None:
                raise InputError("SOURCE_MEMBER_UNREADABLE")
            with stream, output.open("xb") as target:
                data = stream.read(MAX_SOURCE_EXPANDED + 1)
                if len(data) != member.size:
                    raise InputError("SOURCE_MEMBER_SIZE_MISMATCH")
                target.write(data)
            output.chmod(0o600)
        required = (
            "config/mcp-oauth-runtime.example.json",
            "tests/test_mcp_oauth_http_adapter.py",
            "tests/test_native_service_real_gateway_e2e.py",
            "tests/test_native_service_coordinator_composition.py",
            "tests/test_native_service_runtime_adapters.py",
            "tools/armv7_offline_bundle_smoke.py",
        )
        if count < 1 or any(not destination.joinpath(*p.split("/")).is_file() for p in required):
            raise InputError("SOURCE_REQUIRED_FILE_MISSING")
    if count != 46:
        raise InputError("SOURCE_INVENTORY_COUNT_MISMATCH")


def _download_pypi_wheel(wheel, destination):
    project = urllib.parse.quote(wheel["name"].replace("_", "-"), safe="")
    version = urllib.parse.quote(wheel["version"], safe="")
    metadata_url = "https://pypi.org/pypi/%s/%s/json" % (project, version)
    request = urllib.request.Request(metadata_url, headers={"User-Agent": "armv7-offline-smoke/1"})
    with urllib.request.urlopen(request, timeout=30) as response:
        metadata = json.loads(response.read(2_000_000).decode("utf-8"))
    matches = [item for item in metadata.get("urls", []) if item.get("filename") == wheel["filename"]]
    if len(matches) != 1 or matches[0].get("digests", {}).get("sha256") != wheel["sha256"]:
        raise InputError("PYPI_LOCK_METADATA_MISMATCH")
    url = matches[0].get("url", "")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != "files.pythonhosted.org":
        raise InputError("PYPI_WHEEL_HOST_INVALID")
    request = urllib.request.Request(url, headers={"User-Agent": "armv7-offline-smoke/1"})
    with urllib.request.urlopen(request, timeout=60) as response:
        data = response.read(MAX_WHEEL_BYTES + 1)
    if len(data) > MAX_WHEEL_BYTES or sha256(data) != wheel["sha256"]:
        raise InputError("PYPI_WHEEL_SHA256_MISMATCH")
    (destination / wheel["filename"]).write_bytes(data)


def _decode_cffi_audit_log(text, expected_sha256):
    begin = "CFFI_AUDIT_ARCHIVE_BASE64_BEGIN"
    end = "CFFI_AUDIT_ARCHIVE_BASE64_END"
    if text.count(begin) != 1 or text.count(end) != 1:
        raise InputError("CFFI_AUDIT_ARCHIVE_MARKERS_INVALID")
    segment = text.split(begin, 1)[1].split(end, 1)[0]
    chunks = []
    for line in segment.splitlines():
        value = line.split("Z ", 1)[1] if "Z " in line else line.strip()
        value = value.strip()
        if value:
            if not re.fullmatch(r"[A-Za-z0-9+/=]+", value):
                raise InputError("CFFI_AUDIT_BASE64_LINE_INVALID")
            chunks.append(value)
    try:
        archive = base64.b64decode("".join(chunks), validate=True)
    except (ValueError, base64.binascii.Error):
        raise InputError("CFFI_AUDIT_BASE64_INVALID")
    if len(archive) > 8_000_000 or sha256(archive) != expected_sha256:
        raise InputError("CFFI_AUDIT_ARCHIVE_SHA256_MISMATCH")
    return archive


def _recover_cffi_wheel(lock, destination):
    command = ["gh", "run", "view", str(lock["cffi_audit_source"]["run_id"]),
               "--repo", REPO, "--log"]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            check=False, timeout=180)
    if result.returncode:
        raise InputError("CFFI_AUDIT_LOG_UNAVAILABLE")
    text = result.stdout.decode("utf-8", "replace")
    archive = _decode_cffi_audit_log(text, lock["cffi_audit_source"]["archive_sha256"])
    wheel_entry = lock["cffi_audit_source"]["wheel"]
    found = []
    with tarfile.open(fileobj=__import__("io").BytesIO(archive), mode="r:gz") as tar:
        for member in tar.getmembers():
            path = pathlib.PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or not member.isfile():
                continue
            if path.name == wheel_entry:
                found.append(member)
        if len(found) != 1 or found[0].size > MAX_WHEEL_BYTES:
            raise InputError("CFFI_WHEEL_IN_AUDIT_ARCHIVE_INVALID")
        stream = tar.extractfile(found[0])
        if stream is None:
            raise InputError("CFFI_WHEEL_UNREADABLE")
        wheel_bytes = stream.read(MAX_WHEEL_BYTES + 1)
    if sha256(wheel_bytes) != lock["cffi_audit_source"]["wheel_sha256"]:
        raise InputError("CFFI_WHEEL_SHA256_MISMATCH")
    (destination / wheel_entry).write_bytes(wheel_bytes)


def prepare(root, lock_path):
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    results = root / "results"
    results.mkdir(mode=0o700)
    wheelhouse = root / "wheelhouse"
    wheelhouse.mkdir(mode=0o700)
    source_root = root / "private-source"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    archive = _strict_source_archive(lock)
    with tempfile.TemporaryDirectory(prefix="armv7-private-source-") as temp:
        archive_path = pathlib.Path(temp) / "source.tar.gz"
        archive_path.write_bytes(archive)
        _extract_source(archive, source_root)
    for wheel in lock["wheels"]:
        _download_pypi_wheel(wheel, wheelhouse)
    _recover_cffi_wheel(lock, wheelhouse)
    lines = []
    for entry in [lock["cffi_audit_source"]] + lock["wheels"]:
        if "wheel" in entry:
            name, version, digest = entry["wheel"], "2.0.0", entry["wheel_sha256"]
        else:
            name, version, digest = entry["filename"], entry["version"], entry["sha256"]
        lines.append("%s==%s --hash=sha256:%s" % (entry.get("name", "cffi"), version, digest))
    (root / "requirements.lock").write_text("\n".join(lines) + "\n", encoding="ascii")
    (results / "prepare-status.json").write_text(
        json.dumps({"status": "PASS", "wheel_count": 6, "private_source_file_count": 46},
                   sort_keys=True) + "\n", encoding="ascii")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--lock", default="armv7-smoke/wheel-lock.json")
    args = parser.parse_args()
    root = pathlib.Path(args.root)
    try:
        prepare(root, pathlib.Path(args.lock))
        print("ARMV7_INPUT_PREPARATION=PASS")
        return 0
    except Exception as exc:
        code = str(exc) if isinstance(exc, InputError) else "INPUT_PREPARATION_INTERNAL_ERROR"
        try:
            root.mkdir(mode=0o700, parents=True, exist_ok=True)
            results = root / "results"
            results.mkdir(mode=0o700, parents=True, exist_ok=True)
            (results / "prepare-status.json").write_text(
                json.dumps({"status": "FAIL", "code": code}, sort_keys=True) + "\n",
                encoding="ascii")
        except OSError:
            pass
        print("ARMV7_INPUT_PREPARATION=FAIL code=%s" % code)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
