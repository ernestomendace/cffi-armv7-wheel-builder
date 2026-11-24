#!/usr/bin/env python3
"""Recover the private test source and fetch six hash-locked CPython 3.9 x86-64 wheels."""
import argparse
import base64
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import tarfile
import urllib.parse
import urllib.request

MAX_SOURCE_BYTES = 1_000_000
MAX_SOURCE_EXPANDED = 2_000_000
MAX_WHEEL_BYTES = 20_000_000
PART_COUNT = 8


class PrepareError(Exception):
    pass


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _read_source_archive(lock):
    parts = []
    for index in range(1, PART_COUNT + 1):
        key = "SOURCE_PART_%02d" % index
        value = os.environ.get(key, "")
        if not value or len(value) > 40000 or not re.fullmatch(r"[A-Za-z0-9+/=]+", value):
            raise PrepareError("SOURCE_SECRET_PART_INVALID")
        parts.append(value)
    try:
        archive = base64.b64decode("".join(parts), validate=True)
    except (ValueError, base64.binascii.Error):
        raise PrepareError("SOURCE_ARCHIVE_BASE64_INVALID")
    finally:
        for index in range(1, PART_COUNT + 1):
            os.environ.pop("SOURCE_PART_%02d" % index, None)
        parts.clear()
    spec = lock["private_source"]
    if (len(archive) > MAX_SOURCE_BYTES or len(archive) != spec["archive_bytes"]
            or _sha256(archive) != spec["archive_sha256"]):
        raise PrepareError("SOURCE_ARCHIVE_LOCK_MISMATCH")
    return archive


def _extract_source(archive, destination, expected_count):
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    seen = set()
    count = expanded = 0
    with tarfile.open(fileobj=__import__("io").BytesIO(archive), mode="r:gz") as tar:
        members = tar.getmembers()
        if len(members) > 120:
            raise PrepareError("SOURCE_MEMBER_LIMIT")
        for member in members:
            name = member.name
            path = pathlib.PurePosixPath(name)
            if (not name or path.is_absolute() or ".." in path.parts or "\\" in name
                    or name in seen):
                raise PrepareError("SOURCE_PATH_OR_DUPLICATE_INVALID")
            seen.add(name)
            target = destination.joinpath(*path.parts)
            if member.isdir():
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
                continue
            if not member.isfile() or member.issym() or member.islnk():
                raise PrepareError("SOURCE_NON_REGULAR_MEMBER")
            count += 1
            expanded += member.size
            if expanded > MAX_SOURCE_EXPANDED:
                raise PrepareError("SOURCE_EXPANDED_LIMIT")
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            stream = tar.extractfile(member)
            if stream is None:
                raise PrepareError("SOURCE_MEMBER_UNREADABLE")
            with stream, target.open("xb") as output:
                data = stream.read(MAX_SOURCE_EXPANDED + 1)
                if len(data) != member.size:
                    raise PrepareError("SOURCE_MEMBER_SIZE_MISMATCH")
                output.write(data)
            target.chmod(0o600)
    if count != expected_count:
        raise PrepareError("SOURCE_FILE_COUNT_MISMATCH")
    for required in ("src/mcp_document_oauth_entrypoint.py",
                     "tools/native_service_cycle.py",
                     "tests/test_native_service_real_gateway_e2e.py",
                     "config/mcp-oauth-runtime.example.json"):
        path = destination / required
        if path.is_symlink() or not path.is_file():
            raise PrepareError("SOURCE_REQUIRED_FILE_MISSING")


def _download_wheel(entry, wheelhouse):
    project = urllib.parse.quote(entry["name"].replace("_", "-"), safe="")
    version = urllib.parse.quote(entry["version"], safe="")
    metadata_url = "https://pypi.org/pypi/%s/%s/json" % (project, version)
    request = urllib.request.Request(metadata_url, headers={"User-Agent": "native-linux-smoke/1"})
    with urllib.request.urlopen(request, timeout=30) as response:
        metadata = json.loads(response.read(2_000_000).decode("utf-8"))
    matches = [item for item in metadata.get("urls", [])
               if item.get("filename") == entry["filename"]]
    if len(matches) != 1 or matches[0].get("digests", {}).get("sha256") != entry["sha256"]:
        raise PrepareError("PYPI_LOCK_METADATA_MISMATCH")
    url = urllib.parse.urlparse(matches[0].get("url", ""))
    if url.scheme != "https" or url.hostname != "files.pythonhosted.org":
        raise PrepareError("PYPI_WHEEL_HOST_INVALID")
    request = urllib.request.Request(matches[0]["url"], headers={"User-Agent": "native-linux-smoke/1"})
    with urllib.request.urlopen(request, timeout=60) as response:
        data = response.read(MAX_WHEEL_BYTES + 1)
    if len(data) > MAX_WHEEL_BYTES or _sha256(data) != entry["sha256"]:
        raise PrepareError("PYPI_WHEEL_SHA256_MISMATCH")
    target = wheelhouse / entry["filename"]
    target.write_bytes(data)
    target.chmod(0o600)


def _requirements(lock):
    wheels = lock.get("wheels")
    expected = {"cffi":"2.0.0", "cryptography":"50.0.2", "pycparser":"2.23",
                "pyspnego":"0.12.4", "smbprotocol":"1.12.0", "typing-extensions":"4.15.0"}
    normalized = [re.sub(r"[-_.]+", "-", row.get("name", "")).lower() for row in wheels]
    if (len(wheels) != 6 or set(normalized) != set(expected) or len(set(normalized)) != 6
            or any(not re.fullmatch(r"[0-9a-f]{64}", row.get("sha256", "")) for row in wheels)):
        raise PrepareError("NATIVE_WHEEL_LOCK_INVALID")
    for row, name in zip(wheels, normalized):
        if (row.get("version") != expected[name]
                or pathlib.PurePosixPath(row.get("filename", "")).name != row.get("filename")
                or not row.get("filename", "").endswith(".whl")):
            raise PrepareError("NATIVE_WHEEL_LOCK_INVALID")
    return "\n".join("%s==%s --hash=sha256:%s" %
                     (row["name"], row["version"], row["sha256"]) for row in wheels) + "\n"


def prepare(root, lock_path):
    if root.exists() or root.is_symlink() or not root.is_absolute():
        raise PrepareError("NATIVE_STAGE_PATH_INVALID")
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    if lock.get("runtime", {}).get("platform") != "linux/amd64":
        raise PrepareError("NATIVE_RUNTIME_LOCK_INVALID")
    requirements = _requirements(lock)
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    root.chmod(0o700)
    results = root / "results"
    source = root / "private-source"
    wheelhouse = root / "wheelhouse"
    results.mkdir(mode=0o700)
    wheelhouse.mkdir(mode=0o700)
    archive = _read_source_archive(lock)
    _extract_source(archive, source, int(lock["private_source"]["file_count"]))
    del archive
    for wheel in lock["wheels"]:
        _download_wheel(wheel, wheelhouse)
    lock_file = root / "requirements.lock"
    lock_file.write_text(requirements, encoding="ascii")
    lock_file.chmod(0o600)
    report = {"status":"PASS", "platform":lock["runtime"]["platform"],
              "python":lock["runtime"]["python"], "wheel_count":6,
              "source_file_count":int(lock["private_source"]["file_count"]),
              "source_archive_sha256":lock["private_source"]["archive_sha256"],
              "wheel_sha256":{row["filename"]:row["sha256"] for row in lock["wheels"]}}
    (results / "prepare-status.json").write_text(json.dumps(report, sort_keys=True)+"\n", encoding="ascii")
    (results / "prepare-status.json").chmod(0o600)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--lock", default="native-linux-smoke/native-linux-wheel-lock.json")
    args = parser.parse_args()
    try:
        prepare(pathlib.Path(args.root), pathlib.Path(args.lock))
        print("NATIVE_LINUX_INPUT_PREPARATION=PASS")
        return 0
    except Exception as exc:
        code = str(exc) if isinstance(exc, PrepareError) else "NATIVE_INPUT_PREPARATION_INTERNAL_ERROR"
        root = pathlib.Path(args.root)
        try:
            if root.is_symlink():
                raise OSError("stage root symlink")
            root.mkdir(mode=0o700, parents=True, exist_ok=True)
            results = root / "results"
            results.mkdir(mode=0o700, exist_ok=True)
            (results / "prepare-status.json").write_text(
                json.dumps({"status":"FAIL", "code":code}, sort_keys=True)+"\n", encoding="ascii")
        except OSError:
            pass
        print("NATIVE_LINUX_INPUT_PREPARATION=FAIL code=%s" % code)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
