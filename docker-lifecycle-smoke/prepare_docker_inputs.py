#!/usr/bin/env python3
"""Recover the private trial source and build a hash-locked x86 wheel bundle."""
import argparse
import base64
import hashlib
import io
import json
import os
import pathlib
import re
import shutil
import tarfile
import urllib.parse
import urllib.request

SOURCE_SHA256 = "31c34a3e5e84754f557fa6aa151a7b63dcb2870ebe79b2000cdff4fa0d9f2c4b"
SOURCE_BYTES = 119458
SOURCE_FILES = 24
PARTS = 4
MAX_PART = 40000
MAX_SOURCE = 120000  # four 40,000-character Base64 Actions secrets
MAX_EXPANDED = 600000
MAX_WHEEL = 20_000_000
X86_MANIFEST_SHA256 = "720fa4432638f69c1876d9ccb6a89b0dff6f29b530113a0402563cfc7c964187"


class InputError(Exception):
    pass


def sha(data):
    return hashlib.sha256(data).hexdigest()


def _source_bytes(lock):
    parts = []
    for index in range(1, PARTS + 1):
        key = "SOURCE_PART_%02d" % index
        value = os.environ.pop(key, "")
        if not value or len(value) > MAX_PART or not re.fullmatch(r"[A-Za-z0-9+/=]+", value):
            raise InputError("SOURCE_SEGMENT_INVALID")
        parts.append(value)
    try:
        data = base64.b64decode("".join(parts), validate=True)
    except (ValueError, base64.binascii.Error):
        raise InputError("SOURCE_BASE64_INVALID")
    finally:
        parts.clear()
    source_spec = lock.get("private_source", {})
    if (len(data) != source_spec.get("archive_bytes") or len(data) > MAX_SOURCE
            or sha(data) != source_spec.get("archive_sha256")):
        raise InputError("SOURCE_ARCHIVE_LOCK_MISMATCH")
    return data


def _extract(data, root, expected_files):
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    count = total = 0
    seen = set()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        members = archive.getmembers()
        if len(members) > 80:
            raise InputError("SOURCE_MEMBER_LIMIT")
        for member in members:
            rel = pathlib.PurePosixPath(member.name)
            if (not member.isfile() or member.issym() or member.islnk()
                    or rel.is_absolute() or ".." in rel.parts or "\\" in member.name
                    or member.name in seen or not rel.parts or rel.parts[0] != "application"):
                raise InputError("SOURCE_MEMBER_UNSAFE")
            seen.add(member.name)
            count += 1
            total += member.size
            if total > MAX_EXPANDED:
                raise InputError("SOURCE_EXPANDED_LIMIT")
            target = root.joinpath(*rel.parts)
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            stream = archive.extractfile(member)
            if stream is None:
                raise InputError("SOURCE_MEMBER_READ_FAILED")
            with stream, target.open("xb") as output:
                payload = stream.read(MAX_EXPANDED + 1)
                if len(payload) != member.size:
                    raise InputError("SOURCE_MEMBER_SIZE_MISMATCH")
                output.write(payload)
            target.chmod(0o444 if rel.as_posix() ==
                         "application/tools/docker_trial_volume_sentinel" else 0o600)
    if count != expected_files:
        raise InputError("SOURCE_FILE_COUNT_MISMATCH")
    for required in ("tools/Dockerfile.ex4100-trial",
        "tools/docker_trial_container_entrypoint.py", "tools/document_nas_docker_lease_port.py",
        "tools/document_nas_local_service_lease_v2.py", "src/mcp_document_oauth_entrypoint.py",
        "src/mcp_synthetic_tunnel_probe.py", "config/mcp-oauth-runtime.example.json"):
        if not (root / "application" / required).is_file():
            raise InputError("SOURCE_REQUIRED_FILE_MISSING")
    return root / "application"


def _download_wheel(row, destination):
    project = urllib.parse.quote(row["name"].replace("_", "-"), safe="")
    version = urllib.parse.quote(row["version"], safe="")
    url = "https://pypi.org/pypi/{}/{}/json".format(project, version)
    with urllib.request.urlopen(urllib.request.Request(url,
            headers={"User-Agent": "docker-lifecycle-smoke/1"}), timeout=30) as response:
        meta = json.loads(response.read(2_000_000).decode("utf-8"))
    matches = [item for item in meta.get("urls", []) if item.get("filename") == row["filename"]]
    if len(matches) != 1 or matches[0].get("digests", {}).get("sha256") != row["sha256"]:
        raise InputError("PYPI_LOCK_METADATA_MISMATCH")
    parsed = urllib.parse.urlparse(matches[0].get("url", ""))
    if parsed.scheme != "https" or parsed.hostname != "files.pythonhosted.org":
        raise InputError("PYPI_HOST_INVALID")
    with urllib.request.urlopen(urllib.request.Request(matches[0]["url"],
            headers={"User-Agent": "docker-lifecycle-smoke/1"}), timeout=60) as response:
        data = response.read(MAX_WHEEL + 1)
    if len(data) > MAX_WHEEL or sha(data) != row["sha256"]:
        raise InputError("WHEEL_HASH_MISMATCH")
    target = destination / row["filename"]
    target.write_bytes(data)
    target.chmod(0o600)


def _wheel_rows(lock):
    expected = {"cffi":"2.0.0", "cryptography":"50.0.2", "pycparser":"2.23",
        "pyspnego":"0.12.4", "smbprotocol":"1.12.0", "typing-extensions":"4.15.0"}
    rows = lock.get("wheels")
    if not isinstance(rows, list) or len(rows) != 6:
        raise InputError("WHEEL_LOCK_INVALID")
    normalized = [re.sub(r"[-_.]+", "-", row.get("name", "")).lower() for row in rows]
    if set(normalized) != set(expected) or len(set(normalized)) != 6:
        raise InputError("WHEEL_LOCK_INVENTORY_INVALID")
    for row, name in zip(rows, normalized):
        if (row.get("version") != expected[name] or not row.get("filename", "").endswith(".whl")
                or pathlib.PurePosixPath(row["filename"]).name != row["filename"]
                or not re.fullmatch(r"[0-9a-f]{64}", row.get("sha256", ""))):
            raise InputError("WHEEL_LOCK_ENTRY_INVALID")
    return rows


def _make_dependency_bundle(root, lock_path, profile_path):
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    if lock.get("runtime", {}).get("platform") != "linux/amd64":
        raise InputError("X86_RUNTIME_LOCK_INVALID")
    rows = _wheel_rows(lock)
    profile = profile_path.read_bytes()
    if sha(profile) != X86_MANIFEST_SHA256:
        raise InputError("X86_PROFILE_MANIFEST_INVALID")
    profile_value = json.loads(profile.decode("ascii"))
    if len(profile_value.get("python_runtime_packages", [])) != 6:
        raise InputError("X86_PROFILE_INVENTORY_INVALID")
    wheelhouse = root / "dependency-bundle" / "docker-trial-x86" / "wheelhouse"
    wheelhouse.mkdir(mode=0o700, parents=True)
    for row in rows:
        _download_wheel(row, wheelhouse)
    base = wheelhouse.parent
    (base / "manifest.json").write_bytes(profile)
    (base / "requirements.lock").write_text("".join(
        "{}=={} --hash=sha256:{}\n".format(row["name"], row["version"], row["sha256"])
        for row in rows), encoding="ascii")
    archive_path = root / "dependency-bundle.tar.gz"
    with tarfile.open(archive_path, "w:gz", compresslevel=6) as archive:
        for path in sorted(base.rglob("*")):
            info = tarfile.TarInfo(path.relative_to(root / "dependency-bundle").as_posix())
            st = path.lstat()
            info.type = tarfile.DIRTYPE if path.is_dir() else tarfile.REGTYPE
            info.mode = 0o700 if path.is_dir() else 0o600
            info.size = 0 if path.is_dir() else st.st_size
            info.uid = info.gid = info.mtime = 0
            with path.open("rb") if path.is_file() else __import__("contextlib").nullcontext(None) as stream:
                archive.addfile(info, stream)
    data = archive_path.read_bytes()
    return archive_path, sha(data), len(rows)


def prepare(root, docker_lock_path, wheel_lock_path, profile_path):
    if root.exists() or root.is_symlink() or not root.is_absolute():
        raise InputError("STAGING_PATH_INVALID")
    root.mkdir(mode=0o700, parents=False)
    os.chmod(root, 0o700)
    lock = json.loads(docker_lock_path.read_text(encoding="utf-8"))
    source_spec = lock.get("private_source", {})
    if (source_spec.get("file_count") != SOURCE_FILES
            or source_spec.get("archive_sha256") != SOURCE_SHA256
            or source_spec.get("archive_bytes") != SOURCE_BYTES
            or source_spec.get("segments") != PARTS
            or lock.get("base_image_digest") != "sha256:03dee9ce00747bb5390e7b4ad00307b4dbc7790f7da77cc3581f93cfa99a6363"):
        raise InputError("DOCKER_TRIAL_LOCK_INVALID")
    data = _source_bytes(lock)
    source_archive = root / "application-source.tar.gz"
    source_archive.write_bytes(data)
    source_archive.chmod(0o600)
    source = _extract(data, root / "source", SOURCE_FILES)
    source_sha = sha(data)
    del data
    dep_path, dep_sha, _ = _make_dependency_bundle(root, wheel_lock_path, profile_path)
    status = {"status":"PASS", "source_sha256":source_sha,
        "source_file_count":SOURCE_FILES, "dependency_sha256":dep_sha,
        "wheel_count":6, "profile":"x86_64-validation"}
    results = root / "results"
    results.mkdir(mode=0o700)
    (results / "prepare.json").write_text(json.dumps(status, sort_keys=True)+"\n", encoding="ascii")
    (results / "prepare.json").chmod(0o600)
    return source, dep_path, status


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--lock", default="native-linux-smoke/native-linux-wheel-lock.json")
    parser.add_argument("--profile", default="docker-lifecycle-smoke/x86-profile.json")
    parser.add_argument("--docker-lock", default="docker-lifecycle-smoke/docker-lifecycle-lock.json")
    args = parser.parse_args()
    try:
        lock = json.loads(pathlib.Path(args.docker_lock).read_text(encoding="utf-8"))
        if lock.get("x86_wheel_lock") != args.lock:
            raise InputError("DOCKER_TRIAL_LOCK_INVALID")
        source, dep, report = prepare(pathlib.Path(args.root), pathlib.Path(args.docker_lock),
            pathlib.Path(args.lock), pathlib.Path(args.profile))
        print("DOCKER_TRIAL_INPUTS=PASS files={} profile={} source_sha256={} dependency_sha256={}".format(
            SOURCE_FILES, report["profile"], report["source_sha256"], report["dependency_sha256"]))
        return 0
    except Exception as exc:
        code = str(exc) if re.fullmatch(r"[A-Z0-9_]+", str(exc)) else "INPUT_PREPARATION_FAILED"
        print("DOCKER_TRIAL_INPUTS=FAIL code=" + code)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
