#!/usr/bin/env python3
"""Verify actual image-layer permissions for the non-root trial identity."""
import argparse
import io
import json
import os
import pathlib
import re
import stat
import subprocess
import tarfile
import tempfile

UID = 61001
GID = 61001
MAX_IMAGE_BYTES = 512 * 1024 * 1024
MAX_CONFIG_BYTES = 1024 * 1024
MAX_SOURCE_BYTES = 512 * 1024
DIRECTORIES = (
    "opt", "opt/codex-mcp", "opt/codex-mcp/bin",
    "opt/codex-mcp/lib", "opt/codex-mcp/lib/tools",
)
SOURCES = {
    "entrypoint": "opt/codex-mcp/bin/container-entrypoint.py",
    "lease_port": "opt/codex-mcp/lib/tools/document_nas_docker_lease_port.py",
    "lease_store": "opt/codex-mcp/lib/tools/document_nas_local_service_lease_v2.py",
}


class ImagePermissionError(Exception):
    pass


def _safe_member_name(name):
    if not isinstance(name, str) or "\\" in name or name.startswith("/"):
        raise ImagePermissionError("IMAGE_ARCHIVE_MEMBER_UNSAFE")
    while name.startswith("./"):
        name = name[2:]
    parts = pathlib.PurePosixPath(name).parts
    if any(part in ("", ".", "..") for part in parts):
        raise ImagePermissionError("IMAGE_ARCHIVE_MEMBER_UNSAFE")
    return "/".join(parts)


def _read_small(stream, limit, code):
    payload = stream.read(limit + 1)
    if len(payload) > limit:
        raise ImagePermissionError(code)
    return payload


def inspect_image_archive(archive_file):
    """Resolve selected paths through Docker-save layers without extracting them."""
    tracked = set(DIRECTORIES) | set(SOURCES.values())
    state = {}
    try:
        outer = tarfile.open(fileobj=archive_file, mode="r:")
    except (tarfile.TarError, OSError):
        raise ImagePermissionError("IMAGE_ARCHIVE_INVALID")
    with outer:
        manifests = [member for member in outer.getmembers()
                     if member.name == "manifest.json" and member.isfile()]
        if len(manifests) != 1:
            raise ImagePermissionError("IMAGE_MANIFEST_INVALID")
        stream = outer.extractfile(manifests[0])
        if stream is None:
            raise ImagePermissionError("IMAGE_MANIFEST_UNREADABLE")
        try:
            manifest = json.loads(_read_small(stream, MAX_CONFIG_BYTES,
                                               "IMAGE_MANIFEST_TOO_LARGE").decode("utf-8"))
        except (UnicodeError, ValueError):
            raise ImagePermissionError("IMAGE_MANIFEST_INVALID")
        if (not isinstance(manifest, list) or len(manifest) != 1
                or not isinstance(manifest[0], dict)
                or not isinstance(manifest[0].get("Layers"), list)
                or not manifest[0]["Layers"]):
            raise ImagePermissionError("IMAGE_MANIFEST_INVENTORY_INVALID")
        layer_names = manifest[0]["Layers"]
        if len(layer_names) > 128 or any(not isinstance(n, str) for n in layer_names):
            raise ImagePermissionError("IMAGE_LAYER_INVENTORY_INVALID")
        outer_names = {m.name: m for m in outer.getmembers()}
        for layer_name in layer_names:
            layer_member = outer_names.get(layer_name)
            if layer_member is None or not layer_member.isfile():
                raise ImagePermissionError("IMAGE_LAYER_MISSING")
            layer_stream = outer.extractfile(layer_member)
            if layer_stream is None:
                raise ImagePermissionError("IMAGE_LAYER_UNREADABLE")
            try:
                layer = tarfile.open(fileobj=layer_stream, mode="r|*")
                with layer:
                    for member in layer:
                        raw_name = member.name.rstrip("/")
                        if raw_name.endswith("/.wh..wh..opq"):
                            parent = raw_name[:-len("/.wh..wh..opq")]
                            for key in tuple(state):
                                if key.startswith(parent + "/"):
                                    del state[key]
                            continue
                        base = raw_name.rsplit("/", 1)[-1]
                        if base.startswith(".wh."):
                            parent = raw_name.rsplit("/", 1)[0] if "/" in raw_name else ""
                            victim = (parent + "/" if parent else "") + base[4:]
                            for key in tuple(state):
                                if key == victim or key.startswith(victim + "/"):
                                    del state[key]
                            continue
                        try:
                            name = _safe_member_name(raw_name)
                        except ImagePermissionError:
                            # Unrelated image paths are not interpreted, but malformed
                            # tracked-path parents are rejected below if absent.
                            continue
                        if name not in tracked:
                            continue
                        if member.isdir():
                            state[name] = {"kind": "dir", "uid": member.uid,
                                "gid": member.gid, "mode": stat.S_IMODE(member.mode)}
                        elif member.isfile() and name in SOURCES.values():
                            content = layer.extractfile(member)
                            if content is None:
                                raise ImagePermissionError("IMAGE_SOURCE_UNREADABLE")
                            data = _read_small(content, MAX_SOURCE_BYTES,
                                               "IMAGE_SOURCE_TOO_LARGE")
                            if len(data) != member.size:
                                raise ImagePermissionError("IMAGE_SOURCE_SIZE_MISMATCH")
                            state[name] = {"kind": "file", "uid": member.uid,
                                "gid": member.gid, "mode": stat.S_IMODE(member.mode),
                                "data": data}
                        else:
                            state[name] = {"kind": "other", "uid": member.uid,
                                "gid": member.gid, "mode": stat.S_IMODE(member.mode)}
            except (tarfile.TarError, OSError):
                raise ImagePermissionError("IMAGE_LAYER_INVALID")

    for name in DIRECTORIES:
        item = state.get(name)
        if item is None or item["kind"] != "dir":
            raise ImagePermissionError("IMAGE_DIRECTORY_MISSING")
        shift = 6 if UID == item["uid"] else 3 if GID == item["gid"] else 0
        if not (item["mode"] & (0o1 << shift)):
            raise ImagePermissionError("IMAGE_DIRECTORY_NOT_TRAVERSABLE")
    for role, name in SOURCES.items():
        item = state.get(name)
        if item is None or item["kind"] != "file" or item["uid"] != 0 or item["gid"] != 0:
            raise ImagePermissionError("IMAGE_RUNTIME_FILE_IDENTITY_INVALID")
        shift = 6 if UID == item["uid"] else 3 if GID == item["gid"] else 0
        if not (item["mode"] & (0o4 << shift)):
            raise ImagePermissionError("IMAGE_RUNTIME_FILE_NOT_READABLE")
        try:
            compile(item["data"].decode("utf-8"), role, "exec")
        except (UnicodeError, SyntaxError):
            raise ImagePermissionError("IMAGE_RUNTIME_MODULE_INVALID")
    return {"status": "PASS", "uid": UID, "gid": GID,
        "directories": len(DIRECTORIES), "python_files": len(SOURCES),
        "cas_modules": 2}


def verify_image(iid_path):
    path = pathlib.Path(iid_path)
    if path.is_symlink() or not path.is_file():
        raise ImagePermissionError("IMAGE_ID_FILE_INVALID")
    image_id = path.read_text(encoding="ascii").strip()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise ImagePermissionError("IMAGE_ID_INVALID")
    with tempfile.TemporaryDirectory(prefix="docker-image-permission-check-") as directory:
        output = pathlib.Path(directory) / "image.tar"
        result = subprocess.run(["docker", "image", "save", "--output", str(output), image_id],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=120, check=False)
        if result.returncode != 0 or not output.is_file():
            raise ImagePermissionError("IMAGE_SAVE_FAILED")
        if output.stat().st_size > MAX_IMAGE_BYTES:
            raise ImagePermissionError("IMAGE_SAVE_SIZE_LIMIT")
        with output.open("rb") as stream:
            return inspect_image_archive(stream)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iid-file", required=True)
    args = parser.parse_args()
    try:
        result = verify_image(args.iid_file)
    except (ImagePermissionError, OSError, subprocess.TimeoutExpired) as exc:
        code = str(exc) if isinstance(exc, ImagePermissionError) else "IMAGE_PERMISSION_PREFLIGHT_FAILED"
        print("IMAGE_PERMISSION_PREFLIGHT=FAIL code=" + code)
        return 1
    print("IMAGE_PERMISSION_PREFLIGHT=PASS uid={} gid={} directories={} python_files={} cas_modules={}".format(
        result["uid"], result["gid"], result["directories"], result["python_files"], result["cas_modules"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
