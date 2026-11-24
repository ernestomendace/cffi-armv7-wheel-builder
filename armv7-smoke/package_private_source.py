#!/usr/bin/env python3
"""Create deterministic, bounded secret chunks from the project's curated smoke staging."""
import argparse
import base64
import gzip
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tarfile
import tempfile

PART_CHARS = 40000
PART_COUNT = 8
MAX_SOURCE_FILES = 100
MAX_SOURCE_BYTES = 2_000_000

def deterministic_archive(staged, archive_path):
    staged = pathlib.Path(staged).resolve(strict=True)
    entries = sorted(staged.rglob("*"), key=lambda p: p.relative_to(staged).as_posix())
    files = [p for p in entries if p.is_file() and not p.is_symlink()]
    if any(p.is_symlink() for p in entries) or any(not (p.is_file() or p.is_dir()) for p in entries):
        raise ValueError("PRIVATE_SOURCE_ENTRY_TYPE_INVALID")
    if len(files) != 47 or len(files) > MAX_SOURCE_FILES:
        raise ValueError("PRIVATE_SOURCE_FILE_COUNT_INVALID")
    total = sum(p.stat().st_size for p in files)
    if total > MAX_SOURCE_BYTES:
        raise ValueError("PRIVATE_SOURCE_SIZE_LIMIT")
    with archive_path.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as gz:
            with tarfile.open(fileobj=gz, mode="w", format=tarfile.USTAR_FORMAT) as tar:
                for path in entries:
                    relative = path.relative_to(staged).as_posix()
                    info = tarfile.TarInfo(relative + ("/" if path.is_dir() else ""))
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    info.mtime = 0
                    if path.is_dir():
                        info.type = tarfile.DIRTYPE
                        info.mode = 0o755
                        info.size = 0
                        tar.addfile(info)
                    else:
                        info.type = tarfile.REGTYPE
                        info.mode = 0o644
                        info.size = path.stat().st_size
                        with path.open("rb") as stream:
                            tar.addfile(info, stream)
    return files

def prepare(project_root, stager, output_dir):
    project = pathlib.Path(project_root).resolve(strict=True)
    stager = pathlib.Path(stager).resolve(strict=True)
    output = pathlib.Path(output_dir)
    if (not project.is_dir() or not stager.is_file() or not output.is_absolute()
            or output.parent.is_symlink() or not output.parent.is_dir()
            or output.exists() or output.is_symlink()):
        raise ValueError("PRIVATE_SOURCE_PATH_INVALID")
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.chmod(str(output), 0o700)
    try:
        with tempfile.TemporaryDirectory(prefix="mcp-armv7-private-source-") as temp:
            temp = pathlib.Path(temp)
            staged = temp / "staged"
            staged.mkdir(mode=0o700)
            result = subprocess.run([os.environ.get("PYTHON", "python3"), str(stager),
                                     "--source", str(project), "--destination", str(staged)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=60)
            if result.returncode:
                raise ValueError("PRIVATE_SOURCE_STAGING_FAILED")
            archive = temp / "source.tar.gz"
            files = deterministic_archive(staged, archive)
            data = archive.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            encoded = base64.b64encode(data).decode("ascii")
            if len(encoded) > PART_CHARS * PART_COUNT:
                raise ValueError("PRIVATE_SOURCE_SECRET_CHUNK_LIMIT")
            if len(encoded) <= PART_CHARS * (PART_COUNT - 1):
                raise ValueError("PRIVATE_SOURCE_SECRET_PART_COUNT_CHANGED")
            for number in range(PART_COUNT):
                part = encoded[number * PART_CHARS:(number + 1) * PART_CHARS]
                if not part:
                    raise ValueError("PRIVATE_SOURCE_SECRET_PART_EMPTY")
                path = output / ("MCP_ARMV7_SOURCE_B64_%02d.txt" % (number + 1))
                path.write_text(part, encoding="ascii")
                path.chmod(0o600)
            (output / "private-source-summary.json").write_text(
                json.dumps({"archive_sha256": digest, "archive_bytes": len(data),
                            "base64_characters": len(encoded), "part_count": PART_COUNT,
                            "file_count": len(files)}, sort_keys=True) + "\n", encoding="ascii")
            (output / "private-source-summary.json").chmod(0o600)
            return digest, len(data), len(files)
    except Exception:
        shutil.rmtree(str(output), ignore_errors=True)
        raise

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", required=True)
    parser.add_argument("--stager", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    try:
        digest, size, count = prepare(args.project_root, args.stager, args.output_dir)
    except Exception as exc:
        code = str(exc) if str(exc).isupper() and len(str(exc)) < 80 else "PRIVATE_SOURCE_PACKAGING_FAILED"
        print("PRIVATE_SOURCE_PACKAGING=FAIL code=%s" % code)
        raise SystemExit(1)
    print("PRIVATE_SOURCE_PACKAGING=PASS files=%d archive_bytes=%d sha256=%s parts=%d" %
          (count, size, digest, PART_COUNT))
