#!/usr/bin/env bash
set -euo pipefail
umask 077
if [[ $# -ne 1 ]]; then
  printf '%s\n' 'CONTAINER_RUN=FAIL' 'ERROR=RUN_ROOT_ARGUMENT_REQUIRED' >&2
  exit 2
fi
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
if [[ ! -d "$1" || -L "$1" ]]; then
  printf '%s\n' 'CONTAINER_RUN=FAIL' 'ERROR=RUN_ROOT_INVALID' >&2
  exit 2
fi
RUN_ROOT="$(cd "$1" && pwd -P)"
IMAGE='quay.io/pypa/manylinux_2_31_armv7l@sha256:ecb0b7cd6db693d46a399226fd93cfd0d01d0dfbf9c65a8d5a0f6821767178fe'
RESULTS="$RUN_ROOT/results"
if ! python3 - "$RUN_ROOT" <<'PY'
import json
import os
import pathlib
import stat
import sys

root = pathlib.Path(sys.argv[1])
uid, gid = os.geteuid(), os.getegid()

def reject(code):
    print("CONTAINER_PREFLIGHT_ERROR=" + code, file=sys.stderr)
    raise SystemExit(2)

def private_directory(path):
    try:
        info = os.lstat(str(path))
    except OSError:
        return False
    return (stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
            and info.st_uid == uid and info.st_gid == gid
            and stat.S_IMODE(info.st_mode) == 0o700)

if not private_directory(root):
    reject("RUN_ROOT_IDENTITY_INVALID")
for name in ("private-source", "wheelhouse", "results"):
    if not private_directory(root / name):
        reject("STAGING_DIRECTORY_IDENTITY_INVALID")
lock = root / "requirements.lock"
try:
    lock_stat = os.lstat(str(lock))
except OSError:
    reject("REQUIREMENTS_LOCK_MISSING")
if (not stat.S_ISREG(lock_stat.st_mode) or stat.S_ISLNK(lock_stat.st_mode)
        or lock_stat.st_uid != uid or lock_stat.st_gid != gid
        or stat.S_IMODE(lock_stat.st_mode) & 0o022):
    reject("REQUIREMENTS_LOCK_IDENTITY_INVALID")
results = root / "results"
try:
    names = {entry.name for entry in results.iterdir()}
except OSError:
    reject("RESULTS_DIRECTORY_UNREADABLE")
if names != {"prepare-status.json"}:
    reject("RESULTS_INVENTORY_INVALID")
status_path = results / "prepare-status.json"
try:
    status_stat = os.lstat(str(status_path))
    status = json.loads(status_path.read_text(encoding="ascii"))
except (OSError, ValueError):
    reject("PREPARE_STATUS_INVALID")
if (not stat.S_ISREG(status_stat.st_mode) or stat.S_ISLNK(status_stat.st_mode)
        or status_stat.st_uid != uid or status_stat.st_gid != gid
        or stat.S_IMODE(status_stat.st_mode) & 0o022
        or status.get("status") != "PASS" or status.get("wheel_count") != 6
        or status.get("private_source_file_count") != 47):
    reject("PREPARE_STATUS_INVALID")
wheel_files = list((root / "wheelhouse").iterdir())
if len(wheel_files) != 6 or any(path.is_symlink() or not path.is_file() or path.suffix != ".whl"
                                or os.stat(str(path), follow_symlinks=False).st_uid != uid
                                or os.stat(str(path), follow_symlinks=False).st_gid != gid
                                or not (stat.S_IMODE(os.stat(str(path), follow_symlinks=False).st_mode) & 0o400)
                                for path in wheel_files):
    reject("WHEELHOUSE_INVENTORY_INVALID")
source_files = 0
for path in (root / "private-source").rglob("*"):
    info = os.lstat(str(path))
    if stat.S_ISLNK(info.st_mode) or info.st_uid != uid or info.st_gid != gid:
        reject("PRIVATE_SOURCE_IDENTITY_INVALID")
    if stat.S_ISREG(info.st_mode):
        source_files += 1
        if not (stat.S_IMODE(info.st_mode) & 0o400):
            reject("PRIVATE_SOURCE_UNREADABLE")
    elif not stat.S_ISDIR(info.st_mode):
        reject("PRIVATE_SOURCE_ENTRY_INVALID")
if source_files != 47:
    reject("PRIVATE_SOURCE_INVENTORY_INVALID")
PY
then
  printf '%s\n' 'CONTAINER_RUN=FAIL' 'ERROR=STAGING_PREFLIGHT_FAILED' >&2
  exit 2
fi
RUN_UID="$(id -u)"
RUN_GID="$(id -g)"
set +e
docker run --rm --platform linux/arm/v7 --network none --read-only \
  --user "$RUN_UID:$RUN_GID" \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --memory=4096m --memory-swap=4096m \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m \
  --tmpfs "/opt/mcp-armv7-site:rw,nosuid,nodev,exec,size=256m,uid=$RUN_UID,gid=$RUN_GID,mode=0700" \
  --tmpfs "/mcp-armv7-test-tmp:rw,nosuid,nodev,noexec,size=128m,uid=$RUN_UID,gid=$RUN_GID,mode=0700" \
  --volume "$RUN_ROOT/private-source:/private-source:ro" \
  --volume "$RUN_ROOT/wheelhouse:/wheelhouse:ro" \
  --volume "$RUN_ROOT/requirements.lock:/requirements.lock:ro" \
  --volume "$ROOT/armv7-smoke:/smoke:ro" \
  --volume "$RESULTS:/results:rw" --workdir /private-source \
  --env PYTHONDONTWRITEBYTECODE=1 --env TMPDIR=/mcp-armv7-test-tmp "$IMAGE" \
  /opt/python/cp39-cp39/bin/python3.9 -B /smoke/container_runner.py \
  --wheelhouse /wheelhouse --source /private-source --smoke /smoke --results /results --lock /requirements.lock \
  >"$RESULTS/container.log" 2>&1
RESULT=$?
set -e
if [[ ! -f "$RESULTS/runtime-report.json" ]]; then
  printf '%s\n' 'ARMV7_RUNTIME_REPORT=MISSING' 'CONTAINER_RUN=FAIL' > "$RESULTS/container-status.txt"
  printf '%s\n' 'CONTAINER_RUN=FAIL'
  exit 1
fi
printf '%s\n' 'ARMV7_RUNTIME_REPORT=CREATED'
printf 'CONTAINER_RUN_EXIT=%s\n' "$RESULT"
exit "$RESULT"
