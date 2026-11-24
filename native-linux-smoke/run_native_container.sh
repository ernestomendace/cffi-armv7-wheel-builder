#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT="${1:?private native test root required}"
ROOT="$(python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve())' "$ROOT")"
case "$ROOT" in "$RUNNER_TEMP"/native-linux) ;; *) echo NATIVE_STAGE_PATH_INVALID >&2; exit 2 ;; esac
[[ ! -L "$ROOT" && -d "$ROOT" ]] || { echo NATIVE_STAGE_MISSING >&2; exit 2; }
[[ "$(stat -c '%a' "$ROOT")" == 700 ]] || { echo NATIVE_STAGE_MODE_INVALID >&2; exit 2; }

IMAGE="python:3.9.25-slim-bookworm@sha256:03dee9ce00747bb5390e7b4ad00307b4dbc7790f7da77cc3581f93cfa99a6363"
LOCK_IMAGE="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["runtime"]["image"])' native-linux-smoke/native-linux-wheel-lock.json)"
[[ "$IMAGE" == "$LOCK_IMAGE" ]] || { echo NATIVE_IMAGE_LOCK_MISMATCH >&2; exit 2; }
UID_NUM="$(id -u)"
GID_NUM="$(id -g)"
[[ "$(uname -m)" == "x86_64" ]] || { echo NATIVE_RUNNER_ARCH_INVALID >&2; exit 2; }

docker run --rm --platform linux/amd64 --network none --user "$UID_NUM:$GID_NUM" \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true --pids-limit 128 \
  --memory 1g --memory-swap 1g \
  --mount "type=bind,src=$ROOT/private-source,dst=/private-source,readonly" \
  --mount "type=bind,src=$ROOT/wheelhouse,dst=/wheelhouse,readonly" \
  --mount "type=bind,src=$ROOT/requirements.lock,dst=/requirements.lock,readonly" \
  --mount "type=bind,src=$ROOT/results,dst=/results" \
  --mount "type=bind,src=$GITHUB_WORKSPACE/native-linux-smoke,dst=/harness,readonly" \
  --tmpfs "/mcp-native-site:rw,exec,nosuid,nodev,size=192m,mode=0700,uid=$UID_NUM,gid=$GID_NUM" \
  --tmpfs "/mcp-native-test-tmp:rw,noexec,nosuid,nodev,size=192m,mode=0700,uid=$UID_NUM,gid=$GID_NUM" \
  --tmpfs "/tmp:rw,noexec,nosuid,nodev,size=128m,mode=0700,uid=$UID_NUM,gid=$GID_NUM" \
  "$IMAGE" python /harness/native_linux_runner.py \
  --harness /harness --site /mcp-native-site --tmp /mcp-native-test-tmp \
  --source /private-source --wheelhouse /wheelhouse --requirements /requirements.lock
