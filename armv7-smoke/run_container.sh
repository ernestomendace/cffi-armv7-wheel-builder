#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
RUN_ROOT="$(realpath -e "$1")"
IMAGE='quay.io/pypa/manylinux_2_31_armv7l@sha256:ecb0b7cd6db693d46a399226fd93cfd0d01d0dfbf9c65a8d5a0f6821767178fe'
RESULTS="$RUN_ROOT/results"
mkdir -p -m 700 "$RESULTS"
test -d "$RUN_ROOT/private-source" && test -d "$RUN_ROOT/wheelhouse"
test "$(find "$RUN_ROOT/wheelhouse" -maxdepth 1 -type f -name '*.whl' | wc -l | tr -d ' ')" = 6
set +e
docker run --rm --platform linux/arm/v7 --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --memory=4096m --memory-swap=4096m \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m \
  --volume "$RUN_ROOT/private-source:/private-source:ro" \
  --volume "$RUN_ROOT/wheelhouse:/wheelhouse:ro" \
  --volume "$ROOT/armv7-smoke:/smoke:ro" \
  --volume "$RESULTS:/results:rw" --workdir /private-source \
  --env PYTHONDONTWRITEBYTECODE=1 "$IMAGE" \
  /opt/python/cp39-cp39/bin/python3.9 -B /smoke/container_runner.py \
  --wheelhouse /wheelhouse --source /private-source --smoke /smoke --results /results \
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
