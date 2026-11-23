#!/usr/bin/env bash
set -euo pipefail

ROOT=/work
PY=/opt/python/cp39-cp39/bin/python3.9
STAGE=preflight

capture_failure() {
  local status=$?
  trap - ERR
  set +e
  if [[ -z "${WHEEL:-}" ]]; then
    shopt -s nullglob
    local repaired_candidates=("$ROOT"/wheel-repaired/cffi-2.0.0-cp39-cp39-*.whl)
    if [[ ${#repaired_candidates[@]} -eq 1 && -f "${repaired_candidates[0]}" ]]; then
      WHEEL=${repaired_candidates[0]}
    fi
  fi
  if [[ -n "${WHEEL:-}" && -f "$WHEEL" ]]; then
    mkdir -p "$ROOT/output"
    printf 'stage=%s\nexit_code=%s\n' "$STAGE" "$status" > "$ROOT/output/failure-status.txt"
    cp "$WHEEL" "$ROOT/output/"
    (cd "$ROOT/output" && sha256sum "$(basename "$WHEEL")" > failure-wheel-SHA256SUMS)
    shopt -s nullglob
    local report_paths=("$ROOT/output"/*.txt)
    local report_names=()
    local report
    for report in "${report_paths[@]}"; do
      report_names+=("${report##*/}")
    done
    local archive="$ROOT/output/cffi-failure-diagnostics.tar.gz"
    tar -czf "$archive" -C "$ROOT/output" "$(basename "$WHEEL")" failure-wheel-SHA256SUMS "${report_names[@]}"
    if [[ $? -ne 0 ]]; then
      printf '%s\n' 'failure diagnostics archive: NOT CREATED'
    else
      local archive_bytes
      archive_bytes=$(wc -c < "$archive" | tr -d '[:space:]')
      if [[ "$archive_bytes" =~ ^[0-9]+$ ]] && (( archive_bytes <= 5242880 )); then
        local archive_sha
        archive_sha=$(sha256sum "$archive" | awk '{print $1}')
        printf 'CFFI_FAILURE_ARCHIVE_SHA256=%s\n' "$archive_sha"
        printf '%s\n' 'CFFI_FAILURE_ARCHIVE_BASE64_BEGIN'
        base64 < "$archive" | fold -w 76
        printf '%s\n' 'CFFI_FAILURE_ARCHIVE_BASE64_END'
      else
        printf '%s\n' 'failure diagnostics archive: NOT EMITTED (size limit exceeded or size unknown)'
      fi
    fi
  else
    printf 'failure diagnostics archive: NOT AVAILABLE (stage=%s)\n' "$STAGE"
  fi
  exit "$status"
}
trap capture_failure ERR
test -x "$PY"
test "$(uname -m)" = armv7l
"$PY" - <<'PY'
import platform, sys, sysconfig
assert sys.version_info[:2] == (3, 9)
assert platform.machine() == "armv7l"
assert sysconfig.get_config_var("SOABI").startswith("cpython-39-")
print("target interpreter/ABI: PASS")
PY

STAGE=toolchain-preflight
command -v gcc >/dev/null
command -v auditwheel >/dev/null
command -v readelf >/dev/null
command -v pkg-config >/dev/null
pkg-config --exists libffi
"$PY" "$ROOT/audit_repaired_wheel.py" --self-test

STAGE=build-tools-install
mkdir -p "$ROOT/wheel-raw" "$ROOT/wheel-repaired" "$ROOT/import-check"
"$PY" -m pip install --disable-pip-version-check --no-index \
  --find-links "$ROOT/input" --no-deps \
  setuptools==77.0.3 wheel==0.45.1 pycparser==2.23

STAGE=raw-wheel-build
export LDFLAGS="${LDFLAGS:-} -Wl,-z,max-page-size=32768"
"$PY" -m pip wheel --disable-pip-version-check --no-deps --no-build-isolation \
  --wheel-dir "$ROOT/wheel-raw" "$ROOT/input/cffi-2.0.0.tar.gz" \
  2>&1 | tee "$ROOT/output/build.log"
RAW_WHEEL=$(find "$ROOT/wheel-raw" -maxdepth 1 -type f -name 'cffi-2.0.0-*.whl' -print -quit)
test -n "$RAW_WHEEL"
STAGE=auditwheel-repair
auditwheel repair --plat manylinux_2_31_armv7l -w "$ROOT/wheel-repaired" "$RAW_WHEEL"
STAGE=wheel-selection
WHEEL=$("$PY" "$ROOT/audit_repaired_wheel.py" --select "$ROOT/wheel-repaired")
STAGE=post-repair-audit
auditwheel show "$WHEEL" > "$ROOT/output/auditwheel.txt"
"$PY" "$ROOT/audit_repaired_wheel.py" --audit "$WHEEL" \
  --extract-to "$ROOT/import-check/expanded" --report-dir "$ROOT/output"

STAGE=wheel-install
"$PY" -m pip install --disable-pip-version-check --no-index --no-deps \
  --target "$ROOT/import-check/site" "$WHEEL"
STAGE=emulated-import-smoke
PYTHONPATH="$ROOT/import-check/site" "$PY" - <<'PY'
import cffi, platform
assert platform.machine() == "armv7l"
assert cffi.__version__ == "2.0.0"
ffi = cffi.FFI()
assert ffi.sizeof("void *") == 4
print("cffi target import/smoke: PASS")
PY

cp "$WHEEL" "$ROOT/output/"
sha256sum "$ROOT/output"/*.whl > "$ROOT/output/SHA256SUMS"
dpkg-query -W -f='${Package}=${Version}\n' libffi-dev > "$ROOT/output/build-environment.txt" 2>/dev/null || true
gcc --version | head -n 1 >> "$ROOT/output/build-environment.txt"
auditwheel --version >> "$ROOT/output/build-environment.txt"
patchelf --version >> "$ROOT/output/build-environment.txt"
readelf --version | head -n 1 >> "$ROOT/output/build-environment.txt"
"$PY" -V >> "$ROOT/output/build-environment.txt"
printf 'manylinux image digest: %s\n' 'sha256:ecb0b7cd6db693d46a399226fd93cfd0d01d0dfbf9c65a8d5a0f6821767178fe' >> "$ROOT/output/build-environment.txt"

STAGE=success-archive
ARCHIVE="$ROOT/output/cffi-cp39-armv7-glibc231-audit.tar.gz"
shopt -s nullglob
REPORT_PATHS=("$ROOT/output"/*.txt)
REPORT_NAMES=()
for report in "${REPORT_PATHS[@]}"; do
  REPORT_NAMES+=("${report##*/}")
done
tar -czf "$ARCHIVE" -C "$ROOT/output" "$(basename "$WHEEL")" SHA256SUMS "${REPORT_NAMES[@]}"
ARCHIVE_BYTES=$(stat -c '%s' "$ARCHIVE")
test "$ARCHIVE_BYTES" -le 5242880
ARCHIVE_SHA=$(sha256sum "$ARCHIVE" | awk '{print $1}')
printf '%s  %s\n' "$ARCHIVE_SHA" "$ARCHIVE" > "$ARCHIVE.sha256"
printf 'CFFI_AUDIT_ARCHIVE_SHA256=%s\n' "$ARCHIVE_SHA"
printf '%s\n' 'CFFI_AUDIT_ARCHIVE_BASE64_BEGIN'
base64 "$ARCHIVE" | fold -w 76
printf '%s\n' 'CFFI_AUDIT_ARCHIVE_BASE64_END'
