#!/usr/bin/env python3
"""Recover the encrypted report from a public Actions log without printing it."""
import argparse
import base64
import pathlib
import re
import subprocess

REPO = "ernestomendace/cffi-armv7-wheel-builder"
BEGIN = "MCP_ARMV7_ENCRYPTED_DIAGNOSTICS_BEGIN"
END = "MCP_ARMV7_ENCRYPTED_DIAGNOSTICS_END"
MAX_ENCODED = 12_000_000

def extract(log_text):
    if log_text.count(BEGIN) != 1 or log_text.count(END) != 1:
        raise ValueError("ENCRYPTED_REPORT_MARKERS_INVALID")
    segment = log_text.split(BEGIN, 1)[1].split(END, 1)[0]
    chunks = []
    for line in segment.splitlines():
        value = line.split("Z ", 1)[1] if "Z " in line else line.strip()
        value = value.strip()
        if value:
            if not re.fullmatch(r"[A-Za-z0-9+/=]+", value):
                raise ValueError("ENCRYPTED_REPORT_LINE_INVALID")
            chunks.append(value)
    encoded = "".join(chunks)
    if len(encoded) > MAX_ENCODED:
        raise ValueError("ENCRYPTED_REPORT_SIZE_LIMIT")
    return base64.b64decode(encoded, validate=True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("run_id", type=int)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = pathlib.Path(args.output)
    if output.exists() or output.is_symlink():
        raise SystemExit("OUTPUT_ALREADY_EXISTS")
    result = subprocess.run(["gh", "run", "view", str(args.run_id), "--repo", REPO, "--log"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=180)
    if result.returncode:
        raise SystemExit("ACTIONS_LOG_UNAVAILABLE")
    try:
        data = extract(result.stdout.decode("utf-8", "replace"))
    except Exception as exc:
        code = str(exc) if str(exc).isupper() and len(str(exc)) < 80 else "ENCRYPTED_REPORT_INVALID"
        raise SystemExit(code)
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    output.write_bytes(data)
    output.chmod(0o600)
    print("ENCRYPTED_REPORT_RECOVERED bytes=%d" % len(data))
