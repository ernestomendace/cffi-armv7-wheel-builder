#!/usr/bin/env python3
"""Strict post-auditwheel selector and ELF/RECORD audit for CFFI ARMv7."""
import argparse
import base64
import csv
import hashlib
import io
import re
import subprocess
import sys
import zipfile
from email.parser import Parser
from pathlib import Path

TARGET = "manylinux_2_31_armv7l"
ALLOWED_TAGS = {"manylinux2014_armv7l", "manylinux_2_17_armv7l", TARGET}


class AuditError(Exception):
    pass


def wheel_fields(path):
    parts = Path(path).name[:-4].split("-") if str(path).endswith(".whl") else []
    if len(parts) != 5:
        raise AuditError("wheel filename must have exactly five fields and no build tag")
    distribution, version, python_tag, abi_tag, platform_tag = parts
    if distribution.lower().replace("_", "-").replace(".", "-") != "cffi":
        raise AuditError("wrong wheel distribution")
    if (version, python_tag, abi_tag) != ("2.0.0", "cp39", "cp39"):
        raise AuditError("wrong CFFI version or CPython/ABI tag")
    tags = platform_tag.split(".")
    if not tags or len(tags) != len(set(tags)):
        raise AuditError("empty or duplicate platform tag")
    if TARGET not in tags:
        raise AuditError("required manylinux_2_31_armv7l tag missing")
    if any(tag not in ALLOWED_TAGS for tag in tags):
        raise AuditError("incompatible or unapproved platform tag")
    return distribution, version, python_tag, abi_tag, tuple(tags)


def select_wheel(directory):
    root = Path(directory)
    if not root.is_dir() or root.is_symlink():
        raise AuditError("wheel directory is absent or unsafe")
    candidates = []
    for path in sorted(root.iterdir()):
        if path.suffix != ".whl":
            continue
        fields = path.name[:-4].split("-")
        if fields and fields[0].lower().replace("_", "-").replace(".", "-") == "cffi":
            candidates.append(path)
    if len(candidates) != 1:
        raise AuditError("expected exactly one CFFI wheel candidate, found %d" % len(candidates))
    wheel_fields(candidates[0])
    if not candidates[0].is_file() or candidates[0].is_symlink():
        raise AuditError("wheel candidate is not a regular file")
    return candidates[0]


def verify_record(zf, names, record_name):
    rows = list(csv.reader(io.StringIO(zf.read(record_name).decode("utf-8"))))
    entries = {}
    for row in rows:
        if len(row) != 3 or row[0] in entries:
            raise AuditError("malformed or duplicate RECORD row")
        entries[row[0]] = (row[1], row[2])
    if set(entries) != set(names):
        raise AuditError("RECORD inventory does not match wheel contents")
    for name, (encoded, size) in entries.items():
        if name == record_name:
            if encoded or size:
                raise AuditError("RECORD must not hash itself")
            continue
        data = zf.read(name)
        if not encoded.startswith("sha256="):
            raise AuditError("missing SHA-256 RECORD digest")
        actual = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")
        if actual != encoded[7:] or int(size) != len(data):
            raise AuditError("RECORD digest or size mismatch: %s" % name)


def safe_extract(zf, destination):
    root = Path(destination).resolve()
    root.mkdir(parents=True, exist_ok=False)
    names = zf.namelist()
    if len(names) != len(set(names)):
        raise AuditError("duplicate ZIP entry")
    for name in names:
        p = Path(name)
        if p.is_absolute() or ".." in p.parts or "\\" in name:
            raise AuditError("unsafe wheel path")
        mode = zf.getinfo(name).external_attr >> 16
        if mode and (mode & 0o170000) == 0o120000:
            raise AuditError("wheel symlink entries are not accepted")
        target = (root / p).resolve()
        if target != root and root not in target.parents:
            raise AuditError("wheel path escapes extraction root")
    zf.extractall(str(root))


def readelf(path, *args):
    result = subprocess.run(["readelf"] + list(args) + [str(path)], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, universal_newlines=True)
    if result.returncode:
        raise AuditError("readelf failed for ELF member")
    return result.stdout


def audit_elf(path, report_dir, prefix):
    header = readelf(path, "-h")
    if not re.search(r"^\s*Class:\s+ELF32\s*$", header, re.M) or not re.search(r"^\s*Machine:\s+ARM\s*$", header, re.M):
        raise AuditError("ELF is not 32-bit ARM")
    flags = re.search(r"Flags:\s*(0x[0-9a-fA-F]+).*hard-float ABI", header)
    if not flags:
        raise AuditError("ELF hard-float ABI flag absent")
    program = readelf(path, "-lW")
    loads = []
    for line in program.splitlines():
        fields = line.split()
        if fields and fields[0] == "LOAD":
            if len(fields) < 8:
                raise AuditError("unrecognized PT_LOAD record")
            off, va, align = int(fields[1], 16), int(fields[2], 16), int(fields[-1], 16)
            loads.append((off, va, align))
    if not loads or any(align < 32768 or (va - off) % 32768 for off, va, align in loads):
        raise AuditError("PT_LOAD violates the 32 KiB target alignment")
    versions = readelf(path, "--version-info")
    glibc = [tuple(int(x) for x in m.split(".")) for m in re.findall(r"\bGLIBC_([0-9]+(?:\.[0-9]+)+)\b", versions)]
    if any(v > (2, 31) for v in glibc):
        raise AuditError("ELF requires GLIBC newer than 2.31")
    dynamic = readelf(path, "-d")
    soname_match = re.search(r"\(SONAME\).*\[(.*?)\]", dynamic)
    needed = re.findall(r"\(NEEDED\).*\[(.*?)\]", dynamic)
    digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    details = "file=%s\nsha256=%s\nsoname=%s\nneeded=%s\nmax_glibc=%s\npt_load=%s\n" % (
        Path(path).name, digest, soname_match.group(1) if soname_match else "(none)",
        ",".join(needed), ".".join(map(str, max(glibc))) if glibc else "none", loads)
    Path(report_dir, prefix + "-header.txt").write_text(header, encoding="utf-8")
    Path(report_dir, prefix + "-versions.txt").write_text(versions, encoding="utf-8")
    Path(report_dir, prefix + "-program-headers.txt").write_text(program, encoding="utf-8")
    Path(report_dir, prefix + "-dynamic.txt").write_text(dynamic, encoding="utf-8")
    return needed, soname_match.group(1) if soname_match else None, details


def audit_wheel(wheel, extract_to, report_dir):
    wheel = Path(wheel)
    wheel_fields(wheel)
    reports = Path(report_dir)
    reports.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(str(wheel)) as zf:
        names = zf.namelist()
        if any(Path(n).is_absolute() or ".." in Path(n).parts for n in names):
            raise AuditError("unsafe ZIP member")
        dist_infos = sorted({n.split("/", 1)[0] for n in names if ".dist-info/" in n})
        if len(dist_infos) != 1:
            raise AuditError("wheel must contain exactly one dist-info directory")
        dist = dist_infos[0]
        metadata = Parser().parsestr(zf.read(dist + "/METADATA").decode("utf-8"))
        if metadata.get("Name", "").lower() != "cffi" or metadata.get("Version") != "2.0.0":
            raise AuditError("wheel METADATA identity mismatch")
        internal_tags = set()
        for line in zf.read(dist + "/WHEEL").decode("utf-8").splitlines():
            if line.startswith("Tag: "):
                internal_tags.add(line[5:].strip())
        _, _, py, abi, platforms = wheel_fields(wheel)
        expected = {"%s-%s-%s" % (py, abi, platform) for platform in platforms}
        if internal_tags != expected:
            raise AuditError("filename tags and WHEEL metadata tags differ")
        verify_record(zf, names, dist + "/RECORD")
        safe_extract(zf, extract_to)
    root = Path(extract_to)
    extensions = list(root.rglob("_cffi_backend*.so"))
    if len(extensions) != 1:
        raise AuditError("expected exactly one _cffi_backend ELF")
    needed, _, ext_details = audit_elf(extensions[0], reports, "elf")
    ffi_needed = [n for n in needed if n.startswith("libffi")]
    if len(ffi_needed) != 1:
        raise AuditError("expected exactly one libffi dependency")
    ffi_name = ffi_needed[0]
    elfs = []
    # Inspect every packaged ELF, including auditwheel-renamed files such as
    # libffi-<hash>.so.8 (whose Path.suffix is not ".so").
    for candidate in root.rglob("*"):
        if not candidate.is_file() or candidate == extensions[0]:
            continue
        probe = subprocess.run(["readelf", "-h", str(candidate)], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, universal_newlines=True)
        if probe.returncode == 0 and "ELF Header" in probe.stdout:
            elfs.append(candidate)
    packaged = []
    for index, candidate in enumerate(elfs):
        dyn = readelf(candidate, "-d")
        sonames = re.findall(r"\(SONAME\).*\[(.*?)\]", dyn)
        packaged.append((candidate, sonames))
        audit_elf(candidate, reports, "bundled-elf-%d" % index)
    kind, match = classify_libffi(ffi_name, packaged)
    if kind == "bundled":
        bundled_path, soname = match
        _, soname, details = audit_elf(bundled_path, reports, "bundled-libffi")
        if soname and soname not in (ffi_name, bundled_path.name):
            raise AuditError("bundled libffi SONAME does not match DT_NEEDED")
        mode = "bundled: %s\n%s" % (bundled_path.relative_to(root), details)
    else:
        if any(path.name.startswith("libffi") or any(s.startswith("libffi") for s in sonames)
               for path, sonames in packaged):
            raise AuditError("packaged libffi ELF does not match the extension dependency")
        result = subprocess.run(["ldconfig", "-p"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                universal_newlines=True)
        if result.returncode:
            raise AuditError("ldconfig lookup failed for external libffi")
        paths = re.findall(r"libffi\.so\.8\s+\([^)]*\)\s+=>\s+(\S+)", result.stdout)
        if len(set(paths)) != 1:
            raise AuditError("external libffi.so.8 resolution is absent or ambiguous")
        _, soname, details = audit_elf(paths[0], reports, "external-libffi")
        if soname != ffi_name:
            raise AuditError("external libffi SONAME mismatch")
        mode = "external: %s\n%s" % (paths[0], details)
    Path(reports, "libffi-audit.txt").write_text(mode, encoding="utf-8")
    Path(reports, "post-repair-audit.txt").write_text("wheel=%s\nsha256=%s\n%s\n%s" % (
        wheel.name, hashlib.sha256(wheel.read_bytes()).hexdigest(), ext_details, mode), encoding="utf-8")
    return True


def classify_libffi(needed_name, packaged):
    """Return bundled ELF or a strictly approved external dependency."""
    if not needed_name.startswith("libffi"):
        raise AuditError("DT_NEEDED is not a libffi dependency")
    matches = [(path, soname) for path, sonames in packaged
               for soname in sonames if soname == needed_name]
    matches.extend((path, None) for path, _ in packaged if path.name == needed_name
                   and not any(existing[0] == path for existing in matches))
    if len(matches) > 1:
        raise AuditError("multiple bundled libraries match the libffi dependency")
    if matches:
        return "bundled", matches[0]
    if any(path.name.startswith("libffi") or any(name.startswith("libffi") for name in sonames)
           for path, sonames in packaged):
        raise AuditError("packaged libffi ELF does not match the extension dependency")
    if needed_name != "libffi.so.8":
        raise AuditError("unresolved or incompatible external libffi dependency")
    return "external", None


def self_test():
    good = "cffi-2.0.0-cp39-cp39-manylinux2014_armv7l.manylinux_2_17_armv7l.manylinux_2_31_armv7l.whl"
    wheel_fields(good)
    wheel_fields("cffi-2.0.0-cp39-cp39-manylinux_2_31_armv7l.manylinux2014_armv7l.manylinux_2_17_armv7l.whl")
    bad = [good.replace("manylinux_2_31_armv7l", "manylinux_2_32_armv7l"),
           good.replace("cp39-cp39", "cp310-cp310"),
           good.replace("cffi-2.0.0", "cffi-2.1.0"),
           good.replace("armv7l", "x86_64"),
           good.replace("manylinux2014_armv7l.", "manylinux2014_armv7l.manylinux2014_armv7l.")]
    for name in bad:
        try:
            wheel_fields(name)
        except AuditError:
            pass
        else:
            raise AssertionError("incompatible wheel accepted: " + name)
    assert classify_libffi("libffi.so.8", [(Path("libffi-abcd.so.8"), ["libffi.so.8"])])[0] == "bundled"
    assert classify_libffi("libffi.so.8", [])[0] == "external"
    for needed, packaged in [("libffi.so.9", []), ("libffi.so.8", [
            (Path("one.so"), ["libffi.so.8"]), (Path("two.so"), ["libffi.so.8"])]),
            ("libffi.so.8", [(Path("libffi-other.so.8"), ["libffi-other.so.8"])])]:
        try:
            classify_libffi(needed, packaged)
        except AuditError:
            pass
        else:
            raise AssertionError("unsafe libffi dependency classification accepted")
    import tempfile
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        try:
            select_wheel(root)
        except AuditError:
            pass
        else:
            raise AssertionError("zero candidates accepted")
        (root / good).write_bytes(b"test")
        assert select_wheel(root).name == good
        (root / "cffi-2.0.0-cp39-cp39-manylinux_2_31_armv7l.whl").write_bytes(b"duplicate")
        try:
            select_wheel(root)
        except AuditError:
            pass
        else:
            raise AssertionError("duplicate wheel candidates accepted")
        (root / good).unlink()
        (root / "cffi-2.0.0-cp39-cp39-manylinux_2_32_armv7l.whl").write_bytes(b"bad")
        try:
            select_wheel(root)
        except AuditError:
            pass
        else:
            raise AssertionError("incompatible candidate accepted")
    print("wheel tag selector self-test: PASS")


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--select")
    group.add_argument("--audit")
    parser.add_argument("--extract-to")
    parser.add_argument("--report-dir")
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
        elif args.select:
            print(select_wheel(args.select))
        else:
            if not args.extract_to or not args.report_dir:
                raise AuditError("--audit requires --extract-to and --report-dir")
            audit_wheel(args.audit, args.extract_to, args.report_dir)
            print("strict wheel/ELF/RECORD/libffi audit: PASS")
    except (AuditError, OSError, ValueError, zipfile.BadZipFile) as exc:
        print("wheel audit failed: %s" % exc, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
