#!/usr/bin/env python3
"""Check ELF and ZIP alignment of 64-bit native libraries in Android archives."""

from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile

PAGE_SIZE = 16_384
ABIS_64_BIT = ("arm64-v8a", "x86_64")


def data_offset(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> int:
    raw = archive.fp
    if raw is None:
        raise ValueError("archive is closed")
    raw.seek(info.header_offset)
    header = raw.read(30)
    if len(header) != 30 or header[:4] != b"PK\x03\x04":
        raise ValueError(f"invalid local header for {info.filename}")
    fields = struct.unpack("<IHHHHHIIIHH", header)
    return info.header_offset + 30 + fields[-2] + fields[-1]


def check_archive(path: Path) -> bool:
    failures = []
    checked = 0
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            if not info.filename.endswith(".so") or not any(f"/{abi}/" in info.filename for abi in ABIS_64_BIT):
                continue
            checked += 1
            problems = []
            with tempfile.NamedTemporaryFile(suffix=".so") as native:
                native.write(archive.read(info))
                native.flush()
                program_headers = subprocess.check_output(["readelf", "-lW", native.name], text=True)
            alignments = [
                int(line.split()[-1], 16)
                for line in program_headers.splitlines()
                if line.split() and line.split()[0] == "LOAD"
            ]
            if not alignments:
                problems.append("no LOAD segments")
            elif any(alignment < PAGE_SIZE for alignment in alignments):
                problems.append("LOAD alignments " + ",".join(hex(alignment) for alignment in alignments))

            # AAB entries are normally compressed. Bundletool produces the final
            # APKs whose uncompressed native-library offsets must be page-aligned.
            if path.suffix.lower() == ".apk":
                if info.compress_type != zipfile.ZIP_STORED:
                    problems.append("compressed in ZIP")
                else:
                    offset = data_offset(archive, info)
                    if offset % PAGE_SIZE:
                        problems.append(f"ZIP data offset {offset:#x} is not 16 KB aligned")
            if problems:
                failures.append(info.filename)
                print(f"FAIL {path.name}: {info.filename}: {'; '.join(problems)}")
            else:
                print(f"PASS {path.name}: {info.filename}")
    if not checked:
        print(f"FAIL {path.name}: no 64-bit native libraries found")
        return False
    print(f"{path.name}: checked {checked} libraries, {len(failures)} failures")
    return not failures


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit("usage: check_android_16kb.py <apk/aab> [...]")
    if shutil.which("readelf") is None:
        raise SystemExit("readelf is required")
    ok = True
    for argument in sys.argv[1:]:
        ok = check_archive(Path(argument)) and ok
    if not ok:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
