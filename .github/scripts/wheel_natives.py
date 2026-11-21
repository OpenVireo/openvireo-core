#!/usr/bin/env python3
"""Sign the native library inside a wheel: unpack it, let the caller sign, repack with a new RECORD.

The release workflow (.github/workflows/release.yml) signs the macOS dylib (Developer ID) and the
Windows DLL (Azure Artifact Signing) inside the openvireo wheels the same way as the `ov` executables:

    python wheel_natives.py extract <wheel> <dir>   # unpack; print the native libraries, one per line
    ... sign <dir>/<each printed path> in place ...
    python wheel_natives.py repack <wheel> <dir>    # rewrite <wheel> from <dir>, RECORD recomputed
    python wheel_natives.py check <wheel>           # every RECORD hash and size matches

`repack` keeps the original entries' order, times, permissions and compression; only the bytes of
changed files and their RECORD rows differ. The standard library only, no third-party packages.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import os
import sys
import tempfile
import zipfile

NATIVE_SUFFIXES = (".dylib", ".so", ".dll", ".pyd")


def record_name(zf: zipfile.ZipFile) -> str:
    names = [n for n in zf.namelist() if n.endswith(".dist-info/RECORD") and n.count("/") == 1]
    if len(names) != 1:
        raise SystemExit(f"expected one top-level *.dist-info/RECORD, found {names}")
    return names[0]


def digest(data: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def safe_path(root: str, name: str) -> str:
    path = os.path.realpath(os.path.join(root, name))
    if not path.startswith(os.path.realpath(root) + os.sep):
        raise SystemExit(f"unsafe path in wheel: {name}")
    return path


def extract(wheel: str, out: str) -> None:
    with zipfile.ZipFile(wheel) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            path = safe_path(out, info.filename)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                f.write(zf.read(info))
            mode = (info.external_attr >> 16) & 0o777
            if mode:
                os.chmod(path, mode)
            if info.filename.endswith(NATIVE_SUFFIXES):
                print(info.filename)


def repack(wheel: str, src: str) -> None:
    with zipfile.ZipFile(wheel) as zf:
        infos = [i for i in zf.infolist() if not i.is_dir()]
        record = record_name(zf)
    rows = []
    contents = {}
    for info in infos:
        if info.filename == record:
            continue
        with open(safe_path(src, info.filename), "rb") as f:
            data = f.read()
        contents[info.filename] = data
        rows.append([info.filename, digest(data), str(len(data))])
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerows(rows)
    writer.writerow([record, "", ""])
    contents[record] = buf.getvalue().encode()

    fd, tmp = tempfile.mkstemp(suffix=".whl", dir=os.path.dirname(os.path.abspath(wheel)))
    os.close(fd)
    try:
        with zipfile.ZipFile(tmp, "w") as out:
            for info in infos:
                new = zipfile.ZipInfo(info.filename, date_time=info.date_time)
                new.external_attr = info.external_attr
                new.compress_type = info.compress_type
                new.create_system = info.create_system
                out.writestr(new, contents[info.filename])
        os.replace(tmp, wheel)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    check(wheel)


def check(wheel: str) -> None:
    with zipfile.ZipFile(wheel) as zf:
        record = record_name(zf)
        rows = list(csv.reader(io.StringIO(zf.read(record).decode())))
        listed = set()
        for row in rows:
            name, hash_, size = row[0], row[1], row[2]
            listed.add(name)
            if name == record:
                continue
            data = zf.read(name)
            if hash_ != digest(data) or size != str(len(data)):
                raise SystemExit(f"{wheel}: RECORD doesn't match {name}")
        unlisted = [n for n in zf.namelist() if not n.endswith("/") and n not in listed]
        if unlisted:
            raise SystemExit(f"{wheel}: not in RECORD: {unlisted}")
    print(f"{os.path.basename(wheel)}: RECORD matches {len(rows)} files")


def main(argv: list[str]) -> None:
    if len(argv) == 3 and argv[0] == "extract":
        extract(argv[1], argv[2])
    elif len(argv) == 3 and argv[0] == "repack":
        repack(argv[1], argv[2])
    elif len(argv) == 2 and argv[0] == "check":
        check(argv[1])
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
