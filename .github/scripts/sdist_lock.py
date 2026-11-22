#!/usr/bin/env python3
"""Prune the Cargo.lock inside the openvireo sdist so it builds with `locked = true`.

`maturin sdist` packs only the crates bindings/ov-ffi needs, but copies the whole workspace's
Cargo.lock (xtask, benches, bins and their dependencies included). Building the sdist then needs
Cargo to drop those entries, which `--locked` refuses. This lets Cargo prune the lock in an
unpacked copy, checks that every package left is one the original lock pinned (same name, version
and checksum: pruning only, never an upgrade), checks that `cargo metadata --locked` now passes,
and rewrites the tarball with the pruned lock. Every other entry keeps its bytes, order and mode.

    python sdist_lock.py <openvireo-X.Y.Z.tar.gz>

Used by the release workflow's sdist job and `cargo xtask release` (xtask/src/python.rs). Needs
`cargo` on PATH; the standard library only otherwise.
"""

from __future__ import annotations

import io
import os
import re
import subprocess
import sys
import tarfile
import tempfile

PACKAGE = re.compile(
    r'^\[\[package\]\]\nname = "([^"]+)"\nversion = "([^"]+)"\n(?:source = "[^"]+"\n)?(?:checksum = "([^"]+)"\n)?',
    re.M,
)


def packages(lock: str) -> set[tuple[str, str, str | None]]:
    return {(m[1], m[2], m[3]) for m in PACKAGE.finditer(lock)}


def cargo_metadata(manifest: str, *extra: str) -> None:
    subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--manifest-path", manifest, *extra],
        check=True,
        stdout=subprocess.DEVNULL,
    )


def main(path: str) -> int:
    with tarfile.open(path, "r:gz") as tf:
        members = tf.getmembers()
        data = {m.name: tf.extractfile(m).read() for m in members if m.isfile()}  # type: ignore[union-attr]
    locks = [n for n in data if n.count("/") == 1 and n.endswith("/Cargo.lock")]
    if len(locks) != 1:
        sys.exit(f"{path}: expected one top-level Cargo.lock, found {locks}")
    lock_name = locks[0]
    top = lock_name.split("/")[0]
    original = data[lock_name].decode()

    with tempfile.TemporaryDirectory() as work:
        with tarfile.open(path, "r:gz") as tf:
            tf.extractall(work, filter="data")
        manifest = os.path.join(work, top, "Cargo.toml")
        # Without --locked Cargo rewrites the lock to the packed workspace: it only removes entries
        # here, which the subset check below confirms.
        cargo_metadata(manifest)
        with open(os.path.join(work, top, "Cargo.lock"), encoding="utf-8") as f:
            pruned = f.read()
        added = packages(pruned) - packages(original)
        if added:
            sys.exit(f"{path}: pruning the lock changed pinned packages: {sorted(added)}")
        cargo_metadata(manifest, "--locked")

    if pruned == original:
        print(f"{path}: Cargo.lock already matches the packed workspace")
        return 0
    removed = len(packages(original)) - len(packages(pruned))
    buf = io.BytesIO()
    with tarfile.open(path, "r:gz") as src, tarfile.open(fileobj=buf, mode="w:gz", format=src.format) as dst:
        for m in members:
            if m.isfile():
                body = pruned.encode() if m.name == lock_name else data[m.name]
                m.size = len(body)
                dst.addfile(m, io.BytesIO(body))
            else:
                dst.addfile(m)
    with open(path, "wb") as f:
        f.write(buf.getvalue())
    print(f"{path}: pruned {removed} packages from Cargo.lock; `cargo metadata --locked` passes")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1]))
