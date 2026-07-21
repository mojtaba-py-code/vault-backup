"""Filesystem scanning: walk a source tree, apply excludes, capture metadata.

Security stance: symlinks are recorded but **never followed** by default, so a
malicious symlink cannot cause us to read outside the source tree.
"""

from __future__ import annotations

import fnmatch
import os
import stat
from collections.abc import Iterator
from pathlib import Path

from .models import FileEntry


def _is_excluded(rel_posix: str, patterns: list[str]) -> bool:
    name = rel_posix.rsplit("/", 1)[-1]
    for pat in patterns:
        if fnmatch.fnmatch(rel_posix, pat) or fnmatch.fnmatch(name, pat):
            return True
        # Directory-prefix style pattern, e.g. ".git/" excludes everything under it.
        p = pat.rstrip("/")
        if rel_posix == p or rel_posix.startswith(p + "/"):
            return True
    return False


def scan(root: Path, excludes: list[str] | None = None) -> Iterator[FileEntry]:
    """Yield a :class:`FileEntry` for every file/dir/symlink under ``root``.

    Entries are yielded with POSIX-relative paths, in a stable sorted order so
    snapshots are deterministic. Content chunks are filled in later by backup.
    """
    excludes = excludes or []
    root = root.resolve()

    def walk(current: Path) -> Iterator[FileEntry]:
        try:
            children = sorted(current.iterdir(), key=lambda p: p.name)
        except (PermissionError, OSError):
            return
        for child in children:
            rel = child.relative_to(root).as_posix()
            if _is_excluded(rel, excludes):
                continue
            try:
                st = child.lstat()  # lstat: do NOT follow symlinks
            except OSError:
                continue
            mode = stat.S_IMODE(st.st_mode)
            if stat.S_ISLNK(st.st_mode):
                try:
                    target = os.readlink(child)
                except OSError:
                    continue
                yield FileEntry(
                    path=rel, kind="symlink", mode=mode, mtime_ns=st.st_mtime_ns,
                    symlink_target=target,
                )
            elif stat.S_ISDIR(st.st_mode):
                yield FileEntry(path=rel, kind="dir", mode=mode, mtime_ns=st.st_mtime_ns)
                yield from walk(child)
            elif stat.S_ISREG(st.st_mode):
                yield FileEntry(
                    path=rel, kind="file", size=st.st_size, mode=mode,
                    mtime_ns=st.st_mtime_ns,
                )
            # Sockets/FIFOs/devices are intentionally skipped.

    yield from walk(root)
