"""Restore: rebuild files from a sealed snapshot into a target directory.

Security: every destination path is validated to stay inside the target root
(defends against path-traversal entries like ``../../etc/passwd``). Chunks are
authenticated on read (AAD = chunk id), so a swapped or tampered chunk fails
loudly instead of producing corrupt output.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .blockformat import unpack
from .compress import decompress
from .errors import RestoreError
from .models import FileEntry, Snapshot
from .repo import Repository
from .store import atomic_write


@dataclass
class RestoreStats:
    files: int = 0
    dirs: int = 0
    symlinks: int = 0
    bytes_written: int = 0


def _safe_join(target_root: Path, rel_posix: str) -> Path:
    """Join ``rel_posix`` onto ``target_root``, rejecting traversal/absolute paths."""
    pure = PurePosixPath(rel_posix)
    if pure.is_absolute() or any(part == ".." for part in pure.parts):
        raise RestoreError(f"unsafe path in snapshot: {rel_posix!r}")
    dest = (target_root / Path(*pure.parts)).resolve()
    root = target_root.resolve()
    if root != dest and root not in dest.parents:
        raise RestoreError(f"path escapes target directory: {rel_posix!r}")
    return dest


def _read_chunk(repo: Repository, chunk_id: str) -> bytes:
    blob = repo.chunks.get(chunk_id)
    return decompress(unpack(repo.chunk_enc_key, blob, chunk_id.encode("ascii")))


def _restore_file(repo: Repository, entry: FileEntry, dest: Path, stats: RestoreStats) -> None:
    data = bytearray()
    for cid in entry.chunks:
        data.extend(_read_chunk(repo, cid))
    atomic_write(dest, bytes(data))
    stats.files += 1
    stats.bytes_written += len(data)
    _apply_metadata(entry, dest)


def _apply_metadata(entry: FileEntry, dest: Path) -> None:
    # Best-effort metadata restore; failures here must not fail the restore.
    try:
        os.chmod(dest, entry.mode)
    except OSError:
        pass
    try:
        if entry.mtime_ns:
            os.utime(dest, ns=(entry.mtime_ns, entry.mtime_ns))
    except OSError:
        pass


def restore(
    repo: Repository, snapshot: Snapshot, target: Path, *, overwrite: bool = False
) -> RestoreStats:
    """Restore all entries of ``snapshot`` into ``target``."""
    target = Path(target)
    target.mkdir(parents=True, exist_ok=True)
    if not overwrite and any(target.iterdir()):
        raise RestoreError(f"target is not empty (use overwrite): {target}")

    stats = RestoreStats()
    # Directories first (sorted by depth) so parents exist before children.
    for entry in sorted(snapshot.entries, key=lambda e: e.path.count("/")):
        dest = _safe_join(target, entry.path)
        if entry.kind == "dir":
            dest.mkdir(parents=True, exist_ok=True)
            stats.dirs += 1
        elif entry.kind == "file":
            dest.parent.mkdir(parents=True, exist_ok=True)
            _restore_file(repo, entry, dest, stats)
        elif entry.kind == "symlink":
            _restore_symlink(entry, dest, stats)
    return stats


def _restore_symlink(entry: FileEntry, dest: Path, stats: RestoreStats) -> None:
    if entry.symlink_target is None:
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        if dest.exists() or dest.is_symlink():
            dest.unlink()
        os.symlink(entry.symlink_target, dest)
        stats.symlinks += 1
    except (OSError, NotImplementedError):
        # Windows without privilege may reject symlinks; skip rather than fail.
        pass
