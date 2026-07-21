"""Backup: scan a source tree, store deduplicated encrypted chunks, write a
sealed snapshot manifest.

Ordering is deliberate and crash-safe: **all chunks are written and fsynced
before the manifest is written**. If the process dies mid-backup, the worst
outcome is a few orphan chunks (harmless); a manifest can never reference a
chunk that was not durably stored.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .blockformat import pack
from .chunker import iter_chunks
from .compress import compress
from .crypto import mac
from .models import FileEntry, Snapshot
from .repo import Repository
from .scanner import scan
from .state import record_snapshot
from .store import atomic_write

_SNAPSHOT_AAD_PREFIX = b"securesync/snapshot/v1/"


@dataclass
class BackupStats:
    files: int = 0
    dirs: int = 0
    symlinks: int = 0
    chunks_written: int = 0
    chunks_deduped: int = 0
    bytes_read: int = 0
    files_unchanged: int = 0  # reused from parent snapshot without re-reading


def _chunk_id(repo: Repository, data: bytes) -> str:
    """Content id = HMAC(subkey, plaintext). Keyed so outsiders cannot confirm
    which files the repository contains (mitigates the dedup fingerprint leak)."""
    return mac(repo.chunk_id_key, data).hex()


def _store_chunk(repo: Repository, data: bytes, stats: BackupStats) -> str:
    cid = _chunk_id(repo, data)
    if repo.chunks.exists(cid):
        stats.chunks_deduped += 1
        return cid
    # AAD binds the ciphertext to this exact chunk id (anti-substitution).
    blob = pack(repo.chunk_enc_key, compress(data), cid.encode("ascii"))
    repo.chunks.put(cid, blob)
    stats.chunks_written += 1
    return cid


def _new_snapshot_id() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%S%f") + "Z"


def _parent_index(parent: Snapshot | None) -> dict[str, FileEntry]:
    """Map path -> file entry from the parent snapshot, for incremental reuse."""
    if parent is None:
        return {}
    return {e.path: e for e in parent.entries if e.kind == "file"}


def _unchanged(entry: FileEntry, prev: FileEntry | None) -> bool:
    """A file is treated as unchanged if path, size and mtime all match.

    This is the standard fast heuristic. Use ``--full`` (parent=None) to force
    re-reading and hashing every file when absolute certainty is required.
    """
    return (
        prev is not None
        and prev.size == entry.size
        and prev.mtime_ns == entry.mtime_ns
    )


def backup(
    repo: Repository,
    source: Path,
    excludes: list[str] | None = None,
    parent: Snapshot | None = None,
) -> tuple[Snapshot, BackupStats]:
    """Back up ``source`` into ``repo`` and return the created snapshot + stats.

    If ``parent`` is given, unchanged files (same path/size/mtime) reuse the
    parent's chunk list without re-reading them — a true incremental backup.
    """
    source = Path(source).resolve()
    stats = BackupStats()
    entries: list[FileEntry] = []
    prev_files = _parent_index(parent)

    for entry in scan(source, excludes):
        if entry.kind == "dir":
            stats.dirs += 1
            entries.append(entry)
        elif entry.kind == "symlink":
            stats.symlinks += 1
            entries.append(entry)
        elif entry.kind == "file":
            stats.files += 1
            prev = prev_files.get(entry.path)
            if _unchanged(entry, prev):
                assert prev is not None
                stats.files_unchanged += 1
                entries.append(
                    FileEntry(
                        path=entry.path, kind="file", size=entry.size, mode=entry.mode,
                        mtime_ns=entry.mtime_ns, chunks=list(prev.chunks),
                    )
                )
                continue
            chunk_ids: list[str] = []
            for block in iter_chunks(source / entry.path, repo.config.chunk_size):
                stats.bytes_read += len(block)
                chunk_ids.append(_store_chunk(repo, block, stats))
            entries.append(
                FileEntry(
                    path=entry.path, kind="file", size=entry.size, mode=entry.mode,
                    mtime_ns=entry.mtime_ns, chunks=chunk_ids,
                )
            )

    snapshot = Snapshot(
        snapshot_id=_new_snapshot_id(),
        created_utc=datetime.now(UTC).isoformat(),
        root=str(source),
        entries=entries,
    )
    _write_snapshot(repo, snapshot)
    record_snapshot(repo, snapshot.snapshot_id)
    return snapshot, stats


def _write_snapshot(repo: Repository, snapshot: Snapshot) -> None:
    raw = json.dumps(snapshot.to_dict(), ensure_ascii=False).encode("utf-8")
    aad = _SNAPSHOT_AAD_PREFIX + snapshot.snapshot_id.encode("ascii")
    blob = pack(repo.meta_enc_key, compress(raw), aad)
    repo.snapshots_dir.mkdir(parents=True, exist_ok=True)
    atomic_write(repo.snapshots_dir / f"{snapshot.snapshot_id}.snap", blob)
