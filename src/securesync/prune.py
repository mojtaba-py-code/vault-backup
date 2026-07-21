"""Retention and safe garbage collection.

* ``forget`` removes specific snapshots.
* ``apply_retention`` keeps the N most recent snapshots and forgets the rest.
* ``gc`` (mark-and-sweep) deletes chunks that **no remaining snapshot**
  references. A chunk is removed only when it is provably unreferenced, so GC
  can never corrupt a surviving snapshot.

All of these mutate the repository and must be called while holding
``repo.lock()``.
"""

from __future__ import annotations

from dataclasses import dataclass

from .errors import RepositoryError
from .repo import Repository
from .snapshots import list_snapshot_ids, load_snapshot
from .state import set_snapshots


@dataclass
class GCStats:
    chunks_before: int = 0
    chunks_removed: int = 0
    chunks_kept: int = 0


def forget(repo: Repository, snapshot_ids: list[str]) -> list[str]:
    """Delete the given snapshots. Returns the ids actually removed."""
    existing = set(list_snapshot_ids(repo))
    unknown = [s for s in snapshot_ids if s not in existing]
    if unknown:
        raise RepositoryError(f"unknown snapshot(s): {', '.join(unknown)}")
    for sid in snapshot_ids:
        (repo.snapshots_dir / f"{sid}.snap").unlink(missing_ok=True)
    remaining = sorted(existing - set(snapshot_ids))
    set_snapshots(repo, remaining)
    return list(snapshot_ids)


def apply_retention(repo: Repository, keep_last: int) -> list[str]:
    """Keep the ``keep_last`` most recent snapshots; forget the older ones."""
    if keep_last < 0:
        raise RepositoryError("keep_last must be >= 0")
    ids = list_snapshot_ids(repo)  # sorted ascending (ids are timestamps)
    if len(ids) <= keep_last:
        return []
    to_forget = ids[: len(ids) - keep_last]
    forget(repo, to_forget)
    return to_forget


def referenced_chunks(repo: Repository) -> set[str]:
    """The set of chunk ids referenced by any surviving snapshot."""
    refs: set[str] = set()
    for sid in list_snapshot_ids(repo):
        for entry in load_snapshot(repo, sid).entries:
            refs.update(entry.chunks)
    return refs


def gc(repo: Repository) -> GCStats:
    """Mark-and-sweep: delete chunks not referenced by any snapshot."""
    keep = referenced_chunks(repo)
    stats = GCStats()
    for cid in repo.chunks.list_keys():
        stats.chunks_before += 1
        if cid in keep:
            stats.chunks_kept += 1
        else:
            repo.chunks.delete(cid)
            stats.chunks_removed += 1
    return stats
