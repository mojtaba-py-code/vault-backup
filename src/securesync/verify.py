"""Integrity verification (the ``check`` operation).

Re-reads stored chunks, authenticates them, and (in full mode) recomputes each
chunk id from the decrypted plaintext to confirm the store has not silently
rotted or been tampered with. Also confirms every chunk referenced by every
snapshot actually exists.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .blockformat import unpack
from .compress import decompress
from .crypto import constant_time_equal, mac
from .errors import CryptoError, IntegrityError, RepositoryError
from .repo import Repository
from .snapshots import list_snapshot_ids, load_snapshot


@dataclass
class VerifyReport:
    snapshots_checked: int = 0
    chunks_checked: int = 0
    missing_chunks: list[str] = field(default_factory=list)
    corrupt_chunks: list[str] = field(default_factory=list)
    corrupt_snapshots: list[str] = field(default_factory=list)  # manifest failed to authenticate
    state_missing: list[str] = field(default_factory=list)  # in state, not on disk
    state_extra: list[str] = field(default_factory=list)  # on disk, not in state

    @property
    def ok(self) -> bool:
        return not (
            self.missing_chunks
            or self.corrupt_chunks
            or self.corrupt_snapshots
            or self.state_missing
            or self.state_extra
        )


def verify(repo: Repository, *, deep: bool = True) -> VerifyReport:
    """Verify repository integrity.

    ``deep=True`` decrypts and re-hashes every referenced chunk. ``deep=False``
    only checks that referenced chunks exist (fast).
    """
    report = VerifyReport()
    seen: set[str] = set()

    _check_state(repo, report)

    for sid in list_snapshot_ids(repo):
        try:
            snapshot = load_snapshot(repo, sid)  # authenticates the manifest itself
        except (CryptoError, IntegrityError, RepositoryError):
            report.corrupt_snapshots.append(sid)
            continue
        report.snapshots_checked += 1
        for entry in snapshot.entries:
            for cid in entry.chunks:
                if cid in seen:
                    continue
                seen.add(cid)
                report.chunks_checked += 1
                if not repo.chunks.exists(cid):
                    report.missing_chunks.append(cid)
                    continue
                if deep and not _chunk_is_sound(repo, cid):
                    report.corrupt_chunks.append(cid)
    return report


def _check_state(repo: Repository, report: VerifyReport) -> None:
    """Cross-check the authenticated snapshot registry against disk."""
    from .state import load_state

    state = load_state(repo)  # authenticates the state file itself
    if state is None:
        return
    listed = set(state.snapshot_ids)
    actual = set(list_snapshot_ids(repo))
    report.state_missing = sorted(listed - actual)  # deleted snapshot
    report.state_extra = sorted(actual - listed)  # injected snapshot


def _chunk_is_sound(repo: Repository, cid: str) -> bool:
    try:
        blob = repo.chunks.get(cid)
        plaintext = decompress(unpack(repo.chunk_enc_key, blob, cid.encode("ascii")))
    except Exception:  # noqa: BLE001 - any failure means "not sound"
        return False
    return constant_time_equal(mac(repo.chunk_id_key, plaintext), bytes.fromhex(cid))
