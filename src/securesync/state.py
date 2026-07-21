"""Repository state: an authenticated registry of the current snapshot set.

Each snapshot is individually authenticated, but that does not stop an attacker
with repository access from *deleting* a snapshot or *injecting* a foreign one.
The state file is a single sealed (encrypted + authenticated) document listing
exactly which snapshot ids are supposed to exist, plus a monotonically
increasing counter. ``verify`` cross-checks it against the snapshots on disk, so
deletion or injection is detected.

Limitation: full anti-rollback (detecting that the whole repo, state included,
was reverted to an older consistent copy) requires a trusted external reference
(e.g. remembering the last counter elsewhere); that is out of scope for v1.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from .blockformat import pack, unpack
from .compress import compress, decompress
from .errors import IntegrityError
from .repo import Repository
from .store import atomic_write

_STATE_AAD = b"securesync/state/v1"
_STATE_VERSION = 1


@dataclass
class RepoState:
    counter: int = 0
    snapshot_ids: list[str] = field(default_factory=list)

    def to_bytes(self) -> bytes:
        doc = {
            "version": _STATE_VERSION,
            "counter": self.counter,
            "snapshot_ids": sorted(self.snapshot_ids),
        }
        return json.dumps(doc, sort_keys=True).encode("utf-8")

    @classmethod
    def from_bytes(cls, raw: bytes) -> RepoState:
        try:
            doc = json.loads(raw.decode("utf-8"))
            return cls(counter=int(doc["counter"]), snapshot_ids=list(doc["snapshot_ids"]))
        except (KeyError, ValueError, TypeError) as exc:
            raise IntegrityError("corrupt repository state") from exc


def load_state(repo: Repository) -> RepoState | None:
    """Load and authenticate the state file, or ``None`` if it does not exist."""
    try:
        blob = repo.state_path.read_bytes()
    except FileNotFoundError:
        return None
    raw = decompress(unpack(repo.meta_enc_key, blob, _STATE_AAD))
    return RepoState.from_bytes(raw)


def save_state(repo: Repository, state: RepoState) -> None:
    blob = pack(repo.meta_enc_key, compress(state.to_bytes()), _STATE_AAD)
    atomic_write(repo.state_path, blob)


def record_snapshot(repo: Repository, snapshot_id: str) -> None:
    """Add a snapshot id to the authenticated state, bumping the counter."""
    state = load_state(repo) or RepoState()
    if snapshot_id not in state.snapshot_ids:
        state.snapshot_ids.append(snapshot_id)
    state.counter += 1
    save_state(repo, state)


def set_snapshots(repo: Repository, snapshot_ids: list[str]) -> None:
    """Replace the snapshot set (used by forget/prune), bumping the counter."""
    state = load_state(repo) or RepoState()
    state.snapshot_ids = sorted(snapshot_ids)
    state.counter += 1
    save_state(repo, state)
