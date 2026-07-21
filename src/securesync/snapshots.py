"""Loading and listing sealed snapshot manifests."""

from __future__ import annotations

import json

from .blockformat import unpack
from .compress import decompress
from .errors import RepositoryError
from .models import Snapshot
from .repo import Repository

_SNAPSHOT_AAD_PREFIX = b"securesync/snapshot/v1/"


def list_snapshot_ids(repo: Repository) -> list[str]:
    if not repo.snapshots_dir.exists():
        return []
    ids = [p.stem for p in repo.snapshots_dir.glob("*.snap")]
    return sorted(ids)


def load_snapshot(repo: Repository, snapshot_id: str) -> Snapshot:
    path = repo.snapshots_dir / f"{snapshot_id}.snap"
    try:
        blob = path.read_bytes()
    except FileNotFoundError as exc:
        raise RepositoryError(f"snapshot not found: {snapshot_id}") from exc
    aad = _SNAPSHOT_AAD_PREFIX + snapshot_id.encode("ascii")
    raw = decompress(unpack(repo.meta_enc_key, blob, aad))
    return Snapshot.from_dict(json.loads(raw.decode("utf-8")))


def resolve_snapshot(repo: Repository, ref: str) -> Snapshot:
    """Resolve a snapshot reference: an explicit id, or ``latest``."""
    ids = list_snapshot_ids(repo)
    if not ids:
        raise RepositoryError("repository has no snapshots")
    if ref in ("latest", "last"):
        return load_snapshot(repo, ids[-1])
    if ref in ids:
        return load_snapshot(repo, ref)
    raise RepositoryError(f"unknown snapshot: {ref}")
