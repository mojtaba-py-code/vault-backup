"""Data models: the shapes stored inside (encrypted) manifests."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class FileEntry:
    """One file (or directory/symlink) captured in a snapshot.

    ``path`` is always stored relative and POSIX-style (forward slashes) for
    cross-platform restores. ``chunks`` lists the content-chunk ids in order.
    """

    path: str
    kind: str  # "file" | "dir" | "symlink"
    size: int = 0
    mode: int = 0o644
    mtime_ns: int = 0
    chunks: list[str] = field(default_factory=list)
    symlink_target: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if self.symlink_target is None:
            d.pop("symlink_target")
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> FileEntry:
        return cls(
            path=d["path"],
            kind=d["kind"],
            size=int(d.get("size", 0)),
            mode=int(d.get("mode", 0o644)),
            mtime_ns=int(d.get("mtime_ns", 0)),
            chunks=list(d.get("chunks", [])),
            symlink_target=d.get("symlink_target"),
        )


@dataclass(frozen=True)
class Snapshot:
    """A point-in-time backup: metadata plus the list of file entries."""

    snapshot_id: str
    created_utc: str  # ISO-8601, UTC
    root: str  # absolute source root as given at backup time (informational)
    entries: list[FileEntry]

    def to_dict(self) -> dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "created_utc": self.created_utc,
            "root": self.root,
            "entries": [e.to_dict() for e in self.entries],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Snapshot:
        return cls(
            snapshot_id=d["snapshot_id"],
            created_utc=d["created_utc"],
            root=d.get("root", ""),
            entries=[FileEntry.from_dict(e) for e in d.get("entries", [])],
        )
