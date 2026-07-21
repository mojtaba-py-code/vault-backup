"""Storage backends.

``StorageBackend`` is an abstract interface so new backends (SFTP, S3, ...) can
be added without touching backup/restore logic. ``LocalBackend`` writes to a
local directory using **atomic** writes (temp file + fsync + os.replace) so a
crash or power loss can never leave a half-written object behind.
"""

from __future__ import annotations

import os
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path

from .errors import StorageError


def atomic_write(path: Path, data: bytes) -> None:
    """Write ``data`` to ``path`` atomically and durably.

    Writes to a temp file in the same directory, flushes + fsyncs, then
    ``os.replace`` (atomic on the same filesystem). On any error the temp file
    is removed and the original ``path`` is left untouched.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


class StorageBackend(ABC):
    """Content-addressed blob store keyed by opaque string ids."""

    @abstractmethod
    def put(self, key: str, data: bytes) -> None:
        """Store ``data`` under ``key`` (idempotent — overwrite is fine)."""

    @abstractmethod
    def get(self, key: str) -> bytes:
        """Return the bytes stored under ``key``; raise if missing."""

    @abstractmethod
    def exists(self, key: str) -> bool: ...

    @abstractmethod
    def delete(self, key: str) -> None: ...

    @abstractmethod
    def list_keys(self) -> list[str]: ...


class LocalBackend(StorageBackend):
    """Stores blobs as files, fanned out by the first two id characters."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path_for(self, key: str) -> Path:
        # Fan out (aa/bbbb...) so a single directory never holds millions of files.
        if len(key) < 2 or "/" in key or "\\" in key or key in (".", ".."):
            raise StorageError(f"invalid storage key: {key!r}")
        return self.root / key[:2] / key

    def put(self, key: str, data: bytes) -> None:
        atomic_write(self._path_for(key), data)

    def get(self, key: str) -> bytes:
        try:
            return self._path_for(key).read_bytes()
        except FileNotFoundError as exc:
            raise StorageError(f"object not found: {key}") from exc

    def exists(self, key: str) -> bool:
        return self._path_for(key).exists()

    def delete(self, key: str) -> None:
        try:
            self._path_for(key).unlink()
        except FileNotFoundError:
            pass

    def list_keys(self) -> list[str]:
        keys: list[str] = []
        for sub in self.root.iterdir():
            if sub.is_dir():
                keys.extend(p.name for p in sub.iterdir() if p.is_file())
        return keys
