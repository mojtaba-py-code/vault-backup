"""The Repository: the central object tying keys, storage, and subkeys together.

On-disk layout::

    repo/
    ├── config.json            # non-secret parameters (format version, chunk size)
    ├── keys/keyfile.json      # salt, KDF params, wrapped master key
    ├── chunks/aa/<chunk_id>   # sealed, deduplicated content chunks
    ├── snapshots/<id>.snap    # sealed manifests
    └── lock                   # advisory lock during mutating operations

All purpose-specific keys are derived from the master key with HKDF, so no
single key is reused across roles.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .config import RepoConfig
from .crypto import derive_subkey
from .errors import RepositoryError
from .keystore import KeyFile, create_keyfile, load_keyfile, save_keyfile, unlock
from .store import LocalBackend

_INFO_CHUNK_ID = b"securesync/chunk-id/v1"
_INFO_CHUNK_ENC = b"securesync/chunk-enc/v1"
_INFO_META_ENC = b"securesync/metadata-enc/v1"


class Repository:
    """An opened, unlocked repository ready for backup/restore/verify."""

    def __init__(self, path: Path, master_key: bytes, config: RepoConfig) -> None:
        self.path = Path(path)
        self.config = config
        self._master_key = master_key
        self.chunk_id_key = derive_subkey(master_key, _INFO_CHUNK_ID)
        self.chunk_enc_key = derive_subkey(master_key, _INFO_CHUNK_ENC)
        self.meta_enc_key = derive_subkey(master_key, _INFO_META_ENC)
        self.chunks = LocalBackend(self.path / "chunks")

    # ---- paths -----------------------------------------------------------
    @property
    def keyfile_path(self) -> Path:
        return self.path / "keys" / "keyfile.json"

    @property
    def config_path(self) -> Path:
        return self.path / "config.json"

    @property
    def snapshots_dir(self) -> Path:
        return self.path / "snapshots"

    @property
    def lock_path(self) -> Path:
        return self.path / "lock"

    @property
    def state_path(self) -> Path:
        return self.path / "state"

    # ---- lifecycle -------------------------------------------------------
    @classmethod
    def init(cls, path: Path, password: bytes, config: RepoConfig | None = None) -> Repository:
        """Create a brand-new repository at ``path``."""
        path = Path(path)
        if path.exists() and any(path.iterdir()):
            raise RepositoryError(f"target is not empty: {path}")
        config = config or RepoConfig()
        config.validate()
        (path / "keys").mkdir(parents=True, exist_ok=True)
        (path / "chunks").mkdir(parents=True, exist_ok=True)
        (path / "snapshots").mkdir(parents=True, exist_ok=True)
        keyfile, master_key = create_keyfile(password)
        save_keyfile(path / "keys" / "keyfile.json", keyfile)
        config.save(path / "config.json")
        repo = cls(path, master_key, config)
        # Initialize an authenticated (empty) snapshot registry.
        from .state import RepoState, save_state

        save_state(repo, RepoState())
        return repo

    @classmethod
    def open(cls, path: Path, password: bytes) -> Repository:
        """Open and unlock an existing repository."""
        path = Path(path)
        if not (path / "config.json").exists():
            raise RepositoryError(f"not a securesync repository: {path}")
        config = RepoConfig.load(path / "config.json")
        keyfile = load_keyfile(path / "keys" / "keyfile.json")
        master_key = unlock(keyfile, password)  # raises CryptoError on bad password
        return cls(path, master_key, config)

    def change_password(self, old_password: bytes, new_password: bytes) -> None:
        from .keystore import rewrap

        keyfile = load_keyfile(self.keyfile_path)
        new_keyfile: KeyFile = rewrap(keyfile, old_password, new_password)
        save_keyfile(self.keyfile_path, new_keyfile)

    # ---- locking ---------------------------------------------------------
    @contextmanager
    def lock(self) -> Iterator[None]:
        """Advisory exclusive lock preventing concurrent mutating operations."""
        try:
            fd = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError as exc:
            raise RepositoryError(
                f"repository is locked ({self.lock_path}); another operation may be "
                "running. Remove the lock file if you are sure it is stale."
            ) from exc
        try:
            os.write(fd, str(os.getpid()).encode("ascii"))
            os.close(fd)
            yield
        finally:
            try:
                self.lock_path.unlink()
            except FileNotFoundError:
                pass
