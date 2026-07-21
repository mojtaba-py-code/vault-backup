"""Master-key management (two-tier key architecture).

The data itself is encrypted with a random **master key**. The master key is
never derived from the password; instead it is *wrapped* (encrypted) with a
Key-Encryption-Key (KEK) that IS derived from the password via Argon2id.

Why: changing the password only re-wraps the (tiny) master key — it never
requires re-encrypting terabytes of backup data. It also enables multiple
passwords / a recovery key for the same repository later.

The key file (JSON) holds only the salt, KDF params, and the wrapped master key.
It never holds the password, the KEK, or the plaintext master key.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path

from . import FORMAT_VERSION
from .blockformat import pack, unpack
from .crypto import KdfParams, derive_kek, new_key, new_salt
from .errors import CryptoError, RepositoryError
from .store import atomic_write

KEYFILE_VERSION = 1
_MASTERKEY_AAD = b"securesync/master-key/v1"


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str) -> bytes:
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except Exception as exc:  # noqa: BLE001 - normalize to a typed error
        raise CryptoError("corrupt key file (invalid base64)") from exc


@dataclass(frozen=True)
class KeyFile:
    salt: bytes
    kdf: KdfParams
    wrapped_master: bytes

    def to_json(self) -> bytes:
        doc = {
            "keyfile_version": KEYFILE_VERSION,
            "format_version": FORMAT_VERSION,
            "salt": _b64e(self.salt),
            "kdf": self.kdf.to_dict(),
            "wrapped_master": _b64e(self.wrapped_master),
        }
        return json.dumps(doc, indent=2, sort_keys=True).encode("utf-8")

    @classmethod
    def from_json(cls, raw: bytes) -> KeyFile:
        try:
            doc = json.loads(raw.decode("utf-8"))
            return cls(
                salt=_b64d(doc["salt"]),
                kdf=KdfParams.from_dict(doc["kdf"]),
                wrapped_master=_b64d(doc["wrapped_master"]),
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise CryptoError("corrupt or invalid key file") from exc


def create_keyfile(password: bytes, params: KdfParams | None = None) -> tuple[KeyFile, bytes]:
    """Create a fresh key file for a new repository.

    Returns ``(keyfile, master_key)``. The master key is returned so the caller
    can immediately use it; only the *wrapped* form is ever persisted.
    """
    params = params or KdfParams()
    salt = new_salt()
    master_key = new_key()
    kek = derive_kek(password, salt, params)
    wrapped = pack(kek, master_key, _MASTERKEY_AAD)
    return KeyFile(salt=salt, kdf=params, wrapped_master=wrapped), master_key


def unlock(keyfile: KeyFile, password: bytes) -> bytes:
    """Recover the master key from a key file using the password.

    Raises :class:`CryptoError` on a wrong password (authentication failure).
    """
    kek = derive_kek(password, keyfile.salt, keyfile.kdf)
    return unpack(kek, keyfile.wrapped_master, _MASTERKEY_AAD)


def rewrap(keyfile: KeyFile, old_password: bytes, new_password: bytes) -> KeyFile:
    """Change the password: unlock, then re-wrap the same master key.

    The master key is unchanged, so no backup data needs re-encrypting.
    """
    master_key = unlock(keyfile, old_password)
    salt = new_salt()
    kek = derive_kek(new_password, salt, keyfile.kdf)
    wrapped = pack(kek, master_key, _MASTERKEY_AAD)
    return KeyFile(salt=salt, kdf=keyfile.kdf, wrapped_master=wrapped)


def load_keyfile(path: Path) -> KeyFile:
    try:
        return KeyFile.from_json(path.read_bytes())
    except FileNotFoundError as exc:
        raise RepositoryError(f"key file not found: {path}") from exc


def save_keyfile(path: Path, keyfile: KeyFile) -> None:
    atomic_write(path, keyfile.to_json())
    # Best-effort: restrict permissions (effective on POSIX; harmless on Windows).
    try:
        path.chmod(0o600)
    except OSError:
        pass
