"""Cryptographic primitives for securesync.

Design decisions (see SECURITY.md / the project report):

* **AEAD:** AES-256-GCM-SIV. It is *nonce-misuse resistant* — reusing a nonce
  with the same key at worst leaks whether two plaintexts are equal, instead of
  catastrophically breaking confidentiality like plain GCM. This sidesteps the
  single most dangerous crypto pitfall for a backup tool that writes millions of
  chunks.
* **KDF:** Argon2id via ``argon2-cffi`` to derive a Key-Encryption-Key (KEK)
  from the user password.
* **AAD:** every sealed block is bound to an associated-data value (its
  ``chunk_id`` / role), so an attacker cannot swap one valid block for another.
* Never roll your own crypto — everything delegates to ``cryptography`` /
  ``argon2-cffi``.

This module never logs, prints, or stringifies key material.
"""

from __future__ import annotations

import hmac
import os
from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .errors import CryptoError

KEY_SIZE = 32  # 256-bit keys
NONCE_SIZE = 12  # AES-GCM-SIV nonce
SALT_SIZE = 16


@dataclass(frozen=True)
class KdfParams:
    """Argon2id parameters. Stored (non-secret) alongside the key file."""

    time_cost: int = 3
    memory_cost_kib: int = 64 * 1024  # 64 MiB
    parallelism: int = 4

    def to_dict(self) -> dict[str, int]:
        return {
            "time_cost": self.time_cost,
            "memory_cost_kib": self.memory_cost_kib,
            "parallelism": self.parallelism,
        }

    @classmethod
    def from_dict(cls, d: dict[str, int]) -> KdfParams:
        try:
            return cls(
                time_cost=int(d["time_cost"]),
                memory_cost_kib=int(d["memory_cost_kib"]),
                parallelism=int(d["parallelism"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise CryptoError("invalid KDF parameters") from exc


def secure_random(n: int) -> bytes:
    """Cryptographically secure random bytes. Never use ``random`` for this."""
    if n <= 0:
        raise ValueError("n must be positive")
    return os.urandom(n)


def new_salt() -> bytes:
    return secure_random(SALT_SIZE)


def new_key() -> bytes:
    return secure_random(KEY_SIZE)


def derive_kek(password: bytes, salt: bytes, params: KdfParams) -> bytes:
    """Derive a 256-bit Key-Encryption-Key from a password using Argon2id."""
    if not password:
        raise CryptoError("password must not be empty")
    if len(salt) != SALT_SIZE:
        raise CryptoError("salt has wrong length")
    return hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost_kib,
        parallelism=params.parallelism,
        hash_len=KEY_SIZE,
        type=Type.ID,
    )


def derive_subkey(master_key: bytes, info: bytes) -> bytes:
    """Derive a purpose-specific 256-bit subkey from the master key via HKDF.

    Using separate subkeys per purpose (chunk id, chunk encryption, metadata,
    state MAC) means a weakness or reuse in one context cannot affect another.
    """
    if len(master_key) != KEY_SIZE:
        raise CryptoError("master key has wrong length")
    hkdf = HKDF(algorithm=SHA256(), length=KEY_SIZE, salt=None, info=info)
    return hkdf.derive(master_key)


def seal(key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """Encrypt ``plaintext`` with ``key`` bound to ``aad``.

    Returns ``(nonce, ciphertext)`` where ciphertext includes the auth tag.
    """
    if len(key) != KEY_SIZE:
        raise CryptoError("encryption key has wrong length")
    nonce = secure_random(NONCE_SIZE)
    ciphertext = AESGCMSIV(key).encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


def open_sealed(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """Decrypt and authenticate. Raises :class:`CryptoError` on any mismatch.

    A wrong key, tampered ciphertext, or wrong ``aad`` all surface here as an
    authentication failure — never as silently corrupt plaintext.
    """
    if len(key) != KEY_SIZE:
        raise CryptoError("decryption key has wrong length")
    if len(nonce) != NONCE_SIZE:
        raise CryptoError("nonce has wrong length")
    try:
        return AESGCMSIV(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise CryptoError(
            "authentication failed (wrong password or corrupt/tampered data)"
        ) from exc


def mac(key: bytes, data: bytes) -> bytes:
    """HMAC-SHA256 of ``data``. Used for content ids and state authentication."""
    h = HMAC(key, SHA256())
    h.update(data)
    return h.finalize()


def mac_verify(key: bytes, data: bytes, expected: bytes) -> bool:
    """Constant-time HMAC verification (resistant to timing attacks)."""
    h = HMAC(key, SHA256())
    h.update(data)
    try:
        h.verify(expected)
        return True
    except Exception:
        return False


def constant_time_equal(a: bytes, b: bytes) -> bool:
    """Timing-safe comparison. Use this instead of ``==`` for tags/hashes."""
    return hmac.compare_digest(a, b)
