"""On-disk binary format for a sealed (encrypted) block.

Layout::

    ┌────────┬─────────┬────────┬───────────┬─────────────────────┐
    │ magic  │ version │ alg_id │  nonce    │ ciphertext (+ tag)  │
    │ 4 B    │ 1 B     │ 1 B    │ 12 B      │  variable           │
    └────────┴─────────┴────────┴───────────┴─────────────────────┘

* ``magic`` guards against feeding a wrong/foreign file to the parser.
* ``version`` allows evolving the container without breaking old backups.
* ``alg_id`` gives crypto-agility: the algorithm can change later while old
  blocks remain readable.

The parser is deliberately strict and total: any malformed input raises
:class:`IntegrityError` rather than crashing (it is fuzz-tested).
"""

from __future__ import annotations

from .crypto import NONCE_SIZE, open_sealed, seal
from .errors import IntegrityError

MAGIC = b"SSB1"
BLOCK_VERSION = 1

ALG_AES256_GCM_SIV = 1
_SUPPORTED_ALGS = {ALG_AES256_GCM_SIV}

_HEADER_LEN = len(MAGIC) + 1 + 1 + NONCE_SIZE


def pack(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """Encrypt ``plaintext`` and serialize it into a self-describing block."""
    nonce, ciphertext = seal(key, plaintext, aad)
    return MAGIC + bytes([BLOCK_VERSION, ALG_AES256_GCM_SIV]) + nonce + ciphertext


def unpack(key: bytes, blob: bytes, aad: bytes) -> bytes:
    """Parse and decrypt a block produced by :func:`pack`.

    Raises :class:`IntegrityError` for structural problems and
    :class:`~securesync.errors.CryptoError` for authentication failures.
    """
    if len(blob) < _HEADER_LEN:
        raise IntegrityError("block too short")
    if blob[: len(MAGIC)] != MAGIC:
        raise IntegrityError("bad magic bytes (not a securesync block)")
    offset = len(MAGIC)
    version = blob[offset]
    alg_id = blob[offset + 1]
    offset += 2
    if version != BLOCK_VERSION:
        raise IntegrityError(f"unsupported block version: {version}")
    if alg_id not in _SUPPORTED_ALGS:
        raise IntegrityError(f"unsupported algorithm id: {alg_id}")
    nonce = blob[offset : offset + NONCE_SIZE]
    ciphertext = blob[offset + NONCE_SIZE :]
    if not ciphertext:
        raise IntegrityError("block has no ciphertext")
    return open_sealed(key, nonce, ciphertext, aad)
