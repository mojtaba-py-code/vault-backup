"""Compression helpers.

Order matters: compress **before** encrypting. Encrypted data is
indistinguishable from random and does not compress.

We use stdlib ``zlib`` to avoid an extra dependency. The block ``alg_id`` /
format version leaves room to switch to zstd later without breaking old data.
"""

from __future__ import annotations

import zlib

from .errors import IntegrityError

# Guard against decompression bombs: refuse to inflate beyond this size.
MAX_DECOMPRESSED = 512 * 1024 * 1024  # 512 MiB per chunk is far above any real chunk


def compress(data: bytes, level: int = 6) -> bytes:
    return zlib.compress(data, level)


def decompress(data: bytes, *, max_size: int = MAX_DECOMPRESSED) -> bytes:
    """Inflate ``data`` with a hard output-size cap (decompression-bomb guard)."""
    decompressor = zlib.decompressobj()
    try:
        out = decompressor.decompress(data, max_size)
        if decompressor.unconsumed_tail:
            raise IntegrityError("decompressed output exceeds safety limit")
        out += decompressor.flush()
    except zlib.error as exc:
        raise IntegrityError("corrupt compressed data") from exc
    return out
