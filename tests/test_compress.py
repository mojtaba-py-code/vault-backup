from __future__ import annotations

import pytest

from securesync import compress
from securesync.errors import IntegrityError


def test_compress_decompress_roundtrip():
    data = b"the quick brown fox " * 50
    assert compress.decompress(compress.compress(data)) == data


def test_empty_roundtrip():
    assert compress.decompress(compress.compress(b"")) == b""


def test_incompressible_data_roundtrips():
    # High-entropy input barely compresses, but must still survive a roundtrip.
    data = bytes(range(256)) * 8
    assert compress.decompress(compress.compress(data)) == data


def test_corrupt_data_raises_integrity_error():
    with pytest.raises(IntegrityError):
        compress.decompress(b"this is not valid zlib data")


def test_decompression_bomb_is_capped():
    # A tiny compressed payload that inflates far past the allowed size must be
    # rejected rather than silently expanded (decompression-bomb guard).
    bomb = compress.compress(b"\x00" * 100_000)
    with pytest.raises(IntegrityError):
        compress.decompress(bomb, max_size=100)
