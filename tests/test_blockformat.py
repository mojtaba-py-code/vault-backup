from __future__ import annotations

import os

import pytest

from securesync import blockformat, crypto
from securesync.errors import CryptoError, IntegrityError


def test_pack_unpack_roundtrip():
    key = crypto.new_key()
    blob = blockformat.pack(key, b"payload", b"aad")
    assert blob[:4] == blockformat.MAGIC
    assert blockformat.unpack(key, blob, b"aad") == b"payload"


def test_bad_magic():
    key = crypto.new_key()
    blob = bytearray(blockformat.pack(key, b"x", b"aad"))
    blob[0] ^= 0xFF
    with pytest.raises(IntegrityError):
        blockformat.unpack(key, bytes(blob), b"aad")


def test_truncated_block():
    key = crypto.new_key()
    blob = blockformat.pack(key, b"x", b"aad")
    with pytest.raises(IntegrityError):
        blockformat.unpack(key, blob[:5], b"aad")


def test_unsupported_version():
    key = crypto.new_key()
    blob = bytearray(blockformat.pack(key, b"x", b"aad"))
    blob[4] = 99  # version byte
    with pytest.raises(IntegrityError):
        blockformat.unpack(key, bytes(blob), b"aad")


def test_fuzz_parser_never_crashes():
    """Random garbage must raise a typed error, never crash the parser."""
    key = crypto.new_key()
    for _ in range(500):
        blob = os.urandom(int.from_bytes(os.urandom(1), "big"))
        with pytest.raises((IntegrityError, CryptoError)):
            blockformat.unpack(key, blob, b"aad")
