from __future__ import annotations

from pathlib import Path

import pytest

from securesync.errors import StorageError
from securesync.store import LocalBackend, atomic_write


def test_atomic_write_creates_file(tmp_path: Path):
    target = tmp_path / "nested" / "file.bin"
    atomic_write(target, b"data")
    assert target.read_bytes() == b"data"


def test_atomic_write_overwrites(tmp_path: Path):
    target = tmp_path / "file.bin"
    atomic_write(target, b"old")
    atomic_write(target, b"new")
    assert target.read_bytes() == b"new"
    # No leftover temp files.
    assert [p.name for p in tmp_path.iterdir()] == ["file.bin"]


def test_localbackend_roundtrip(tmp_path: Path):
    be = LocalBackend(tmp_path / "store")
    be.put("abcd1234", b"payload")
    assert be.exists("abcd1234")
    assert be.get("abcd1234") == b"payload"
    assert be.list_keys() == ["abcd1234"]
    be.delete("abcd1234")
    assert not be.exists("abcd1234")


def test_localbackend_rejects_bad_key(tmp_path: Path):
    be = LocalBackend(tmp_path / "store")
    for bad in ("a", "../evil", "..", "a/b"):
        with pytest.raises(StorageError):
            be.put(bad, b"x")
