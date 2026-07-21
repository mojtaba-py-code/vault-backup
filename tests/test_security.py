from __future__ import annotations

from pathlib import Path

import pytest

from securesync.backup import backup
from securesync.errors import CryptoError, RepositoryError, RestoreError
from securesync.repo import Repository
from securesync.restore import _safe_join, restore
from securesync.verify import verify

PW = b"pw"


def test_path_traversal_rejected(tmp_path: Path):
    with pytest.raises(RestoreError):
        _safe_join(tmp_path, "../../etc/passwd")
    with pytest.raises(RestoreError):
        _safe_join(tmp_path, "/absolute/evil")


def test_safe_join_allows_normal(tmp_path: Path):
    dest = _safe_join(tmp_path, "sub/dir/file.txt")
    assert str(tmp_path.resolve()) in str(dest)


def test_wrong_password_cannot_open_repo(tmp_path: Path):
    Repository.init(tmp_path / "repo", PW)
    with pytest.raises(CryptoError):
        Repository.open(tmp_path / "repo", b"not-the-password")


def test_chunk_substitution_detected(tmp_path: Path):
    """Swapping one valid chunk's bytes for another's must fail on restore
    because the AAD binds each ciphertext to its own chunk id."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "a").write_text("aaaa", encoding="utf-8")
    (src / "b").write_text("bbbb", encoding="utf-8")
    repo = Repository.init(tmp_path / "repo", PW)
    snap, _ = backup(repo, src)

    ids = repo.chunks.list_keys()
    assert len(ids) == 2
    # Overwrite chunk ids[0] with the ciphertext stored for ids[1].
    repo.chunks.put(ids[0], repo.chunks.get(ids[1]))

    dest = tmp_path / "out"
    with pytest.raises(CryptoError):
        restore(repo, snap, dest, overwrite=True)


def test_verify_detects_corruption(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "f").write_text("payload", encoding="utf-8")
    repo = Repository.init(tmp_path / "repo", PW)
    backup(repo, src)

    assert verify(repo).ok

    cid = repo.chunks.list_keys()[0]
    blob = bytearray(repo.chunks.get(cid))
    blob[-1] ^= 0x01  # flip a bit
    repo.chunks.put(cid, bytes(blob))

    report = verify(repo)
    assert not report.ok
    assert cid in report.corrupt_chunks


def test_verify_detects_missing_chunk(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "f").write_text("payload", encoding="utf-8")
    repo = Repository.init(tmp_path / "repo", PW)
    backup(repo, src)
    repo.chunks.delete(repo.chunks.list_keys()[0])
    report = verify(repo)
    assert report.missing_chunks


def test_tampered_manifest_fails_to_load(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "f").write_text("x", encoding="utf-8")
    repo = Repository.init(tmp_path / "repo", PW)
    snap, _ = backup(repo, src)

    snap_path = repo.snapshots_dir / f"{snap.snapshot_id}.snap"
    data = bytearray(snap_path.read_bytes())
    data[-1] ^= 0x01
    snap_path.write_bytes(bytes(data))

    from securesync.snapshots import load_snapshot

    with pytest.raises(CryptoError):
        load_snapshot(repo, snap.snapshot_id)


def test_lock_prevents_concurrent_ops(tmp_path: Path):
    repo = Repository.init(tmp_path / "repo", PW)
    with repo.lock():
        with pytest.raises(RepositoryError):
            with repo.lock():
                pass


def test_symlink_not_followed(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "real.txt").write_text("real", encoding="utf-8")
    try:
        (src / "link").symlink_to(src / "real.txt")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted on this platform")

    repo = Repository.init(tmp_path / "repo", PW)
    snap, _ = backup(repo, src)
    link_entry = next(e for e in snap.entries if e.path == "link")
    assert link_entry.kind == "symlink"
    assert link_entry.symlink_target is not None
