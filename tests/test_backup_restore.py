from __future__ import annotations

import os
from pathlib import Path

import pytest

from securesync.backup import backup
from securesync.repo import Repository
from securesync.restore import restore
from securesync.snapshots import list_snapshot_ids, resolve_snapshot

PW = b"test-password"


def _make_tree(root: Path) -> None:
    (root / "sub").mkdir(parents=True)
    (root / "a.txt").write_bytes(b"hello alpha\n")
    (root / "sub" / "b.bin").write_bytes(os.urandom(10 * 1024 * 1024))  # spans chunks
    (root / "sub" / "c.txt").write_text("some text content", encoding="utf-8")
    (root / "empty").mkdir()


def _read_all(root: Path) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for p in sorted(root.rglob("*")):
        if p.is_file():
            out[p.relative_to(root).as_posix()] = p.read_bytes()
    return out


def test_backup_restore_roundtrip_byte_for_byte(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    _make_tree(src)

    repo = Repository.init(tmp_path / "repo", PW)
    snap, stats = backup(repo, src)
    assert stats.files == 3

    dest = tmp_path / "restored"
    restore(repo, snap, dest)

    assert _read_all(src) == _read_all(dest)


def test_reopen_repo_and_restore_latest(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "f.txt").write_text("data", encoding="utf-8")

    repo = Repository.init(tmp_path / "repo", PW)
    backup(repo, src)

    repo2 = Repository.open(tmp_path / "repo", PW)
    snap = resolve_snapshot(repo2, "latest")
    dest = tmp_path / "out"
    restore(repo2, snap, dest)
    assert (dest / "f.txt").read_text(encoding="utf-8") == "data"


def test_dedup_second_backup_writes_no_new_chunks(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "big.bin").write_bytes(os.urandom(8 * 1024 * 1024))

    repo = Repository.init(tmp_path / "repo", PW)
    _, s1 = backup(repo, src)
    _, s2 = backup(repo, src)  # identical content

    assert s1.chunks_written > 0
    assert s2.chunks_written == 0
    assert s2.chunks_deduped == s1.chunks_written


def test_exclude_patterns(tmp_path: Path):
    src = tmp_path / "src"
    (src / ".git").mkdir(parents=True)
    (src / ".git" / "config").write_text("x", encoding="utf-8")
    (src / "keep.txt").write_text("y", encoding="utf-8")
    (src / "tmp.tmp").write_text("z", encoding="utf-8")

    repo = Repository.init(tmp_path / "repo", PW)
    snap, _ = backup(repo, src, excludes=[".git/", "*.tmp"])
    paths = {e.path for e in snap.entries}
    assert "keep.txt" in paths
    assert not any(p.startswith(".git") for p in paths)
    assert "tmp.tmp" not in paths


def test_two_snapshots_listed(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "f").write_text("1", encoding="utf-8")
    repo = Repository.init(tmp_path / "repo", PW)
    backup(repo, src)
    (src / "f").write_text("2", encoding="utf-8")
    backup(repo, src)
    assert len(list_snapshot_ids(repo)) == 2


def test_restore_refuses_nonempty_target(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "f").write_text("1", encoding="utf-8")
    repo = Repository.init(tmp_path / "repo", PW)
    snap, _ = backup(repo, src)
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "existing").write_text("x", encoding="utf-8")
    from securesync.errors import RestoreError

    with pytest.raises(RestoreError):
        restore(repo, snap, dest)
