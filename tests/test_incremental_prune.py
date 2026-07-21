from __future__ import annotations

import os
from pathlib import Path

from securesync.backup import backup
from securesync.prune import apply_retention, forget, gc, referenced_chunks
from securesync.repo import Repository
from securesync.restore import restore
from securesync.snapshots import list_snapshot_ids, resolve_snapshot

PW = b"pw"


def test_incremental_skips_unchanged_files(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.bin").write_bytes(os.urandom(4 * 1024 * 1024))
    (src / "b.txt").write_text("hello", encoding="utf-8")

    repo = Repository.init(tmp_path / "repo", PW)
    parent, _ = backup(repo, src)

    # Change only b.txt; a.bin untouched.
    (src / "b.txt").write_text("changed", encoding="utf-8")
    snap, stats = backup(repo, src, parent=parent)

    assert stats.files == 2
    assert stats.files_unchanged == 1  # a.bin reused
    assert stats.bytes_read < 1024 * 1024  # only the small changed file was read


def test_incremental_restore_is_correct(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "keep.bin").write_bytes(os.urandom(2 * 1024 * 1024))
    (src / "edit.txt").write_text("v1", encoding="utf-8")

    repo = Repository.init(tmp_path / "repo", PW)
    parent, _ = backup(repo, src)
    (src / "edit.txt").write_text("v2 content", encoding="utf-8")
    snap, _ = backup(repo, src, parent=parent)

    out = tmp_path / "out"
    restore(repo, snap, out)
    assert (out / "edit.txt").read_text(encoding="utf-8") == "v2 content"
    assert (out / "keep.bin").read_bytes() == (src / "keep.bin").read_bytes()


def test_forget_removes_snapshot(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "f").write_text("1", encoding="utf-8")
    repo = Repository.init(tmp_path / "repo", PW)
    s1, _ = backup(repo, src)
    (src / "f").write_text("2", encoding="utf-8")
    backup(repo, src)

    assert len(list_snapshot_ids(repo)) == 2
    forget(repo, [s1.snapshot_id])
    assert s1.snapshot_id not in list_snapshot_ids(repo)
    assert len(list_snapshot_ids(repo)) == 1


def test_gc_removes_only_unreferenced_chunks(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "shared").write_bytes(b"shared-content")
    (src / "unique1").write_bytes(b"unique-to-snap1")
    repo = Repository.init(tmp_path / "repo", PW)
    s1, _ = backup(repo, src)

    (src / "unique1").unlink()
    (src / "unique2").write_bytes(b"unique-to-snap2")
    backup(repo, src, parent=s1)

    before = len(repo.chunks.list_keys())
    forget(repo, [s1.snapshot_id])
    stats = gc(repo)

    # The chunk unique to snap1 is gone; shared + unique2 remain.
    assert stats.chunks_removed == 1
    assert set(repo.chunks.list_keys()) == referenced_chunks(repo)
    assert len(repo.chunks.list_keys()) == before - 1


def test_gc_keeps_everything_when_all_referenced(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "f").write_bytes(b"data")
    repo = Repository.init(tmp_path / "repo", PW)
    backup(repo, src)
    stats = gc(repo)
    assert stats.chunks_removed == 0


def test_retention_keeps_last_n(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    repo = Repository.init(tmp_path / "repo", PW)
    parent = None
    for i in range(5):
        (src / "f").write_text(f"version-{i}", encoding="utf-8")
        parent, _ = backup(repo, src, parent=parent)

    assert len(list_snapshot_ids(repo)) == 5
    forgotten = apply_retention(repo, keep_last=2)
    assert len(forgotten) == 3
    assert len(list_snapshot_ids(repo)) == 2
    # Surviving snapshots still restore correctly.
    snap = resolve_snapshot(repo, "latest")
    out = tmp_path / "out"
    restore(repo, snap, out)
    assert (out / "f").read_text(encoding="utf-8") == "version-4"
