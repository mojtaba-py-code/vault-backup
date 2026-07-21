from __future__ import annotations

from pathlib import Path

import pytest

from securesync.backup import backup
from securesync.errors import CryptoError
from securesync.repo import Repository
from securesync.state import load_state, save_state
from securesync.verify import verify

PW = b"pw"


def _repo_with_snapshot(tmp_path: Path) -> tuple[Repository, str]:
    src = tmp_path / "src"
    src.mkdir()
    (src / "f").write_text("data", encoding="utf-8")
    repo = Repository.init(tmp_path / "repo", PW)
    snap, _ = backup(repo, src)
    return repo, snap.snapshot_id


def test_state_records_snapshots(tmp_path: Path):
    repo, sid = _repo_with_snapshot(tmp_path)
    state = load_state(repo)
    assert state is not None
    assert sid in state.snapshot_ids
    assert state.counter >= 1


def test_verify_detects_deleted_snapshot(tmp_path: Path):
    """Deleting a snapshot file behind the tool's back is caught by state check."""
    repo, sid = _repo_with_snapshot(tmp_path)
    (repo.snapshots_dir / f"{sid}.snap").unlink()  # bypass forget()
    report = verify(repo)
    assert not report.ok
    assert sid in report.state_missing


def test_verify_detects_injected_snapshot(tmp_path: Path):
    repo, sid = _repo_with_snapshot(tmp_path)
    # Copy the valid snapshot under a new id (an "injected" snapshot).
    blob = (repo.snapshots_dir / f"{sid}.snap").read_bytes()
    (repo.snapshots_dir / "99999999T999999999999Z.snap").write_bytes(blob)
    report = verify(repo)
    assert not report.ok
    assert report.state_extra


def test_tampered_state_file_fails(tmp_path: Path):
    repo, _ = _repo_with_snapshot(tmp_path)
    data = bytearray(repo.state_path.read_bytes())
    data[-1] ^= 0x01
    repo.state_path.write_bytes(bytes(data))
    with pytest.raises(CryptoError):
        load_state(repo)


def test_state_survives_reopen(tmp_path: Path):
    repo, sid = _repo_with_snapshot(tmp_path)
    repo2 = Repository.open(tmp_path / "repo", PW)
    state = load_state(repo2)
    assert state is not None and sid in state.snapshot_ids
    save_state(repo2, state)  # smoke: re-seal works after reopen
