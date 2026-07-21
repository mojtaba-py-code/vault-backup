"""End-to-end CLI tests driving ``main()`` in-process."""

from __future__ import annotations

from pathlib import Path

import pytest

from securesync.cli import main


def test_cli_full_flow(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repo, src, out = tmp_path / "repo", tmp_path / "src", tmp_path / "out"
    (src / "sub").mkdir(parents=True)
    (src / "f.txt").write_text("hello", encoding="utf-8")
    (src / "sub" / "g.bin").write_bytes(b"\x00\x01\x02" * 100000)
    (src / "skip.tmp").write_text("junk", encoding="utf-8")
    monkeypatch.setenv("SECURESYNC_PASSWORD", "pw")

    assert main(["--repo", str(repo), "init"]) == 0
    assert main(["--repo", str(repo), "backup", str(src), "--exclude", "*.tmp"]) == 0
    assert main(["--repo", str(repo), "list"]) == 0
    assert main(["--repo", str(repo), "verify"]) == 0
    assert main(["--repo", str(repo), "restore", "latest", str(out)]) == 0

    assert (out / "f.txt").read_text(encoding="utf-8") == "hello"
    assert (out / "sub" / "g.bin").read_bytes() == b"\x00\x01\x02" * 100000
    assert not (out / "skip.tmp").exists()


def test_cli_wrong_password_exit_code(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repo = tmp_path / "repo"
    monkeypatch.setenv("SECURESYNC_PASSWORD", "pw")
    assert main(["--repo", str(repo), "init"]) == 0
    monkeypatch.setenv("SECURESYNC_PASSWORD", "wrong")
    assert main(["--repo", str(repo), "list"]) == 3  # CryptoError exit code


def test_cli_prune_and_gc(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repo, src = tmp_path / "repo", tmp_path / "src"
    src.mkdir()
    monkeypatch.setenv("SECURESYNC_PASSWORD", "pw")
    assert main(["--repo", str(repo), "init"]) == 0
    for i in range(3):
        (src / "f").write_text(f"version-{i}", encoding="utf-8")
        assert main(["--repo", str(repo), "backup", str(src)]) == 0
    assert main(["--repo", str(repo), "prune", "--keep-last", "1"]) == 0
    assert main(["--repo", str(repo), "gc"]) == 0
    assert main(["--repo", str(repo), "verify"]) == 0


def test_cli_change_password(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repo = tmp_path / "repo"
    monkeypatch.setenv("SECURESYNC_PASSWORD", "old-pw")
    assert main(["--repo", str(repo), "init"]) == 0

    # passwd prompts via getpass; feed it (current, new, confirm).
    monkeypatch.delenv("SECURESYNC_PASSWORD", raising=False)
    answers = iter(["old-pw", "new-pw", "new-pw"])
    monkeypatch.setattr("securesync.cli.getpass.getpass", lambda *a, **k: next(answers))
    assert main(["--repo", str(repo), "passwd"]) == 0

    # The new password now works; the old one does not.
    monkeypatch.setenv("SECURESYNC_PASSWORD", "new-pw")
    assert main(["--repo", str(repo), "verify"]) == 0
    monkeypatch.setenv("SECURESYNC_PASSWORD", "old-pw")
    assert main(["--repo", str(repo), "verify"]) == 3


def test_cli_forget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repo, src = tmp_path / "repo", tmp_path / "src"
    src.mkdir()
    monkeypatch.setenv("SECURESYNC_PASSWORD", "pw")
    main(["--repo", str(repo), "init"])
    (src / "f").write_text("a", encoding="utf-8")
    main(["--repo", str(repo), "backup", str(src)])

    from securesync.repo import Repository
    from securesync.snapshots import list_snapshot_ids

    sid = list_snapshot_ids(Repository.open(repo, b"pw"))[0]
    assert main(["--repo", str(repo), "forget", sid, "--prune"]) == 0
    assert main(["--repo", str(repo), "verify"]) == 0
