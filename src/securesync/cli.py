"""Command-line interface.

Password handling: read from the ``SECURESYNC_PASSWORD`` environment variable if
set, otherwise prompt securely with :func:`getpass.getpass`. The password is
**never** accepted as a command-line argument (it would leak into shell history
and the process list).
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from . import __version__
from .backup import backup
from .config import DEFAULT_CHUNK_SIZE, RepoConfig
from .errors import SecureSyncError, exit_code_for
from .prune import apply_retention, forget, gc
from .repo import Repository
from .restore import restore
from .snapshots import list_snapshot_ids, load_snapshot, resolve_snapshot
from .verify import verify

_ENV_PASSWORD = "SECURESYNC_PASSWORD"  # noqa: S105 - env var name, not a secret


def _get_password(confirm: bool = False) -> bytes:
    env = os.environ.get(_ENV_PASSWORD)
    if env is not None:
        return env.encode("utf-8")
    pw = getpass.getpass("Repository password: ")
    if confirm:
        again = getpass.getpass("Confirm password: ")
        if pw != again:
            raise SecureSyncError("passwords do not match")
    if not pw:
        raise SecureSyncError("password must not be empty")
    return pw.encode("utf-8")


def _cmd_init(args: argparse.Namespace) -> int:
    password = _get_password(confirm=True)
    config = RepoConfig(chunk_size=args.chunk_size)
    Repository.init(Path(args.repo), password, config)
    print(f"Initialized empty securesync repository at {args.repo}")
    print(
        "IMPORTANT: there is no password recovery. If you lose this password, "
        "your backups are permanently unrecoverable."
    )
    return 0


def _cmd_backup(args: argparse.Namespace) -> int:
    repo = Repository.open(Path(args.repo), _get_password())
    with repo.lock():
        parent = None
        if not args.full and list_snapshot_ids(repo):
            parent = resolve_snapshot(repo, "latest")
        snapshot, stats = backup(repo, Path(args.source), args.exclude, parent=parent)
    mode = "full" if parent is None else "incremental"
    print(f"Snapshot {snapshot.snapshot_id} created ({mode}).")
    print(
        f"  files={stats.files} unchanged={stats.files_unchanged} dirs={stats.dirs} "
        f"symlinks={stats.symlinks} chunks_new={stats.chunks_written} "
        f"chunks_deduped={stats.chunks_deduped} bytes_read={stats.bytes_read}"
    )
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    repo = Repository.open(Path(args.repo), _get_password())
    ids = list_snapshot_ids(repo)
    if not ids:
        print("(no snapshots)")
        return 0
    for sid in ids:
        snap = load_snapshot(repo, sid)
        print(f"{sid}  {snap.created_utc}  root={snap.root}  entries={len(snap.entries)}")
    return 0


def _cmd_restore(args: argparse.Namespace) -> int:
    repo = Repository.open(Path(args.repo), _get_password())
    snapshot = resolve_snapshot(repo, args.snapshot)
    stats = restore(repo, snapshot, Path(args.target), overwrite=args.overwrite)
    print(
        f"Restored snapshot {snapshot.snapshot_id}: files={stats.files} "
        f"dirs={stats.dirs} symlinks={stats.symlinks} bytes={stats.bytes_written}"
    )
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    repo = Repository.open(Path(args.repo), _get_password())
    report = verify(repo, deep=not args.fast)
    print(
        f"Checked {report.snapshots_checked} snapshot(s), "
        f"{report.chunks_checked} chunk(s)."
    )
    if report.ok:
        print("Integrity OK.")
        return 0
    for cid in report.missing_chunks:
        print(f"MISSING chunk: {cid}")
    for cid in report.corrupt_chunks:
        print(f"CORRUPT chunk: {cid}")
    for sid in report.corrupt_snapshots:
        print(f"CORRUPT snapshot (failed authentication): {sid}")
    for sid in report.state_missing:
        print(f"MISSING snapshot (in state, not on disk): {sid}")
    for sid in report.state_extra:
        print(f"UNREGISTERED snapshot (on disk, not in state): {sid}")
    return 4


def _cmd_forget(args: argparse.Namespace) -> int:
    repo = Repository.open(Path(args.repo), _get_password())
    with repo.lock():
        removed = forget(repo, args.snapshot)
        gc_stats = gc(repo) if args.prune else None
    print(f"Forgot {len(removed)} snapshot(s).")
    if gc_stats is not None:
        print(f"  gc: removed {gc_stats.chunks_removed} chunk(s), kept {gc_stats.chunks_kept}.")
    return 0


def _cmd_prune(args: argparse.Namespace) -> int:
    repo = Repository.open(Path(args.repo), _get_password())
    with repo.lock():
        forgotten = apply_retention(repo, args.keep_last)
        gc_stats = gc(repo)
    print(f"Retention: forgot {len(forgotten)} snapshot(s), kept last {args.keep_last}.")
    print(f"  gc: removed {gc_stats.chunks_removed} chunk(s), kept {gc_stats.chunks_kept}.")
    return 0


def _cmd_gc(args: argparse.Namespace) -> int:
    repo = Repository.open(Path(args.repo), _get_password())
    with repo.lock():
        gc_stats = gc(repo)
    print(
        f"gc: {gc_stats.chunks_before} chunk(s) scanned, "
        f"{gc_stats.chunks_removed} removed, {gc_stats.chunks_kept} kept."
    )
    return 0


def _cmd_passwd(args: argparse.Namespace) -> int:
    repo_path = Path(args.repo)
    old = getpass.getpass("Current password: ").encode("utf-8")
    repo = Repository.open(repo_path, old)  # verifies old password
    new1 = getpass.getpass("New password: ")
    new2 = getpass.getpass("Confirm new password: ")
    if new1 != new2:
        raise SecureSyncError("passwords do not match")
    repo.change_password(old, new1.encode("utf-8"))
    print("Password changed. (Backup data was not re-encrypted.)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="securesync", description=__doc__)
    p.add_argument("--version", action="version", version=f"securesync {__version__}")
    p.add_argument("--repo", required=True, help="path to the repository")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("init", help="create a new repository")
    sp.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE)
    sp.set_defaults(func=_cmd_init)

    sp = sub.add_parser("backup", help="back up a directory")
    sp.add_argument("source", help="directory to back up")
    sp.add_argument("--exclude", action="append", default=[], help="glob to exclude (repeatable)")
    sp.add_argument(
        "--full", action="store_true", help="re-read every file (disable incremental reuse)"
    )
    sp.set_defaults(func=_cmd_backup)

    sp = sub.add_parser("list", help="list snapshots")
    sp.set_defaults(func=_cmd_list)

    sp = sub.add_parser("restore", help="restore a snapshot")
    sp.add_argument("snapshot", help="snapshot id or 'latest'")
    sp.add_argument("target", help="destination directory")
    sp.add_argument("--overwrite", action="store_true", help="allow non-empty target")
    sp.set_defaults(func=_cmd_restore)

    sp = sub.add_parser("verify", help="check repository integrity")
    sp.add_argument("--fast", action="store_true", help="only check chunks exist")
    sp.set_defaults(func=_cmd_verify)

    sp = sub.add_parser("forget", help="delete specific snapshots")
    sp.add_argument("snapshot", nargs="+", help="snapshot id(s) to forget")
    sp.add_argument("--prune", action="store_true", help="also garbage-collect freed chunks")
    sp.set_defaults(func=_cmd_forget)

    sp = sub.add_parser("prune", help="apply retention (keep last N) and garbage-collect")
    sp.add_argument(
        "--keep-last", type=int, required=True, help="number of recent snapshots to keep"
    )
    sp.set_defaults(func=_cmd_prune)

    sp = sub.add_parser("gc", help="garbage-collect unreferenced chunks")
    sp.set_defaults(func=_cmd_gc)

    sp = sub.add_parser("passwd", help="change the repository password")
    sp.set_defaults(func=_cmd_passwd)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except SecureSyncError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exit_code_for(exc)
    except KeyboardInterrupt:
        print("aborted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
