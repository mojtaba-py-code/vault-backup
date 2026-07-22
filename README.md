# securesync 🔐

[![CI](https://github.com/mojtaba-py-code/vault_back/actions/workflows/ci.yml/badge.svg)](https://github.com/mojtaba-py-code/vault_back/actions/workflows/ci.yml)

A secure, encrypted, deduplicating backup & restore tool (CLI).

Data is encrypted **before** it is written to the repository. A stolen backup
repository reveals nothing without the password.

## Security properties

- **AES-256-GCM-SIV** authenticated encryption (nonce-misuse resistant).
- **Two-tier keys:** a random master key encrypts data; it is wrapped by a
  Key-Encryption-Key derived from your password with **Argon2id**. Changing the
  password never re-encrypts your data.
- **Per-chunk AAD binding:** each ciphertext is tied to its own chunk id, so
  chunks cannot be swapped or reordered undetectably.
- **Keyed deduplication:** chunk ids are `HMAC(subkey, plaintext)`, so an
  outsider cannot confirm which files a repository holds.
- **Crash-safe writes:** temp file + fsync + atomic replace; chunks are durable
  before any manifest references them.
- **Safe restores:** path-traversal and absolute paths are rejected; symlinks
  are recorded but never followed during backup.
- **Authenticated snapshot registry:** an encrypted, MAC-protected state file
  records the valid snapshot set, so deleting or injecting a snapshot behind the
  tool's back is detected by `verify`.
- **Incremental backups** reuse unchanged files (by path/size/mtime); **prune**
  applies retention and **safe mark-and-sweep GC** never deletes a chunk that a
  surviving snapshot still references.

## ⚠️ There is no password recovery

If you lose your password, your backups are **permanently unrecoverable** by
design. There is no backdoor. Store the password safely.

## Install

```bash
pip install -e ".[dev]"
```

## Usage

```bash
# Create a repository
securesync --repo /path/to/repo init

# Back up a directory (incremental by default: unchanged files are reused)
securesync --repo /path/to/repo backup /path/to/data --exclude "*.tmp" --exclude ".git/"
securesync --repo /path/to/repo backup /path/to/data --full   # force full re-read

# List snapshots
securesync --repo /path/to/repo list

# Restore the latest snapshot (or a specific snapshot id)
securesync --repo /path/to/repo restore latest /path/to/output

# Verify integrity (chunks + snapshot registry)
securesync --repo /path/to/repo verify

# Retention: keep the last 7 snapshots, delete + garbage-collect the rest
securesync --repo /path/to/repo prune --keep-last 7

# Forget specific snapshots (optionally reclaim space)
securesync --repo /path/to/repo forget <snapshot-id> --prune

# Reclaim space from unreferenced chunks
securesync --repo /path/to/repo gc

# Change password (does not re-encrypt data)
securesync --repo /path/to/repo passwd
```

The password is read from the `SECURESYNC_PASSWORD` environment variable if set,
otherwise prompted securely. It is never taken as a command-line argument.

## Development

```bash
pytest            # run tests
ruff check .      # lint (incl. security rules)
mypy src          # type-check
```
