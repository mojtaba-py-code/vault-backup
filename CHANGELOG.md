# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Contributing guide describing the exact checks CI runs.
- Compression tests: round-trip, corrupted input, and the decompression-bomb guard.
- Security job running `bandit` and `pip-audit`, so a CVE in the resolved
  dependency tree fails the build.
- Weekly scheduled pipeline run, so an advisory published after the last commit
  still turns the build red.
- Dependency-free secret scan that fails the build on a committed private key
  block or provider token.
- Coverage floor of 80% on the test job.
- `.mailmap` collapsing the two spellings of the author into one identity.

### Changed

- Repository links and project naming aligned with the `vault-backup` repository
  name; README badges expanded.
- README shows a real backup, incremental re-run, verify and restore session.
- GitHub Actions pinned to commit SHAs and the workflow token scoped to
  `contents: read`.
- Dependency floors raised past releases with published CVEs.
- `.gitignore` now excludes local backup repositories, key files and
  certificates, so a test vault or exported key cannot be committed by accident.
- Licence and package metadata credit the full copyright holder name.

### Fixed

- `securesync --version` and the package metadata reported `0.1.0`, a lower
  number than the released 1.0.0.

## [1.0.0] - 2026-07-22

### Added

- Initial release of `securesync`: an encrypted, deduplicating backup and
  restore CLI.
- AES-256-GCM-SIV authenticated encryption with per-chunk AAD binding.
- Two-tier keys: a random master key wrapped by an Argon2id-derived KEK, so a
  password change never re-encrypts the data.
- Keyed deduplication — chunk ids are `HMAC(subkey, plaintext)`.
- Incremental backups, retention (`prune`), mark-and-sweep `gc`, and `verify`
  over chunks and the authenticated snapshot registry.
- Crash-safe atomic writes and an advisory repository lock.
- Path-traversal-safe restores; symlinks recorded but never followed.
- CI matrix across Linux, Windows and macOS on Python 3.11 and 3.12.

[Unreleased]: https://github.com/mojtaba-py-code/vault-backup/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/mojtaba-py-code/vault-backup/releases/tag/v1.0.0
