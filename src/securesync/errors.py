"""Typed error hierarchy for securesync.

Every failure the tool raises inherits from :class:`SecureSyncError`, so callers
(and the CLI) can map error classes to exit codes cleanly.
"""

from __future__ import annotations


class SecureSyncError(Exception):
    """Base class for all securesync errors."""


class ConfigError(SecureSyncError):
    """Invalid or missing configuration."""


class CryptoError(SecureSyncError):
    """Encryption/decryption or key-derivation failure.

    Raised for a wrong password, a tampered/corrupt block, or an unsupported
    algorithm id. The message intentionally never contains key material.
    """


class IntegrityError(SecureSyncError):
    """A stored object failed an integrity/authentication check."""


class StorageError(SecureSyncError):
    """A storage backend could not complete an operation."""


class RepositoryError(SecureSyncError):
    """The repository is missing, locked, or structurally invalid."""


class RestoreError(SecureSyncError):
    """A restore could not be completed safely (e.g. unsafe path)."""


# Exit codes returned by the CLI, keyed by error type.
EXIT_CODES: dict[type[BaseException], int] = {
    ConfigError: 2,
    CryptoError: 3,
    IntegrityError: 4,
    StorageError: 5,
    RepositoryError: 6,
    RestoreError: 7,
    SecureSyncError: 1,
}


def exit_code_for(exc: BaseException) -> int:
    """Return the process exit code for a raised exception."""
    for cls in type(exc).__mro__:
        if cls in EXIT_CODES:
            return EXIT_CODES[cls]
    return 1
