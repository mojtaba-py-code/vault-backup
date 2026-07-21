"""Repository configuration (non-secret), persisted as ``config.json``."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import FORMAT_VERSION
from .errors import ConfigError
from .store import atomic_write

DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024  # 4 MiB


@dataclass(frozen=True)
class RepoConfig:
    format_version: int = FORMAT_VERSION
    chunk_size: int = DEFAULT_CHUNK_SIZE
    aead: str = "AES-256-GCM-SIV"
    kdf: str = "argon2id"

    def validate(self) -> None:
        if self.format_version != FORMAT_VERSION:
            raise ConfigError(
                f"repository format v{self.format_version} not supported "
                f"(this build understands v{FORMAT_VERSION})"
            )
        if not (64 * 1024 <= self.chunk_size <= 64 * 1024 * 1024):
            raise ConfigError("chunk_size out of allowed range (64 KiB .. 64 MiB)")

    def to_dict(self) -> dict[str, Any]:
        return {
            "format_version": self.format_version,
            "chunk_size": self.chunk_size,
            "aead": self.aead,
            "kdf": self.kdf,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> RepoConfig:
        try:
            cfg = cls(
                format_version=int(d.get("format_version", FORMAT_VERSION)),
                chunk_size=int(d.get("chunk_size", DEFAULT_CHUNK_SIZE)),
                aead=str(d.get("aead", "AES-256-GCM-SIV")),
                kdf=str(d.get("kdf", "argon2id")),
            )
        except (TypeError, ValueError) as exc:
            raise ConfigError("invalid config.json") from exc
        cfg.validate()
        return cfg

    def save(self, path: Path) -> None:
        atomic_write(path, json.dumps(self.to_dict(), indent=2, sort_keys=True).encode("utf-8"))

    @classmethod
    def load(cls, path: Path) -> RepoConfig:
        try:
            return cls.from_dict(json.loads(path.read_bytes().decode("utf-8")))
        except FileNotFoundError as exc:
            raise ConfigError(f"config.json not found: {path}") from exc
        except json.JSONDecodeError as exc:
            raise ConfigError("config.json is not valid JSON") from exc
