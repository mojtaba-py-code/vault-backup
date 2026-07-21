"""File chunking.

v1 uses fixed-size chunks read in a streaming fashion, so a 10 GB file never
loads fully into RAM. The block format leaves room to switch to content-defined
chunking (FastCDC) later for better incremental dedup.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path


def iter_chunks(path: Path, chunk_size: int) -> Iterator[bytes]:
    """Yield successive fixed-size byte chunks of ``path`` (last may be short)."""
    with open(path, "rb") as f:
        while True:
            block = f.read(chunk_size)
            if not block:
                break
            yield block
