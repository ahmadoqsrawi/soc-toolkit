"""
parsers/base.py
---------------
The parser contract. Every log format gets its own BaseParser subclass.
No parser is allowed to return a list — only iterators. This enforces
streaming-safe behavior from the start.
"""

from __future__ import annotations

import gzip
import bz2
import lzma
from abc       import ABC, abstractmethod
from pathlib   import Path
from typing    import Iterator

from soc_toolkit.models.event import Event


class BaseParser(ABC):

    @abstractmethod
    def can_parse(self, path: Path) -> bool:
        """
        Return True if this parser can handle the given file.
        Used by the router to auto-select the right parser.
        Implementations should check file extension and/or magic bytes.
        """
        ...

    @abstractmethod
    def parse(self, path: Path) -> Iterator[Event]:
        """
        Yield normalized Event objects one at a time.
        Must never load the entire file into memory.
        """
        ...

    # ------------------------------------------------------------------
    # Shared helpers available to all parsers
    # ------------------------------------------------------------------

    def open(self, path: Path):
        """
        Transparent open — handles plain text, .gz, .bz2, and .xz files
        automatically. All parsers call this instead of open() directly.
        """
        suffix = path.suffix.lower()
        if suffix == '.gz':
            return gzip.open(path, 'rt', errors='replace')
        if suffix == '.bz2':
            return bz2.open(path, 'rt', errors='replace')
        if suffix in ('.xz', '.lzma'):
            return lzma.open(path, 'rt', errors='replace')
        return open(path, 'r', errors='replace')
