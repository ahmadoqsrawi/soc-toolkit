"""
exporters/base.py
-----------------
Exporters consume Findings and write output in a specific format.
"""

from __future__ import annotations

from abc    import ABC, abstractmethod
from typing import Iterator, IO

from soc_toolkit.models.finding import Finding


class BaseExporter(ABC):

    @abstractmethod
    def export(self, findings: Iterator[Finding], stream: IO[str]) -> None:
        """Write findings to stream. stream can be stdout or a file handle."""
        ...
