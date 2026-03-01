"""KryptosBot configuration and data types."""

from __future__ import annotations

from enum import Enum


class HypothesisStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    PROMISING = "promising"
    DISPROVED = "disproved"
    INCONCLUSIVE = "inconclusive"
    SOLVED = "solved"
