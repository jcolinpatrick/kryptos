"""
Configuration for KryptosBot.

Contains K4 ciphertext, known plaintext cribs, hypothesis status lifecycle,
and runtime tuning parameters.

PARADIGM (2026-03-02):
    The carved K4 text is SCRAMBLED. The solver searches for the
    unscrambling permutation. When found, it writes the real CT to
    results/real_ct.json. This module loads that file if present,
    otherwise falls back to the carved (scrambled) text.

Strategy definitions and categories are in strategies.py.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

logger = logging.getLogger("kryptosbot.config")

# ---------------------------------------------------------------------------
# K4 Ciphertext & Known Plaintext
# ---------------------------------------------------------------------------

# The carved text — this is SCRAMBLED, not the real ciphertext
K4_CARVED = (
    "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFB"
    "NYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
)


def _load_real_ct() -> str | None:
    """Load the real (unscrambled) CT if the solver has found it.

    Checks in order:
    1. KBOT_REAL_CT environment variable (path to JSON file)
    2. results/real_ct.json relative to project root
    3. kbot_results/real_ct.json relative to this file's parent (legacy)

    The JSON file schema:
        {"real_ct": "...", "permutation": [...], "method": "...", "score": N}

    Returns the real CT string, or None if not found.
    """
    search_paths = [
        os.environ.get("KBOT_REAL_CT"),
        Path(__file__).resolve().parent.parent.parent / "results" / "real_ct.json",
        Path(__file__).resolve().parent.parent / "kbot_results" / "real_ct.json",
        Path("kbot_results/real_ct.json"),
    ]

    for p in search_paths:
        if p is None:
            continue
        p = Path(p)
        if p.exists():
            try:
                data = json.loads(p.read_text())
                ct = data.get("real_ct", "").strip().upper()
                if len(ct) == 97 and ct.isalpha():
                    logger.info("Loaded REAL CT from %s (method: %s)",
                                p, data.get("method", "unknown"))
                    return ct
                else:
                    logger.warning("real_ct.json at %s has invalid CT (len=%d)", p, len(ct))
            except (json.JSONDecodeError, KeyError, AttributeError) as e:
                logger.warning("Failed to parse real_ct.json at %s: %s", p, e)

    return None


_real_ct = _load_real_ct()

# K4_CIPHERTEXT is what the rest of the system operates on.
# If we've found the real CT, use it. Otherwise, use the carved (scrambled) text.
if _real_ct:
    K4_CIPHERTEXT = _real_ct
    K4_SOURCE = "real_ct.json (unscrambled)"
else:
    K4_CIPHERTEXT = K4_CARVED
    K4_SOURCE = "carved (scrambled — real CT not yet found)"

K4_LENGTH = len(K4_CIPHERTEXT)  # 97

# Sanborn / Scheidt confirmed cribs (0-indexed, half-open intervals)
KNOWN_CRIBS: dict[str, tuple[int, int]] = {
    "EASTNORTHEAST": (21, 34),  # positions 21-33 inclusive
    "BERLIN": (63, 69),         # positions 63-68 inclusive
    "CLOCK": (69, 74),          # positions 69-73 inclusive
}

# K1-K3 solution methods (for cross-referencing / inspiration)
PRIOR_METHODS = {
    "K1": "Vigenère (keyword PALIMPSEST)",
    "K2": "Vigenère (keyword ABSCISSA)",
    "K3": "Transposition + Vigenère (keyword KRYPTOS)",
}


# ---------------------------------------------------------------------------
# Hypothesis Status Lifecycle
# ---------------------------------------------------------------------------

class HypothesisStatus(str, Enum):
    """Tracks where a hypothesis sits in the investigation pipeline."""
    QUEUED = "queued"
    RUNNING = "running"
    PROMISING = "promising"      # partial plaintext or statistical signal
    DISPROVED = "disproved"      # conclusively eliminated
    INCONCLUSIVE = "inconclusive"  # no signal but not fully eliminated
    SOLVED = "solved"            # full plaintext recovered


# ---------------------------------------------------------------------------
# Runtime Configuration
# ---------------------------------------------------------------------------

@dataclass
class KryptosBotConfig:
    """Runtime settings for the campaign runner."""

    # Parallelism
    max_workers: int = 4                  # concurrent Agent SDK sessions
    max_local_workers: int = 28           # CPU cores for local compute
    worker_timeout_minutes: int = 30      # kill stuck agents

    # Agent SDK settings
    allowed_tools: list[str] = field(
        default_factory=lambda: ["Read", "Write", "Edit", "Bash", "Glob", "Grep"]
    )
    permission_mode: str = "bypassPermissions"

    # Paths
    project_root: Path = Path(".")
    results_db_path: Path = field(default=Path("results/results.db"))
    log_dir: Path = Path("logs")

    # Session management
    resume_on_restart: bool = True
    session_store_path: Path = Path("sessions.json")

    # Scheduling
    strategy_names: list[str] | None = None
    priority_cutoff: int = 10
    repeat_disproved: bool = False
    skip_completed: bool = True

    def __post_init__(self) -> None:
        """Resolve all relative paths against project_root."""
        root = self.project_root.resolve()
        if not self.results_db_path.is_absolute():
            self.results_db_path = root / self.results_db_path
        if not self.log_dir.is_absolute():
            self.log_dir = root / self.log_dir
        if not self.session_store_path.is_absolute():
            self.session_store_path = root / self.session_store_path

    # System prompt prefix injected into every agent
    system_prompt_prefix: str = (
        "You are KryptosBot, an expert cryptanalyst working to decipher "
        "Kryptos K4 — the only unsolved section of Jim Sanborn's 1990 CIA "
        "headquarters sculpture."
    )
