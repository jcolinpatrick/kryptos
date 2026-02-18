"""Single source of truth for ALL Kryptos K4 constants.

Every other module must import from here — never define CT, cribs,
or Bean constraints independently.

All positions are 0-indexed.
"""
from __future__ import annotations

from typing import Dict, FrozenSet, Tuple

# ── Ciphertext ────────────────────────────────────────────────────────────

CT: str = (
    "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWAT"
    "JKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
)
CT_LEN: int = 97

# ── Standard alphabet ─────────────────────────────────────────────────────

ALPH: str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPH_IDX: Dict[str, int] = {c: i for i, c in enumerate(ALPH)}
MOD: int = 26

# ── Kryptos-keyed alphabet ────────────────────────────────────────────────

KRYPTOS_ALPHABET: str = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

# ── Cribs (0-indexed) ────────────────────────────────────────────────────

CRIB_WORDS: Tuple[Tuple[int, str], ...] = (
    (21, "EASTNORTHEAST"),   # positions 21–33, 13 chars
    (63, "BERLINCLOCK"),     # positions 63–73, 11 chars
)

CRIB_ENTRIES: Tuple[Tuple[int, str], ...] = tuple(
    (start + i, ch)
    for start, word in CRIB_WORDS
    for i, ch in enumerate(word)
)

N_CRIBS: int = 24
CRIB_DICT: Dict[int, str] = dict(CRIB_ENTRIES)
CRIB_POSITIONS: FrozenSet[int] = frozenset(CRIB_DICT.keys())

# ── Self-encrypting positions ─────────────────────────────────────────────

SELF_ENCRYPTING: Dict[int, str] = {32: "S", 73: "K"}

# ── Bean constraints ──────────────────────────────────────────────────────

BEAN_EQ: Tuple[Tuple[int, int], ...] = ((27, 65),)

BEAN_INEQ: Tuple[Tuple[int, int], ...] = (
    (24, 28), (28, 33), (24, 33), (21, 30), (21, 64), (30, 64),
    (68, 25), (22, 31), (66, 70), (26, 71), (69, 72), (23, 32),
    (71, 21), (25, 26), (24, 66), (31, 73), (29, 63), (32, 33),
    (67, 68), (27, 72), (23, 28),
)

# ── Known keystream values (verified at crib positions) ───────────────────

VIGENERE_KEY_ENE: Tuple[int, ...] = (1, 11, 25, 2, 3, 2, 24, 24, 6, 2, 10, 0, 25)
VIGENERE_KEY_BC: Tuple[int, ...] = (12, 20, 24, 10, 11, 6, 10, 14, 17, 13, 0)
BEAUFORT_KEY_ENE: Tuple[int, ...] = (9, 11, 9, 14, 3, 4, 6, 10, 20, 10, 10, 10, 11)
BEAUFORT_KEY_BC: Tuple[int, ...] = (14, 2, 6, 6, 1, 6, 14, 10, 19, 17, 20)

# ── Reference thresholds ─────────────────────────────────────────────────

NOISE_FLOOR: int = 6          # Typical random score
STORE_THRESHOLD: int = 10     # Minimum score to persist
SIGNAL_THRESHOLD: int = 18    # Score worth investigating
BREAKTHROUGH_THRESHOLD: int = 24  # Full crib match required

# ── IC reference values ──────────────────────────────────────────────────

IC_K4: float = 0.0361
IC_RANDOM: float = 1.0 / 26   # 0.03846
IC_ENGLISH: float = 0.0667
IC_PRE_ENE: float = 0.0667    # Positions 0-20, suspiciously English-like

# ── Import-time verification ─────────────────────────────────────────────

def _verify() -> None:
    """Verify all constants at import time. Raises AssertionError on failure."""
    assert len(CT) == CT_LEN, f"CT length {len(CT)} != {CT_LEN}"
    assert CT[0] == "O" and CT[-1] == "R", "CT boundary check failed"
    assert CT.isalpha() and CT.isupper(), "CT must be uppercase A-Z"
    assert len(CRIB_ENTRIES) == N_CRIBS, f"Crib count {len(CRIB_ENTRIES)} != {N_CRIBS}"
    assert CRIB_DICT[21] == "E" and CRIB_DICT[33] == "T", "ENE crib check failed"
    assert CRIB_DICT[63] == "B" and CRIB_DICT[73] == "K", "BC crib check failed"
    assert 74 not in CRIB_DICT, "Position 74 should not be a crib"
    assert CT[32] == CRIB_DICT[32] == "S", "Self-encrypt pos 32 failed"
    assert CT[73] == CRIB_DICT[73] == "K", "Self-encrypt pos 73 failed"
    assert len(ALPH) == MOD and len(set(ALPH)) == MOD, "ALPH malformed"
    assert len(KRYPTOS_ALPHABET) == MOD and len(set(KRYPTOS_ALPHABET)) == MOD, "KA malformed"
    assert set(KRYPTOS_ALPHABET) == set(ALPH), "KA and ALPH char sets differ"
    assert len(BEAN_EQ) == 1, "Expected 1 Bean equality"
    assert len(BEAN_INEQ) == 21, f"Expected 21 Bean inequalities, got {len(BEAN_INEQ)}"

_verify()
