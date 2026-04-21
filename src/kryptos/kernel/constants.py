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

def _derive_bean_ineq() -> Tuple[Tuple[int, int], ...]:
    """Derive the full variant-independent Bean inequality set.

    A pair (a, b) is a variant-independent inequality iff the derived
    keystream values differ for ALL three cipher variants (Vigenère,
    Beaufort, Variant Beaufort).  This ensures the constraint holds
    regardless of which additive variant is correct.

    Previous versions hardcoded only 21 of 242 pairs, causing false
    PASSes for keywords with repeated letters (KOLOPHON, DEFECTOR, etc.).
    """
    positions = sorted(CRIB_DICT.keys())
    pairs: list[tuple[int, int]] = []
    for i in range(len(positions)):
        for j in range(i + 1, len(positions)):
            a, b = positions[i], positions[j]
            ca, pa = ALPH_IDX[CT[a]], ALPH_IDX[CRIB_DICT[a]]
            cb, pb = ALPH_IDX[CT[b]], ALPH_IDX[CRIB_DICT[b]]
            vig_eq = (ca - pa) % MOD == (cb - pb) % MOD
            beau_eq = (ca + pa) % MOD == (cb + pb) % MOD
            vbeau_eq = (pa - ca) % MOD == (pb - cb) % MOD
            if not vig_eq and not beau_eq and not vbeau_eq:
                pairs.append((a, b))
    return tuple(pairs)


BEAN_INEQ: Tuple[Tuple[int, int], ...] = _derive_bean_ineq()


def _derive_bean_linear() -> Tuple[Tuple[int, int, int, int], ...]:
    """Derive variant-independent 4-position linear constraints on keystream.

    For each 4-tuple of crib positions (a, b, c, d), check whether
    k[a] - k[b] - k[c] + k[d] ≡ 0 (mod 26) holds under ALL three
    additive cipher variants (Vigenère, Beaufort, Variant Beaufort).

    These constraints encode that key DIFFERENCES at crib positions are
    fully determined (up to the global additive constant). Together with
    the pairwise equality/inequality constraints, they reduce the valid
    keystream space from 26^24 to exactly 624 solutions.

    Derived from the Gröbner basis of the crib system (cf. Bean's
    kryptos-k4-sage.txt, HistoCrypt 2021). The full set has 101
    constraints; only 22 are independent (rank 22 over Z, plus the
    1 equality = rank 23 total, leaving 1 free variable over Q).
    """
    positions = sorted(CRIB_DICT.keys())
    n = len(positions)
    constraints: list[tuple[int, int, int, int]] = []

    for i in range(n):
        for j in range(i + 1, n):
            for k in range(j + 1, n):
                for l in range(k + 1, n):
                    a, b, c, d = positions[i], positions[j], positions[k], positions[l]
                    for p1, p2, p3, p4 in ((a, b, c, d), (a, c, b, d), (a, d, b, c)):
                        ca, pa = ALPH_IDX[CT[p1]], ALPH_IDX[CRIB_DICT[p1]]
                        cb, pb = ALPH_IDX[CT[p2]], ALPH_IDX[CRIB_DICT[p2]]
                        cc, pc = ALPH_IDX[CT[p3]], ALPH_IDX[CRIB_DICT[p3]]
                        cd, pd = ALPH_IDX[CT[p4]], ALPH_IDX[CRIB_DICT[p4]]
                        vig = ((ca - pa) - (cb - pb) - (cc - pc) + (cd - pd)) % MOD
                        beau = ((ca + pa) - (cb + pb) - (cc + pc) + (cd + pd)) % MOD
                        vbeau = ((pa - ca) - (pb - cb) - (pc - cc) + (pd - cd)) % MOD
                        if vig == 0 and beau == 0 and vbeau == 0:
                            constraints.append((p1, p2, p3, p4))

    return tuple(constraints)


BEAN_LINEAR: Tuple[Tuple[int, int, int, int], ...] = _derive_bean_linear()

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

# ── Stego layer constants ──────────────────────────────────────────────

# ── Retired palette / null-mask constants ────────────────────────────────
# NULL_PALETTE, CONSENSUS_NULL_POSITIONS, and BEAUFORT_KEYSTREAM_AT_CRIBS
# moved to `kryptos.kernel.retired` on 2026-04-20 as part of framework
# internal phase 2 (see `<internal>phase_02_report.md`).
#
# Retirement claim: claim_id `null_palette_retired` / C-PALETTE-01 (see
# `docs/claims_registry.json`), retired 2026-04-14 after matched controls
# disproved the palette's specificity.
#
# Historical-reproducibility importers: from kryptos.kernel.retired import ...
# The allow-list in `tests/test_retired_usage.py` enumerates every file
# permitted to depend on the retired namespace.
#
# DO NOT IMPORT into new live code. See `kryptos.kernel.retired` for detail.

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
    assert len(BEAN_INEQ) == 242, f"Expected 242 Bean inequalities, got {len(BEAN_INEQ)}"
    assert len(BEAN_LINEAR) == 101, f"Expected 101 Bean linear constraints, got {len(BEAN_LINEAR)}"
    # Retired constants (palette, consensus null positions, Beaufort
    # crib keystream) live in `kryptos.kernel.retired` and self-verify
    # at their own import time.

_verify()
