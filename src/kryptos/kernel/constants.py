"""Single source of truth for ALL Kryptos K4 constants.

Every other module must import from here — never define CT, cribs,
or Bean constraints independently.

All positions are 0-indexed.

=== SYNTHETIC MODE (calibration use only) ===

If the environment variable ``KRYPTOS_CT_OVERRIDE`` is set at module-import
time, this module loads the override CT instead of the real K4 ciphertext
and propagates it through Bean derivation. This is intended ONLY for
controlled synthetic-signal calibration runs (see
``<internal>/SYNTHETIC_SIGNAL_CALIBRATION_SPEC.md`` and the
K4Bench harness); synthetic results MUST never be merged with real-K4
work.

The override:
- replaces ``CT`` with the override string (which must be 97 uppercase A-Z chars),
- prints a stderr warning at import,
- gates K4-specific assertions in ``_verify()`` (CT boundary, self-encrypt
  positions, Bean inequality count, Bean linear count) so they don't fire
  on synthetic CTs whose derivation differs from K4's.

If ``KRYPTOS_CRIB_DICT_OVERRIDE`` is also set (JSON object mapping
position-string to single uppercase letter), the kernel rebuilds
``CRIB_DICT``, ``CRIB_WORDS``, ``CRIB_ENTRIES``, ``CRIB_POSITIONS``,
``N_CRIBS``, ``SELF_ENCRYPTING``, and re-derives the Bean constraint sets
against the override cribs. This is what the K4Bench loader sets so that
each synthetic challenge has its own crib content while preserving the
0-indexed 21-33 / 63-73 span structure. ``KRYPTOS_CRIB_DICT_OVERRIDE``
without ``KRYPTOS_CT_OVERRIDE`` is rejected — crib content overrides
are valid only inside synthetic mode.

The boolean ``_SYNTHETIC_MODE`` is exported for downstream sentinel
handling (e.g., DB taint files, log warnings).
"""
from __future__ import annotations

import json
import os
import sys
from typing import Dict, FrozenSet, Tuple

# ── Ciphertext (real K4 by default; overridable for synthetic calibration) ──

_CT_OVERRIDE: str | None = os.environ.get("KRYPTOS_CT_OVERRIDE")
_SYNTHETIC_MODE: bool = _CT_OVERRIDE is not None

if _SYNTHETIC_MODE:
    assert _CT_OVERRIDE is not None  # for type-checker
    if len(_CT_OVERRIDE) != 97:
        raise ValueError(
            f"KRYPTOS_CT_OVERRIDE must be exactly 97 chars; got {len(_CT_OVERRIDE)}"
        )
    if not _CT_OVERRIDE.isalpha() or not _CT_OVERRIDE.isupper():
        raise ValueError(
            "KRYPTOS_CT_OVERRIDE must be uppercase A-Z only"
        )
    CT: str = _CT_OVERRIDE
    print(
        f"[kryptos.kernel.constants] WARNING: KRYPTOS_CT_OVERRIDE active. "
        f"Synthetic CT loaded ({_CT_OVERRIDE[:8]}...{_CT_OVERRIDE[-8:]}). "
        f"This is NOT real K4. Synthetic-mode results must not be merged "
        f"with real K4 work; see <internal>/SYNTHETIC_SIGNAL_CALIBRATION_SPEC.md.",
        file=sys.stderr,
    )
else:
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

_CRIB_OVERRIDE: str | None = os.environ.get("KRYPTOS_CRIB_DICT_OVERRIDE")
if _CRIB_OVERRIDE is not None and not _SYNTHETIC_MODE:
    raise ValueError(
        "KRYPTOS_CRIB_DICT_OVERRIDE requires KRYPTOS_CT_OVERRIDE to also be "
        "set (synthetic mode). Crib-content overrides on the real K4 CT "
        "are not permitted; they would corrupt downstream analysis."
    )


def _parse_crib_override(payload: str) -> Dict[int, str]:
    """Parse the KRYPTOS_CRIB_DICT_OVERRIDE JSON payload.

    Expected shape: ``{"21": "S", "22": "E", ...}`` with integer-string
    keys and single-letter uppercase values. The K4Bench loader writes
    this verbatim from the public challenge JSON.
    """
    try:
        raw = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"KRYPTOS_CRIB_DICT_OVERRIDE is not valid JSON: {exc}"
        ) from exc
    if not isinstance(raw, dict) or not raw:
        raise ValueError(
            "KRYPTOS_CRIB_DICT_OVERRIDE must be a non-empty JSON object "
            "of {position: letter}"
        )
    out: Dict[int, str] = {}
    for k, v in raw.items():
        try:
            pos = int(k)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"KRYPTOS_CRIB_DICT_OVERRIDE key {k!r} is not an integer"
            ) from exc
        if not isinstance(v, str) or len(v) != 1 or not v.isupper() or not v.isalpha():
            raise ValueError(
                f"KRYPTOS_CRIB_DICT_OVERRIDE value at key {k!r} must be a "
                f"single uppercase A-Z letter; got {v!r}"
            )
        if pos < 0 or pos >= CT_LEN:
            raise ValueError(
                f"KRYPTOS_CRIB_DICT_OVERRIDE position {pos} is out of "
                f"range [0, {CT_LEN})"
            )
        if pos in out:
            raise ValueError(
                f"KRYPTOS_CRIB_DICT_OVERRIDE duplicate position {pos} "
                f"after normalizing key {k!r}"
            )
        out[pos] = v
    return out


def _spans_from_dict(d: Dict[int, str]) -> Tuple[Tuple[int, str], ...]:
    """Group consecutive crib positions into ``(start, word)`` spans.

    Mirrors the legacy ``CRIB_WORDS`` shape so every consumer that walks
    spans (rather than the dict) keeps working under crib-override mode.
    """
    if not d:
        return ()
    positions = sorted(d.keys())
    spans: list[tuple[int, str]] = []
    span_start = positions[0]
    span_chars = [d[span_start]]
    for prev, p in zip(positions, positions[1:]):
        if p == prev + 1:
            span_chars.append(d[p])
        else:
            spans.append((span_start, "".join(span_chars)))
            span_start = p
            span_chars = [d[p]]
    spans.append((span_start, "".join(span_chars)))
    return tuple(spans)


if _CRIB_OVERRIDE is not None:
    CRIB_DICT: Dict[int, str] = _parse_crib_override(_CRIB_OVERRIDE)
    CRIB_WORDS: Tuple[Tuple[int, str], ...] = _spans_from_dict(CRIB_DICT)
    CRIB_ENTRIES: Tuple[Tuple[int, str], ...] = tuple(
        sorted(CRIB_DICT.items())
    )
    N_CRIBS: int = len(CRIB_DICT)
    CRIB_POSITIONS: FrozenSet[int] = frozenset(CRIB_DICT.keys())
    # Self-encrypting positions are derived from the synthetic CT and
    # crib content. A position is self-encrypting iff CT[pos] == PT[pos].
    SELF_ENCRYPTING: Dict[int, str] = {
        pos: ch for pos, ch in CRIB_DICT.items() if CT[pos] == ch
    }
else:
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

    # ── Self-encrypting positions ────────────────────────────────────
    SELF_ENCRYPTING: Dict[int, str] = {32: "S", 73: "K"}

# ── Bean constraints ──────────────────────────────────────────────────────

def _derive_bean_eq() -> Tuple[Tuple[int, int], ...]:
    """Derive variant-independent Bean equality constraints.

    A pair (a, b) is in BEAN_EQ iff the implied keystream values are
    EQUAL under ALL three additive cipher variants (Vigenère, Beaufort,
    Variant Beaufort). For real K4, this yields exactly ((27, 65),) —
    the position pair where both CT and PT chars match (CT[27]=CT[65]=P,
    PT[27]=PT[65]=R).

    Under synthetic CTs the derivation runs against the override CT and
    may produce a different (often empty) set; this is correct.
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
            if vig_eq and beau_eq and vbeau_eq:
                pairs.append((a, b))
    return tuple(pairs)


BEAN_EQ: Tuple[Tuple[int, int], ...] = _derive_bean_eq()

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
    """Verify all constants at import time. Raises AssertionError on failure.

    Under synthetic mode (``_SYNTHETIC_MODE`` True), K4-specific assertions
    are skipped: CT boundary chars, self-encrypt positions, and the K4
    Bean count invariants. Crib content checks are also skipped when a
    crib override is active, because K4Bench challenges deliberately
    install non-K4 crib text. Structural alphabet checks still run
    unconditionally because they are properties of the kernel contract,
    not of any specific CT.
    """
    # Always-on: structural invariants of the kernel contract
    assert len(CT) == CT_LEN, f"CT length {len(CT)} != {CT_LEN}"
    assert CT.isalpha() and CT.isupper(), "CT must be uppercase A-Z"
    assert len(CRIB_ENTRIES) == N_CRIBS, f"Crib count {len(CRIB_ENTRIES)} != {N_CRIBS}"
    assert len(ALPH) == MOD and len(set(ALPH)) == MOD, "ALPH malformed"
    assert len(KRYPTOS_ALPHABET) == MOD and len(set(KRYPTOS_ALPHABET)) == MOD, "KA malformed"
    assert set(KRYPTOS_ALPHABET) == set(ALPH), "KA and ALPH char sets differ"

    # Crib content checks are K4-specific. Skip when an explicit crib
    # override is active; the K4Bench loader installs different content
    # at the same span positions (21-33, 63-73) per challenge.
    if _CRIB_OVERRIDE is None:
        assert CRIB_DICT[21] == "E" and CRIB_DICT[33] == "T", "ENE crib check failed"
        assert CRIB_DICT[63] == "B" and CRIB_DICT[73] == "K", "BC crib check failed"
        assert 74 not in CRIB_DICT, "Position 74 should not be a crib"
        assert CRIB_DICT[32] == "S", "Crib content @ 32 must be S"
        assert CRIB_DICT[73] == "K", "Crib content @ 73 must be K"

    if not _SYNTHETIC_MODE:
        # K4-specific: real CT boundary, self-encrypt CT==PT, and
        # the K4 Bean constraint counts that hold for the carved CT.
        assert CT[0] == "O" and CT[-1] == "R", "CT boundary check failed"
        assert CT[32] == CRIB_DICT[32] == "S", "Self-encrypt pos 32 failed"
        assert CT[73] == CRIB_DICT[73] == "K", "Self-encrypt pos 73 failed"
        assert len(BEAN_EQ) == 1, f"Expected 1 Bean equality on K4, got {len(BEAN_EQ)}"
        assert BEAN_EQ == ((27, 65),), f"K4 Bean equality must be ((27, 65),), got {BEAN_EQ}"
        assert len(BEAN_INEQ) == 242, f"Expected 242 Bean inequalities on K4, got {len(BEAN_INEQ)}"
        assert len(BEAN_LINEAR) == 101, f"Expected 101 Bean linear constraints on K4, got {len(BEAN_LINEAR)}"
    # Under _SYNTHETIC_MODE the Bean derivation runs against the override
    # CT and produces whatever counts that yields. We do not assert the
    # synthetic counts here; the synthetic-build script verifies the
    # derivation produces a non-degenerate constraint set before launch.

    # Retired constants (palette, consensus null positions, Beaufort
    # crib keystream) live in `kryptos.kernel.retired` and self-verify
    # at their own import time.

_verify()
