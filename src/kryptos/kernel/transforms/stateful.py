"""Stateful and architecture-specific masking transforms for K4.

These are NOT standard periodic ciphers. They are finite-state systems
where the active offset, alphabet, or polarity changes according to a
deterministic hand-executable rule tied to position class, band structure,
or state recurrence.

All transforms are position-preserving (no reordering).
All are reversible given the same parameters.
"""
from __future__ import annotations

from typing import Callable, Dict, List, Optional, Tuple

from kryptos.kernel.constants import ALPH, ALPH_IDX, MOD


# ══════════════════════════════════════════════════════════════════════════
# Berlin clock band structure (1-4-4-11-4 = 24)
# ══════════════════════════════════════════════════════════════════════════

# Band membership for positions 0-23 within each 24-char block
BAND_A = (0,)             # 1 indicator
BAND_B = (1, 2, 3, 4)    # 4 five-hour
BAND_C = (5, 6, 7, 8)    # 4 one-hour
BAND_D = tuple(range(9, 20))  # 11 five-minute
BAND_E = (20, 21, 22, 23)    # 4 one-minute

ALL_BANDS = (BAND_A, BAND_B, BAND_C, BAND_D, BAND_E)
BAND_SIZES = tuple(len(b) for b in ALL_BANDS)  # (1, 4, 4, 11, 4)

def position_to_band(pos: int, block_size: int = 24) -> int:
    """Map a position within a 24-block to its band index (0-4)."""
    p = pos % block_size
    if p < 1:
        return 0
    elif p < 5:
        return 1
    elif p < 9:
        return 2
    elif p < 20:
        return 3
    else:
        return 4


def position_to_band_97(pos: int) -> int:
    """Map position 0-96 to band index. Last block (pos 96) → band 0."""
    return position_to_band(pos, 24)


# ══════════════════════════════════════════════════════════════════════════
# Family 1: Band-scheduled offset mask
# ══════════════════════════════════════════════════════════════════════════

def band_offset_encrypt(text: str, band_offsets: List[int]) -> str:
    """Apply band-scheduled additive offsets.

    Each position gets an offset determined by which Berlin clock band
    it falls in. band_offsets[0..4] gives the shift for bands A-E.
    """
    assert len(band_offsets) == 5
    out = []
    for i, c in enumerate(text):
        band = position_to_band_97(i)
        shift = band_offsets[band]
        out.append(ALPH[(ALPH_IDX[c] + shift) % MOD])
    return "".join(out)


def band_offset_decrypt(text: str, band_offsets: List[int]) -> str:
    """Remove band-scheduled additive offsets."""
    assert len(band_offsets) == 5
    out = []
    for i, c in enumerate(text):
        band = position_to_band_97(i)
        shift = band_offsets[band]
        out.append(ALPH[(ALPH_IDX[c] - shift) % MOD])
    return "".join(out)


# ══════════════════════════════════════════════════════════════════════════
# Family 2: Polarity-switching schedule
# ══════════════════════════════════════════════════════════════════════════

def polarity_switch_decrypt(
    text: str,
    key: List[int],
    schedule: List[int],
) -> str:
    """Decrypt with a polarity-switching schedule.

    schedule[i] selects cipher variant for position i:
      0 = Vigenere: P = (C - K) mod 26
      1 = Beaufort: P = (K - C) mod 26
      2 = Variant Beaufort: P = (C + K) mod 26

    The key is periodic; the schedule is periodic with its own period.
    """
    key_len = len(key)
    sched_len = len(schedule)
    out = []
    for i, c in enumerate(text):
        cv = ALPH_IDX[c]
        kv = key[i % key_len]
        variant = schedule[i % sched_len]
        if variant == 0:    # Vigenere
            pv = (cv - kv) % MOD
        elif variant == 1:  # Beaufort
            pv = (kv - cv) % MOD
        else:               # Variant Beaufort
            pv = (cv + kv) % MOD
        out.append(ALPH[pv])
    return "".join(out)


def polarity_switch_encrypt(
    text: str,
    key: List[int],
    schedule: List[int],
) -> str:
    """Encrypt with a polarity-switching schedule."""
    key_len = len(key)
    sched_len = len(schedule)
    out = []
    for i, c in enumerate(text):
        pv = ALPH_IDX[c]
        kv = key[i % key_len]
        variant = schedule[i % sched_len]
        if variant == 0:    # Vigenere
            cv = (pv + kv) % MOD
        elif variant == 1:  # Beaufort
            cv = (kv - pv) % MOD
        else:               # Variant Beaufort
            cv = (pv - kv) % MOD
        out.append(ALPH[cv])
    return "".join(out)


# ══════════════════════════════════════════════════════════════════════════
# Family 3: Progressive key mutation (Fibonacci-like additive)
# ══════════════════════════════════════════════════════════════════════════

def progressive_key_stream(seed: List[int], length: int) -> List[int]:
    """Generate a progressive key stream from a seed.

    After the seed is exhausted, each new key value is
    (key[i-1] + key[i-2]) mod 26 — a Fibonacci-like recurrence.
    This is the key generation used in Gromark-family ciphers.
    """
    stream = list(seed)
    while len(stream) < length:
        stream.append((stream[-1] + stream[-2]) % MOD)
    return stream[:length]


def progressive_key_encrypt(text: str, seed: List[int]) -> str:
    """Encrypt with Fibonacci-like progressive key."""
    ks = progressive_key_stream(seed, len(text))
    return "".join(ALPH[(ALPH_IDX[c] + ks[i]) % MOD] for i, c in enumerate(text))


def progressive_key_decrypt(text: str, seed: List[int]) -> str:
    """Decrypt with Fibonacci-like progressive key."""
    ks = progressive_key_stream(seed, len(text))
    return "".join(ALPH[(ALPH_IDX[c] - ks[i]) % MOD] for i, c in enumerate(text))


# ══════════════════════════════════════════════════════════════════════════
# Family 4: State-selected alphabet rotation
# ══════════════════════════════════════════════════════════════════════════

def state_alphabet_decrypt(
    text: str,
    base_key: List[int],
    state_offsets: List[int],
    state_schedule: List[int],
) -> str:
    """Decrypt where state modifies the effective key.

    Effective key at position i = (base_key[i % key_len] + state_offsets[state]) mod 26
    where state = state_schedule[i % schedule_len].

    This models a system where position class selects a state,
    and the state shifts the effective key before decryption.
    """
    key_len = len(base_key)
    sched_len = len(state_schedule)
    out = []
    for i, c in enumerate(text):
        state = state_schedule[i % sched_len]
        kv = (base_key[i % key_len] + state_offsets[state]) % MOD
        pv = (ALPH_IDX[c] - kv) % MOD  # Vigenere decrypt
        out.append(ALPH[pv])
    return "".join(out)


def state_alphabet_encrypt(
    text: str,
    base_key: List[int],
    state_offsets: List[int],
    state_schedule: List[int],
) -> str:
    """Encrypt with state-modified key."""
    key_len = len(base_key)
    sched_len = len(state_schedule)
    out = []
    for i, c in enumerate(text):
        state = state_schedule[i % sched_len]
        kv = (base_key[i % key_len] + state_offsets[state]) % MOD
        pv = (ALPH_IDX[c] + kv) % MOD  # Vigenere encrypt
        out.append(ALPH[pv])
    return "".join(out)


# ══════════════════════════════════════════════════════════════════════════
# Family 5: Band-scheduled polarity (Berlin clock selects Vig/Beau/VarBeau)
# ══════════════════════════════════════════════════════════════════════════

def band_polarity_decrypt(
    text: str,
    key: List[int],
    band_variants: List[int],
) -> str:
    """Decrypt where Berlin clock band selects cipher variant.

    band_variants[0..4] ∈ {0, 1, 2} selects Vig/Beau/VarBeau for each band.
    """
    assert len(band_variants) == 5
    key_len = len(key)
    out = []
    for i, c in enumerate(text):
        band = position_to_band_97(i)
        variant = band_variants[band]
        cv = ALPH_IDX[c]
        kv = key[i % key_len]
        if variant == 0:
            pv = (cv - kv) % MOD
        elif variant == 1:
            pv = (kv - cv) % MOD
        else:
            pv = (cv + kv) % MOD
        out.append(ALPH[pv])
    return "".join(out)


def band_polarity_encrypt(
    text: str,
    key: List[int],
    band_variants: List[int],
) -> str:
    """Encrypt where Berlin clock band selects cipher variant."""
    assert len(band_variants) == 5
    key_len = len(key)
    out = []
    for i, c in enumerate(text):
        band = position_to_band_97(i)
        variant = band_variants[band]
        pv = ALPH_IDX[c]
        kv = key[i % key_len]
        if variant == 0:
            cv = (pv + kv) % MOD
        elif variant == 1:
            cv = (kv - pv) % MOD
        else:
            cv = (pv - kv) % MOD
        out.append(ALPH[cv])
    return "".join(out)


# ══════════════════════════════════════════════════════════════════════════
# Family 6: Compass-bearing state schedule
# ══════════════════════════════════════════════════════════════════════════

# 8 compass bearings, mapped from EASTNORTHEAST keyword positions
COMPASS_POINTS = {
    'N': 0, 'NE': 1, 'E': 2, 'SE': 3,
    'S': 4, 'SW': 5, 'W': 6, 'NW': 7,
}

def compass_schedule(keyword: str, length: int) -> List[int]:
    """Generate a compass-based state schedule from keyword.

    Each letter in the keyword maps to a compass bearing (0-7)
    via its position mod 8. The schedule repeats with the keyword period.
    """
    return [ALPH_IDX[c] % 8 for c in keyword[:length]]


def compass_offset_encrypt(text: str, keyword: str, bearing_offsets: List[int]) -> str:
    """Apply compass-bearing-scheduled offsets.

    Each keyword position determines a bearing (mod 8).
    bearing_offsets[0..7] gives the additive shift for that bearing.
    """
    assert len(bearing_offsets) == 8
    kw_vals = [ALPH_IDX[c] for c in keyword.upper()]
    kw_len = len(kw_vals)
    out = []
    for i, c in enumerate(text):
        bearing = kw_vals[i % kw_len] % 8
        shift = bearing_offsets[bearing]
        out.append(ALPH[(ALPH_IDX[c] + shift) % MOD])
    return "".join(out)


def compass_offset_decrypt(text: str, keyword: str, bearing_offsets: List[int]) -> str:
    """Remove compass-bearing-scheduled offsets."""
    assert len(bearing_offsets) == 8
    kw_vals = [ALPH_IDX[c] for c in keyword.upper()]
    kw_len = len(kw_vals)
    out = []
    for i, c in enumerate(text):
        bearing = kw_vals[i % kw_len] % 8
        shift = bearing_offsets[bearing]
        out.append(ALPH[(ALPH_IDX[c] - shift) % MOD])
    return "".join(out)
