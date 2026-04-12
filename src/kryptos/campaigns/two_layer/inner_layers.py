"""Inner layer generators for the two-layer campaign.

Biased HEAVILY toward NEAR_IDENTITY and WEAKLY_MIXING. No strongly mixing
inner layers are included — the hypothesis under test is that the inner
layer is weak.
"""
from __future__ import annotations

import math
from itertools import combinations
from typing import List

from kryptos.campaigns.two_layer.families import (
    InnerFamily,
    InnerMixingClass,
    ProvenanceClass,
)
from kryptos.kernel.constants import ALPH, ALPH_IDX, MOD


_K123_KEYWORDS = ("KRYPTOS", "PALIMPSEST", "ABSCISSA", "IQLUSION")
_INNER_VARIANTS = ("vigenere", "beaufort", "var_beaufort")


def _per_short_instances() -> List[InnerFamily]:
    """Periodic additive with short periods and K1-K3 keywords."""
    out: List[InnerFamily] = []
    periods = (2, 3, 4, 5)
    combos: list = []
    for p in periods:
        for kw in _K123_KEYWORDS:
            trunc = kw[:p]
            for v in _INNER_VARIANTS:
                combos.append((p, kw, trunc, v))
    total = len(combos)
    for p, kw, trunc, v in combos:
        out.append(InnerFamily(
            family_id="INNER-PER-SHORT",
            name=f"per_{p}_{kw}_{v}",
            description=f"Period-{p} {v} with key={trunc} (from {kw})",
            parameters={"period": p, "keyword": kw, "trunc_key": trunc, "variant": v},
            parameter_space_size=total,
            complexity_score=math.log2(max(total, 2)),
            mixing_class=InnerMixingClass.WEAKLY_MIXING,
            preserves_letter_distance=False,
            provenance=ProvenanceClass.STRUCTURAL,
        ))
    return out


def _drift_instances() -> List[InnerFamily]:
    out: List[InnerFamily] = []
    drifts = (0, 1, -1, 2, -2)
    seg_lens = (7, 10, 14)
    base_shifts = range(0, 26, 2)  # small sample, not full 26
    combos = [(d, s, b) for d in drifts for s in seg_lens for b in base_shifts]
    total = len(combos)
    for d, s, b in combos:
        out.append(InnerFamily(
            family_id="INNER-DRIFT",
            name=f"drift_d{d}_s{s}_k{b}",
            description=f"k[i] = {b} + {d}*floor(i/{s}) mod 26",
            parameters={"drift": d, "seg_len": s, "base": b},
            parameter_space_size=total,
            complexity_score=math.log2(max(total, 2)),
            mixing_class=InnerMixingClass.WEAKLY_MIXING,
            preserves_letter_distance=False,
            provenance=ProvenanceClass.STRUCTURAL,
        ))
    return out


def _near_id_instances() -> List[InnerFamily]:
    """Monoalphabetic substitutions within Hamming distance M of identity."""
    out: List[InnerFamily] = []
    # M=0: identity
    combos: list = [("identity", ())]
    # M=1: single swap pair (26 choose 2 = 325, but scope limit = 26 adjacent swaps)
    for i in range(26):
        j = (i + 1) % 26
        combos.append((f"swap_{ALPH[i]}{ALPH[j]}", ((i, j),)))
    # M=2: two disjoint adjacent swaps (bounded sample)
    adj = [(i, (i + 1) % 26) for i in range(0, 26, 2)]
    for a, b in combinations(adj, 2):
        combos.append((f"swap2_{ALPH[a[0]]}{ALPH[a[1]]}_{ALPH[b[0]]}{ALPH[b[1]]}", (a, b)))
    # M=3 would blow up; cap here
    total = len(combos)
    for name, swaps in combos:
        out.append(InnerFamily(
            family_id="INNER-NEAR-ID",
            name=f"near_id_{name}",
            description=f"Monoalphabetic w/ swaps={swaps}",
            parameters={"swaps": [list(s) for s in swaps]},
            parameter_space_size=total,
            complexity_score=math.log2(max(total, 2)),
            mixing_class=InnerMixingClass.NEAR_IDENTITY,
            preserves_letter_distance=True,
            provenance=ProvenanceClass.STRUCTURAL,
        ))
    return out


def _local_caesar_instances() -> List[InnerFamily]:
    out: List[InnerFamily] = []
    total = 26
    for s in range(26):
        out.append(InnerFamily(
            family_id="INNER-LOCAL-CAESAR",
            name=f"caesar_{s}",
            description=f"Caesar shift {s}",
            parameters={"shift": s},
            parameter_space_size=total,
            complexity_score=math.log2(total),
            mixing_class=InnerMixingClass.NEAR_IDENTITY,
            preserves_letter_distance=True,
            provenance=ProvenanceClass.STRUCTURAL,
        ))
    return out


def generate_instances() -> List[InnerFamily]:
    out: List[InnerFamily] = []
    out.extend(_per_short_instances())
    out.extend(_drift_instances())
    out.extend(_near_id_instances())
    out.extend(_local_caesar_instances())
    return out


# ── Inverse application (decrypt) ───────────────────────────────────────

def _decrypt_additive(stream: str, key_vals: List[int], variant: str) -> str:
    L = len(key_vals)
    out_chars: List[str] = []
    for i, ch in enumerate(stream):
        c = ALPH_IDX[ch]
        k = key_vals[i % L]
        if variant == "vigenere":
            p = (c - k) % MOD
        elif variant == "beaufort":
            p = (k - c) % MOD
        elif variant == "var_beaufort":
            p = (c + k) % MOD
        else:
            raise ValueError(f"unknown variant {variant}")
        out_chars.append(ALPH[p])
    return "".join(out_chars)


def apply_inner_inverse(inner: InnerFamily, stream: str) -> str:
    """Apply the inner layer's INVERSE (decrypt) to `stream`.

    Returns a candidate plaintext fragment — same length as `stream`.
    """
    fid = inner.family_id
    if fid == "INNER-PER-SHORT":
        kw = inner.parameters["trunc_key"]
        variant = inner.parameters["variant"]
        key_vals = [ALPH_IDX[c] for c in kw]
        return _decrypt_additive(stream, key_vals, variant)
    if fid == "INNER-DRIFT":
        drift = inner.parameters["drift"]
        seg_len = inner.parameters["seg_len"]
        base = inner.parameters["base"]
        out_chars: List[str] = []
        for i, ch in enumerate(stream):
            k = (base + drift * (i // seg_len)) % MOD
            p = (ALPH_IDX[ch] - k) % MOD  # vigenere-style
            out_chars.append(ALPH[p])
        return "".join(out_chars)
    if fid == "INNER-NEAR-ID":
        swaps = inner.parameters["swaps"]
        mapping = list(range(26))
        for a, b in swaps:
            mapping[a], mapping[b] = mapping[b], mapping[a]
        # mapping[i] = substitution(i); inverse under involution is itself
        return "".join(ALPH[mapping[ALPH_IDX[c]]] for c in stream)
    if fid == "INNER-LOCAL-CAESAR":
        s = inner.parameters["shift"]
        return "".join(ALPH[(ALPH_IDX[c] - s) % MOD] for c in stream)
    raise ValueError(f"Unknown inner family_id: {fid}")
