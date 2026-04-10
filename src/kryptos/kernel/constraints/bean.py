"""Bean constraint verification.

Verifies the equality and inequality constraints on keystream values
derived from the known cribs. [DERIVED FACT] conditional on:
  A1: Crib positions correct (21-33, 63-73)
  A2: Crib content correct (EASTNORTHEAST, BERLINCLOCK)
  A3: Additive key model (single mod-26 shift per position)
If ANY of these assumptions fail, Bean constraints are invalid.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from kryptos.kernel.constants import (
    ALPH_IDX,
    BEAN_EQ,
    BEAN_INEQ,
    BEAN_LINEAR,
    CRIB_DICT,
    CT,
    CT_LEN,
    MOD,
)


@dataclass
class BeanResult:
    """Detailed result of Bean constraint checking."""
    passed: bool
    eq_satisfied: int
    eq_total: int
    ineq_satisfied: int
    ineq_total: int
    linear_satisfied: int
    linear_total: int
    eq_failures: List[Tuple[int, int, int, int]]  # (posA, posB, valA, valB)
    ineq_failures: List[Tuple[int, int, int]]  # (posA, posB, shared_val)
    linear_failures: List[Tuple[int, int, int, int, int]]  # (a, b, c, d, residue)

    @property
    def summary(self) -> str:
        if self.passed:
            return (
                f"PASS: {self.eq_satisfied}/{self.eq_total} eq, "
                f"{self.ineq_satisfied}/{self.ineq_total} ineq, "
                f"{self.linear_satisfied}/{self.linear_total} linear"
            )
        parts = []
        if self.eq_failures:
            parts.append(f"eq fail: {self.eq_failures}")
        if self.ineq_failures:
            parts.append(f"ineq fail: {self.ineq_failures}")
        if self.linear_failures:
            parts.append(f"linear fail: {len(self.linear_failures)} of {self.linear_total}")
        return f"FAIL: {'; '.join(parts)}"


def verify_bean(keystream: List[int]) -> BeanResult:
    """Verify Bean constraints on a keystream.

    The keystream must be indexed such that keystream[pos] gives the key
    value at position pos. Must be at least CT_LEN long.

    Checks three constraint types:
    1. Equality: k[27] == k[65]  (1 pair)
    2. Inequality: k[a] != k[b]  (242 pairs)
    3. Linear: k[a] - k[b] - k[c] + k[d] ≡ 0 mod 26  (101 constraints)

    The linear constraints (derived from the Gröbner basis of the crib
    system) are INDEPENDENT of the pairwise constraints. Together they
    reduce valid keystreams at crib positions from 26^24 to exactly 624.

    Returns detailed BeanResult with diagnostic information.
    """
    eq_failures: list[tuple[int, int, int, int]] = []
    ineq_failures: list[tuple[int, int, int]] = []
    linear_failures: list[tuple[int, int, int, int, int]] = []

    for a, b in BEAN_EQ:
        if a < len(keystream) and b < len(keystream):
            if keystream[a] != keystream[b]:
                eq_failures.append((a, b, keystream[a], keystream[b]))

    for a, b in BEAN_INEQ:
        if a < len(keystream) and b < len(keystream):
            if keystream[a] == keystream[b]:
                ineq_failures.append((a, b, keystream[a]))

    for a, b, c, d in BEAN_LINEAR:
        if (a < len(keystream) and b < len(keystream)
                and c < len(keystream) and d < len(keystream)):
            residue = (keystream[a] - keystream[b]
                       - keystream[c] + keystream[d]) % MOD
            if residue != 0:
                linear_failures.append((a, b, c, d, residue))

    eq_sat = len(BEAN_EQ) - len(eq_failures)
    ineq_sat = len(BEAN_INEQ) - len(ineq_failures)
    linear_sat = len(BEAN_LINEAR) - len(linear_failures)

    return BeanResult(
        passed=(len(eq_failures) == 0
                and len(ineq_failures) == 0
                and len(linear_failures) == 0),
        eq_satisfied=eq_sat,
        eq_total=len(BEAN_EQ),
        ineq_satisfied=ineq_sat,
        ineq_total=len(BEAN_INEQ),
        linear_satisfied=linear_sat,
        linear_total=len(BEAN_LINEAR),
        eq_failures=eq_failures,
        ineq_failures=ineq_failures,
        linear_failures=linear_failures,
    )


def verify_bean_simple(keystream: List[int]) -> bool:
    """Fast Bean verification — returns True/False only.

    Use this as a prefilter when you don't need diagnostics.
    Checks all three constraint types: equality, inequality, and linear.
    """
    for a, b in BEAN_EQ:
        if a < len(keystream) and b < len(keystream):
            if keystream[a] != keystream[b]:
                return False
    for a, b in BEAN_INEQ:
        if a < len(keystream) and b < len(keystream):
            if keystream[a] == keystream[b]:
                return False
    for a, b, c, d in BEAN_LINEAR:
        if (a < len(keystream) and b < len(keystream)
                and c < len(keystream) and d < len(keystream)):
            if (keystream[a] - keystream[b]
                    - keystream[c] + keystream[d]) % MOD != 0:
                return False
    return True


def expand_keystream_vimark(
    primer: Tuple[int, ...], length: int = CT_LEN,
) -> List[int]:
    """Expand a Vimark primer into a full keystream.

    Recurrence: k[i] = k[i - period] + k[i - (period-1)] mod 26
    Requires period >= 2 (period=1 is undefined due to self-reference).
    """
    period = len(primer)
    if period < 2:
        raise ValueError(f"Vimark requires period >= 2, got {period}")
    k = list(primer)
    while len(k) < length:
        k.append((k[-period] + k[-(period - 1)]) % MOD)
    return k[:length]


def verify_bean_from_primer(
    primer: Tuple[int, ...], length: int = CT_LEN,
) -> BeanResult:
    """Expand primer to keystream and verify Bean constraints."""
    ks = expand_keystream_vimark(primer, length)
    return verify_bean(ks)


def rederive_bean_for_transposition(
    pt_to_ct: List[int],
    alph_idx: Optional[Dict[str, int]] = None,
) -> Tuple[Tuple[Tuple[int, int], ...], Tuple[Tuple[int, int], ...]]:
    """Re-derive Bean equality and inequality constraints under a
    transposition-first cipher model.

    Encryption model:
        carved_CT[i] = substitute(intermediate[i], key[i])
        intermediate = transpose(PT)  applied BEFORE substitution
        pt_to_ct[k]  = position in carved CT where plaintext position k lands

    Under this model, the crib letter at plaintext position k appears at
    carved CT position pt_to_ct[k], paired with the (known) carved CT letter
    CT[pt_to_ct[k]]. The implied keystream value at that CT position is:

        Vigenère:        key = (CT[pt_to_ct[k]] - PT[k]) mod 26
        Beaufort:        key = (CT[pt_to_ct[k]] + PT[k]) mod 26
        Variant Beaufort: key = (PT[k] - CT[pt_to_ct[k]]) mod 26

    Bean constraints compare implied keys at pairs of crib positions. Under
    the direct-positional model (pt_to_ct[i] = i) with the default standard
    alphabet indexing, this must reproduce the canonical BEAN_EQ (1 pair)
    and BEAN_INEQ (242 pairs) exactly — enforced by the
    identity-reproduction test.

    The returned pairs are in **carved CT coordinate space**, NOT plaintext
    coordinate space. Downstream filters check the implied keystream at
    those CT positions directly, without further T application.

    Args:
        pt_to_ct: Length-97 permutation. pt_to_ct[k] is the position in the
            carved CT where plaintext position k's letter lands after the
            outer transposition is applied at encryption time.
        alph_idx: Optional character-to-index mapping for the substitution
            alphabet. Defaults to the standard A-Z indexing. For KA
            (KRYPTOS-keyed) alphabet work, pass `{c: i for i, c in
            enumerate(KRYPTOS_ALPHABET)}` — the eq/ineq sets will differ
            because the variant-independence predicate is computed in the
            new indexing. Identity T with the default AZ mapping must
            always reproduce the canonical BEAN_EQ/BEAN_INEQ; identity T
            with a KA mapping produces a DIFFERENT but equally valid
            constraint set.

    Returns:
        (eq_pairs, ineq_pairs) where each pair (ca, cb) has ca < cb and is
        a pair of CT coordinates. An EQ pair means the implied key values
        at those two CT positions MUST be equal under every additive
        variant under the chosen alphabet. An INEQ pair means they MUST
        be unequal under every variant. Pairs that are variant-dependent
        (equal under some, unequal under others) are dropped from both sets.

    Raises:
        ValueError: if pt_to_ct is not a valid length-97 permutation.
    """
    if len(pt_to_ct) != CT_LEN:
        raise ValueError(
            f"pt_to_ct must be length {CT_LEN}, got {len(pt_to_ct)}"
        )
    if set(pt_to_ct) != set(range(CT_LEN)):
        raise ValueError("pt_to_ct must be a permutation of 0..96")

    idx = alph_idx if alph_idx is not None else ALPH_IDX

    positions = sorted(CRIB_DICT.keys())
    eq_pairs: list[tuple[int, int]] = []
    ineq_pairs: list[tuple[int, int]] = []

    for i in range(len(positions)):
        for j in range(i + 1, len(positions)):
            a, b = positions[i], positions[j]
            ta, tb = pt_to_ct[a], pt_to_ct[b]

            ca = idx[CT[ta]]
            pa = idx[CRIB_DICT[a]]
            cb = idx[CT[tb]]
            pb = idx[CRIB_DICT[b]]

            vig_eq = (ca - pa) % MOD == (cb - pb) % MOD
            beau_eq = (ca + pa) % MOD == (cb + pb) % MOD
            vbeau_eq = (pa - ca) % MOD == (pb - cb) % MOD

            # Normalize ordering so downstream set comparisons are stable
            ct_pair = (ta, tb) if ta < tb else (tb, ta)

            if vig_eq and beau_eq and vbeau_eq:
                eq_pairs.append(ct_pair)
            elif not vig_eq and not beau_eq and not vbeau_eq:
                ineq_pairs.append(ct_pair)
            # else: variant-dependent — cannot be used as a pre-filter

    return tuple(eq_pairs), tuple(ineq_pairs)


def verify_bean_from_implied(implied_keys: Dict[int, int]) -> bool:
    """Check Bean constraints directly from implied key values at crib positions.

    Unlike verify_bean/verify_bean_simple (which require a full keystream),
    this works with a sparse dict of {position: key_value} from any period.
    This enables Bean checking even when no full primer is available
    (e.g., at periods 19, 20, 23, 24, 26 where not all residue classes
    have crib data).

    Returns True if all Bean constraints that CAN be checked are satisfied.
    Constraints where any required position is missing are skipped.
    """
    for a, b in BEAN_EQ:
        if a in implied_keys and b in implied_keys:
            if implied_keys[a] != implied_keys[b]:
                return False
    for a, b in BEAN_INEQ:
        if a in implied_keys and b in implied_keys:
            if implied_keys[a] == implied_keys[b]:
                return False
    for a, b, c, d in BEAN_LINEAR:
        if (a in implied_keys and b in implied_keys
                and c in implied_keys and d in implied_keys):
            if (implied_keys[a] - implied_keys[b]
                    - implied_keys[c] + implied_keys[d]) % MOD != 0:
                return False
    return True
