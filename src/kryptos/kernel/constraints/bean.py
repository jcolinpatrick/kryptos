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

from kryptos.kernel.constants import BEAN_EQ, BEAN_INEQ, CT_LEN, MOD


@dataclass
class BeanResult:
    """Detailed result of Bean constraint checking."""
    passed: bool
    eq_satisfied: int
    eq_total: int
    ineq_satisfied: int
    ineq_total: int
    eq_failures: List[Tuple[int, int, int, int]]  # (posA, posB, valA, valB)
    ineq_failures: List[Tuple[int, int, int]]  # (posA, posB, shared_val)

    @property
    def summary(self) -> str:
        if self.passed:
            return f"PASS: {self.eq_satisfied}/{self.eq_total} eq, {self.ineq_satisfied}/{self.ineq_total} ineq"
        parts = []
        if self.eq_failures:
            parts.append(f"eq fail: {self.eq_failures}")
        if self.ineq_failures:
            parts.append(f"ineq fail: {self.ineq_failures}")
        return f"FAIL: {'; '.join(parts)}"


def verify_bean(keystream: List[int]) -> BeanResult:
    """Verify Bean constraints on a keystream.

    The keystream must be indexed such that keystream[pos] gives the key
    value at position pos. Must be at least CT_LEN long.

    Returns detailed BeanResult with diagnostic information.
    """
    eq_failures: list[tuple[int, int, int, int]] = []
    ineq_failures: list[tuple[int, int, int]] = []

    for a, b in BEAN_EQ:
        if a < len(keystream) and b < len(keystream):
            if keystream[a] != keystream[b]:
                eq_failures.append((a, b, keystream[a], keystream[b]))

    for a, b in BEAN_INEQ:
        if a < len(keystream) and b < len(keystream):
            if keystream[a] == keystream[b]:
                ineq_failures.append((a, b, keystream[a]))

    eq_sat = len(BEAN_EQ) - len(eq_failures)
    ineq_sat = len(BEAN_INEQ) - len(ineq_failures)

    return BeanResult(
        passed=(len(eq_failures) == 0 and len(ineq_failures) == 0),
        eq_satisfied=eq_sat,
        eq_total=len(BEAN_EQ),
        ineq_satisfied=ineq_sat,
        ineq_total=len(BEAN_INEQ),
        eq_failures=eq_failures,
        ineq_failures=ineq_failures,
    )


def verify_bean_simple(keystream: List[int]) -> bool:
    """Fast Bean verification — returns True/False only.

    Use this as a prefilter when you don't need diagnostics.
    """
    for a, b in BEAN_EQ:
        if a < len(keystream) and b < len(keystream):
            if keystream[a] != keystream[b]:
                return False
    for a, b in BEAN_INEQ:
        if a < len(keystream) and b < len(keystream):
            if keystream[a] == keystream[b]:
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


def verify_bean_from_implied(implied_keys: Dict[int, int]) -> bool:
    """Check Bean constraints directly from implied key values at crib positions.

    Unlike verify_bean/verify_bean_simple (which require a full keystream),
    this works with a sparse dict of {position: key_value} from any period.
    This enables Bean checking even when no full primer is available
    (e.g., at periods 19, 20, 23, 24, 26 where not all residue classes
    have crib data).

    Returns True if all Bean constraints that CAN be checked are satisfied.
    Constraints where either position is missing from implied_keys are skipped.
    """
    for a, b in BEAN_EQ:
        if a in implied_keys and b in implied_keys:
            if implied_keys[a] != implied_keys[b]:
                return False
    for a, b in BEAN_INEQ:
        if a in implied_keys and b in implied_keys:
            if implied_keys[a] == implied_keys[b]:
                return False
    return True
