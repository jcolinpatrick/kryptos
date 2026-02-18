"""Bean constraint verification.

Verifies the equality and inequality constraints on keystream values
derived by Jim Bean's analysis. These are non-negotiable ground truth.
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
    """
    period = len(primer)
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
