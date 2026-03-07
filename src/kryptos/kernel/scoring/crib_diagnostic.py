"""Crib diagnostic analysis — spatial reasoning about partial crib matches.

When a candidate scores N/24 on cribs, the RAW SCORE discards critical spatial
information. This module answers: WHICH positions matched? Are they clustered?
What does the pattern of matches/misses imply about the key or permutation?

Key diagnostics:
  - Match clustering: contiguous runs suggest partial key recovery
  - Key consistency: do matched positions imply a consistent key fragment?
  - Near-miss analysis: how close are failed positions to matching?
  - Permutation hints: if cribs are at wrong positions, where ARE they?
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from kryptos.kernel.constants import CT, CRIB_DICT


@dataclass
class CribDiagnostic:
    """Full diagnostic analysis of crib matches in a candidate."""

    # Raw match data
    matched_positions: List[int] = field(default_factory=list)
    failed_positions: List[int] = field(default_factory=list)
    total_score: int = 0

    # Spatial analysis
    longest_run: int = 0                    # longest contiguous matched run
    runs: List[Tuple[int, int]] = field(default_factory=list)  # (start, length)
    ene_contiguous: int = 0                 # longest run within ENE (21-33)
    bc_contiguous: int = 0                  # longest run within BC (63-73)

    # Key analysis (Vigenere-derived key at matched positions)
    implied_key_chars: Dict[int, str] = field(default_factory=dict)
    key_consistent: bool = False            # do implied keys form a periodic pattern?
    best_period: int = 0                    # best-fit period if consistent
    period_residuals: Dict[int, List[str]] = field(default_factory=dict)

    # Near-miss analysis
    off_by_one: List[int] = field(default_factory=list)  # positions where |expected-actual| = 1
    off_by_n: Dict[int, int] = field(default_factory=dict)  # position -> distance

    # Permutation hints
    displaced_cribs: List[Tuple[str, int]] = field(default_factory=list)  # (crib_char, found_at_pos)

    @property
    def summary(self) -> str:
        parts = [
            f"score={self.total_score}/24",
            f"longest_run={self.longest_run}",
            f"ene_run={self.ene_contiguous}",
            f"bc_run={self.bc_contiguous}",
            f"off_by_1={len(self.off_by_one)}",
        ]
        if self.key_consistent:
            parts.append(f"period={self.best_period}")
        if self.implied_key_chars:
            key_sample = "".join(
                self.implied_key_chars[p]
                for p in sorted(self.implied_key_chars)[:8]
            )
            parts.append(f"key_hint={key_sample}...")
        return " | ".join(parts)

    def to_dict(self) -> dict:
        return {
            "total_score": self.total_score,
            "matched_positions": self.matched_positions,
            "failed_positions": self.failed_positions,
            "longest_run": self.longest_run,
            "runs": self.runs,
            "ene_contiguous": self.ene_contiguous,
            "bc_contiguous": self.bc_contiguous,
            "key_consistent": self.key_consistent,
            "best_period": self.best_period,
            "implied_key_chars": {str(k): v for k, v in self.implied_key_chars.items()},
            "off_by_one": self.off_by_one,
            "off_by_n": {str(k): v for k, v in self.off_by_n.items()},
        }


def diagnose_cribs(plaintext: str, ciphertext: str = CT) -> CribDiagnostic:
    """Full diagnostic analysis of crib matches.

    Args:
        plaintext: Candidate plaintext (uppercase A-Z, len 97)
        ciphertext: The ciphertext used (default: K4 CT)

    Returns:
        CribDiagnostic with spatial, key, and near-miss analysis
    """
    text = plaintext.upper()
    ct = ciphertext.upper()

    matched = []
    failed = []
    implied_keys: Dict[int, str] = {}
    off_by_one = []
    off_by_n: Dict[int, int] = {}

    for pos, expected in CRIB_DICT.items():
        if pos >= len(text):
            failed.append(pos)
            continue

        actual = text[pos]
        if actual == expected:
            matched.append(pos)
            # Derive implied Vigenere key: k = (CT - PT) mod 26
            if pos < len(ct):
                k_val = (ord(ct[pos]) - ord(actual)) % 26
                implied_keys[pos] = chr(k_val + ord('A'))
        else:
            failed.append(pos)
            # How far off?
            dist = (ord(actual) - ord(expected)) % 26
            dist = min(dist, 26 - dist)  # shortest circular distance
            off_by_n[pos] = dist
            if dist == 1:
                off_by_one.append(pos)

    # Find contiguous runs
    crib_positions = sorted(CRIB_DICT.keys())
    matched_set = set(matched)
    runs = []
    current_run_start = None
    current_run_len = 0

    for i, pos in enumerate(crib_positions):
        if pos in matched_set:
            if current_run_start is None:
                current_run_start = pos
                current_run_len = 1
            else:
                # Check if contiguous with previous crib position
                if i > 0 and pos == crib_positions[i - 1] + 1:
                    current_run_len += 1
                else:
                    runs.append((current_run_start, current_run_len))
                    current_run_start = pos
                    current_run_len = 1
        else:
            if current_run_start is not None:
                runs.append((current_run_start, current_run_len))
                current_run_start = None
                current_run_len = 0

    if current_run_start is not None:
        runs.append((current_run_start, current_run_len))

    longest_run = max((length for _, length in runs), default=0)

    # ENE and BC contiguous runs
    ene_positions = [p for p in range(21, 34) if p in matched_set]
    bc_positions = [p for p in range(63, 74) if p in matched_set]
    ene_contiguous = _longest_contiguous(ene_positions)
    bc_contiguous = _longest_contiguous(bc_positions)

    # Period consistency check
    key_consistent = False
    best_period = 0
    period_residuals: Dict[int, List[str]] = {}

    if len(implied_keys) >= 4:
        key_consistent, best_period, period_residuals = _check_period_consistency(
            implied_keys
        )

    return CribDiagnostic(
        matched_positions=matched,
        failed_positions=failed,
        total_score=len(matched),
        longest_run=longest_run,
        runs=runs,
        ene_contiguous=ene_contiguous,
        bc_contiguous=bc_contiguous,
        implied_key_chars=implied_keys,
        key_consistent=key_consistent,
        best_period=best_period,
        period_residuals=period_residuals,
        off_by_one=off_by_one,
        off_by_n=off_by_n,
    )


def _longest_contiguous(positions: List[int]) -> int:
    """Find longest contiguous run in a sorted list of positions."""
    if not positions:
        return 0
    best = 1
    current = 1
    for i in range(1, len(positions)):
        if positions[i] == positions[i - 1] + 1:
            current += 1
            best = max(best, current)
        else:
            current = 1
    return best


def _check_period_consistency(
    implied_keys: Dict[int, str],
) -> Tuple[bool, int, Dict[int, List[str]]]:
    """Check if implied key characters are consistent with a periodic key.

    Tests periods 1-26. A period is consistent if all positions with the
    same residue have the same implied key character.

    Returns (is_consistent, best_period, residual_map).
    """
    positions = sorted(implied_keys.keys())

    best_period = 0
    best_score = 0
    best_residuals: Dict[int, List[str]] = {}

    for period in range(1, 27):
        residuals: Dict[int, List[str]] = {}
        for pos in positions:
            r = pos % period
            if r not in residuals:
                residuals[r] = []
            residuals[r].append(implied_keys[pos])

        # Count consistent residues (all same letter)
        consistent = sum(
            1 for chars in residuals.values()
            if len(set(chars)) == 1 and len(chars) > 1
        )
        total_constrained = sum(
            1 for chars in residuals.values() if len(chars) > 1
        )

        if total_constrained > 0:
            score = consistent / total_constrained
            if score > best_score or (score == best_score and period < best_period):
                best_score = score
                best_period = period
                best_residuals = residuals

    is_consistent = best_score == 1.0 and best_period > 0
    return is_consistent, best_period, best_residuals
