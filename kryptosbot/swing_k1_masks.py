"""Swing K-1 Tier 1 mask enumeration (mod-N and boundary-region)."""
from __future__ import annotations

import hashlib
import itertools
from dataclasses import dataclass
from typing import FrozenSet, Iterable, Literal, Tuple

CT_LEN = 97
DEFAULT_NULL_COUNTS = (17, 20, 24, 28)


@dataclass(frozen=True)
class Mask:
    mask_id: str
    class_label: Literal["mod_n", "boundary_region"]
    positions: FrozenSet[int]
    params: tuple[Tuple[str, object], ...]  # (key, value) pairs for reproducibility

    @property
    def null_count(self) -> int:
        return len(self.positions)


def _mod_n_positions(N: int, residues: FrozenSet[int], text_len: int = CT_LEN) -> FrozenSet[int]:
    return frozenset(i for i in range(text_len) if (i % N) in residues)


def _mask_id_for(class_label: str, params: tuple[Tuple[str, object], ...]) -> str:
    serialized = f"{class_label}|" + "|".join(f"{k}={v}" for k, v in params)
    h = hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:12]
    return f"{class_label}_{h}"


def enumerate_mod_n_masks(
    target_null_counts: Tuple[int, ...] = DEFAULT_NULL_COUNTS,
    n_range: Tuple[int, int] = (2, 13),
    text_len: int = CT_LEN,
) -> Iterable[Mask]:
    """Emit one Mask per (N, residue-subset) combo whose null count is in target_null_counts.

    For each N in [n_range[0], n_range[1]], enumerate all non-empty proper subsets of
    {0, ..., N-1}. Keep only those whose induced null-position count is in target_null_counts.
    """
    seen: set[FrozenSet[int]] = set()
    for N in range(n_range[0], n_range[1] + 1):
        for k in range(1, N):  # subset size 1..N-1
            for combo in itertools.combinations(range(N), k):
                residues = frozenset(combo)
                positions = _mod_n_positions(N, residues, text_len)
                if len(positions) not in target_null_counts:
                    continue
                if positions in seen:
                    continue
                seen.add(positions)
                params = (
                    ("N", N),
                    ("residues", tuple(sorted(residues))),
                    ("null_count", len(positions)),
                )
                yield Mask(
                    mask_id=_mask_id_for("mod_n", params),
                    class_label="mod_n",
                    positions=positions,
                    params=params,
                )
