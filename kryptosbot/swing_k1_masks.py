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
    class_label: Literal["mod_n", "boundary_region", "sentinel"]
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


# Gap regions (positions NOT covered by any disclosed crib).
CRIB_POSITIONS_LITERAL = frozenset(range(21, 34)) | frozenset(range(63, 74))
GAP_REGIONS: tuple[range, ...] = (range(0, 21), range(34, 63), range(74, 97))


def _boundary_positions_evenly_spaced(total_null_count: int) -> FrozenSet[int]:
    """Distribute total_null_count evenly across the three gap regions, then evenly within each."""
    gap_lens = [len(r) for r in GAP_REGIONS]
    total_gap = sum(gap_lens)
    # Allocate per region in proportion to gap length, rounded.
    alloc = [round(total_null_count * gl / total_gap) for gl in gap_lens]
    # Fix any rounding drift to ensure sum equals total_null_count.
    drift = total_null_count - sum(alloc)
    alloc[0] += drift
    out: set[int] = set()
    for r, count in zip(GAP_REGIONS, alloc):
        if count <= 0:
            continue
        step = max(1, len(r) // count)
        positions = [r.start + i * step for i in range(count)]
        # Clamp to range.
        positions = [p for p in positions if r.start <= p < r.stop]
        out.update(positions[:count])
    return frozenset(out)


def _boundary_positions_contiguous_block(total_null_count: int, anchor: str) -> FrozenSet[int]:
    """Place a contiguous block of total_null_count positions at the start, middle, or end of the gap union."""
    flat = []
    for r in GAP_REGIONS:
        flat.extend(r)
    if anchor == "start":
        return frozenset(flat[:total_null_count])
    elif anchor == "middle":
        mid = (len(flat) - total_null_count) // 2
        return frozenset(flat[mid:mid + total_null_count])
    elif anchor == "end":
        return frozenset(flat[-total_null_count:])
    else:
        raise ValueError(f"unknown anchor {anchor!r}")


def enumerate_boundary_region_masks(
    target_null_counts: Tuple[int, ...] = DEFAULT_NULL_COUNTS,
) -> Iterable[Mask]:
    """Boundary-region masks: nulls confined to gap regions (no crib position is null).

    Two sub-patterns:
    1. Evenly-spaced: nulls distributed proportionally across the three gap regions.
    2. Contiguous block: a contiguous run anchored at start, middle, or end of the gap union.
    """
    seen: set[FrozenSet[int]] = set()
    for count in target_null_counts:
        evenly = _boundary_positions_evenly_spaced(count)
        if evenly not in seen and len(evenly) == count:
            seen.add(evenly)
            params = (("pattern", "evenly_spaced"), ("null_count", count))
            yield Mask(
                mask_id=_mask_id_for("boundary_region", params),
                class_label="boundary_region",
                positions=evenly,
                params=params,
            )
        for anchor in ("start", "middle", "end"):
            block = _boundary_positions_contiguous_block(count, anchor)
            if block not in seen and len(block) == count:
                seen.add(block)
                params = (("pattern", f"block_{anchor}"), ("null_count", count))
                yield Mask(
                    mask_id=_mask_id_for("boundary_region", params),
                    class_label="boundary_region",
                    positions=block,
                    params=params,
                )


def build_mask_catalog(
    target_null_counts: Tuple[int, ...] = DEFAULT_NULL_COUNTS,
    strict_crib_safe: bool = False,
) -> tuple[Mask, ...]:
    """Build the full Tier 1 mask catalog.

    If strict_crib_safe is True, mod-N masks that overlap crib positions are
    excluded. Default (False) keeps them: M3 (null-skip) re-projects cribs to
    CT73 coordinates, so a null at a crib position is a legitimate model.
    """
    masks: list[Mask] = []
    for m in enumerate_mod_n_masks(target_null_counts=target_null_counts):
        if strict_crib_safe and (m.positions & CRIB_POSITIONS_LITERAL):
            continue
        masks.append(m)
    for m in enumerate_boundary_region_masks(target_null_counts=target_null_counts):
        # Boundary masks are crib-safe by construction.
        masks.append(m)
    # Sort by mask_id for deterministic order.
    masks.sort(key=lambda m: m.mask_id)
    return tuple(masks)


def serialize_catalog(catalog: tuple[Mask, ...]) -> dict:
    return {
        "schema_version": "swing_k1.mask_catalog.v1",
        "mask_count": len(catalog),
        "masks": [
            {
                "mask_id": m.mask_id,
                "class_label": m.class_label,
                "null_count": m.null_count,
                "positions": sorted(m.positions),
                "params": [list(p) for p in m.params],
            }
            for m in catalog
        ],
    }
