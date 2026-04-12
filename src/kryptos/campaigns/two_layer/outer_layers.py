"""Outer layer generators for the two-layer campaign.

Every generator returns a SMALL, JUSTIFIED set of OuterFamily instances.
No arbitrary mask enumeration. Outer layers must come from low-complexity
parameterized families, or the sweep must carry an explicit multiplicity
penalty via is_post_hoc_selected / selection_pool_size.
"""
from __future__ import annotations

import math
from itertools import product
from typing import List, Tuple

from kryptos.campaigns.two_layer.families import OuterFamily, ProvenanceClass


# ── Mask / selector family ──────────────────────────────────────────────

_EVERY_NTH_N = (2, 3, 4, 5, 7)


def _every_nth_instances() -> List[OuterFamily]:
    out: List[OuterFamily] = []
    total = sum(_EVERY_NTH_N)  # phase count summed across n values
    for n in _EVERY_NTH_N:
        for phase in range(n):
            out.append(OuterFamily(
                family_id="OUTER-MASK-EVERYNTH",
                name=f"every_{n}_phase_{phase}",
                description=f"Keep positions i where (i - {phase}) mod {n} == 0",
                parameters={"n": n, "phase": phase},
                parameter_space_size=total,
                complexity_score=math.log2(max(total, 2)),
                breaks_direct_positional_alignment=True,
                is_post_hoc_selected=False,
                selection_pool_size=1,
                provenance=ProvenanceClass.STRUCTURAL,
            ))
    return out


def _bounded_periodic_mask_instances() -> List[OuterFamily]:
    """Length-L periodic keep/drop mask, L in {5,7,9}, weight <= ceil(L/2)."""
    out: List[OuterFamily] = []
    patterns: List[Tuple[int, Tuple[int, ...]]] = []
    for L in (5, 7, 9):
        max_w = (L + 1) // 2  # ceil(L/2)
        for bits in product((0, 1), repeat=L):
            w = sum(bits)
            if w == 0 or w > max_w:
                continue
            patterns.append((L, bits))
    total = len(patterns)
    for L, bits in patterns:
        out.append(OuterFamily(
            family_id="OUTER-MASK-PERIODIC",
            name=f"periodic_L{L}_{''.join(str(b) for b in bits)}",
            description=f"Length-{L} periodic mask, keep where bit=1",
            parameters={"L": L, "bits": list(bits)},
            parameter_space_size=total,
            complexity_score=math.log2(max(total, 2)),
            breaks_direct_positional_alignment=True,
            is_post_hoc_selected=False,
            selection_pool_size=1,
            provenance=ProvenanceClass.STRUCTURAL,
        ))
    return out


# ── Projection / transposition family ───────────────────────────────────

_JUSTIFIED_WIDTHS = (7, 10, 14, 17, 21)
_WIDTH_JUSTIFICATION = {
    7: "KRYPTOS length",
    10: "Polybius row",
    14: "K1+K2 chart width",
    17: "~sqrt(289)",
    21: "Bean width-21 noted anomaly",
}

_KRYPTOS_ORDER = "KRYPTOS"


def _kryptos_column_order(width: int) -> List[int]:
    """Column read order derived from KRYPTOS keyword repeated to width."""
    # Build KRYPTOS.. sequence of length width, then argsort stably.
    letters = [(_KRYPTOS_ORDER[i % len(_KRYPTOS_ORDER)], i) for i in range(width)]
    # Sort by (letter, original index) — stable, deterministic
    ordered = sorted(range(width), key=lambda i: (letters[i][0], i))
    return ordered


def _projection_instances() -> List[OuterFamily]:
    out: List[OuterFamily] = []
    methods = ("row_identity", "columnar_kryptos", "serpentine")
    total = len(_JUSTIFIED_WIDTHS) * len(methods)
    for w in _JUSTIFIED_WIDTHS:
        for m in methods:
            params: dict = {"width": w, "method": m, "justification": _WIDTH_JUSTIFICATION[w]}
            if m == "columnar_kryptos":
                params["column_order"] = _kryptos_column_order(w)
            out.append(OuterFamily(
                family_id="OUTER-PROJECT",
                name=f"project_w{w}_{m}",
                description=f"Width-{w} {m}; justified by {_WIDTH_JUSTIFICATION[w]}",
                parameters=params,
                parameter_space_size=total,
                complexity_score=math.log2(max(total, 2)),
                breaks_direct_positional_alignment=True,
                is_post_hoc_selected=False,
                selection_pool_size=1,
                provenance=ProvenanceClass.STRUCTURAL,
            ))
    return out


def _projection_swept_instances() -> List[OuterFamily]:
    """Comparison bucket: sweep widths 2-30. Marked post-hoc-selected."""
    out: List[OuterFamily] = []
    widths = list(range(2, 31))
    pool = len(widths)
    for w in widths:
        out.append(OuterFamily(
            family_id="OUTER-PROJECT-SWEPT",
            name=f"project_swept_w{w}",
            description=f"Width-{w} row identity, from unconstrained sweep (post-hoc)",
            parameters={"width": w, "method": "row_identity"},
            parameter_space_size=pool,
            complexity_score=math.log2(pool) + 2.0,  # extra complexity penalty
            breaks_direct_positional_alignment=True,
            is_post_hoc_selected=True,
            selection_pool_size=pool,
            provenance=ProvenanceClass.EXPLORATORY,
        ))
    return out


# ── Segmentation / reset family ─────────────────────────────────────────

_BREAK_POINTS = (21, 33, 48, 63, 73)  # structural anchors
_RESET_RULES = ("same_key", "k1k2k3_keywords", "increment_offset")


def _segmentation_instances() -> List[OuterFamily]:
    out: List[OuterFamily] = []
    # Choose K in {2,3,4}: pick subsets of break points
    splits = [
        (48,),                  # K=2
        (33, 63),               # K=3
        (21, 48, 73),           # K=4
        (21, 33, 63),           # K=4 alt
    ]
    total = len(splits) * len(_RESET_RULES)
    for split in splits:
        for rule in _RESET_RULES:
            K = len(split) + 1
            out.append(OuterFamily(
                family_id="OUTER-SEG",
                name=f"seg_K{K}_{'_'.join(str(s) for s in split)}_{rule}",
                description=f"Split at {split} with reset rule {rule}",
                parameters={"split": list(split), "rule": rule, "K": K},
                parameter_space_size=total,
                complexity_score=math.log2(max(total, 2)),
                # Segmentation preserves positions; it just partitions the key
                breaks_direct_positional_alignment=False,
                is_post_hoc_selected=False,
                selection_pool_size=1,
                provenance=ProvenanceClass.STRUCTURAL,
            ))
    return out


# ── Public entry point ──────────────────────────────────────────────────

def generate_instances(include_swept: bool = False) -> List[OuterFamily]:
    """Return all outer family instances for the default campaign run.

    include_swept: if True, also include the comparison bucket of width 2-30
    projection instances (marked post-hoc-selected).
    """
    out: List[OuterFamily] = []
    out.extend(_every_nth_instances())
    out.extend(_bounded_periodic_mask_instances())
    out.extend(_projection_instances())
    out.extend(_segmentation_instances())
    if include_swept:
        out.extend(_projection_swept_instances())
    return out


# ── Application: apply outer layer to a string ──────────────────────────

def apply_outer(outer: OuterFamily, text: str) -> str:
    """Apply the outer layer to `text`, returning the extracted stream.

    For masks: returns the kept subset.
    For projections: returns the reordered text.
    For segmentation: returns the text unchanged (segmentation is a key
    structure, not a position rearrangement).
    """
    fid = outer.family_id
    if fid == "OUTER-MASK-EVERYNTH":
        n = outer.parameters["n"]
        phase = outer.parameters["phase"]
        return "".join(c for i, c in enumerate(text) if (i - phase) % n == 0)
    if fid == "OUTER-MASK-PERIODIC":
        bits = outer.parameters["bits"]
        L = outer.parameters["L"]
        return "".join(c for i, c in enumerate(text) if bits[i % L] == 1)
    if fid in ("OUTER-PROJECT", "OUTER-PROJECT-SWEPT"):
        w = outer.parameters["width"]
        m = outer.parameters["method"]
        # Write into rows of width w
        rows: List[List[str]] = []
        for i, c in enumerate(text):
            r = i // w
            if r >= len(rows):
                rows.append([])
            rows[r].append(c)
        if m == "row_identity":
            return "".join("".join(r) for r in rows)
        if m == "serpentine":
            out_chars: List[str] = []
            for idx, r in enumerate(rows):
                out_chars.extend(r if idx % 2 == 0 else list(reversed(r)))
            return "".join(out_chars)
        if m == "columnar_kryptos":
            order = outer.parameters.get("column_order") or _kryptos_column_order(w)
            cols: List[List[str]] = [[] for _ in range(w)]
            for r in rows:
                for ci, ch in enumerate(r):
                    cols[ci].append(ch)
            return "".join("".join(cols[idx]) for idx in order)
    if fid == "OUTER-SEG":
        # Segmentation does not rearrange characters; it labels key zones.
        return text
    raise ValueError(f"Unknown outer family_id: {fid}")
