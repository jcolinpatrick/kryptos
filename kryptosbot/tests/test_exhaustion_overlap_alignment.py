"""Suite-assurance Task A — exhaustion-overlap must be alignment-aware.

The exhaustion log has no alignment_model field; every historical entry was
recorded under the direct-positional (H1) frame unless its id/family/
description explicitly says otherwise. ``_exhaustion_overlap`` matched on
family substrings ONLY, so a spec declaring ``crib_alignment=
"post_transposition"`` or ``"free"`` could be admissibility-blocked by a
direct-scope entry — an H1-scoped elimination killing a hypothesis outside
its scope (the exact AUDIT-1 error class, at the dispatch gate).

Live collision is real, not hypothetical: at 2026-06-10 the log holds 28
exhausted/completed entries whose family contains a cipher kind substring
(columnar 10, grille 17, beaufort 1).

Rule pinned here: an exhaustion entry counts as overlapping a NON-direct
spec only if the entry itself is marked non-direct (id/family/description/
audit_reason contains a non-direct marker). Direct specs keep the old
behavior verbatim.
"""
from __future__ import annotations

from kryptosbot.hypothesis_dsl import CipherLayer, HypothesisSpec, ParamRange
from kryptosbot.job_dispatcher import _exhaustion_overlap


def _spec(crib_alignment: str, kind: str = "columnar") -> HypothesisSpec:
    params = []
    if kind == "columnar":
        params = [ParamRange(name="width", values=[6, 8])]
    elif kind == "vigenere":
        params = [ParamRange(name="keyword", values=["PALIMPSEST"])]
    return HypothesisSpec(
        hypothesis_id=f"T-OVERLAP-{crib_alignment}",
        pipeline=[CipherLayer(kind=kind, alphabet="AZ", params=params)],
        compute_budget_cpu_minutes=1,
        crib_alignment=crib_alignment,
    )


_DIRECT_ENTRY = {
    "family": "transposition/columnar",
    "status": "exhausted",
    "audit_reason": "exhaustive direct sweep, max 13/24",
    "description": "columnar w6/8/9 under direct correspondence",
}

_NONDIRECT_ENTRY = {
    "family": "campaigns/columnar_posttrans",
    "status": "exhausted",
    "audit_reason": "clean null",
    "description": "route-outer columnar inner under post_transposition",
}


def test_direct_spec_still_overlaps_unmarked_entry():
    """Regression pin: direct specs keep the historical advisory behavior."""
    overlap = _exhaustion_overlap(
        _spec("direct_positional"), {"old_direct_scan": dict(_DIRECT_ENTRY)},
    )
    assert overlap == ["old_direct_scan"]


def test_post_transposition_spec_not_blocked_by_direct_scope_entry():
    """A direct-scope (unmarked) entry must NOT cover a post_transposition
    spec — the elimination was proven under a different alignment model."""
    overlap = _exhaustion_overlap(
        _spec("post_transposition"), {"old_direct_scan": dict(_DIRECT_ENTRY)},
    )
    assert overlap == [], (
        "H1-scope exhaustion entry blocked a post_transposition spec: "
        f"{overlap}"
    )


def test_free_spec_not_blocked_by_direct_scope_entry():
    overlap = _exhaustion_overlap(
        _spec("free"), {"old_direct_scan": dict(_DIRECT_ENTRY)},
    )
    assert overlap == []


def test_post_transposition_spec_blocked_by_nondirect_marked_entry():
    """An entry explicitly recorded as non-direct still covers a
    matching non-direct spec (closed non-direct cells stay closed)."""
    overlap = _exhaustion_overlap(
        _spec("post_transposition"),
        {"f_columnar_posttrans_2026": dict(_NONDIRECT_ENTRY)},
    )
    assert overlap == ["f_columnar_posttrans_2026"]


def test_nondirect_marker_in_script_id_counts():
    """The marker may live in the script_id itself (real registered ids
    look like f_route_outer_quagmire_iii_posttrans_2026_06_09)."""
    entry = {
        "family": "campaigns/columnar",
        "status": "exhausted",
        "description": "",
    }
    overlap = _exhaustion_overlap(
        _spec("post_transposition"),
        {"f_columnar_post_transposition_cell": entry},
    )
    assert overlap == ["f_columnar_post_transposition_cell"]
