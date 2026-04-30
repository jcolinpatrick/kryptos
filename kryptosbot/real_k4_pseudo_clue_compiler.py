"""Real-K4 LLM↔HCC bridge: pseudo-clue pack compiler.

Takes a ``PseudoCluePack`` (structured roles + provenance) and emits
a deterministic list of ``GeneratedSpec`` from the existing HCC
family generators. The compiler does NOT rely on a natural-language
clue string; it routes pack contents to family generators directly.

Routing logic:
  * Each ``CompositionTemplate`` selects a family generator by its
    ``layer_kinds`` shape (sorted set of operation kinds).
  * Required ``OperationHint`` values further constrain which
    families fire — a template that doesn't include a required
    operation is skipped.
  * Per-pack ``Bounds`` cap the keyword pool, allowed widths/depths/
    shifts, and the per-pack spec count.
  * The compiler falls back to project-safe HCC defaults only when
    ``Bounds.allow_project_safe_defaults`` is True.
  * The output is sliced at ``Bounds.max_specs`` per pack; the audit
    runner enforces a global cap on top of this.

Every emitted spec carries the pack's ``pack_id`` in its
``coverage_vector.extras`` so downstream candidates can be linked
back to their pack and provenance.

This module is pure-Python and does not write to disk. It does not
read sealed-answer files or K4Bench data.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Iterable, Optional, Sequence

from kryptosbot.hand_cipher_core import (
    GeneratedSpec,
    AlphabetMode,
    _gen_keyword_pair_family,
    _gen_keywordless_trans_pair_family,
    _gen_reverse_blocks_alone_family,
    _gen_reverse_blocks_substitution_family,
    _gen_skip_route_alone_family,
    _gen_skip_route_substitution_family,
    _gen_route_boustrophedon_alone_family,
    _gen_route_boustrophedon_substitution_family,
    _gen_row_reverse_alone_family,
    _gen_row_reverse_substitution_family,
    _gen_diagonal_alone_family,
    _gen_diagonal_substitution_family,
    _gen_canonical_diagonal_alone_family,
    _gen_independent_three_role_keyword_family,
    _gen_independent_keyword_rail_fence_family,
    _gen_caesar_alone_family,
    _gen_numeric_caesar_route_columnar_family,
    _diagonal_canonical_route_layer,
    _route_boustrophedon_layer,
    _diagonal_route_layer,
    _DEFAULT_DIAGONAL_GRIDS,
)
from kryptosbot.real_k4_pseudo_clue_pack import (
    PseudoCluePack,
    KeywordHint,
    NumericRoleHint,
    OperationHint,
    CompositionTemplate,
)


# Project-safe defaults. The compiler uses these only when a pack's
# ``Bounds.allow_project_safe_defaults`` is True AND no pack-supplied
# pool covers the parameter.
_DEFAULT_RAIL_DEPTHS: tuple[int, ...] = (3, 4, 5)
_DEFAULT_BOUSTROPHEDON_WIDTHS: tuple[int, ...] = (7, 8, 9, 10)
_DEFAULT_DIAGONAL_GRID_TUPLES: tuple[tuple[int, int], ...] = (
    (10, 10), (13, 8), (8, 13), (7, 14),
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _pool_keywords_by_role(
    pack: PseudoCluePack, role: str,
) -> list[str]:
    """Collect keyword candidates for a role hint, deduplicated and
    upper-cased. Falls back to ``Bounds.allowed_keywords`` if the
    pack has no keyword hints with the requested role.
    """
    seen: set[str] = set()
    out: list[str] = []
    for kh in pack.keywords:
        if kh.role_hint not in (role, "unknown"):
            continue
        kw = kh.token.upper().strip()
        if kw and kw.isalpha() and len(kw) >= 2 and kw not in seen:
            seen.add(kw)
            out.append(kw)
    if not out and pack.bounds.allowed_keywords:
        for kw in pack.bounds.allowed_keywords:
            up = kw.upper().strip()
            if up and up.isalpha() and len(up) >= 2 and up not in seen:
                seen.add(up)
                out.append(up)
    return out


def _pool_all_keywords(pack: PseudoCluePack) -> list[str]:
    """All distinct keyword candidates regardless of role hint."""
    seen: set[str] = set()
    out: list[str] = []
    for kh in pack.keywords:
        kw = kh.token.upper().strip()
        if kw and kw.isalpha() and len(kw) >= 2 and kw not in seen:
            seen.add(kw)
            out.append(kw)
    for kw in pack.bounds.allowed_keywords:
        up = kw.upper().strip()
        if up and up.isalpha() and len(up) >= 2 and up not in seen:
            seen.add(up)
            out.append(up)
    return out


def _pool_numerics(
    pack: PseudoCluePack, role: str,
) -> list[int]:
    """Numeric candidates with a given role hint, plus pack-bound
    pool entries when available. Returns deduplicated, in pack order.
    """
    seen: set[int] = set()
    out: list[int] = []
    for nh in pack.numeric_roles:
        if nh.role_hint not in (role, "unknown"):
            continue
        if nh.value not in seen and isinstance(nh.value, int):
            seen.add(nh.value)
            out.append(nh.value)
    return out


def _depths_pool(pack: PseudoCluePack) -> list[int]:
    out = _pool_numerics(pack, "depth")
    if pack.bounds.allowed_depths:
        for d in pack.bounds.allowed_depths:
            if d not in out:
                out.append(int(d))
    if not out and pack.bounds.allow_project_safe_defaults:
        out = list(_DEFAULT_RAIL_DEPTHS)
    return [d for d in out if 2 <= d <= 20]


def _widths_pool(pack: PseudoCluePack) -> list[int]:
    out = _pool_numerics(pack, "width")
    if pack.bounds.allowed_widths:
        for w in pack.bounds.allowed_widths:
            if w not in out:
                out.append(int(w))
    if not out and pack.bounds.allow_project_safe_defaults and pack.bounds.allow_default_widths:
        out = list(_DEFAULT_BOUSTROPHEDON_WIDTHS)
    return [w for w in out if 1 <= w <= 50]


def _shifts_pool(pack: PseudoCluePack) -> list[int]:
    out = _pool_numerics(pack, "shift")
    if pack.bounds.allowed_shifts:
        for s in pack.bounds.allowed_shifts:
            if s not in out:
                out.append(int(s))
    return [s for s in out if 0 <= s <= 25]


def _required_ops(pack: PseudoCluePack) -> set[str]:
    return {h.operation for h in pack.operation_hints if h.role == "required"}


def _allowed_ops(pack: PseudoCluePack) -> set[str]:
    """Operations that may appear in emitted specs.

    A template's operations must be a subset of ``allowed_ops``;
    operations not mentioned in the pack's ``operation_hints`` are
    rejected unless the pack's bounds explicitly allow defaults.
    """
    ops = {h.operation for h in pack.operation_hints}
    if pack.bounds.allow_project_safe_defaults and not ops:
        # Pack has no operation hints but allows defaults: enumerate
        # the full operation surface.
        return set()  # empty == allow everything
    return ops


def _template_matches_required(
    tpl: CompositionTemplate, required: set[str],
) -> bool:
    if not required:
        return True
    return required.issubset(set(tpl.layer_kinds))


def _template_within_allowed(
    tpl: CompositionTemplate, allowed: set[str],
) -> bool:
    if not allowed:  # empty == allow everything
        return True
    return set(tpl.layer_kinds).issubset(allowed)


def _normalize_template(tpl: CompositionTemplate) -> tuple[str, ...]:
    """Sorted, deduplicated tuple of layer kinds — used as routing
    key. The compiler maps each unique key to ONE family generator
    call (with the template's ``ordered`` flag passed through where
    relevant)."""
    return tuple(sorted(set(tpl.layer_kinds)))


def _stamp_with_pack_id(
    specs: Iterable[GeneratedSpec], pack_id: str, evidence_tier: str,
) -> list[GeneratedSpec]:
    """Replace each spec's coverage with a copy carrying pack_id +
    evidence_tier in the extras tuple. Frozen-dataclass safe.
    """
    out: list[GeneratedSpec] = []
    for s in specs:
        new_extras = tuple(s.coverage.extras) + (
            ("pack_id", pack_id),
            ("evidence_tier", evidence_tier),
        )
        new_cov = dataclasses.replace(s.coverage, extras=new_extras)
        out.append(dataclasses.replace(s, coverage=new_cov))
    return out


# ---------------------------------------------------------------------------
# Per-template emitters
# ---------------------------------------------------------------------------

# Canonical sorted-set keys → generator callables. Each callable takes
# ``(pack, ordered)`` and returns a list of ``GeneratedSpec``.


_SUB_KINDS: tuple[str, ...] = ("vigenere", "beaufort", "variant_beaufort")


def _emit_caesar_alone(pack: PseudoCluePack, ordered: bool) -> list[GeneratedSpec]:
    shifts = _shifts_pool(pack)
    pairs: list[tuple[int, str]] = [
        (s, "pack_numeric_role") for s in shifts if s != 0
    ]
    if not pairs:
        return []
    return _gen_caesar_alone_family(
        bench_slug=pack.pack_id,
        shifts=tuple(pairs),
    )


def _emit_sub_columnar(pack: PseudoCluePack, ordered: bool) -> list[GeneratedSpec]:
    sub_pool = _pool_keywords_by_role(pack, "substitution")
    col_pool = _pool_keywords_by_role(pack, "columnar") or _pool_all_keywords(pack)
    all_kws = _pool_all_keywords(pack)
    if not all_kws:
        return []
    out: list[GeneratedSpec] = []
    sub_kws = sub_pool or all_kws
    if len(all_kws) >= 2:
        # Use the i3 independent-role generator, which covers both
        # keyword orientations across the role pool.
        for sub_kind in _SUB_KINDS:
            specs = _gen_independent_three_role_keyword_family(
                bench_slug=pack.pack_id,
                sub_kind=sub_kind,
                trans_kind="columnar",
                clue_keywords=all_kws[:3],
                role_pool_size=min(3, len(all_kws)),
                allow_self_pairs=True,
            )
            out.extend(specs)
    else:
        # Single-keyword fallback: legacy pair generator with same
        # keyword in both roles.
        kw = sub_kws[0]
        for sub_kind in _SUB_KINDS:
            out.extend(_gen_keyword_pair_family(
                bench_slug=pack.pack_id,
                sub_kind=sub_kind,
                trans_kind="columnar",
                keyword_a=kw, keyword_b=kw,
                alphabet_modes=(AlphabetMode("AZ", "AZ", None, "default"),),
            ))
    return out


def _emit_sub_rail_fence(pack: PseudoCluePack, ordered: bool) -> list[GeneratedSpec]:
    all_kws = _pool_all_keywords(pack)
    depths = _depths_pool(pack)
    if not all_kws or not depths:
        return []
    out: list[GeneratedSpec] = []
    for sub_kind in _SUB_KINDS:
        for depth in depths:
            for kw in all_kws[:3]:
                out.extend(_gen_keywordless_trans_pair_family(
                    bench_slug=pack.pack_id,
                    sub_kind=sub_kind,
                    trans_kind="rail_fence",
                    keyword=kw,
                    extra_params={"depth": int(depth)},
                    alphabet_modes=(AlphabetMode("AZ", "AZ", None, "default"),),
                ))
    return out


def _emit_sub_columnar_rail_fence(
    pack: PseudoCluePack, ordered: bool,
) -> list[GeneratedSpec]:
    """LESSON-022: independent two-keyword + rail_fence three-role."""
    all_kws = _pool_all_keywords(pack)
    depths = _depths_pool(pack)
    if len(all_kws) < 2 or not depths:
        return []
    out: list[GeneratedSpec] = []
    for sub_kind in _SUB_KINDS:
        out.extend(_gen_independent_keyword_rail_fence_family(
            bench_slug=pack.pack_id,
            sub_kind=sub_kind,
            clue_keywords=all_kws[:3],
            rail_fence_depths=depths[:3],
            role_pool_size=min(3, len(all_kws)),
        ))
    return out


def _emit_caesar_route_columnar(
    pack: PseudoCluePack, ordered: bool,
) -> list[GeneratedSpec]:
    """LESSON-019: numeric Caesar + route + columnar three-layer.
    Uses route_boustrophedon as the route partner by default; if the
    pack signals diagonal explicitly via operation_hints, switch."""
    shifts = _shifts_pool(pack)
    cols = _pool_keywords_by_role(pack, "columnar") or _pool_all_keywords(pack)
    if not shifts or not cols:
        return []
    promoted = [
        {
            "shift_value": s,
            "shift_source": "pack_numeric_role",
            "token": str(s),
            "role": "explicit_caesar",
            "shift_direction": "as_given",
        }
        for s in shifts if s != 0
    ]
    if not promoted:
        return []
    diagonal_requested = any(
        h.operation in ("route_diagonal", "route_diagonal_canonical")
        for h in pack.operation_hints
    )
    out: list[GeneratedSpec] = []
    if diagonal_requested:
        # 4 axis variants × top-2 grids
        l019_diag_grids = ((10, 10), (13, 8))
        l019_diag_variants = [
            ("main", "forward", "top_then_left"),
            ("anti", "forward", "top_then_right"),
            ("main", "reverse", "top_then_left"),
            ("anti", "reverse", "top_then_right"),
        ]

        def _layer_factory() -> list[dict[str, Any]]:
            layers: list[dict[str, Any]] = []
            for rows, c in l019_diag_grids:
                for axis, order, start_edge in l019_diag_variants:
                    layers.append(_diagonal_route_layer(
                        rows, c, axis=axis, order=order, start_edge=start_edge,
                    ))
            return layers

        def _extras(layer):
            params = {p["name"]: p["values"][0] for p in layer.get("params", [])}
            return (
                ("diag_rows", params.get("rows")),
                ("diag_cols", params.get("cols")),
                ("diag_axis", params.get("diagonal_axis")),
                ("diag_order", params.get("diagonal_order")),
                ("diag_start_edge", params.get("diagonal_start_edge")),
            )

        def _cov_extras(layer):
            params = {p["name"]: p["values"][0] for p in layer.get("params", [])}
            rows = int(params["rows"]); cs = int(params["cols"])
            return {
                "route_mode": "route_diagonal",
                "route_rows": rows, "route_cols": cs,
                "route_width": cs,
                "route_ragged": (rows * cs) > 97,
                "route_direction": str(params["diagonal_axis"]),
                "route_width_source": "pack_numeric_role",
                "diagonal_axis": str(params["diagonal_axis"]),
                "diagonal_order": str(params["diagonal_order"]),
                "diagonal_start_edge": str(params["diagonal_start_edge"]),
            }

        out.extend(_gen_numeric_caesar_route_columnar_family(
            bench_slug=pack.pack_id,
            route_partner_kind="route_diagonal",
            route_layer_factory=_layer_factory,
            route_partner_extras_factory=_extras,
            coverage_extras_factory=_cov_extras,
            promoted_shifts=promoted,
            columnar_keywords=cols[:2],
            numeric_only=True,
        ))
    else:
        widths = _widths_pool(pack)
        if not widths:
            return []

        def _rb_layer_factory() -> list[dict[str, Any]]:
            layers: list[dict[str, Any]] = []
            for w in widths[:3]:
                for vert in (False, True):
                    layers.append(_route_boustrophedon_layer(
                        w, vertical=vert,
                    ))
            return layers

        def _rb_extras(layer):
            params = {p["name"]: p["values"][0] for p in layer.get("params", [])}
            return (
                ("rb_width", params.get("width")),
                ("rb_vertical", params.get("vertical", False)),
            )

        def _rb_cov_extras(layer):
            params = {p["name"]: p["values"][0] for p in layer.get("params", [])}
            width = int(params.get("width"))
            vert = bool(params.get("vertical", False))
            rows = (97 + width - 1) // width
            return {
                "route_mode": "route_boustrophedon",
                "route_rows": rows, "route_cols": width,
                "route_width": width,
                "route_ragged": (97 % width) != 0,
                "route_direction": "vertical" if vert else "horizontal",
                "route_width_source": "pack_numeric_role",
            }

        out.extend(_gen_numeric_caesar_route_columnar_family(
            bench_slug=pack.pack_id,
            route_partner_kind="route_boustrophedon",
            route_layer_factory=_rb_layer_factory,
            route_partner_extras_factory=_rb_extras,
            coverage_extras_factory=_rb_cov_extras,
            promoted_shifts=promoted,
            columnar_keywords=cols[:2],
            numeric_only=True,
        ))
    return out


def _emit_diagonal_substitution(
    pack: PseudoCluePack, ordered: bool,
) -> list[GeneratedSpec]:
    """LESSON-016 diagonal route + substitution."""
    all_kws = _pool_all_keywords(pack)
    if not all_kws:
        return []
    widths = _widths_pool(pack)
    grids: list[tuple[tuple[int, int], str]] = []
    if widths:
        for w in widths[:4]:
            rows = (97 + w - 1) // w
            grids.append(((rows, w), "pack_numeric_role"))
    elif pack.bounds.allow_project_safe_defaults:
        for r, c in _DEFAULT_DIAGONAL_GRID_TUPLES:
            grids.append(((r, c), "default_set"))
    if not grids:
        return []
    out: list[GeneratedSpec] = []
    for sub_kind in _SUB_KINDS:
        out.extend(_gen_diagonal_substitution_family(
            bench_slug=pack.pack_id,
            sub_kind=sub_kind,
            keyword_a=all_kws[0],
            keyword_b=all_kws[1] if len(all_kws) > 1 else all_kws[0],
            grids=grids,
            cell_orders=("forward", "reverse"),
        ))
    return out


def _emit_diagonal_canonical_alone(
    pack: PseudoCluePack, ordered: bool,
) -> list[GeneratedSpec]:
    widths = _widths_pool(pack)
    if not widths and pack.bounds.allow_project_safe_defaults:
        widths = [10, 13]
    if not widths:
        return []
    pairs = [(w, "pack_numeric_role") for w in widths[:4]]
    return _gen_canonical_diagonal_alone_family(
        bench_slug=pack.pack_id, widths=pairs,
    )


def _emit_route_boustrophedon_substitution(
    pack: PseudoCluePack, ordered: bool,
) -> list[GeneratedSpec]:
    all_kws = _pool_all_keywords(pack)
    widths = _widths_pool(pack)
    if not all_kws or not widths:
        return []
    width_pairs = [(w, "pack_numeric_role") for w in widths[:4]]
    out: list[GeneratedSpec] = []
    for sub_kind in _SUB_KINDS:
        out.extend(_gen_route_boustrophedon_substitution_family(
            bench_slug=pack.pack_id,
            sub_kind=sub_kind,
            keyword_a=all_kws[0],
            keyword_b=all_kws[1] if len(all_kws) > 1 else all_kws[0],
            widths=width_pairs,
            directions=(False, True),
        ))
    return out


def _emit_row_reverse_substitution(
    pack: PseudoCluePack, ordered: bool,
) -> list[GeneratedSpec]:
    all_kws = _pool_all_keywords(pack)
    widths = _widths_pool(pack)
    if not all_kws or not widths:
        return []
    width_pairs = [(w, "pack_numeric_role") for w in widths[:4]]
    out: list[GeneratedSpec] = []
    for sub_kind in _SUB_KINDS:
        out.extend(_gen_row_reverse_substitution_family(
            bench_slug=pack.pack_id,
            sub_kind=sub_kind,
            keyword_a=all_kws[0],
            keyword_b=all_kws[1] if len(all_kws) > 1 else all_kws[0],
            widths=width_pairs,
            parities=("odd", "even"),
        ))
    return out


def _emit_reverse_blocks_substitution(
    pack: PseudoCluePack, ordered: bool,
) -> list[GeneratedSpec]:
    all_kws = _pool_all_keywords(pack)
    block_sizes = _pool_numerics(pack, "period") or _pool_numerics(pack, "width")
    if not all_kws or not block_sizes:
        return []
    out: list[GeneratedSpec] = []
    for sub_kind in _SUB_KINDS:
        out.extend(_gen_reverse_blocks_substitution_family(
            bench_slug=pack.pack_id,
            sub_kind=sub_kind,
            keyword_a=all_kws[0],
            keyword_b=all_kws[1] if len(all_kws) > 1 else all_kws[0],
            block_sizes=tuple(int(b) for b in block_sizes[:3]),
            block_modes=("reverse_full", "reverse_partial"),
        ))
    return out


# Canonical sorted-set routing key → emitter
_TEMPLATE_ROUTING: dict[tuple[str, ...], Any] = {
    ("caesar",): _emit_caesar_alone,
    ("columnar", "vigenere"): _emit_sub_columnar,
    ("beaufort", "columnar"): _emit_sub_columnar,
    ("columnar", "variant_beaufort"): _emit_sub_columnar,
    ("rail_fence", "vigenere"): _emit_sub_rail_fence,
    ("beaufort", "rail_fence"): _emit_sub_rail_fence,
    ("rail_fence", "variant_beaufort"): _emit_sub_rail_fence,
    ("columnar", "rail_fence", "vigenere"): _emit_sub_columnar_rail_fence,
    ("beaufort", "columnar", "rail_fence"): _emit_sub_columnar_rail_fence,
    ("columnar", "rail_fence", "variant_beaufort"):
        _emit_sub_columnar_rail_fence,
    ("caesar", "columnar", "route_boustrophedon"): _emit_caesar_route_columnar,
    ("caesar", "columnar", "route_diagonal"): _emit_caesar_route_columnar,
    ("route_diagonal", "vigenere"): _emit_diagonal_substitution,
    ("beaufort", "route_diagonal"): _emit_diagonal_substitution,
    ("route_diagonal", "variant_beaufort"): _emit_diagonal_substitution,
    ("route_diagonal_canonical",): _emit_diagonal_canonical_alone,
    ("route_boustrophedon", "vigenere"):
        _emit_route_boustrophedon_substitution,
    ("beaufort", "route_boustrophedon"):
        _emit_route_boustrophedon_substitution,
    ("route_boustrophedon", "variant_beaufort"):
        _emit_route_boustrophedon_substitution,
    ("row_reverse", "vigenere"): _emit_row_reverse_substitution,
    ("beaufort", "row_reverse"): _emit_row_reverse_substitution,
    ("row_reverse", "variant_beaufort"): _emit_row_reverse_substitution,
    ("reverse_blocks", "vigenere"): _emit_reverse_blocks_substitution,
    ("beaufort", "reverse_blocks"): _emit_reverse_blocks_substitution,
    ("reverse_blocks", "variant_beaufort"): _emit_reverse_blocks_substitution,
}


# ---------------------------------------------------------------------------
# Public compile entry points
# ---------------------------------------------------------------------------


class CompileError(ValueError):
    """Raised when a pack fails validation OR routes to no families."""


def compile_pack(pack: PseudoCluePack) -> list[GeneratedSpec]:
    """Compile one pack to a deterministic list of GeneratedSpec.

    Routing:
      * Each composition_template is matched to a family generator
        by its sorted layer_kinds set.
      * Templates that include a ``required`` operation absent from
        their layer_kinds are skipped.
      * Templates that include operations not in
        ``allowed_ops`` (when allowed_ops is non-empty) are skipped.
      * Generated specs are deduplicated by hypothesis_id.
      * The output is capped at ``pack.bounds.max_specs``.

    A pack with NO matching templates AND NO trivial fallback emits
    an empty list (NOT an error). The audit runner reports this as
    ``packs_with_zero_specs`` for diagnostic surfacing.
    """
    errors = pack.validate()
    if errors:
        raise CompileError(
            f"PseudoCluePack {pack.pack_id!r} failed validation: {errors}"
        )

    required = _required_ops(pack)
    # Note: ``operation_hints`` are role DECLARATIONS, not an
    # exhaustive whitelist — a template's layer_kinds are its OWN
    # operation choice and must be allowed regardless of whether
    # operation_hints names them. The required-op gate
    # (every required operation must appear in the template) is the
    # only operation-level gating we apply at this layer.

    seen_hids: set[str] = set()
    out: list[GeneratedSpec] = []
    for tpl in pack.composition_templates:
        if not _template_matches_required(tpl, required):
            continue
        key = _normalize_template(tpl)
        emitter = _TEMPLATE_ROUTING.get(key)
        if emitter is None:
            continue
        emitted = emitter(pack, tpl.ordered)
        for spec in emitted:
            if spec.hypothesis_id in seen_hids:
                continue
            seen_hids.add(spec.hypothesis_id)
            out.append(spec)

    out = _stamp_with_pack_id(out, pack.pack_id, pack.evidence_tier)
    return out[: int(pack.bounds.max_specs)]


def compile_packs(
    packs: Sequence[PseudoCluePack],
    *,
    global_max_specs: int = 5000,
) -> tuple[list[GeneratedSpec], list[dict[str, Any]]]:
    """Compile a list of packs into a single deterministic spec
    list, with provenance.

    Returns ``(specs, pack_summaries)`` where each entry in
    ``pack_summaries`` is a dict with pack_id, title, evidence_tier,
    n_specs_emitted, n_specs_retained, validation_errors,
    routed_templates, skipped_templates, etc.

    Specs are merged in pack-declaration order; the global cap is
    enforced AFTER per-pack caps. Duplicates across packs are
    dropped.
    """
    summaries: list[dict[str, Any]] = []
    seen_hids: set[str] = set()
    out: list[GeneratedSpec] = []
    if global_max_specs <= 0:
        raise ValueError("global_max_specs must be positive")
    for pack in packs:
        errors = pack.validate()
        summary: dict[str, Any] = {
            "pack_id": pack.pack_id,
            "title": pack.title,
            "evidence_tier": pack.evidence_tier,
            "validation_errors": errors,
            "n_specs_emitted": 0,
            "n_specs_retained": 0,
            "routed_templates": [],
            "skipped_templates": [],
        }
        if errors:
            summaries.append(summary)
            continue
        try:
            specs = compile_pack(pack)
        except CompileError as e:
            summary["validation_errors"] = [str(e)]
            summaries.append(summary)
            continue
        summary["n_specs_emitted"] = len(specs)
        retained = 0
        for spec in specs:
            if len(out) >= global_max_specs:
                break
            if spec.hypothesis_id in seen_hids:
                continue
            seen_hids.add(spec.hypothesis_id)
            out.append(spec)
            retained += 1
        summary["n_specs_retained"] = retained
        # Routed-template summary (sorted-set keys per template)
        for tpl in pack.composition_templates:
            key = _normalize_template(tpl)
            if key in _TEMPLATE_ROUTING:
                summary["routed_templates"].append(list(key))
            else:
                summary["skipped_templates"].append({
                    "layer_kinds": list(key),
                    "reason": "no_matching_emitter",
                })
        summaries.append(summary)
        if len(out) >= global_max_specs:
            # Mark remaining packs as skipped due to global cap
            continue
    return out, summaries


__all__ = [
    "CompileError",
    "compile_pack",
    "compile_packs",
]
