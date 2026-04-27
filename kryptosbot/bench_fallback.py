"""K4Bench HandCipherCore programmatic fallback.

When the theorist agent emits unparseable output during a K4Bench run,
``ResearchController._programmatic_fallback`` previously returned an
empty list (the real-K4 fallback corpus draws from the K4 family /
anomaly registries that don't apply to a synthetic challenge). The
result was Proposed=0 / Tested=0 cycles whenever the theorist hiccupped.

This module provides ``hand_cipher_core_fallback`` — a deterministic,
challenge-local generator that emits >= ``n_target`` valid finite DSL
specs derived from the challenge's own clue pack. Every spec is run
through ``validate_hypothesis_spec`` AND each layer kind is checked for
dispatcher translation before being returned, so any spec that survives
is guaranteed dispatchable.

Design constraints:

- No real-K4 vocabulary. Keywords come exclusively from the challenge
  ``clue_text``, ``title``, and a small pool of project-wide-safe
  defaults (KRYPTOS, PALIMPSEST, ABSCISSA, KEY) that the controller
  tolerates in either mode.
- Pure data adapter. No SDK calls, no kernel imports beyond what the
  validator drags in. The fallback runs in <100 ms even when the
  theorist took 30 seconds to fail.
- Fail closed. A spec that fails ``validate_hypothesis_spec`` is
  silently dropped; the function returns whatever did validate. The
  caller (the controller) is responsible for asserting non-emptiness
  and surfacing a halt if every spec dropped.

Typical use site (``ResearchController._programmatic_fallback``)::

    if not self.config.problem.is_real_k4:
        from .bench_fallback import hand_cipher_core_fallback
        return hand_cipher_core_fallback(
            payload=self.config.bench_challenge_payload or {},
            n_target=self.config.theories_per_cycle,
        )
"""

from __future__ import annotations

import logging
import re
from typing import Any, Mapping, Optional

from .hypothesis_dsl import validate_hypothesis_spec
from .job_dispatcher import _SUPPORTED_KINDS, _kind_has_translation
from .models import TheoryRecord


logger = logging.getLogger("kryptosbot.bench_fallback")


# Project-wide-safe keyword fallbacks. KRYPTOS / PALIMPSEST / ABSCISSA
# are real-K4 known keywords and will appear in either prompt context
# without provoking a contamination signal — they are part of the
# canonical English-language Kryptos vocabulary. KEY is a generic
# stand-in. Used only when the challenge clue text yields no usable
# tokens.
_DEFAULT_KEYWORDS: tuple[str, ...] = (
    "KRYPTOS",
    "PALIMPSEST",
    "ABSCISSA",
    "KEY",
)

# Stop-words excluded from clue-text tokenization. These are short or
# generic words that produce noisy keys; they are conservative and
# erring on the side of "drop" rather than "include" because we have a
# guaranteed default pool to fall back on.
_CLUE_STOPWORDS: frozenset[str] = frozenset({
    "THE", "AND", "FOR", "ARE", "BUT", "NOT", "WAS", "WERE",
    "WITH", "FROM", "INTO", "OVER", "UNDER", "ABOVE", "BELOW",
    "ALL", "ANY", "SOME", "EACH", "EVERY", "ONE", "TWO", "THREE",
    "FOUR", "FIVE", "SIX", "EIGHT", "NINE", "TEN",
    "THIS", "THAT", "THESE", "THOSE", "WHICH", "WHAT", "WHO", "WHOM",
    "HIS", "HER", "ITS", "OUR", "THEIR",
    "HAS", "HAVE", "HAD", "DOES", "DID", "BEEN", "BEING",
    "ONLY", "JUST", "ALSO", "VERY", "MORE", "MOST", "LESS",
    "LABELS", "MARGIN", "FIELD", "BELOW",  # K4B-001 prose-noise
})

# Minimum and maximum keyword length when mining clue text. Vigenere
# accepts any length >= 1 over the canonical alphabet, but very short
# keywords degenerate to Caesar shifts and very long ones overrun a
# 97-char text. The 3..14 band covers CEDAR, LANTERN, KRYPTOS,
# PALIMPSEST, ABSCISSA without clipping the canonical real-K4
# vocabulary.
_MIN_KEYWORD_LEN: int = 3
_MAX_KEYWORD_LEN: int = 14


def _extract_clue_keywords(payload: Mapping[str, Any]) -> list[str]:
    """Mine clue-text and title for plausible cipher-keyword candidates.

    Returns an ordered, de-duplicated list of uppercase A-Z words from
    ``payload["clue_text"]`` and ``payload["title"]``.

    Ordering rule (priority for downstream key selection):
      1. ALL-CAPS tokens in ``clue_text`` first — these are the
         convention K4Bench uses to mark deliberate clue anchors
         (e.g. CEDAR, LANTERN in K4B-001's "CEDAR posts below a
         LANTERN"). They are the most likely intended keys.
      2. Mixed-case tokens in ``clue_text`` next, in document order.
      3. Tokens from ``title`` last, in document order.

    Tokens shorter than ``_MIN_KEYWORD_LEN`` or longer than
    ``_MAX_KEYWORD_LEN``, and tokens in ``_CLUE_STOPWORDS``, are
    excluded. The result may legally be empty; the caller is expected
    to fall back to ``_DEFAULT_KEYWORDS`` in that case.
    """
    clue_text = payload.get("clue_text") if isinstance(payload.get("clue_text"), str) else ""
    title = payload.get("title") if isinstance(payload.get("title"), str) else ""

    seen: set[str] = set()
    keywords: list[str] = []

    def _accept(token_raw: str) -> None:
        upper = token_raw.upper()
        if upper in seen:
            return
        if len(upper) < _MIN_KEYWORD_LEN or len(upper) > _MAX_KEYWORD_LEN:
            return
        if upper in _CLUE_STOPWORDS:
            return
        seen.add(upper)
        keywords.append(upper)

    # Priority 1: ALL-CAPS clue-text tokens — the K4Bench anchor
    # convention. We re-scan the clue_text only for tokens that are
    # already entirely uppercase in the source.
    if clue_text:
        for token in re.findall(r"[A-Za-z]+", clue_text):
            if token.isupper() and token.isalpha():
                _accept(token)

    # Priority 2: remaining clue-text tokens (mixed-case, lowercase),
    # in document order.
    if clue_text:
        for token in re.findall(r"[A-Za-z]+", clue_text):
            _accept(token)

    # Priority 3: title tokens.
    if title:
        for token in re.findall(r"[A-Za-z]+", title):
            _accept(token)

    return keywords


def _resolve_keyword_pool(
    payload: Mapping[str, Any],
    *,
    minimum: int = 4,
) -> list[str]:
    """Combine clue-mined keywords with the safe default pool.

    Priority order:
      1. Clue-mined keywords (in document order).
      2. ``_DEFAULT_KEYWORDS`` (deterministic order).

    Duplicates are removed while preserving first-seen order. The
    function guarantees the returned list has at least ``minimum``
    keywords; it never returns an empty list.
    """
    pool: list[str] = []
    seen: set[str] = set()
    for kw in _extract_clue_keywords(payload):
        if kw not in seen:
            seen.add(kw)
            pool.append(kw)
    for kw in _DEFAULT_KEYWORDS:
        if kw not in seen:
            seen.add(kw)
            pool.append(kw)
    # Defensive: if both clue-mined and defaults degenerate to nothing
    # (e.g., DEFAULTS got edited to empty), produce at least one
    # placeholder so downstream cardinality stays >= 1. The real
    # validator will reject "X" as too short for some kinds, but the
    # vigenere/beaufort path tolerates any positive-length A-Z string.
    if len(pool) < minimum:
        for filler in ("ALPHA", "BRAVO", "CHARLIE", "DELTA"):
            if filler not in seen:
                seen.add(filler)
                pool.append(filler)
            if len(pool) >= minimum:
                break
    return pool


def _vigenere_spec(hid: str, keyword: str) -> dict[str, Any]:
    return {
        "hypothesis_id": hid,
        "pipeline": [{
            "kind": "vigenere", "alphabet": "AZ",
            "params": [{"name": "keyword", "values": [keyword]}],
        }],
        "crib_alignment": "direct_positional",
        "scoring": "crib_plus_bean",
        "compute_budget_cpu_minutes": 1,
        "assumption_bundle": ["bench_fallback", "single_layer"],
    }


def _beaufort_spec(hid: str, keyword: str) -> dict[str, Any]:
    return {
        "hypothesis_id": hid,
        "pipeline": [{
            "kind": "beaufort", "alphabet": "AZ",
            "params": [{"name": "keyword", "values": [keyword]}],
        }],
        "crib_alignment": "direct_positional",
        "scoring": "crib_plus_bean",
        "compute_budget_cpu_minutes": 1,
        "assumption_bundle": ["bench_fallback", "single_layer"],
    }


def _variant_beaufort_spec(hid: str, keyword: str) -> dict[str, Any]:
    return {
        "hypothesis_id": hid,
        "pipeline": [{
            "kind": "variant_beaufort", "alphabet": "AZ",
            "params": [{"name": "keyword", "values": [keyword]}],
        }],
        "crib_alignment": "direct_positional",
        "scoring": "crib_plus_bean",
        "compute_budget_cpu_minutes": 1,
        "assumption_bundle": ["bench_fallback", "single_layer"],
    }


def _keyword_to_col_order(keyword: str) -> list[int]:
    """Convert a keyword into the columnar col_order permutation.

    Mirrors ``kryptos.kernel.transforms.transposition.keyword_to_order``
    bit-for-bit: stable left-to-right tie-break on letter rank, so
    repeated letters resolve in document order. Inlined here so
    ``bench_fallback`` stays kernel-import-free at module load
    (the dispatcher is the only kernel-touching dependency, and it
    imports lazily in workers).

    Example: keyword="LANTERN" (width 7) ->
        ranked: A(1), E(2), L(3), N#0(4), N#1(5), R(6), T(7)
            wait — rank assignment by sorted (ch, original_pos):
            sort gives A@1, E@4, L@0, N@2, N@6, R@5, T@3
            then for rank, (_, pos) order positions get rank
        So col_order at original column index:
            L@0 -> rank 2
            A@1 -> rank 0
            N@2 -> rank 3
            T@3 -> rank 6
            E@4 -> rank 1
            R@5 -> rank 5
            N@6 -> rank 4
        Returns [2, 0, 3, 6, 1, 5, 4]

    Refusing to operate on a keyword shorter than 2 keeps Caesar-shift
    degeneracies out of the fallback (a width-1 columnar is identity).
    """
    kw = keyword.upper()
    width = len(kw)
    if width < 2:
        raise ValueError(
            f"_keyword_to_col_order: keyword {keyword!r} too short; "
            "need len >= 2 to define a non-degenerate column permutation"
        )
    indexed = [(ch, i) for i, ch in enumerate(kw)]
    ranked = sorted(indexed, key=lambda x: (x[0], x[1]))
    order = [0] * width
    for rank, (_, pos) in enumerate(ranked):
        order[pos] = rank
    return order


def _columnar_identity_spec(hid: str, width: int = 7) -> dict[str, Any]:
    """Columnar with identity column-order — a no-op transposition that
    still exercises the columnar dispatch path. Useful as a layer-
    composition baseline; on its own returns the input unchanged.

    NOTE (2026-04-27): this is kept ONLY for the single-layer baseline
    catalogue entry. Multi-layer specs that pair columnar with another
    cipher MUST use ``_keyword_columnar_layer`` so the columnar layer
    actually permutes the text; otherwise the catalog never tests a
    real two-keyword two-layer hypothesis (the K4B-001 failure mode).
    """
    return {
        "hypothesis_id": hid,
        "pipeline": [{
            "kind": "columnar", "alphabet": "AZ",
            "params": [
                {"name": "width", "values": [width]},
                {"name": "col_order",
                 "values": [list(range(width))]},
            ],
        }],
        "crib_alignment": "post_transposition",
        "scoring": "crib_plus_bean",
        "compute_budget_cpu_minutes": 1,
        "assumption_bundle": ["bench_fallback", "single_layer"],
    }


def _keyword_columnar_layer(keyword: str) -> dict[str, Any]:
    """Build a single columnar layer dict whose width and col_order
    are derived from ``keyword``. The returned layer dispatches
    correctly through ``_translate_layer`` (width >= 2, col_order is
    a permutation of [0, width)).
    """
    width = len(keyword)
    col_order = _keyword_to_col_order(keyword)
    return {
        "kind": "columnar",
        "alphabet": "AZ",
        "params": [
            {"name": "width", "values": [width]},
            {"name": "col_order", "values": [col_order]},
        ],
    }


def _keyword_substitution_layer(kind: str, keyword: str) -> dict[str, Any]:
    """Build a single substitution layer dict (vigenere / beaufort /
    variant_beaufort) keyed by ``keyword``. ``alphabet`` is fixed to
    AZ — the bench-fallback catalog deliberately does not exercise
    KA / keyword_mixed alphabets to keep the universe tractable.
    """
    if kind not in ("vigenere", "beaufort", "variant_beaufort"):
        raise ValueError(
            f"_keyword_substitution_layer: kind {kind!r} not a "
            "keyword-substitution kind"
        )
    return {
        "kind": kind,
        "alphabet": "AZ",
        "params": [{"name": "keyword", "values": [keyword]}],
    }


def _keyword_myszkowski_layer(keyword: str) -> dict[str, Any]:
    """Build a Myszkowski transposition layer keyed by ``keyword``.

    Myszkowski's params live entirely on the keyword (the kernel
    builds the column rank internally, including the tied-column
    handling for repeated letters), so width is implicit.
    """
    return {
        "kind": "myszkowski",
        "alphabet": "AZ",
        "params": [{"name": "keyword", "values": [keyword]}],
    }


def _two_layer_keyword_role_specs(
    *,
    bench_slug: str,
    family_label: str,
    sub_kind: str,
    trans_kind: str,
    keyword_a: str,
    keyword_b: str,
) -> list[tuple[str, dict[str, Any]]]:
    """Permute two keywords across the two layer roles AND across both
    decrypt-stack orders, for a substitution + keyword-transposition
    pair.

    For an ordered pair (kw1, kw2) and a (sub_kind, trans_kind), this
    emits four specs:

        1. [sub_kind(kw1), trans_kind(kw2)]   -- sub-first, kw1=sub
        2. [trans_kind(kw2), sub_kind(kw1)]   -- trans-first, kw1=sub
        3. [sub_kind(kw2), trans_kind(kw1)]   -- sub-first, kw2=sub (role-swapped)
        4. [trans_kind(kw1), sub_kind(kw2)]   -- trans-first, kw2=sub (role-swapped)

    For K4B-001 with (CEDAR, LANTERN) and (vigenere, columnar) this
    produces exactly the four specs the user enumerated, including the
    formerly-missing ``Vigenere(LANTERN) + Columnar(CEDAR)`` case.

    Skips quietly when either keyword is too short for the
    transposition layer's hard floor (columnar / myszkowski require
    len >= 2). The caller filters out empty results.
    """
    if sub_kind not in ("vigenere", "beaufort", "variant_beaufort"):
        raise ValueError(f"unsupported sub_kind {sub_kind!r}")
    if trans_kind not in ("columnar", "myszkowski"):
        raise ValueError(f"unsupported trans_kind {trans_kind!r}")

    # Width requirement: both keywords must be >= 2 chars to define
    # a non-degenerate transposition. Drop the entire family pair
    # silently when this fails — never emit a spec the dispatcher
    # would reject downstream.
    if len(keyword_a) < 2 or len(keyword_b) < 2:
        return []

    def _build_trans_layer(kw: str) -> dict[str, Any]:
        if trans_kind == "columnar":
            return _keyword_columnar_layer(kw)
        return _keyword_myszkowski_layer(kw)

    def _spec(
        slug_suffix: str,
        layers: list[dict[str, Any]],
        peel_label: str,
    ) -> tuple[str, dict[str, Any]]:
        hid = (
            f"hcc-{bench_slug}-{family_label}-{slug_suffix}"
        )
        spec = {
            "hypothesis_id": hid,
            "pipeline": layers,
            "crib_alignment": "post_transposition",
            "scoring": "crib_plus_bean",
            "compute_budget_cpu_minutes": 2,
            "assumption_bundle": [
                "bench_fallback", "multilayer",
                f"{family_label}_keyword_role_perm",
                peel_label,
            ],
        }
        return hid, spec

    out: list[tuple[str, dict[str, Any]]] = []
    # Build the four role × order combinations. Slug encodes the
    # decrypt-order pipeline so two specs that differ only by stack
    # order have distinct hypothesis_ids and the ledger does not
    # collapse them.
    for kw_sub, kw_trans in ((keyword_a, keyword_b), (keyword_b, keyword_a)):
        sub_layer = _keyword_substitution_layer(sub_kind, kw_sub)
        trans_layer = _build_trans_layer(kw_trans)
        # Order 1: substitution-first (decrypt order ⇒ sub was the
        # outermost / last-applied encryption layer).
        out.append(_spec(
            f"sub-{kw_sub.lower()}-trans-{kw_trans.lower()}",
            [sub_layer, trans_layer],
            "sub_first",
        ))
        # Order 2: transposition-first.
        out.append(_spec(
            f"trans-{kw_trans.lower()}-sub-{kw_sub.lower()}",
            [trans_layer, sub_layer],
            "trans_first",
        ))
    return out


def _rail_fence_spec(hid: str, depth: int = 3) -> dict[str, Any]:
    return {
        "hypothesis_id": hid,
        "pipeline": [{
            "kind": "rail_fence", "alphabet": "AZ",
            "params": [{"name": "depth", "values": [depth]}],
        }],
        "crib_alignment": "post_transposition",
        "scoring": "crib_plus_bean",
        "compute_budget_cpu_minutes": 1,
        "assumption_bundle": ["bench_fallback", "single_layer"],
    }


def _myszkowski_spec(hid: str, keyword: str) -> dict[str, Any]:
    return {
        "hypothesis_id": hid,
        "pipeline": [{
            "kind": "myszkowski", "alphabet": "AZ",
            "params": [{"name": "keyword", "values": [keyword]}],
        }],
        "crib_alignment": "post_transposition",
        "scoring": "crib_plus_bean",
        "compute_budget_cpu_minutes": 1,
        "assumption_bundle": ["bench_fallback", "single_layer"],
    }


def _route_spec(hid: str, rows: int = 10, cols: int = 10) -> dict[str, Any]:
    return {
        "hypothesis_id": hid,
        "pipeline": [{
            "kind": "route", "alphabet": "AZ",
            "params": [
                {"name": "variant", "values": ["serpentine"]},
                {"name": "rows", "values": [rows]},
                {"name": "cols", "values": [cols]},
            ],
        }],
        "crib_alignment": "post_transposition",
        "scoring": "crib_plus_bean",
        "compute_budget_cpu_minutes": 1,
        "assumption_bundle": ["bench_fallback", "single_layer"],
    }


def _quagmire_iii_spec(hid: str, keyword: str) -> dict[str, Any]:
    """Quagmire III: ct_alphabet_keyword == pt_alphabet_keyword (the
    translator enforces this). Indicator A keeps the indicator within
    the canonical alphabet."""
    return {
        "hypothesis_id": hid,
        "pipeline": [{
            "kind": "quagmire", "alphabet": "AZ",
            "params": [
                {"name": "period_keyword", "values": [keyword]},
                {"name": "indicator", "values": ["A"]},
                {"name": "ct_alphabet_keyword", "values": [keyword]},
                {"name": "pt_alphabet_keyword", "values": [keyword]},
                {"name": "variant", "values": ["quagmire_iii"]},
            ],
        }],
        "crib_alignment": "direct_positional",
        "scoring": "crib_plus_bean",
        "compute_budget_cpu_minutes": 1,
        "assumption_bundle": ["bench_fallback", "single_layer"],
    }


# NOTE (2026-04-27): the previous _rail_fence_then_substitution_spec
# and _substitution_then_rail_fence_spec helpers were removed when
# bench_fallback._build_catalog was refactored to delegate multi-layer
# spec generation to hand_cipher_core.generate_layered_specs(). The
# generic generator handles rail_fence_vigenere and rail_fence_beaufort
# across both layer orders + multiple depths. See
# hand_cipher_core._gen_keywordless_trans_pair_family for the
# replacement code path.


def _build_catalog(payload: Mapping[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Build the ordered (slug, raw_spec_dict) catalogue.

    Architecture (2026-04-27):

    Single-layer specs come first as the cheap baseline. The bulk of
    the catalogue is then produced by ``hand_cipher_core
    .generate_layered_specs`` over the clue keywords, which emits the
    full clue-role × layer-order permutation matrix for every
    supported two-layer (and simple three-layer) family. The previous
    behaviour — one hand-rolled spec per family — missed half the
    symmetry classes (lesson 001) and used an identity-permutation
    columnar layer that was indistinguishable from a single-layer
    Vigenere (lesson 004 violation). The generator-driven path closes
    both gaps.
    """
    from .hand_cipher_core import generate_layered_specs

    pool = _resolve_keyword_pool(payload, minimum=4)
    bench_id = str(payload.get("bench_id") or payload.get("title") or "bench")
    # Normalize bench_id into an id-safe slug fragment.
    bench_slug = re.sub(r"[^A-Za-z0-9]+", "-", bench_id).strip("-").lower() or "bench"

    kw0 = pool[0]
    kw1 = pool[1] if len(pool) > 1 else pool[0]
    kw2 = pool[2] if len(pool) > 2 else kw1

    catalog: list[tuple[str, dict[str, Any]]] = []

    # Multi-layer catalogue FIRST. The generic generator produces the
    # role × layer-order × family × alphabet-mode permutation matrix
    # that the K4B-001 + K4B-002 patches were about. These are the
    # deterministic-coverage seeds — placing them at the front of
    # the catalog ensures that ``--hcc-seeds N`` for small N still
    # preserves the critical multi-layer combos (columnar+vigenere
    # first).
    #
    # 2026-04-27 K4B-002 generalization: pass clue_text through so
    # the generator can detect mirror/reverse trigger language and
    # extract numeric depth candidates for rail_fence specs.
    clue_text = (
        payload.get("clue_text") if isinstance(payload.get("clue_text"), str) else ""
    )
    # max_specs uses the generator's default ceiling (600 as of
    # 2026-04-27 — accommodates the alphabet × family × role × order
    # × depth matrix). The controller's ``--hcc-seeds N`` caps the
    # downstream dispatched set; this is the catalogue ceiling, not
    # the dispatch ceiling.
    generated = generate_layered_specs(
        pool, bench_slug=bench_slug,
        clue_text=clue_text,
    )
    for gs in generated:
        # Tag each generated spec's assumption_bundle with the bench
        # provenance so the controller's existing assumption-tracking
        # paths recognize it as a fallback emission.
        gs.raw_spec.setdefault("assumption_bundle", []).extend(
            ["bench_fallback"]
        )
        catalog.append((gs.hypothesis_id, gs.raw_spec))

    # Single-layer baselines AFTER the role-permutation matrix. These
    # are useful for fast disproof of trivial single-layer hypotheses
    # but are NOT the deterministic-coverage seeds the HCC architecture
    # is centered on. A small ``--hcc-seeds`` cap will exclude these,
    # which is the desired behavior — the operator wanted the
    # multi-layer critical combos.
    catalog.extend([
        (f"hcc-{bench_slug}-vig-{kw0.lower()}",   _vigenere_spec(f"hcc-{bench_slug}-vig-{kw0.lower()}", kw0)),
        (f"hcc-{bench_slug}-vig-{kw1.lower()}",   _vigenere_spec(f"hcc-{bench_slug}-vig-{kw1.lower()}", kw1)),
        (f"hcc-{bench_slug}-beau-{kw0.lower()}",  _beaufort_spec(f"hcc-{bench_slug}-beau-{kw0.lower()}", kw0)),
        (f"hcc-{bench_slug}-beau-{kw1.lower()}",  _beaufort_spec(f"hcc-{bench_slug}-beau-{kw1.lower()}", kw1)),
        (f"hcc-{bench_slug}-vbeau-{kw2.lower()}", _variant_beaufort_spec(f"hcc-{bench_slug}-vbeau-{kw2.lower()}", kw2)),
        (f"hcc-{bench_slug}-rail-d3",             _rail_fence_spec(f"hcc-{bench_slug}-rail-d3", 3)),
        (f"hcc-{bench_slug}-rail-d4",             _rail_fence_spec(f"hcc-{bench_slug}-rail-d4", 4)),
        (f"hcc-{bench_slug}-col-w7",              _columnar_identity_spec(f"hcc-{bench_slug}-col-w7", 7)),
        (f"hcc-{bench_slug}-route-serp-10x10",    _route_spec(f"hcc-{bench_slug}-route-serp-10x10", 10, 10)),
        (f"hcc-{bench_slug}-myz-{kw0.lower()}",   _myszkowski_spec(f"hcc-{bench_slug}-myz-{kw0.lower()}", kw0)),
    ])

    return catalog


def _spec_passes_validation(raw: dict[str, Any]) -> tuple[bool, list[str]]:
    """Return (ok, errors) — the same contract the dispatcher applies.

    Validates the spec via ``validate_hypothesis_spec`` (covers DSL
    structure, alphabets, parameter names, cardinality cap, etc.) and
    additionally checks that EVERY layer kind has a dispatcher
    translation. A spec with a kind in ``_VALID_CIPHER_KINDS`` but
    absent from ``_SUPPORTED_KINDS`` (e.g., the deferred ``key_tape``
    kind) would validate at the DSL boundary but be rejected by the
    critic / dispatcher; we drop it here so the fallback never returns
    a known-undispatchable spec.
    """
    parsed = validate_hypothesis_spec(raw)
    if not parsed.is_valid:
        return False, list(parsed.errors)
    spec = parsed.value
    untranslatable = [
        layer.kind for layer in spec.pipeline
        if not _kind_has_translation(layer.kind)
    ]
    if untranslatable:
        return False, [
            f"layer kinds {untranslatable} have no dispatcher translation "
            f"(supported: {sorted(_SUPPORTED_KINDS)})"
        ]
    return True, []


def hand_cipher_core_fallback(
    payload: Mapping[str, Any],
    *,
    n_target: int = 5,
    family_label: str = "bench_hand_cipher_core",
) -> list[TheoryRecord]:
    """Return a list of validated, dispatchable bench-mode theories.

    The function emits at least ``n_target`` ``TheoryRecord`` objects
    (each with a populated ``dsl_spec`` field) drawn from the
    challenge's clue pack and the safe default keyword pool. Every
    returned record's ``dsl_spec`` has been verified against
    ``validate_hypothesis_spec`` AND every layer kind has a dispatcher
    translation; the controller can dispatch any of them without
    additional gating.

    Args:
        payload: ``ControllerConfig.bench_challenge_payload`` (the dict
            shape produced by ``K4BenchChallenge.canonical_facts``).
            Must carry ``clue_text`` and ideally ``title`` and
            ``bench_id``; missing fields fall back to the default
            keyword pool.
        n_target: Minimum number of theories to return. The fallback
            emits as many as the catalogue holds (currently 13);
            ``n_target`` is a *floor*, not a cap. The caller usually
            sets this to ``ControllerConfig.theories_per_cycle``.
        family_label: ``TheoryRecord.family`` value to assign. Defaults
            to ``"bench_hand_cipher_core"`` so bench fallback theories
            are easy to filter in the ledger and don't collide with
            the real-K4 family-registry IDs (which the bench-mode
            ProblemContext refuses to consult anyway).

    Returns:
        A list of ``TheoryRecord`` objects, length >= ``n_target``
        whenever the catalogue has at least that many valid specs.
        The list is empty only if every catalogue spec failed
        validation, which would indicate a kernel/DSL contract drift
        — the caller should treat empty as a halt condition.

    The function is pure with respect to its inputs: the same payload
    produces the same theories every call. No I/O, no SDK, no kernel
    dispatch — just spec construction + DSL validation.
    """
    from .hand_cipher_core import (
        CoverageVector, generate_layered_specs,
    )

    catalog = _build_catalog(payload)
    bench_id = payload.get("bench_id") or payload.get("title") or "K4Bench"

    # Build a slug -> CoverageVector index from the generic generator
    # so theories carry their symmetry-class coordinate. Single-layer
    # baselines synthesized in _build_catalog get a generic 1-layer
    # CoverageVector built inline below.
    pool = _resolve_keyword_pool(payload, minimum=4)
    bench_slug = re.sub(
        r"[^A-Za-z0-9]+", "-", str(bench_id),
    ).strip("-").lower() or "bench"
    # Use the same clue_text and the generator's default cap (600) so
    # the slug -> coverage index covers every spec _build_catalog
    # produces (otherwise high-index slugs map to a generic CV and
    # lose the alphabet_mode/alphabet_source telemetry).
    clue_text_for_cov = (
        payload.get("clue_text") if isinstance(payload.get("clue_text"), str) else ""
    )
    coverage_by_slug: dict[str, CoverageVector] = {}
    for gs in generate_layered_specs(
        pool, bench_slug=bench_slug, clue_text=clue_text_for_cov,
    ):
        coverage_by_slug[gs.hypothesis_id] = gs.coverage

    theories: list[TheoryRecord] = []
    rejected: list[tuple[str, list[str]]] = []
    for slug, raw_spec in catalog:
        ok, errors = _spec_passes_validation(raw_spec)
        if not ok:
            rejected.append((slug, errors))
            continue
        # Build TheoryRecord. Note: hypothesis_id mirrors the spec's id
        # so the ledger's hypothesis-id-as-primary-key invariant holds
        # and dispatch logs can be cross-referenced by id.
        layer_kinds = [
            layer["kind"] for layer in raw_spec["pipeline"]
        ]
        layer_summary = "+".join(layer_kinds)
        # Pull the CoverageVector from the generic generator when this
        # spec came from there; otherwise synthesize a minimal vector
        # describing the single-layer baseline so coverage telemetry is
        # complete across the catalog.
        cv = coverage_by_slug.get(slug)
        if cv is None:
            # Single-layer baseline path. Extract the single keyword
            # if any; fall back to "" for keyword-free layers.
            params = raw_spec["pipeline"][0].get("params") or []
            keyword_value = ""
            for p in params:
                if p.get("name") == "keyword" and p.get("values"):
                    keyword_value = str(p["values"][0])
                    break
            role = (
                ((layer_kinds[0], keyword_value),) if keyword_value
                else ((layer_kinds[0], ""),)
            )
            cv = CoverageVector(
                layer_family=layer_kinds[0],
                layer_order=tuple(layer_kinds),
                role_assignment=role,
                alphabet=raw_spec["pipeline"][0].get("alphabet", "AZ"),
                n_layers=1,
            )
        theory = TheoryRecord(
            hypothesis_id=slug,
            title=f"HandCipherCore fallback: {layer_summary}",
            core_claim=(
                f"K4Bench challenge {bench_id} can be decrypted by a "
                f"hand-executable {layer_summary} pipeline using clue-"
                "derived key material."
            ),
            mechanism=(
                f"Apply layers {layer_kinds} in declared order; key "
                "material drawn from the challenge clue pack and the "
                "project-safe default keyword pool."
            ),
            family=family_label,
            kill_criteria=[
                "All emitted parameter combinations produce crib_score < 10",
                "Bean constraints violated for every parameter combination",
            ],
            expected_signal="crib_score >= 10 with Bean PASS",
            compute_cost_estimate="low",
            minimal_test_spec={
                "method": "bench_hand_cipher_core",
                "parameters": {
                    "layers": layer_kinds,
                    "bench_id": str(bench_id),
                },
                # Coverage telemetry (lesson 006: failed-method coverage).
                # The bench_attempts emitter surfaces this onto the
                # attempt artifact so the offline evaluator can answer
                # "have we tested all role inversions for this clue
                # pair and family?".
                "coverage_vector": cv.to_dict(),
            },
            dsl_spec=raw_spec,
            origin="programmatic_fallback",
        )
        theories.append(theory)

    if rejected:
        logger.info(
            "bench_fallback dropped %d/%d catalogue specs at validation: %s",
            len(rejected), len(catalog),
            "; ".join(f"{slug}={errs[0]}" for slug, errs in rejected[:3]),
        )

    if len(theories) < n_target:
        logger.warning(
            "bench_fallback emitted %d theories below n_target=%d "
            "(catalogue=%d, rejected=%d)",
            len(theories), n_target, len(catalog), len(rejected),
        )

    return theories


__all__ = [
    "hand_cipher_core_fallback",
    "_extract_clue_keywords",
    "_resolve_keyword_pool",
]
