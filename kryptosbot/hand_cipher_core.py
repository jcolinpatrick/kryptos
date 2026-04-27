"""HandCipherCore — generic clue-to-spec generator for layered hand ciphers.

Purpose
-------
Convert a small, structured input (clue words + budget hints + cipher
family allow-list) into a deterministic, bounded list of dispatchable
DSL specs that systematically cover the symmetry classes of supported
two-layer (and simple three-layer) hand-cipher families.

The generator is **problem-agnostic**. It does not know about K4Bench,
real K4, or any specific challenge: callers pass in clue words and
optional budget knobs, and they get back specs. The bench-mode and
real-K4 callers wrap this module with their own keyword-extraction +
TheoryRecord-building adapters.

Symmetry classes covered
------------------------
For two clue words A and B and a two-layer family (X, Y) where both
layers admit a keyword role, the generator emits ALL FOUR
combinations:

    1. X(A) ∘ Y(B)        - role assignment {X:A, Y:B}, decrypt order [X, Y]
    2. X(B) ∘ Y(A)        - role-swapped, same order
    3. Y(A) ∘ X(B)        - flipped layer order, original assignment
    4. Y(B) ∘ X(A)        - flipped order AND role-swapped

This is the symmetry class that the K4B-001 fallback missed in its
original form: it tested only one of the four. The generator now
guarantees every (clue_pair, family) symmetry class is covered.

For families where one layer is keyword-free (rail-fence depth, route
variant + grid), the role-permutation collapses to two specs (just the
layer-order flip) because there is no keyword to swap.

For three-layer "simple" families (substitution + transposition +
substitution where the two substitutions can use different keywords),
the generator emits the role permutations for both substitution slots
and the layer-order flip; the universe is bounded by an explicit cap.

Coverage vector
---------------
Every emitted ``GeneratedSpec`` carries a ``CoverageVector`` describing
exactly which symmetry-class point it tests:

    layer_family       - canonical "kind1+kind2[+kind3]" slug
    layer_order        - 0-indexed kind names in dispatch order
    role_assignment    - {kind: keyword} or {kind: param_value}
    alphabet           - "AZ" | "KA" | "keyword_mixed"
    extras             - dict of secondary params (width, depth, route_variant, ...)
    n_layers           - integer

Two specs share a symmetry class iff their (clue_pair, layer_family)
matches; their (layer_order, role_assignment) is the in-class
coordinate. ``coverage_class_key`` and ``gap_analysis`` operate on
this representation.

Lesson registry interaction
---------------------------
The default generator behaviour bakes in the lessons listed in
``solver_capabilities``:

    LESSON-001  clue_role_permutation
    LESSON-002  layer_order_inversion
    LESSON-003  keyword_tableau_role_ambiguity
    LESSON-004  transposition_width_from_keyword_length
    LESSON-005  stable_column_order_tie_handling
    LESSON-006  failed_method_coverage
    LESSON-007  trigger_driven_alphabet_enumeration  (alphabet_modes_for_payload)

Callers may override the active-lesson set to disable any subset, but
the defaults are the project-wide HandCipherCore tactic floor.

What this module deliberately does NOT do
-----------------------------------------
- Read or write any sealed material (plaintexts, answer keys).
- Call out to the SDK / LLM.
- Touch the kernel beyond the lazy import inside the dispatcher's
  translator (the validation step does drag in the DSL parser, which
  is dependency-free).
- Handle running keys, autokey, OTP, or any cipher kind not currently
  in ``job_dispatcher._SUPPORTED_KINDS``. New kinds are added by
  extending ``_FAMILY_TEMPLATES``.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Optional, Sequence

from .hypothesis_dsl import validate_hypothesis_spec
from .job_dispatcher import _SUPPORTED_KINDS, _kind_has_translation


logger = logging.getLogger("kryptosbot.hand_cipher_core")


# Substitution kinds that take a single ``keyword`` parameter. These
# are the kinds that can swap roles with a transposition keyword in a
# two-layer family.
_SUBSTITUTION_KEYWORD_KINDS: tuple[str, ...] = (
    "vigenere", "beaufort", "variant_beaufort",
)

# Transposition kinds whose primary parameter is itself a keyword.
# Columnar derives (width, col_order) from the keyword via
# ``_keyword_to_col_order``; Myszkowski uses the keyword directly.
_KEYWORD_TRANSPOSITION_KINDS: tuple[str, ...] = (
    "columnar", "myszkowski",
)

# Transposition kinds with no keyword role. The layer-order flip is
# still meaningful (you can do sub-then-trans or trans-then-sub) but
# the keyword-role-swap collapses to a single assignment.
_KEYWORDLESS_TRANSPOSITION_KINDS: tuple[str, ...] = (
    "rail_fence", "route",
)

# Hard cap on the number of generated specs. With alphabet-mode
# enumeration on top of (family × role × order), the universe is
# bounded by:
#
#   keyword_pair_families (5) × role-perm (2) × order-perm (2)
#                              × alphabet_modes (≤6)        =  120
#   keywordless_pair_families (4) × keywords (2) × depths (≤4)
#                              × order-perm (2) × alphabets (≤6) = ≤384
#   quagmire (≤4 specs, alphabet variation handled by IV roles)
#   three-layer sandwiches (2 × 2 × ≤6)                          =   24
#
# Worst-case ≈ 530 specs. Each spec dispatches as a single kernel
# config (microseconds), so the dispatch cost is dominated by
# multiprocessing startup (~1s/spec) — ~9 min/cycle at the worst
# case. Operators can lower the ceiling via --hcc-seeds N when they
# want a faster cycle. Cap at 600 to leave headroom for future
# kinds without breaking the deterministic-coverage contract.
_DEFAULT_MAX_SPECS: int = 600


# ============================================================================
# Coverage Vector
# ============================================================================


@dataclass(frozen=True)
class CoverageVector:
    """Normalized record of which symmetry-class point a spec tests.

    Frozen + hashable so coverage analysis can use it as a dict key
    and dedupe across re-runs. The ``role_assignment`` is stored as
    a tuple of ``(kind, keyword_or_value)`` pairs sorted by ``kind``
    so two equivalent assignments hash the same regardless of how
    the caller iterated their pipeline.

    2026-04-27 — alphabet permutation fields:
      ``alphabet_mode``    : labelled mode (e.g. "AZ", "KA",
                             "keyword_mixed", "mirrored_az",
                             "mirrored_ka"). Distinguishes the
                             alphabet variant tested for the
                             substitution layer(s) of the spec.
      ``alphabet_source``  : provenance tag for the alphabet
                             keyword. "default" for AZ; "kryptos_alphabet"
                             for KA; the clue word for keyword_mixed
                             (e.g. "LANTERN"); "reversed_az" /
                             "reversed_ka" for mirrored modes.

    The legacy ``alphabet`` field is preserved for backward
    compatibility and now mirrors ``alphabet_mode`` so older
    consumers keep reading meaningful values.
    """

    layer_family: str                                  # e.g. "columnar+vigenere"
    layer_order: tuple[str, ...]                       # ("vigenere", "columnar")
    role_assignment: tuple[tuple[str, str], ...]       # (("columnar","LANTERN"),)
    alphabet: str                                      # "AZ" — kept for back-compat
    n_layers: int                                      # 2 / 3
    extras: tuple[tuple[str, Any], ...] = ()           # (("depth", 3), ...)
    alphabet_mode: str = "AZ"                          # AZ|KA|keyword_mixed|mirrored_az|mirrored_ka
    alphabet_source: str = "default"                   # default|kryptos_alphabet|<clue_word>|reversed_az|reversed_ka

    def to_dict(self) -> dict[str, Any]:
        return {
            "layer_family": self.layer_family,
            "layer_order": list(self.layer_order),
            "role_assignment": {k: v for k, v in self.role_assignment},
            "alphabet": self.alphabet,
            "n_layers": self.n_layers,
            "extras": {k: v for k, v in self.extras},
            "alphabet_mode": self.alphabet_mode,
            "alphabet_source": self.alphabet_source,
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "CoverageVector":
        """Lenient deserialization for read-back from the ledger /
        attempt artifact. Missing optional fields default to safe
        empty values.
        """
        role = d.get("role_assignment") or {}
        if isinstance(role, dict):
            role_tuple = tuple(sorted(role.items()))
        else:
            role_tuple = tuple(role)
        extras = d.get("extras") or {}
        if isinstance(extras, dict):
            extras_tuple = tuple(sorted(extras.items()))
        else:
            extras_tuple = tuple(extras)
        layer_order = d.get("layer_order") or []
        # alphabet_mode default mirrors the legacy alphabet field for
        # rows persisted before 2026-04-27.
        legacy_alphabet = str(d.get("alphabet", "AZ"))
        return cls(
            layer_family=str(d.get("layer_family", "")),
            layer_order=tuple(layer_order),
            role_assignment=role_tuple,
            alphabet=legacy_alphabet,
            n_layers=int(d.get("n_layers", len(layer_order))),
            extras=extras_tuple,
            alphabet_mode=str(d.get("alphabet_mode", legacy_alphabet)),
            alphabet_source=str(d.get("alphabet_source", "default")),
        )

    @property
    def clue_pair(self) -> tuple[str, ...]:
        """The set of keywords used by this vector, sorted. Two specs
        belong to the same clue pair iff this matches.
        """
        return tuple(sorted({v for _, v in self.role_assignment}))


@dataclass(frozen=True)
class GeneratedSpec:
    """One emitted spec + its coverage vector + a stable id slug.

    Frozen so callers can safely use it as a dict key. The raw spec
    dict is the dispatcher input; the coverage vector describes the
    symmetry-class point. The ``hypothesis_id`` slug is stable across
    runs (no random suffixes) so the ledger's deduplication catches
    re-emissions.
    """
    hypothesis_id: str
    raw_spec: dict[str, Any]
    coverage: CoverageVector
    family_label: str
    notes: str = ""


# ============================================================================
# Layer builders (kernel-free; produce dispatcher-shaped layer dicts)
# ============================================================================


def _keyword_to_col_order(keyword: str) -> list[int]:
    """Convert a keyword to a stable rank-order column permutation.

    Mirrors ``kryptos.kernel.transforms.transposition.keyword_to_order``
    bit-for-bit. Stable left-to-right tie-break on letter rank, so
    repeated letters resolve in document order. Refuses keywords
    shorter than 2 (a width-1 columnar is identity).

    Lesson 005 (stable_column_order_tie_handling): repeated letters
    always rank in document order, never random / locale-dependent.
    """
    kw = keyword.upper()
    width = len(kw)
    if width < 2:
        raise ValueError(
            f"_keyword_to_col_order: keyword {keyword!r} too short; "
            "need len >= 2 for a non-degenerate column permutation"
        )
    indexed = [(ch, i) for i, ch in enumerate(kw)]
    ranked = sorted(indexed, key=lambda x: (x[0], x[1]))
    order = [0] * width
    for rank, (_, pos) in enumerate(ranked):
        order[pos] = rank
    return order


def _keyword_substitution_layer(
    kind: str,
    keyword: str,
    *,
    alphabet: str = "AZ",
    alphabet_keyword: Optional[str] = None,
) -> dict[str, Any]:
    """Build a single substitution layer dict (vig / beau / var_beau).

    2026-04-27: ``alphabet`` may be ``"AZ"``, ``"KA"``, or
    ``"keyword_mixed"``. When ``"keyword_mixed"``, ``alphabet_keyword``
    must be a non-empty A-Z string — used by the dispatcher's
    ``_resolve_alphabet_sequence`` to build the mixed tableau via
    ``keyword_mixed_alphabet``. For mirrored alphabets, pass the
    fully-reversed canonical alphabet as ``alphabet_keyword`` (e.g.
    ``"ZYXWVUTSRQPONMLKJIHGFEDCBA"`` for mirrored AZ); the kernel's
    ``keyword_mixed_alphabet`` returns it unchanged when all 26
    letters are present.
    """
    if kind not in _SUBSTITUTION_KEYWORD_KINDS:
        raise ValueError(
            f"_keyword_substitution_layer: kind {kind!r} not in "
            f"{_SUBSTITUTION_KEYWORD_KINDS}"
        )
    params: list[dict[str, Any]] = [
        {"name": "keyword", "values": [keyword]}
    ]
    if alphabet == "keyword_mixed":
        if not alphabet_keyword:
            raise ValueError(
                "_keyword_substitution_layer: alphabet='keyword_mixed' "
                "requires non-empty alphabet_keyword"
            )
        params.append({
            "name": "alphabet_keyword", "values": [alphabet_keyword],
        })
    return {
        "kind": kind,
        "alphabet": alphabet,
        "params": params,
    }


# ============================================================================
# Alphabet-mode enumeration (2026-04-27)
# ============================================================================


# Trigger words for mirrored / reversed alphabet variants. When ANY of
# these tokens (case-insensitive) appears in the challenge clue text,
# the generator enumerates mirrored_AZ + mirrored_KA in addition to
# the standard modes. Sourced from the user's spec for K4B-002-style
# clues that allude to a "mirrored alpha strip" or "reversed tableau".
_MIRROR_TRIGGER_TOKENS: frozenset[str] = frozenset({
    "mirror", "mirrored",
    "alpha", "alphabet",
    "strip", "table", "tableau",
    "reverse", "reversed",
    "fold", "folded",
})

# Canonical alphabets used as the mirror "keywords" for the
# keyword_mixed dispatcher path. Both are exactly 26 chars with all
# letters, so keyword_mixed_alphabet returns them unchanged — the
# tableau IS the mirror of AZ / KA respectively.
_REVERSED_AZ: str = "ZYXWVUTSRQPONMLKJIHGFEDCBA"
_REVERSED_KA: str = "ZXWVUQNMLJIHGFEDCBASOTPYRK"  # KRYPTOSABCDEFGHIJLMNQUVWXZ reversed


@dataclass(frozen=True)
class AlphabetMode:
    """One alphabet variant + its provenance.

    Used to drive substitution-layer enumeration and surfaces directly
    in the CoverageVector ``alphabet_mode`` / ``alphabet_source``
    fields.
    """
    mode_label: str               # "AZ" | "KA" | "keyword_mixed" | "mirrored_az" | "mirrored_ka"
    dsl_alphabet: str             # "AZ" | "KA" | "keyword_mixed"   (what _translate_layer accepts)
    alphabet_keyword: Optional[str]   # required when dsl_alphabet=="keyword_mixed"
    source: str                   # "default" | "kryptos_alphabet" | <clue_word> | "reversed_az" | "reversed_ka"


def _detect_mirror_trigger(clue_text: str) -> bool:
    """Case-insensitive check for any mirror/reverse trigger token in
    the clue text. Returns True iff the operator's clue language
    suggests a mirrored or reversed tableau.

    Uses simple word-boundary substring matching so multi-word phrases
    like "mirrored alpha strip" trigger on each component.
    """
    if not isinstance(clue_text, str) or not clue_text:
        return False
    lower = clue_text.lower()
    for token in _MIRROR_TRIGGER_TOKENS:
        # Use a word-boundary check by checking surrounding chars.
        # A simple ``token in lower`` would over-match (e.g. "table"
        # is a substring of "tablespoon"). Reject when adjacent
        # alphanumerics indicate a longer word.
        idx = 0
        while True:
            pos = lower.find(token, idx)
            if pos < 0:
                break
            before_ok = pos == 0 or not lower[pos - 1].isalnum()
            after_pos = pos + len(token)
            after_ok = after_pos >= len(lower) or not lower[after_pos].isalnum()
            if before_ok and after_ok:
                return True
            idx = pos + 1
    return False


def _alphabet_modes_for_payload(
    clue_text: str,
    clue_words: Sequence[str],
    *,
    max_keyword_mixed: int = 2,
) -> list[AlphabetMode]:
    """Enumerate alphabet modes derivable from a clue pack.

    Always emits:
      * AZ (canonical)
      * KA (KRYPTOS-prefixed, the K1/K2 standard)
      * keyword_mixed for the first ``max_keyword_mixed`` clue words

    Conditionally emits (when ``_detect_mirror_trigger(clue_text)``):
      * mirrored_az
      * mirrored_ka

    Order: deterministic so two runs with the same payload produce
    the same enumeration. Keyword-mixed entries follow the order of
    ``clue_words``; mirrored entries always come last so a small
    per-family alphabet cap preserves the standard modes first.
    """
    modes: list[AlphabetMode] = [
        AlphabetMode(
            mode_label="AZ", dsl_alphabet="AZ",
            alphabet_keyword=None, source="default",
        ),
        AlphabetMode(
            mode_label="KA", dsl_alphabet="KA",
            alphabet_keyword=None, source="kryptos_alphabet",
        ),
    ]
    seen_keywords: set[str] = set()
    for kw in clue_words[:max_keyword_mixed]:
        if not isinstance(kw, str):
            continue
        upper = kw.upper().strip()
        if not upper.isalpha() or upper in seen_keywords:
            continue
        seen_keywords.add(upper)
        modes.append(AlphabetMode(
            mode_label="keyword_mixed",
            dsl_alphabet="keyword_mixed",
            alphabet_keyword=upper,
            source=upper,
        ))
    if _detect_mirror_trigger(clue_text):
        modes.append(AlphabetMode(
            mode_label="mirrored_az",
            dsl_alphabet="keyword_mixed",
            alphabet_keyword=_REVERSED_AZ,
            source="reversed_az",
        ))
        modes.append(AlphabetMode(
            mode_label="mirrored_ka",
            dsl_alphabet="keyword_mixed",
            alphabet_keyword=_REVERSED_KA,
            source="reversed_ka",
        ))
    return modes


# Numeral extraction for rail-fence depth selection ---------------------------

_NUMBER_WORDS: dict[str, int] = {
    "two": 2, "three": 3, "four": 4, "five": 5, "six": 6,
    "seven": 7, "eight": 8, "nine": 9, "ten": 10,
    "eleven": 11, "twelve": 12, "thirteen": 13, "fourteen": 14,
    "fifteen": 15, "sixteen": 16, "seventeen": 17,
    "eighteen": 18, "nineteen": 19, "twenty": 20,
}

# Rail-fence depths default set when no clue numerals apply. The
# generator unions clue-derived depths with these so a clue-free
# payload still produces a useful enumeration.
_DEFAULT_RAIL_FENCE_DEPTHS_BASE: tuple[int, ...] = (3, 5)


def _depths_from_clue_text(clue_text: str) -> list[int]:
    """Extract rail-fence depth candidates from the clue text.

    Picks digit literals (1-49) and small spelled numbers
    (two..twenty). Returns a sorted, deduped list. Caller is
    responsible for unioning with default depths.
    """
    if not isinstance(clue_text, str) or not clue_text:
        return []
    import re
    found: set[int] = set()
    for m in re.finditer(r"\d+", clue_text):
        try:
            n = int(m.group(0))
        except ValueError:
            continue
        if 2 <= n <= 49:
            found.add(n)
    lower = clue_text.lower()
    for word, n in _NUMBER_WORDS.items():
        # Word-boundary match.
        for m in re.finditer(rf"\b{re.escape(word)}\b", lower):
            found.add(n)
    return sorted(found)


def _rail_fence_depths_for_payload(clue_text: str) -> list[int]:
    """Combine clue-derived depths with the safe default set.

    Order: clue-derived depths first (they are more meaningful), then
    defaults that are not already present. Always returns a
    deterministic, deduplicated list with at least
    ``len(_DEFAULT_RAIL_FENCE_DEPTHS_BASE)`` entries.
    """
    out: list[int] = []
    seen: set[int] = set()
    for d in _depths_from_clue_text(clue_text):
        if d not in seen:
            seen.add(d)
            out.append(d)
    for d in _DEFAULT_RAIL_FENCE_DEPTHS_BASE:
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


def _keyword_columnar_layer(keyword: str) -> dict[str, Any]:
    """Build a columnar layer where width and col_order derive from
    the keyword (lesson 004: transposition_width_from_keyword_length).
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


def _keyword_myszkowski_layer(keyword: str) -> dict[str, Any]:
    """Myszkowski layer keyed by ``keyword``; the kernel handles the
    tied-column rank logic internally.
    """
    return {
        "kind": "myszkowski",
        "alphabet": "AZ",
        "params": [{"name": "keyword", "values": [keyword]}],
    }


def _rail_fence_layer(depth: int) -> dict[str, Any]:
    """Rail fence (zigzag) layer with explicit integer depth. No
    keyword role, so this layer is invariant under role-permutation.
    """
    return {
        "kind": "rail_fence",
        "alphabet": "AZ",
        "params": [{"name": "depth", "values": [depth]}],
    }


def _route_layer(
    *,
    variant: str = "serpentine",
    rows: int = 7,
    cols: int = 14,
) -> dict[str, Any]:
    """Route layer with a fixed variant + grid. The serpentine variant
    is the project-wide default per Sanborn's "serpentine copper screen
    with Vigenere tableau" anchor.
    """
    return {
        "kind": "route",
        "alphabet": "AZ",
        "params": [
            {"name": "variant", "values": [variant]},
            {"name": "rows", "values": [rows]},
            {"name": "cols", "values": [cols]},
        ],
    }


def _quagmire_iii_layer(keyword: str, *, indicator: str = "A") -> dict[str, Any]:
    """Quagmire III layer (ct_alphabet_keyword == pt_alphabet_keyword,
    K1/K2 convention enforced by the dispatcher's translator).
    """
    return {
        "kind": "quagmire",
        "alphabet": "AZ",
        "params": [
            {"name": "period_keyword", "values": [keyword]},
            {"name": "indicator", "values": [indicator]},
            {"name": "ct_alphabet_keyword", "values": [keyword]},
            {"name": "pt_alphabet_keyword", "values": [keyword]},
            {"name": "variant", "values": ["quagmire_iii"]},
        ],
    }


def _quagmire_iv_layer(
    pt_keyword: str,
    ct_keyword: str,
    *,
    indicator: str = "A",
    period_keyword: Optional[str] = None,
) -> dict[str, Any]:
    """Quagmire IV: pt_alphabet_keyword != ct_alphabet_keyword.
    The translator rejects identical keywords for variant=quagmire_iv,
    so caller is responsible for passing distinct strings.
    """
    pk = period_keyword or pt_keyword
    return {
        "kind": "quagmire",
        "alphabet": "AZ",
        "params": [
            {"name": "period_keyword", "values": [pk]},
            {"name": "indicator", "values": [indicator]},
            {"name": "ct_alphabet_keyword", "values": [ct_keyword]},
            {"name": "pt_alphabet_keyword", "values": [pt_keyword]},
            {"name": "variant", "values": ["quagmire_iv"]},
        ],
    }


# ============================================================================
# Spec builder + family templates
# ============================================================================


def _make_spec(
    *,
    bench_slug: str,
    family_label: str,
    pipeline: list[dict[str, Any]],
    coverage: CoverageVector,
    notes: str = "",
    compute_budget_minutes: int = 2,
    crib_alignment: str = "post_transposition",
) -> GeneratedSpec:
    """Wrap a pipeline + coverage vector into a GeneratedSpec.

    The hypothesis_id slug encodes the family + role assignment + layer
    order + alphabet_mode so two specs with different coverage vectors
    get distinct ledger ids. Re-emissions of the same coverage point
    share a slug and the ledger dedupes.
    """
    role_part = "-".join(f"{k}={v.lower()}" for k, v in coverage.role_assignment)
    order_part = "_".join(coverage.layer_order)
    extras_part = (
        "-" + "-".join(f"{k}={v}" for k, v in coverage.extras)
        if coverage.extras else ""
    )
    # alphabet_mode is tucked into the slug so two specs that differ
    # ONLY by alphabet mode get distinct hypothesis_ids. The "AZ"
    # case is the historical default — when alphabet_mode == "AZ"
    # we omit the alphabet suffix to keep slugs backward-compatible
    # for the prior catalog entries (so re-runs don't double-emit).
    #
    # 2026-04-27: alphabet_source is included so two ``keyword_mixed``
    # modes on different clue words (e.g. CEDAR vs LANTERN) get
    # distinct slugs. Without this the catalogue has hypothesis_id
    # collisions that the merge dedup silently eats.
    if coverage.alphabet_mode == "AZ":
        alpha_part = ""
    elif coverage.alphabet_source and coverage.alphabet_source != "default":
        alpha_part = f"-alpha={coverage.alphabet_mode}-src={coverage.alphabet_source}"
    else:
        alpha_part = f"-alpha={coverage.alphabet_mode}"
    hid = (
        f"hcc-{bench_slug}-{family_label}-{order_part}-{role_part}{extras_part}{alpha_part}"
    ).lower()
    spec = {
        "hypothesis_id": hid,
        "pipeline": pipeline,
        "crib_alignment": crib_alignment,
        "scoring": "crib_plus_bean",
        "compute_budget_cpu_minutes": compute_budget_minutes,
        "assumption_bundle": [
            "hand_cipher_core",
            f"family={family_label}",
            f"order={order_part}",
            f"n_layers={coverage.n_layers}",
            f"alphabet_mode={coverage.alphabet_mode}",
        ],
    }
    return GeneratedSpec(
        hypothesis_id=hid,
        raw_spec=spec,
        coverage=coverage,
        family_label=family_label,
        notes=notes,
    )


# --- Family generators -------------------------------------------------------


def _gen_keyword_pair_family(
    *,
    bench_slug: str,
    sub_kind: str,
    trans_kind: str,
    keyword_a: str,
    keyword_b: str,
    alphabet_modes: Optional[Sequence[AlphabetMode]] = None,
) -> list[GeneratedSpec]:
    """Two-layer family where BOTH layers take a keyword.

    For sub_kind ∈ {vigenere, beaufort, variant_beaufort} and
    trans_kind ∈ {columnar, myszkowski}, this emits the four-spec
    role × order matrix per alphabet mode described in the module
    docstring.

    2026-04-27: enumerates ``alphabet_modes`` over the substitution
    layer. Default is just ``[AlphabetMode("AZ", "AZ", None, "default")]``
    which preserves the historical 4-spec output. With multiple modes
    the output grows to 4 × len(modes) specs.

    Lesson 001 (clue_role_permutation) and lesson 002 (layer_order_
    inversion) together justify the 4-spec coverage. Lesson 003
    (keyword_tableau_role_ambiguity) drives the per-alphabet-mode
    expansion. Lesson 006 (failed_method_coverage) is what the GAP
    analyzer enforces.
    """
    if sub_kind not in _SUBSTITUTION_KEYWORD_KINDS:
        raise ValueError(f"unsupported sub_kind {sub_kind!r}")
    if trans_kind not in _KEYWORD_TRANSPOSITION_KINDS:
        raise ValueError(f"unsupported trans_kind {trans_kind!r}")
    if len(keyword_a) < 2 or len(keyword_b) < 2:
        return []

    family_label = f"{trans_kind}_{sub_kind}"
    if alphabet_modes is None:
        alphabet_modes = (
            AlphabetMode("AZ", "AZ", None, "default"),
        )

    def _trans_layer(kw: str) -> dict[str, Any]:
        if trans_kind == "columnar":
            return _keyword_columnar_layer(kw)
        return _keyword_myszkowski_layer(kw)

    out: list[GeneratedSpec] = []
    # For each role assignment (kw_sub, kw_trans), each layer order,
    # and each alphabet mode for the substitution layer.
    for kw_sub, kw_trans in ((keyword_a, keyword_b), (keyword_b, keyword_a)):
        for mode in alphabet_modes:
            sub_layer = _keyword_substitution_layer(
                sub_kind, kw_sub,
                alphabet=mode.dsl_alphabet,
                alphabet_keyword=mode.alphabet_keyword,
            )
            trans_layer = _trans_layer(kw_trans)
            role = tuple(sorted(
                ((sub_kind, kw_sub), (trans_kind, kw_trans))
            ))
            # Order 1: substitution first
            cov_sub_first = CoverageVector(
                layer_family=family_label,
                layer_order=(sub_kind, trans_kind),
                role_assignment=role,
                alphabet=mode.mode_label,
                n_layers=2,
                alphabet_mode=mode.mode_label,
                alphabet_source=mode.source,
            )
            out.append(_make_spec(
                bench_slug=bench_slug, family_label=family_label,
                pipeline=[sub_layer, trans_layer],
                coverage=cov_sub_first,
                notes=(
                    f"{sub_kind}({kw_sub}, alpha={mode.mode_label}) ∘ "
                    f"{trans_kind}({kw_trans}) [sub-first decrypt order]"
                ),
            ))
            # Order 2: transposition first
            cov_trans_first = CoverageVector(
                layer_family=family_label,
                layer_order=(trans_kind, sub_kind),
                role_assignment=role,
                alphabet=mode.mode_label,
                n_layers=2,
                alphabet_mode=mode.mode_label,
                alphabet_source=mode.source,
            )
            out.append(_make_spec(
                bench_slug=bench_slug, family_label=family_label,
                pipeline=[trans_layer, sub_layer],
                coverage=cov_trans_first,
                notes=(
                    f"{trans_kind}({kw_trans}) ∘ "
                    f"{sub_kind}({kw_sub}, alpha={mode.mode_label}) "
                    "[trans-first decrypt order]"
                ),
            ))
    return out


def _gen_keywordless_trans_pair_family(
    *,
    bench_slug: str,
    sub_kind: str,
    trans_kind: str,
    keyword: str,
    extra_params: dict[str, Any],
    alphabet_modes: Optional[Sequence[AlphabetMode]] = None,
) -> list[GeneratedSpec]:
    """Two-layer family where the transposition is keyword-free
    (rail_fence depth, route variant + grid). Only the layer-order
    flip is meaningful here; the role-swap collapses (only one
    keyword in play).

    2026-04-27: enumerates ``alphabet_modes`` for the substitution
    layer. Default preserves the historical 2-spec output (one mode,
    two layer orders); with multiple modes the output grows to
    2 × len(modes).
    """
    if sub_kind not in _SUBSTITUTION_KEYWORD_KINDS:
        raise ValueError(f"unsupported sub_kind {sub_kind!r}")
    if trans_kind not in _KEYWORDLESS_TRANSPOSITION_KINDS:
        raise ValueError(f"unsupported trans_kind {trans_kind!r}")

    family_label = f"{trans_kind}_{sub_kind}"
    extras_tuple = tuple(sorted(extra_params.items()))
    if trans_kind == "rail_fence":
        depth = int(extra_params.get("depth", 3))
        trans_layer = _rail_fence_layer(depth)
    else:  # route
        trans_layer = _route_layer(
            variant=str(extra_params.get("variant", "serpentine")),
            rows=int(extra_params.get("rows", 7)),
            cols=int(extra_params.get("cols", 14)),
        )

    role_tuple = ((sub_kind, keyword),)
    if alphabet_modes is None:
        alphabet_modes = (AlphabetMode("AZ", "AZ", None, "default"),)

    out: list[GeneratedSpec] = []
    for mode in alphabet_modes:
        sub_layer = _keyword_substitution_layer(
            sub_kind, keyword,
            alphabet=mode.dsl_alphabet,
            alphabet_keyword=mode.alphabet_keyword,
        )
        out.append(_make_spec(
            bench_slug=bench_slug, family_label=family_label,
            pipeline=[sub_layer, trans_layer],
            coverage=CoverageVector(
                layer_family=family_label,
                layer_order=(sub_kind, trans_kind),
                role_assignment=role_tuple,
                alphabet=mode.mode_label, n_layers=2,
                extras=extras_tuple,
                alphabet_mode=mode.mode_label,
                alphabet_source=mode.source,
            ),
            notes=(
                f"{sub_kind}({keyword}, alpha={mode.mode_label}) ∘ "
                f"{trans_kind}({extra_params}) [sub-first]"
            ),
        ))
        out.append(_make_spec(
            bench_slug=bench_slug, family_label=family_label,
            pipeline=[trans_layer, sub_layer],
            coverage=CoverageVector(
                layer_family=family_label,
                layer_order=(trans_kind, sub_kind),
                role_assignment=role_tuple,
                alphabet=mode.mode_label, n_layers=2,
                extras=extras_tuple,
                alphabet_mode=mode.mode_label,
                alphabet_source=mode.source,
            ),
            notes=(
                f"{trans_kind}({extra_params}) ∘ "
                f"{sub_kind}({keyword}, alpha={mode.mode_label}) [trans-first]"
            ),
        ))
    return out


def _gen_quagmire_family(
    *,
    bench_slug: str,
    keyword_a: str,
    keyword_b: str,
) -> list[GeneratedSpec]:
    """Quagmire single-layer specs spanning III (one keyword) and IV
    (two distinct keywords).

    Lesson 003 (keyword_tableau_role_ambiguity): in Quagmire IV the
    pt_alphabet_keyword and ct_alphabet_keyword are distinct roles; we
    test BOTH (A,B) and (B,A) assignments to surface the ambiguity.
    """
    family_label = "quagmire"
    out: list[GeneratedSpec] = []

    # Quagmire III: one keyword each.
    for kw in (keyword_a, keyword_b):
        if len(kw) < 2:
            continue
        out.append(_make_spec(
            bench_slug=bench_slug, family_label=family_label,
            pipeline=[_quagmire_iii_layer(kw)],
            coverage=CoverageVector(
                layer_family=family_label,
                layer_order=("quagmire",),
                role_assignment=(("quagmire", kw),),
                alphabet="AZ", n_layers=1,
                extras=(("variant", "quagmire_iii"),),
            ),
            notes=f"quagmire_iii({kw})",
            crib_alignment="direct_positional",
        ))

    # Quagmire IV: distinct keywords. Test both role assignments.
    if keyword_a != keyword_b and len(keyword_a) >= 2 and len(keyword_b) >= 2:
        for pt_kw, ct_kw in ((keyword_a, keyword_b), (keyword_b, keyword_a)):
            out.append(_make_spec(
                bench_slug=bench_slug, family_label=family_label,
                pipeline=[_quagmire_iv_layer(pt_kw, ct_kw)],
                coverage=CoverageVector(
                    layer_family=family_label,
                    layer_order=("quagmire",),
                    role_assignment=tuple(sorted(
                        (("quagmire_pt", pt_kw), ("quagmire_ct", ct_kw))
                    )),
                    alphabet="AZ", n_layers=1,
                    extras=(("variant", "quagmire_iv"),),
                ),
                notes=f"quagmire_iv(pt={pt_kw}, ct={ct_kw})",
                crib_alignment="direct_positional",
            ))
    return out


def _gen_three_layer_sandwich_family(
    *,
    bench_slug: str,
    sub_kind_a: str,
    trans_kind: str,
    sub_kind_b: str,
    keyword_a: str,
    keyword_b: str,
    alphabet_modes: Optional[Sequence[AlphabetMode]] = None,
    rail_fence_depth: int = 3,
) -> list[GeneratedSpec]:
    """Simple three-layer sandwich: sub_a + trans + sub_b.

    The transposition is keyword-free here (rail_fence) so the
    universe stays bounded — adding a keyword-bearing transposition
    in the middle would multiply by another role-permutation factor.
    Emits 2 × len(alphabet_modes) specs (two role assignments for the
    substitution slots × per-alphabet-mode); layer order is implicit
    (the sandwich is asymmetric only at the keyword slots).

    2026-04-27: same alphabet mode is applied to both substitution
    layers in a given spec — testing two DIFFERENT modes in one
    sandwich would multiply the universe quadratically with little
    extra coverage benefit on a single-clue-pack budget.
    """
    if sub_kind_a not in _SUBSTITUTION_KEYWORD_KINDS:
        raise ValueError(f"unsupported sub_kind_a {sub_kind_a!r}")
    if sub_kind_b not in _SUBSTITUTION_KEYWORD_KINDS:
        raise ValueError(f"unsupported sub_kind_b {sub_kind_b!r}")
    if trans_kind != "rail_fence":
        raise ValueError(
            "three-layer sandwich currently supports rail_fence as the "
            "middle transposition only (keeps universe bounded)"
        )

    family_label = f"{sub_kind_a}_{trans_kind}_{sub_kind_b}"
    if alphabet_modes is None:
        alphabet_modes = (AlphabetMode("AZ", "AZ", None, "default"),)

    out: list[GeneratedSpec] = []
    for kw_a, kw_b in ((keyword_a, keyword_b), (keyword_b, keyword_a)):
        for mode in alphabet_modes:
            layers = [
                _keyword_substitution_layer(
                    sub_kind_a, kw_a,
                    alphabet=mode.dsl_alphabet,
                    alphabet_keyword=mode.alphabet_keyword,
                ),
                _rail_fence_layer(rail_fence_depth),
                _keyword_substitution_layer(
                    sub_kind_b, kw_b,
                    alphabet=mode.dsl_alphabet,
                    alphabet_keyword=mode.alphabet_keyword,
                ),
            ]
            cov = CoverageVector(
                layer_family=family_label,
                layer_order=(sub_kind_a, trans_kind, sub_kind_b),
                role_assignment=tuple(sorted(
                    ((f"{sub_kind_a}_outer", kw_a), (f"{sub_kind_b}_inner", kw_b))
                )),
                alphabet=mode.mode_label, n_layers=3,
                extras=(("rail_fence_depth", rail_fence_depth),),
                alphabet_mode=mode.mode_label,
                alphabet_source=mode.source,
            )
            out.append(_make_spec(
                bench_slug=bench_slug, family_label=family_label,
                pipeline=layers, coverage=cov,
                notes=(
                    f"{sub_kind_a}({kw_a}, alpha={mode.mode_label}) ∘ "
                    f"{trans_kind}({rail_fence_depth}) ∘ "
                    f"{sub_kind_b}({kw_b}, alpha={mode.mode_label})"
                ),
                compute_budget_minutes=3,
            ))
    return out


# ============================================================================
# Top-level generator
# ============================================================================


# Default rail-fence depths to enumerate when generating
# rail_fence + substitution families. Kept short so the universe stays
# bounded; callers can override via family_extras.
_DEFAULT_RAIL_FENCE_DEPTHS: tuple[int, ...] = (3, 5)

# Default route grids (rows, cols). Two grids cover the common K4-shape
# 7x14=98 (over) and 10x10=100 (over). Both rows*cols >= 97.
_DEFAULT_ROUTE_GRIDS: tuple[tuple[int, int], ...] = ((7, 14), (10, 10))


def generate_layered_specs(
    clue_words: Sequence[str],
    *,
    bench_slug: str = "k",
    families: Optional[Iterable[str]] = None,
    max_specs: int = _DEFAULT_MAX_SPECS,
    include_three_layer: bool = True,
    clue_text: str = "",
    alphabet_modes: Optional[Sequence[AlphabetMode]] = None,
    rail_fence_depths: Optional[Sequence[int]] = None,
) -> list[GeneratedSpec]:
    """Generate the deterministic GeneratedSpec list for the given clues.

    Args:
        clue_words: Ordered, deduplicated list of A-Z keywords mined from
            the clue text. The first two entries drive the role-permutation
            matrix; additional entries cycle in for diversity but do not
            multiply the matrix exponentially.
        bench_slug: Short id-safe slug used inside generated hypothesis_ids.
            Callers in bench mode pass the bench_id; real-K4 callers can
            pass any descriptive label.
        families: Optional iterable of family labels to emit. When None,
            the full default set runs. Useful for testing and for the
            gap-analysis path which targets specific missing classes.
        max_specs: Hard cap on total emitted specs (after validation).
            Cuts the list at the cap; remaining family combinations
            are silently dropped to keep dispatch budget predictable.
        include_three_layer: When True (default), append the simple
            three-layer sandwich families after the two-layer set.
        clue_text: Raw clue text from the challenge payload. Used to
            (a) detect mirror/reverse trigger language for alphabet
            enumeration, and (b) extract numeric depth candidates for
            rail-fence specs. Empty string disables both clue-driven
            enumerations and falls back to the safe default sets.
        alphabet_modes: Override for the alphabet-mode enumeration.
            When None, derived from clue_words + clue_text via
            ``_alphabet_modes_for_payload``. Pass an explicit list
            (e.g. ``[AlphabetMode("AZ", ...)]``) to suppress the
            default enumeration in tests.
        rail_fence_depths: Override for rail-fence depth enumeration.
            When None, derived from clue_text via
            ``_rail_fence_depths_for_payload``.

    Returns:
        A deterministic list of GeneratedSpec. Same inputs always
        produce the same output ordering. Every returned spec passes
        ``validate_hypothesis_spec`` AND every layer kind has a
        dispatcher translation.
    """
    # Normalize + filter clue words. Need at least one keyword to do
    # ANYTHING useful; need at least two to exercise the role-permutation
    # matrix.
    cleaned: list[str] = []
    seen_clue: set[str] = set()
    for kw in clue_words:
        if not isinstance(kw, str):
            continue
        upper = kw.upper().strip()
        if not upper.isalpha():
            continue
        if upper in seen_clue:
            continue
        seen_clue.add(upper)
        cleaned.append(upper)
    if len(cleaned) == 0:
        logger.warning(
            "generate_layered_specs: no usable clue words; emitting empty list"
        )
        return []

    # When the caller supplied just one clue, synthesize a placeholder
    # second so the role-permutation pipeline still runs (it will emit
    # both role assignments; the placeholder is structurally valid even
    # if semantically thin).
    keyword_a = cleaned[0]
    keyword_b = cleaned[1] if len(cleaned) > 1 else cleaned[0]
    keyword_c = cleaned[2] if len(cleaned) > 2 else keyword_b

    # Resolve alphabet modes + rail-fence depths. Caller overrides win;
    # otherwise derive from clue_text + clue_words.
    if alphabet_modes is None:
        alphabet_modes = tuple(
            _alphabet_modes_for_payload(clue_text, cleaned)
        )
    if rail_fence_depths is None:
        rail_fence_depths = tuple(_rail_fence_depths_for_payload(clue_text))
        if not rail_fence_depths:
            rail_fence_depths = _DEFAULT_RAIL_FENCE_DEPTHS_BASE

    # Family allow-list. None ⇒ full default set.
    default_families = {
        "columnar_vigenere", "columnar_beaufort", "columnar_variant_beaufort",
        "myszkowski_vigenere", "myszkowski_beaufort",
        "rail_fence_vigenere", "rail_fence_beaufort",
        "route_vigenere", "route_beaufort",
        "quagmire",
    }
    if include_three_layer:
        default_families |= {
            "vigenere_rail_fence_beaufort",
            "beaufort_rail_fence_vigenere",
        }
    active = set(families) if families is not None else default_families

    out: list[GeneratedSpec] = []

    # --- Two-layer keyword-pair families ---
    keyword_pair_specs: list[tuple[str, str, str]] = [
        # (family_label, sub_kind, trans_kind)
        ("columnar_vigenere",         "vigenere",         "columnar"),
        ("columnar_beaufort",         "beaufort",         "columnar"),
        ("columnar_variant_beaufort", "variant_beaufort", "columnar"),
        ("myszkowski_vigenere",       "vigenere",         "myszkowski"),
        ("myszkowski_beaufort",       "beaufort",         "myszkowski"),
    ]
    for label, sub_kind, trans_kind in keyword_pair_specs:
        if label not in active:
            continue
        out.extend(_gen_keyword_pair_family(
            bench_slug=bench_slug,
            sub_kind=sub_kind, trans_kind=trans_kind,
            keyword_a=keyword_a, keyword_b=keyword_b,
            alphabet_modes=alphabet_modes,
        ))

    # --- Two-layer keywordless-transposition families ---
    keywordless_pairs: list[tuple[str, str, str]] = [
        ("rail_fence_vigenere", "vigenere", "rail_fence"),
        ("rail_fence_beaufort", "beaufort", "rail_fence"),
        ("route_vigenere",      "vigenere", "route"),
        ("route_beaufort",      "beaufort", "route"),
    ]
    for label, sub_kind, trans_kind in keywordless_pairs:
        if label not in active:
            continue
        if trans_kind == "rail_fence":
            # Use the resolved rail_fence_depths (clue numerals + safe
            # defaults). Both layer orders (sub-first, trans-first)
            # come from _gen_keywordless_trans_pair_family per call.
            for depth in rail_fence_depths:
                for kw in (keyword_a, keyword_b):
                    out.extend(_gen_keywordless_trans_pair_family(
                        bench_slug=bench_slug,
                        sub_kind=sub_kind, trans_kind=trans_kind,
                        keyword=kw, extra_params={"depth": depth},
                        alphabet_modes=alphabet_modes,
                    ))
        else:  # route
            for rows, cols in _DEFAULT_ROUTE_GRIDS:
                for kw in (keyword_a, keyword_b):
                    out.extend(_gen_keywordless_trans_pair_family(
                        bench_slug=bench_slug,
                        sub_kind=sub_kind, trans_kind=trans_kind,
                        keyword=kw,
                        extra_params={
                            "variant": "serpentine",
                            "rows": rows, "cols": cols,
                        },
                        alphabet_modes=alphabet_modes,
                    ))

    # --- Quagmire family (III + IV with role permutation) ---
    if "quagmire" in active:
        out.extend(_gen_quagmire_family(
            bench_slug=bench_slug,
            keyword_a=keyword_a, keyword_b=keyword_b,
        ))

    # --- Three-layer sandwiches ---
    if include_three_layer:
        # Use the first rail-fence depth from the resolved set so the
        # sandwich enumerates the most-clue-relevant depth without
        # multiplying the universe by every candidate depth.
        sandwich_depth = rail_fence_depths[0] if rail_fence_depths else 3
        if "vigenere_rail_fence_beaufort" in active:
            out.extend(_gen_three_layer_sandwich_family(
                bench_slug=bench_slug,
                sub_kind_a="vigenere", trans_kind="rail_fence",
                sub_kind_b="beaufort",
                keyword_a=keyword_a, keyword_b=keyword_c,
                alphabet_modes=alphabet_modes,
                rail_fence_depth=sandwich_depth,
            ))
        if "beaufort_rail_fence_vigenere" in active:
            out.extend(_gen_three_layer_sandwich_family(
                bench_slug=bench_slug,
                sub_kind_a="beaufort", trans_kind="rail_fence",
                sub_kind_b="vigenere",
                keyword_a=keyword_a, keyword_b=keyword_c,
                alphabet_modes=alphabet_modes,
                rail_fence_depth=sandwich_depth,
            ))

    # Validate every emitted spec; drop the ones the dispatcher would
    # reject. This is a belt-and-suspenders check — the family
    # generators already produce dispatcher-shaped specs, but a future
    # kernel-side enforcement change could invalidate one of them and
    # we want fail-closed silence rather than cascading dispatch
    # failures inside the worker.
    validated: list[GeneratedSpec] = []
    for gs in out:
        ok, errs = _spec_passes_validation(gs.raw_spec)
        if not ok:
            logger.info(
                "hand_cipher_core dropped spec %s at validation: %s",
                gs.hypothesis_id[:48], errs[0] if errs else "<no detail>",
            )
            continue
        validated.append(gs)
        if len(validated) >= max_specs:
            break
    return validated


def _spec_passes_validation(raw: dict[str, Any]) -> tuple[bool, list[str]]:
    """Mirror of bench_fallback._spec_passes_validation — kept here so
    hand_cipher_core has no upward dependency on bench_fallback.
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


# ============================================================================
# Coverage analysis
# ============================================================================


def coverage_class_key(cv: CoverageVector) -> tuple[tuple[str, ...], str]:
    """Return the symmetry-class key for a coverage vector.

    Two vectors are in the same class iff they share BOTH:
      * the clue pair (set of keywords used)
      * the layer family (e.g. "columnar_vigenere")

    Within a class, the (layer_order, role_assignment) is the
    in-class coordinate that distinguishes different symmetry points.
    """
    return (cv.clue_pair, cv.layer_family)


def gap_analysis(
    prior_coverage: Iterable[CoverageVector],
) -> dict[tuple[tuple[str, ...], str], dict[str, Any]]:
    """For each symmetry class touched by ``prior_coverage``, report
    which (layer_order, role_assignment) points have been tested and
    which are missing.

    Returns a dict keyed by ``coverage_class_key`` whose values look
    like::

        {
            "tested": [(layer_order, role_assignment), ...],
            "missing": [(layer_order, role_assignment), ...],
            "covered_count": int,
            "expected_count": int,
            "fully_covered": bool,
        }

    "Expected" depends on the family: keyword-pair families expect 4
    points (2 role × 2 order), keywordless-transposition families
    expect 2 (just the order flip), Quagmire IV expects 2 role
    assignments, single-layer Quagmire III is always covered after
    1 spec.

    The missing-points list uses the same (layer_order,
    role_assignment) tuple shape as the in-class coordinate so the
    caller can feed them straight back into the family generator.
    """
    by_class: dict[tuple[tuple[str, ...], str], list[CoverageVector]] = defaultdict(list)
    for cv in prior_coverage:
        by_class[coverage_class_key(cv)].append(cv)

    result: dict[tuple[tuple[str, ...], str], dict[str, Any]] = {}
    for class_key, vectors in by_class.items():
        clue_pair, family = class_key
        tested = sorted({(v.layer_order, v.role_assignment) for v in vectors})

        # Determine the expected universe for this class.
        sample = vectors[0]
        expected: set[tuple[tuple[str, ...], tuple[tuple[str, str], ...]]] = set()
        if (
            family.startswith(("columnar_", "myszkowski_"))
            and family.endswith(_SUBSTITUTION_KEYWORD_KINDS)
            and sample.n_layers == 2
            and len(clue_pair) == 2
        ):
            kinds = sample.layer_order
            sub_kind = next((k for k in kinds if k in _SUBSTITUTION_KEYWORD_KINDS), None)
            trans_kind = next((k for k in kinds if k in _KEYWORD_TRANSPOSITION_KINDS), None)
            if sub_kind is not None and trans_kind is not None:
                kw_a, kw_b = clue_pair
                for kw_sub, kw_trans in ((kw_a, kw_b), (kw_b, kw_a)):
                    role = tuple(sorted(
                        ((sub_kind, kw_sub), (trans_kind, kw_trans))
                    ))
                    for order in ((sub_kind, trans_kind), (trans_kind, sub_kind)):
                        expected.add((order, role))
        elif (
            family.startswith(("rail_fence_", "route_"))
            and sample.n_layers == 2
            and len(clue_pair) == 1
        ):
            kinds = sample.layer_order
            sub_kind = next((k for k in kinds if k in _SUBSTITUTION_KEYWORD_KINDS), None)
            trans_kind = next(
                (k for k in kinds if k in _KEYWORDLESS_TRANSPOSITION_KINDS),
                None,
            )
            if sub_kind and trans_kind:
                role = ((sub_kind, clue_pair[0]),)
                for order in ((sub_kind, trans_kind), (trans_kind, sub_kind)):
                    expected.add((order, role))
        elif family == "quagmire" and sample.n_layers == 1:
            # Quagmire IV expects 2 role assignments; III expects 1.
            # We can't tell variant from the family label alone, so
            # use the union of what could be expected.
            for v in vectors:
                expected.add((v.layer_order, v.role_assignment))
        else:
            # Three-layer / unknown families: use the seen set as the
            # expected set (so fully_covered is True after any test).
            for v in vectors:
                expected.add((v.layer_order, v.role_assignment))

        # Anything in expected that isn't tested is missing.
        tested_set = set(tested)
        missing = sorted(expected - tested_set)
        result[class_key] = {
            "tested": tested,
            "missing": missing,
            "covered_count": len(tested_set & expected),
            "expected_count": len(expected),
            "fully_covered": len(missing) == 0 and len(expected) > 0,
        }
    return result


def missing_combos_as_specs(
    prior_coverage: Iterable[CoverageVector],
    *,
    bench_slug: str = "gap",
) -> list[GeneratedSpec]:
    """Convert the gaps from ``gap_analysis`` back into a list of
    GeneratedSpec the controller can dispatch as next-cycle targets.

    Lesson 006 (failed_method_coverage): when a class has gaps, the
    next cycle must close them before exploring unrelated families.
    """
    gaps = gap_analysis(prior_coverage)
    out: list[GeneratedSpec] = []
    for class_key, info in gaps.items():
        if info["fully_covered"]:
            continue
        clue_pair, family = class_key
        # Re-use the family generator to produce the missing
        # combinations. We regenerate the full family then filter
        # down to the missing (order, role) points.
        if (
            family.startswith(("columnar_", "myszkowski_"))
            and len(clue_pair) == 2
        ):
            kinds = family.split("_", 1)
            trans_kind, sub_kind = kinds[0], kinds[1]
            full = _gen_keyword_pair_family(
                bench_slug=bench_slug,
                sub_kind=sub_kind, trans_kind=trans_kind,
                keyword_a=clue_pair[0], keyword_b=clue_pair[1],
            )
            tested_set = set(info["tested"])
            for gs in full:
                ckey = (gs.coverage.layer_order, gs.coverage.role_assignment)
                if ckey not in tested_set:
                    out.append(gs)
        elif (
            family.startswith(("rail_fence_", "route_"))
            and len(clue_pair) == 1
        ):
            trans_kind, sub_kind = family.split("_", 1)
            keyword = clue_pair[0]
            extras = _DEFAULT_RAIL_FENCE_DEPTHS if trans_kind == "rail_fence" else None
            if extras is not None:
                for depth in extras:
                    full = _gen_keywordless_trans_pair_family(
                        bench_slug=bench_slug,
                        sub_kind=sub_kind, trans_kind=trans_kind,
                        keyword=keyword, extra_params={"depth": depth},
                    )
                    tested_set = set(info["tested"])
                    for gs in full:
                        ckey = (gs.coverage.layer_order, gs.coverage.role_assignment)
                        if ckey not in tested_set:
                            out.append(gs)
            else:
                for rows, cols in _DEFAULT_ROUTE_GRIDS:
                    full = _gen_keywordless_trans_pair_family(
                        bench_slug=bench_slug,
                        sub_kind=sub_kind, trans_kind=trans_kind,
                        keyword=keyword,
                        extra_params={
                            "variant": "serpentine",
                            "rows": rows, "cols": cols,
                        },
                    )
                    tested_set = set(info["tested"])
                    for gs in full:
                        ckey = (gs.coverage.layer_order, gs.coverage.role_assignment)
                        if ckey not in tested_set:
                            out.append(gs)
    return out


# ============================================================================
# Synthesis recommendation (next-cycle feedback)
# ============================================================================


def coverage_gap_recommendations(
    prior_coverage: Iterable[CoverageVector],
    *,
    bench_slug: str = "gap",
    max_recommendations: int = 16,
) -> dict[str, Any]:
    """Build a structured next-cycle recommendation block from prior
    coverage. Designed to be appended to the next-cycle theorist
    prompt as concrete "do these before exploring unrelated families"
    guidance (lesson 006: failed_method_coverage).

    The output is a plain dict (not a CycleSynthesis) so the controller
    can stitch it into existing landscape blocks without further
    coupling. Shape::

        {
            "schema_version": "hand_cipher_core.coverage_recs.v1",
            "n_classes_with_gaps": int,
            "n_recommended_specs": int,
            "classes": [
                {
                    "clue_pair": ["CEDAR", "LANTERN"],
                    "family": "columnar_vigenere",
                    "tested_count": 1,
                    "missing_count": 3,
                    "next_specs": [
                        {"hypothesis_id": "...", "layer_order": [...],
                         "role_assignment": {...}},
                        ...
                    ],
                },
                ...
            ],
            "render_block": str   # human-readable text for prompt inclusion
        }

    The ``next_specs`` list is bounded by ``max_recommendations`` so a
    pathological run with dozens of partially-tested classes does not
    flood the prompt.
    """
    gaps = gap_analysis(prior_coverage)
    next_specs = missing_combos_as_specs(prior_coverage, bench_slug=bench_slug)

    classes_block: list[dict[str, Any]] = []
    rendered_lines: list[str] = []
    for class_key, info in sorted(gaps.items()):
        if info["fully_covered"]:
            continue
        clue_pair, family = class_key
        per_class_specs = [
            {
                "hypothesis_id": gs.hypothesis_id,
                "layer_order": list(gs.coverage.layer_order),
                "role_assignment": dict(gs.coverage.role_assignment),
                "notes": gs.notes,
            }
            for gs in next_specs
            if (gs.coverage.clue_pair, gs.coverage.layer_family) == class_key
        ]
        if not per_class_specs:
            continue
        classes_block.append({
            "clue_pair": list(clue_pair),
            "family": family,
            "tested_count": info["covered_count"],
            "missing_count": len(info["missing"]),
            "next_specs": per_class_specs,
        })
        rendered_lines.append(
            f"  • {family} for clues {list(clue_pair)}: "
            f"{info['covered_count']}/{info['expected_count']} covered, "
            f"{len(info['missing'])} missing role/order combos."
        )
        for spec in per_class_specs[:4]:
            rendered_lines.append(
                f"      - try {spec['layer_order']} role={spec['role_assignment']}"
            )

    # Cap the next_specs across all classes
    flat_count = sum(len(c["next_specs"]) for c in classes_block)
    if flat_count > max_recommendations:
        # Trim from the back so high-priority (alphabetical-first)
        # classes keep their full coverage.
        remaining = max_recommendations
        trimmed: list[dict[str, Any]] = []
        for c in classes_block:
            keep = c["next_specs"][:remaining]
            c2 = dict(c)
            c2["next_specs"] = keep
            trimmed.append(c2)
            remaining -= len(keep)
            if remaining <= 0:
                break
        classes_block = trimmed
        flat_count = sum(len(c["next_specs"]) for c in classes_block)

    render = ""
    if classes_block:
        render = (
            "Coverage gaps from prior cycles (lesson 006: close the symmetry "
            "class before moving on):\n" + "\n".join(rendered_lines)
        )

    return {
        "schema_version": "hand_cipher_core.coverage_recs.v1",
        "n_classes_with_gaps": len(classes_block),
        "n_recommended_specs": flat_count,
        "classes": classes_block,
        "render_block": render,
    }


def coverage_vectors_from_theories(theories: Iterable[Any]) -> list[CoverageVector]:
    """Extract CoverageVectors from an iterable of TheoryRecord
    (or anything with a ``minimal_test_spec`` dict carrying a
    ``coverage_vector`` sub-dict).

    Theories without a coverage vector are silently skipped — the
    gap analyzer does not penalize legacy theory rows.
    """
    out: list[CoverageVector] = []
    for theory in theories:
        spec = getattr(theory, "minimal_test_spec", None)
        if not isinstance(spec, dict):
            continue
        cv_raw = spec.get("coverage_vector")
        if not isinstance(cv_raw, dict) or not cv_raw:
            continue
        try:
            out.append(CoverageVector.from_dict(cv_raw))
        except (TypeError, ValueError):
            continue
    return out


__all__ = [
    "CoverageVector",
    "GeneratedSpec",
    "generate_layered_specs",
    "coverage_class_key",
    "gap_analysis",
    "missing_combos_as_specs",
    "coverage_gap_recommendations",
    "coverage_vectors_from_theories",
    # Layer-builder helpers exposed for re-use by bench_fallback /
    # tests / future real-K4 caller.
    "_keyword_to_col_order",
    "_keyword_substitution_layer",
    "_keyword_columnar_layer",
    "_keyword_myszkowski_layer",
    "_rail_fence_layer",
    "_route_layer",
    "_quagmire_iii_layer",
    "_quagmire_iv_layer",
]
