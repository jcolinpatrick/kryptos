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

# 2026-04-28 (LESSON-008): block-reversal trigger vocabulary. Sourced
# from the lesson's ``tactic_parameters.trigger_tokens`` and kept here
# as a runtime constant so the generator does not have to re-load the
# registry on the hot path. A drift test asserts the runtime list
# matches the registry. Phrases (multi-word triggers) are listed
# alongside single tokens; ``_detect_block_reversal_trigger`` matches
# whole phrases case-insensitively.
_BLOCK_REVERSAL_TRIGGER_TOKENS: frozenset[str] = frozenset({
    "block", "blocks",
    "chunk", "chunks",
    "group", "groups",
    "small group",
    "backward", "backwards",
    "reverse", "reversed", "reversal",
    "turn",
    "clockwise", "counterclockwise", "clock",
    "route before",
    "read first", "read last",
    "before key", "after key",
})

# Default block sizes when no clue numerals apply (LESSON-008
# tactic_parameters.default_block_sizes). The generator unions clue-
# derived block sizes with these so a clue-free payload still produces
# a useful enumeration.
_DEFAULT_BLOCK_SIZES: tuple[int, ...] = (2, 3, 4, 5, 6, 7, 8, 10)

# 2026-04-28 (LESSON-008): "shift" trigger tokens. When ANY of these
# appears alongside a block-reversal trigger, the generator emits the
# three-layer sandwiches that include Atbash or a Caesar shift (e.g.
# vigenere ∘ reverse_blocks ∘ atbash). Without a shift trigger, the
# three-layer sandwiches stay with the existing rail_fence center to
# preserve historical coverage.
_SHIFT_TRIGGER_TOKENS: frozenset[str] = frozenset({
    "shift", "shifted", "rotate", "rotated", "rotation",
    "turn", "clockwise", "counterclockwise",
})

# Caesar shift enumeration. The dispatcher now exposes a first-class
# ``caesar`` DSL kind (LESSON-009) so HCC emits caesar layers directly
# rather than collapsing them into 1-letter Vigeneres; this keeps
# coverage_vector and attempt artifact layers explicit.
#
# Default shift set (LESSON-009 tactic_parameters.default_shifts):
# common hand-cipher shifts including ROT13. Shift 0 is identity and
# is excluded by callers. Clue-derived numerals are unioned in front
# of the defaults via ``_caesar_shifts_for_payload``.
_DEFAULT_CAESAR_SHIFTS: tuple[int, ...] = (1, 3, 5, 7, 8, 13, 17, 23)

# Smaller shift set used by LESSON-008's ``reverse_blocks_caesar``
# generator. LESSON-009 already exercises the full shift space against
# every transposition kind; the LESSON-008 sub-family only needs a
# small representative cover here so the universe stays bounded when
# both triggers fire on the same clue pack.
_DEFAULT_REV_BLOCKS_CAESAR_SHIFTS: tuple[int, ...] = (1, 3, 13)

# 2026-04-28 (LESSON-009): Caesar / ROT trigger vocabulary. When ANY
# of these tokens appears in the clue text (case-insensitive,
# word-boundary match), the generator emits the full Caesar +
# transposition + Atbash family matrix. Without a trigger the family
# generators are absent and the historical catalogue is preserved.
_CAESAR_TRIGGER_TOKENS: frozenset[str] = frozenset({
    "shift", "shifted", "offset",
    "rotate", "rotated", "rotation",
    "step",
    "caesar",
    "rot",
    "additive", "subtractive",
})


def _shift_to_keyword(shift: int) -> str:
    """Map an integer shift in [1, 25] to its Vigenere keyword char.
    Shift k → chr(ord('A') + k). Shift 0 is identity (excluded by
    callers).

    Retained for backwards compatibility with the LESSON-008
    reverse_blocks_caesar generator that still wraps Caesar inside a
    Vigenere layer when emitting the LESSON-008 family. New callers
    SHOULD prefer ``_caesar_layer`` so the canonical caesar kind
    surfaces in coverage_vector.
    """
    if not 1 <= shift <= 25:
        raise ValueError(
            f"_shift_to_keyword: shift must be in [1, 25]; got {shift}"
        )
    return chr(ord("A") + shift)


# 2026-04-28 (LESSON-011): skip / step / stride route trigger
# vocabulary. When ANY of these tokens appears in the clue text
# (case-insensitive, word-boundary match), the generator emits the
# skip_route family matrix. Pulled from the lesson registry's
# ``tactic_parameters.trigger_tokens``; the runtime constant lets
# the generator avoid re-loading the registry on the hot path.
_SKIP_ROUTE_TRIGGER_TOKENS: frozenset[str] = frozenset({
    "skip", "skipped",
    "step", "stepped",
    "stride",
    "every",
    "nth",
    "offset",
    "route", "path",
    "tunnel", "passage",
    "layer",
    "hide", "hides", "hidden",
    "read", "reads",
    "walk", "walks",
    "margin", "margins",
})

# 2026-04-28 (LESSON-011): default step set for skip_route. K4
# (CT_LEN=97) is prime, so every step in [1, 96] is coprime —
# the dispatcher's coprimality guard never fires for the standard
# K4 length. The default set covers small primes + a handful of
# slightly larger primes / composites that show up in hand-cipher
# folklore. Clue-derived numerals are unioned in front.
_DEFAULT_SKIP_ROUTE_STEPS: tuple[int, ...] = (
    2, 3, 4, 5, 6, 7, 8, 10, 13, 17, 23,
)

# Bounded default offset window. The lesson allows 0..min(step-1, 25)
# but emitting all of those for every (family × keyword × alphabet
# × layer-order) combination would explode the universe. The default
# is a small window that covers the common offsets; clue-derived
# offsets are always appended on top.
_DEFAULT_SKIP_ROUTE_OFFSETS: tuple[int, ...] = (0, 1, 2)

# Bound on the number of (step, offset) pairs the substitution-
# paired families enumerate. The skip_route alone family is
# uncapped because it produces only ~11×3 = 33 specs even at the
# default. The substitution-paired and three-layer-sandwich
# families pre-multiply by keywords and alphabet modes, so we cap
# the (step, offset) cartesian aggressively.
_SKIP_ROUTE_PAIR_CAP: int = 12
# Smaller cap for three-layer sandwiches where the (sub × alpha
# × layer-orders × pair) cartesian explodes the universe. Six
# pairs is enough to hit the two clue-derived offsets plus four
# default-set options.
_SKIP_ROUTE_THREE_LAYER_PAIR_CAP: int = 6
# Smallest possible Caesar shift set for the LESSON-011 three-
# layer skip_route + sub + caesar variant — LESSON-009 already
# exercises the full Caesar shift space against the keyed
# transpositions; the skip-route sandwich just needs a token
# Caesar to demonstrate the ordering.
_SKIP_ROUTE_THREE_LAYER_CAESAR_SHIFTS: tuple[int, ...] = (13,)

# 2026-04-28 (LESSON-014): caps on (width, direction) enumeration for
# substitution-paired and three-layer route_boustrophedon families.
# The alone family is uncapped because it produces only ~10 widths × 2
# directions = 20 specs at the default. Substitution-paired families
# pre-multiply by keywords × alphabets × layer-orders, so capping the
# (width, direction) cartesian keeps the universe bounded.
_ROUTE_BOUSTROPHEDON_PAIR_WIDTH_CAP: int = 8
# Smaller cap for three-layer sandwiches where (sub × alpha × widths
# × directions × layer-orders) cartesian explodes the universe. Six
# widths is enough to hit any phrase-bound width plus the most common
# defaults.
_ROUTE_BOUSTROPHEDON_THREE_LAYER_WIDTH_CAP: int = 6

# 2026-04-28 (LESSON-015): caps on (width × parity) enumeration for
# substitution-paired and three-layer row_reverse families. The alone
# family is uncapped because it produces only ~9 widths × 2 parities =
# 18 specs at the default; substitution-paired families pre-multiply
# by keywords × alphabets × layer-orders, so capping the (width,
# parity) cartesian keeps the universe bounded.
_ROW_REVERSE_PAIR_WIDTH_CAP: int = 8
_ROW_REVERSE_THREE_LAYER_WIDTH_CAP: int = 5


def _skip_route_layer(step: int, offset: int) -> dict[str, Any]:
    """Build a skip_route layer dict (LESSON-011).

    The dispatcher translator validates that step ∈ [1, CT_LEN-1],
    offset ∈ [0, CT_LEN-1], and gcd(step, CT_LEN) == 1; this layer
    builder accepts any int in those bounds, leaving the kernel
    coprimality guard as the single source of truth.
    """
    if not isinstance(step, int) or step < 1:
        raise ValueError(
            f"_skip_route_layer: step must be int >= 1; got {step!r}"
        )
    if not isinstance(offset, int) or offset < 0:
        raise ValueError(
            f"_skip_route_layer: offset must be int >= 0; got "
            f"{offset!r}"
        )
    return {
        "kind": "skip_route",
        "alphabet": "AZ",
        "params": [
            {"name": "step", "values": [step]},
            {"name": "offset", "values": [offset]},
        ],
    }


def _detect_skip_route_trigger(clue_text: str) -> bool:
    """Whole-word match for any LESSON-011 skip-route trigger token.

    Used by ``generate_layered_specs`` to gate emission of the
    skip_route family matrix. A clue text without any of these
    tokens leaves the historical catalog bit-identical (skip_route
    families are absent).
    """
    if not isinstance(clue_text, str) or not clue_text:
        return False
    lower = clue_text.lower()
    for token in _SKIP_ROUTE_TRIGGER_TOKENS:
        idx = 0
        while True:
            pos = lower.find(token, idx)
            if pos < 0:
                break
            before_ok = pos == 0 or not lower[pos - 1].isalnum()
            after_pos = pos + len(token)
            after_ok = (
                after_pos >= len(lower) or not lower[after_pos].isalnum()
            )
            if before_ok and after_ok:
                return True
            idx = pos + 1
    return False


def _skip_route_steps_for_payload(
    clue_text: str,
    *,
    ct_length: int = 97,
) -> list[tuple[int, str]]:
    """Return the (step, operation_source) list for the payload.

    LESSON-012 ordering:
      ``phrase_bound_step`` — anchor-bound numerals from
                          ``extract_phrase_bound_numerics``
                          ("step five" → 5, "stride seven" → 7,
                          "every fifth step" → 5). Highest
                          priority — never starved by cap budget
                          downstream.
      ``clue_numeral``     — legacy flat extraction for any
                          coprime numeral 2..ct_length-1 not
                          phrase-bound to a different parameter.
                          Cross-contamination filter prevents
                          "four rails" from contributing step=4.
      ``default_set``      — ``_DEFAULT_SKIP_ROUTE_STEPS`` final
                          fallback.

    Steps coprime with ``ct_length`` only; non-coprime values
    silently dropped. For canonical K4 length 97 (prime), every
    step survives.
    """
    import math
    out: list[tuple[int, str]] = []
    seen: set[int] = set()
    bound = extract_phrase_bound_numerics(clue_text, ct_length=ct_length)
    # 1. Phrase-bound first
    for n in bound["step"]:
        if 1 <= n < ct_length and math.gcd(n, ct_length) == 1 and n not in seen:
            seen.add(n)
            out.append((n, "phrase_bound_step"))
    # Cross-contamination filter for legacy fallback
    other_param_bound: set[int] = set()
    for k in ("offset", "rail_depth", "block_size", "shift_value"):
        for v in bound[k]:
            other_param_bound.add(v)
    # 2. Legacy flat fallback (filtered)
    for n in _depths_from_clue_text(clue_text):
        if not 1 <= n < ct_length:
            continue
        if math.gcd(n, ct_length) != 1:
            continue
        if n in seen or n in other_param_bound:
            continue
        seen.add(n)
        out.append((n, "clue_numeral"))
    for d in _DEFAULT_SKIP_ROUTE_STEPS:
        if d in seen:
            continue
        if not 1 <= d < ct_length:
            continue
        if math.gcd(d, ct_length) != 1:
            continue
        seen.add(d)
        out.append((d, "default_set"))
    return out


def _skip_route_offsets_for_payload(
    clue_text: str,
    step: int,
    *,
    ct_length: int = 97,
    extra_window: int = 5,
) -> list[tuple[int, str]]:
    """Return the (offset, operation_source) list for a given step.

    LESSON-012 ordering:
      ``phrase_bound_offset`` — anchor-bound numerals
                          ("offset three" → 3, "offset of five"
                          → 5).
      ``clue_numeral``     — legacy flat extraction filtered to
                          drop numerals already bound to other
                          parameters.
      ``default_set``      — bounded default window
                          0..min(step-1, extra_window) + the
                          project-wide ``_DEFAULT_SKIP_ROUTE_OFFSETS``.

    Caller is expected to truncate the returned list when
    composing with substitution layers; the alone family iterates
    the full list.
    """
    out: list[tuple[int, str]] = []
    seen: set[int] = set()
    bound = extract_phrase_bound_numerics(clue_text, ct_length=ct_length)
    # 1. Phrase-bound first
    for n in bound["offset"]:
        if 0 <= n < ct_length and n not in seen:
            seen.add(n)
            out.append((n, "phrase_bound_offset"))
    # Cross-contamination filter
    other_param_bound: set[int] = set()
    for k in ("step", "rail_depth", "block_size", "shift_value"):
        for v in bound[k]:
            other_param_bound.add(v)
    # 2. Legacy flat fallback (filtered)
    for n in _depths_from_clue_text(clue_text):
        if not 0 <= n < ct_length:
            continue
        if n in seen or n in other_param_bound:
            continue
        seen.add(n)
        out.append((n, "clue_numeral"))
    # 3. Bounded default window
    cap = min(step - 1, extra_window)
    for d in range(cap + 1):
        if d in seen:
            continue
        seen.add(d)
        out.append((d, "default_set"))
    # 4. Project-wide explicit defaults
    for d in _DEFAULT_SKIP_ROUTE_OFFSETS:
        if d in seen or d >= ct_length:
            continue
        seen.add(d)
        out.append((d, "default_set"))
    return out


def _skip_route_pairs_for_payload(
    clue_text: str,
    *,
    ct_length: int = 97,
    cap: Optional[int] = None,
) -> list[tuple[int, int, str]]:
    """Cartesian (step, offset) enumeration with provenance.

    LESSON-012 cap-priority rule (2026-04-28): pairs whose step
    AND offset are BOTH phrase-bound to their parameter slots are
    emitted FIRST, in step-major / offset-major order, before any
    cap budget is consumed. This guarantees the most semantically
    prominent (step, offset) pair survives the per-family cap on
    substitution-paired and three-layer families. K4B-006 evidence:
    "step five" + "offset three" was previously starved when the
    cap=12 list filled with step=3, step=4 (from "three steps" and
    "four rails") before reaching step=5.

    Provenance labels (most-specific first):
      ``phrase_bound``  — both step and offset are phrase-bound
      ``phrase_bound_step`` — step phrase-bound, offset from
                              clue_numeral / default
      ``phrase_bound_offset`` — offset phrase-bound, step from
                              clue_numeral / default
      ``clue_numeral``  — both came from clue (legacy)
      ``mixed``         — exactly one came from clue (legacy)
      ``default_set``   — neither from clue
    """
    out: list[tuple[int, int, str]] = []
    seen_pairs: set[tuple[int, int]] = set()

    def _emit(pair: tuple[int, int, str]) -> bool:
        """Emit a pair if not already seen and not at cap. Returns
        False if cap is reached."""
        key = (pair[0], pair[1])
        if key in seen_pairs:
            return True
        seen_pairs.add(key)
        out.append(pair)
        return cap is None or len(out) < cap

    # 1. Phrase-bound (step, offset) FIRST — guaranteed to survive
    #    the cap. This is the LESSON-012 starvation fix.
    bound = extract_phrase_bound_numerics(
        clue_text, ct_length=ct_length,
    )
    import math
    for step in bound["step"]:
        if not 1 <= step < ct_length:
            continue
        if math.gcd(step, ct_length) != 1:
            continue
        for offset in bound["offset"]:
            if not 0 <= offset < ct_length:
                continue
            if not _emit((step, offset, "phrase_bound")):
                return out

    # 2. Phrase-bound step × default-window offset (priority for
    #    the named step value even when no offset phrase fired)
    for step in bound["step"]:
        if not 1 <= step < ct_length:
            continue
        if math.gcd(step, ct_length) != 1:
            continue
        for offset, off_src in _skip_route_offsets_for_payload(
            clue_text, step, ct_length=ct_length,
        ):
            if (step, offset) in seen_pairs:
                continue
            label = (
                "phrase_bound_step" if off_src != "phrase_bound_offset"
                else "phrase_bound"
            )
            if not _emit((step, offset, label)):
                return out

    # 3. Phrase-bound offset × full-step list (priority for the
    #    named offset value across step alternatives)
    for offset in bound["offset"]:
        if not 0 <= offset < ct_length:
            continue
        for step, step_src in _skip_route_steps_for_payload(
            clue_text, ct_length=ct_length,
        ):
            if (step, offset) in seen_pairs:
                continue
            label = (
                "phrase_bound_offset" if step_src != "phrase_bound_step"
                else "phrase_bound"
            )
            if not _emit((step, offset, label)):
                return out

    # 4. Legacy step-major × offset-major fallback for any
    #    remaining (step, offset) combinations from clue_numeral /
    #    default_set sources.
    for step, step_src in _skip_route_steps_for_payload(
        clue_text, ct_length=ct_length,
    ):
        for offset, off_src in _skip_route_offsets_for_payload(
            clue_text, step, ct_length=ct_length,
        ):
            if (step, offset) in seen_pairs:
                continue
            if step_src == "clue_numeral" and off_src == "clue_numeral":
                src = "clue_numeral"
            elif (
                step_src == "clue_numeral"
                or off_src == "clue_numeral"
            ):
                src = "mixed"
            else:
                src = "default_set"
            if not _emit((step, offset, src)):
                return out
    return out


def _caesar_layer(shift: int) -> dict[str, Any]:
    """Build a canonical caesar layer dict (LESSON-009).

    The dispatcher translates ``kind='caesar'`` with a single
    ``shift`` parameter into a Vigenere transform with key=[shift]
    so the kernel arithmetic is exactly C = (P + shift) mod 26.
    Using a first-class kind (rather than collapsing into a 1-letter
    Vigenere) keeps coverage_vector + attempt layers explicit.

    The shift must be in [0, 25]. Shift 0 is identity and most
    callers exclude it; it is permitted at the layer-builder level so
    tests can verify the boundary behaviour.
    """
    if not isinstance(shift, int) or not 0 <= shift <= 25:
        raise ValueError(
            f"_caesar_layer: shift must be int in [0, 25]; got {shift!r}"
        )
    return {
        "kind": "caesar",
        "alphabet": "AZ",
        "params": [{"name": "shift", "values": [shift]}],
    }


def _detect_caesar_trigger(clue_text: str) -> bool:
    """Whole-word match for any LESSON-009 Caesar / ROT trigger token.

    Used by ``generate_layered_specs`` to gate emission of the
    caesar family matrix. A clue text without any of these tokens
    leaves the historical catalogue bit-identical.

    Special case for the "rot" token: the standard naming convention
    for ROT-N ciphers is "rotN" (rot13, rot8, etc.). A strict
    word-boundary check would reject those because the digits are
    alphanumeric. The detector therefore accepts "rot" followed by
    one or more decimal digits as a valid match. This is the only
    digit-tolerant trigger; every other token uses the standard
    alphanumeric word-boundary rule.
    """
    if not isinstance(clue_text, str) or not clue_text:
        return False
    lower = clue_text.lower()
    for token in _CAESAR_TRIGGER_TOKENS:
        idx = 0
        while True:
            pos = lower.find(token, idx)
            if pos < 0:
                break
            before_ok = pos == 0 or not lower[pos - 1].isalnum()
            after_pos = pos + len(token)
            if after_pos >= len(lower):
                after_ok = True
            else:
                next_ch = lower[after_pos]
                if not next_ch.isalnum():
                    after_ok = True
                elif token == "rot" and next_ch.isdigit():
                    # ROT13 naming convention. Accept "rot" followed
                    # by digits then a non-alphanumeric (or EOL) so
                    # "rot13", "rot-3", "rot8" all trigger.
                    j = after_pos
                    while j < len(lower) and lower[j].isdigit():
                        j += 1
                    after_ok = j >= len(lower) or not lower[j].isalpha()
                else:
                    after_ok = False
            if before_ok and after_ok:
                return True
            idx = pos + 1
    return False


def _caesar_shifts_for_payload(clue_text: str) -> list[tuple[int, str]]:
    """Return the (shift, operation_source) list for the payload.

    LESSON-012 ordering:
      ``phrase_bound_shift_value`` — anchor-bound numerals from
                          ``extract_phrase_bound_numerics``
                          ("shift eight" → 8, "rotated three" → 3,
                          "shift by five" → 5). Never starved.
      ``clue_numeral``     — legacy flat extraction for digit
                          literals + spelled numerals 1..25 not
                          already phrase-bound to a different
                          parameter (rail_depth / step / offset /
                          block_size). Cross-contamination filter
                          prevents "four rails" from polluting the
                          Caesar shift list with shift=4.
      ``default_set``      — ``_DEFAULT_CAESAR_SHIFTS`` final fallback.

    Caller is expected to filter shift 0 when it would render a
    layer identity.
    """
    out: list[tuple[int, str]] = []
    seen: set[int] = set()
    bound = extract_phrase_bound_numerics(clue_text)
    # 1. Phrase-bound shifts first (priority)
    for n in bound["shift_value"]:
        if 1 <= n <= 25 and n not in seen:
            seen.add(n)
            out.append((n, "phrase_bound_shift_value"))
    # Build a set of numerals that are bound to OTHER parameters
    # so the legacy flat extraction doesn't promote them as
    # Caesar shifts. This prevents "four rails" from contributing
    # shift=4 when no anchor said "shift four".
    other_param_bound: set[int] = set()
    for k in ("step", "offset", "rail_depth", "block_size"):
        for v in bound[k]:
            other_param_bound.add(v)
    # 2. Legacy flat fallback (filtered by cross-contamination)
    for n in _depths_from_clue_text(clue_text):
        if 1 <= n <= 25 and n not in seen and n not in other_param_bound:
            seen.add(n)
            out.append((n, "clue_numeral"))
    # Also pick up digit "0" and "1" that _depths_from_clue_text
    # filters out (band starts at 2). Same cross-contamination
    # filter applies.
    import re
    if isinstance(clue_text, str) and clue_text:
        for m in re.finditer(r"(?<!\w)([01])(?!\w)", clue_text):
            try:
                n = int(m.group(1))
            except ValueError:
                continue
            if n not in seen and n not in other_param_bound:
                seen.add(n)
                out.append((n, "clue_numeral"))
    for d in _DEFAULT_CAESAR_SHIFTS:
        if d in seen:
            continue
        seen.add(d)
        out.append((d, "default_set"))
    return out


# ============================================================================
# LESSON-018: numeric clue → Caesar/ROT trigger semantics
# ============================================================================
#
# Pre-LESSON-018 the Caesar family generator was gated by
# ``_detect_caesar_trigger`` matching one of the explicit trigger
# words: shift / shifted / offset / rotate / rotated / rotation /
# step / caesar / rot / additive / subtractive. Clues with a salient
# but bare numeric (e.g. "small tag says seventeen", "marker 17",
# "label 8") would extract the numeral but never emit Caesar
# specs, because no trigger word fired.
#
# LESSON-018 adds a NUMERIC role classifier. For each numeric token
# in the clue, the classifier assigns a role from a fixed taxonomy
# based on surrounding context. Free / tag / explicit-Caesar
# numerals are ELIGIBLE FOR PROMOTION as Caesar shift candidates
# even without an explicit Caesar trigger word. Structurally bound
# numerals (route width, grid dimension, rail depth, block size,
# skip step, object count) are NOT promoted — they retain their
# original role.
#
# This is a benchmark-curriculum capability that does NOT change
# normal real-K4 mode (HCC remains bench-only via
# _collect_hcc_seeds).

# Tokens that, when appearing immediately BEFORE a numeral within
# a small lookback window, mark the numeral as a free numeric tag /
# label / inscription value. These are most strongly suggestive of
# a Caesar/ROT shift value when the rest of the clue is silent
# about the numeral's structural role.
_NUMERIC_TAG_PRECURSOR_TOKENS: frozenset[str] = frozenset({
    "tag", "tagged",
    "marked", "marking", "marker",
    "label", "labeled", "labelled",
    "inscription", "inscribed",
    "number", "numbered", "numeric",
    "code", "coded",
    "value", "valued",
    "says", "said",
    "reads", "read",
    "shows", "showed",
    "stamped",
    "etched",
    "engraved",
    "carved",
    "noted",
    "displays", "displayed",
    "indicates", "indicated",
})

# Tokens that, when appearing immediately BEFORE a numeral, mark
# the numeral as belonging to an explicit Caesar/ROT operation
# (this overlaps with _CAESAR_TRIGGER_TOKENS and reuses the same
# vocabulary for clarity).
_EXPLICIT_CAESAR_PRECURSOR_TOKENS: frozenset[str] = frozenset({
    "shift", "shifted", "shifts",
    "rotate", "rotated", "rotation",
    "caesar",
    "rot",
    "additive", "subtractive",
})

# Tokens that, when appearing immediately AFTER a numeral, bind
# the numeral to a structural role (NOT eligible for Caesar
# promotion).
_STRUCTURAL_ROLE_AFTER_TOKENS: dict[str, str] = {
    # route width / grid dimension
    "wide": "route_width",
    "column": "route_width", "columns": "route_width",
    "col": "route_width", "cols": "route_width",
    "row": "route_width", "rows": "route_width",
    "line": "route_width", "lines": "route_width",
    "grid": "grid_dimension",
    "deep": "rail_depth",
    "depth": "rail_depth",
    "rail": "rail_depth", "rails": "rail_depth",
    "fence": "rail_depth",
}

# Tokens that, when appearing immediately BEFORE a numeral, bind
# the numeral to a structural role (NOT eligible for Caesar
# promotion). Distinct from _EXPLICIT_CAESAR_PRECURSOR_TOKENS
# (which IS eligible).
_STRUCTURAL_ROLE_BEFORE_TOKENS: dict[str, str] = {
    "step": "skip_step", "stepped": "skip_step", "stride": "skip_step",
    "skip": "skip_step", "skipped": "skip_step",
    "every": "skip_step",
    "offset": "skip_step",
    "depth": "rail_depth",
    "block": "block_size", "blocks": "block_size",
    "groups": "block_size", "group": "block_size",
    "width": "route_width",
}

# Plural object-count nouns that, when appearing immediately AFTER
# a numeral, mark it as an object count (NOT eligible for Caesar
# promotion). This is a defense against false-positive promotion
# from cardinal-numeral + plural-noun phrases like "five stones".
# We deliberately keep this list focused on physical-object plurals
# that show up in K4Bench-style clue prose; structural plurals
# (rows, columns, rails) are already in
# _STRUCTURAL_ROLE_AFTER_TOKENS.
_OBJECT_COUNT_AFTER_TOKENS: frozenset[str] = frozenset({
    "stones", "stone",
    "marbles", "marble",
    "letters", "letter",
    "characters", "character",
    "words", "word",
    "items", "item",
    "panels", "panel",
    "pieces", "piece",
    "tiles", "tile",
    "bricks", "brick",
    "posts", "post",
    "tags",   # "five tags" → object count, but "tag 5" → free tag
              # (handled by precedence: tag-precursor checks BEFORE
              # the numeral, object-count checks AFTER)
    "labels",
    "objects", "object",
    "things", "thing",
    "people", "person", "persons",
    "guards", "guard",
    "lanterns", "lantern",
    "candles", "candle",
    "doors", "door",
    "gates", "gate",
    "windows", "window",
    "tomb", "tombs",
    "arrows", "arrow",
    "diagonals",  # "five diagonals" — object count of diagonal
                  # stripes, NOT a Caesar shift
})


def _classify_numeric_roles(
    clue_text: str,
) -> list[dict[str, Any]]:
    """Walk the clue text and classify every numeric token by role.

    Returns a list of dicts, one per numeric token in document
    order. Each dict carries:

      ``value``        — int (or None if the value falls outside
                          the in-range band [1, 25] used for
                          Caesar promotion)
      ``token``        — the original token string ("seventeen", "17")
      ``role``         — classification from the LESSON-018
                          taxonomy (route_width, grid_dimension,
                          rail_depth, block_size, skip_step,
                          object_count, explicit_caesar,
                          free_numeric_tag, ambiguous_numeric,
                          ignored_out_of_range)
      ``position``     — 0-indexed token index within the
                          tokenized clue
      ``raw_value``    — int parsed from the token (may be outside
                          [1, 25]; ``value`` is None in that case)

    Classification rules (first match wins; precedence shown):
      1. Out-of-range (value <= 0 or value > 25): "ignored_out_of_range"
      2. Preceded by an explicit Caesar precursor token (within 1-2
         tokens): "explicit_caesar"
      3. Preceded by a tag/label/inscription/says precursor (within
         1-3 tokens): "free_numeric_tag"
      4. Preceded by a structural-role-before token (within 1-2
         tokens): the corresponding structural role (route_width,
         skip_step, block_size, rail_depth, ...)
      5. Followed by a structural-role-after token (within 1-2
         tokens): the corresponding structural role
      6. Followed by an object-count plural noun (within 1-2
         tokens): "object_count"
      7. Hyphen-suffix patterns ("ten-wide", "8-row"): treated as
         AFTER-anchor of the suffix token.
      8. Otherwise: "ambiguous_numeric"
    """
    if not isinstance(clue_text, str) or not clue_text:
        return []
    import re
    lower = clue_text.lower()
    tokens: list[tuple[str, int, int]] = []
    for m in re.finditer(r"[A-Za-z]+|\d+", lower):
        tokens.append((m.group(0), m.start(), m.end()))

    def _numeric_of(tok: str) -> Optional[int]:
        if tok.isdigit():
            try:
                return int(tok)
            except ValueError:
                return None
        return _NUMBER_WORDS.get(tok)

    out: list[dict[str, Any]] = []
    for i, (tok, start, end) in enumerate(tokens):
        v = _numeric_of(tok)
        if v is None:
            continue
        role: Optional[str] = None
        if v < 1 or v > 25:
            role = "ignored_out_of_range"
        # Hyphen-suffix: numeral followed by '-' then a structural
        # token (e.g. "ten-wide"). Recognised as AFTER-anchor.
        hyphen_role: Optional[str] = None
        if role is None and i + 1 < len(tokens):
            next_tok, next_start, _ = tokens[i + 1]
            if lower[end:next_start] == "-":
                if next_tok in _STRUCTURAL_ROLE_AFTER_TOKENS:
                    hyphen_role = _STRUCTURAL_ROLE_AFTER_TOKENS[next_tok]
                elif next_tok in _OBJECT_COUNT_AFTER_TOKENS:
                    hyphen_role = "object_count"
        # Lookback for explicit Caesar (highest priority among
        # precursors).
        if role is None:
            for j in (1, 2):
                if i - j < 0:
                    break
                prev = tokens[i - j][0]
                if prev in _EXPLICIT_CAESAR_PRECURSOR_TOKENS:
                    role = "explicit_caesar"
                    break
        # Hyphen-suffix structural binding (e.g. "eight-column",
        # "ten-wide", "five-stones") wins over the more permissive
        # tag-precursor lookback because the hyphen makes the
        # binding immediate and unambiguous, whereas
        # ``_NUMERIC_TAG_PRECURSOR_TOKENS`` is searched up to 3
        # tokens back (so e.g. "shows ... eight-column" would
        # otherwise mis-classify as free_numeric_tag).
        if role is None and hyphen_role is not None:
            role = hyphen_role
        # Lookback for tag/label precursor.
        if role is None:
            for j in (1, 2, 3):
                if i - j < 0:
                    break
                prev = tokens[i - j][0]
                if prev in _NUMERIC_TAG_PRECURSOR_TOKENS:
                    role = "free_numeric_tag"
                    break
        # Lookback for structural-before tokens.
        if role is None:
            for j in (1, 2):
                if i - j < 0:
                    break
                prev = tokens[i - j][0]
                if prev in _STRUCTURAL_ROLE_BEFORE_TOKENS:
                    role = _STRUCTURAL_ROLE_BEFORE_TOKENS[prev]
                    break
        if role is None:
            for j in (1, 2):
                if i + j >= len(tokens):
                    break
                nxt = tokens[i + j][0]
                if nxt in _STRUCTURAL_ROLE_AFTER_TOKENS:
                    role = _STRUCTURAL_ROLE_AFTER_TOKENS[nxt]
                    break
                if nxt in _OBJECT_COUNT_AFTER_TOKENS:
                    role = "object_count"
                    break
        if role is None:
            role = "ambiguous_numeric"
        out.append({
            "value": v if 1 <= v <= 25 else None,
            "token": tok,
            "role": role,
            "position": i,
            "raw_value": v,
        })
    return out


# Roles that are eligible for Caesar promotion.
_NUMERIC_CAESAR_ELIGIBLE_ROLES: frozenset[str] = frozenset({
    "explicit_caesar",
    "free_numeric_tag",
    "ambiguous_numeric",
})


def _detect_numeric_caesar_promotion(
    clue_text: str,
) -> list[dict[str, Any]]:
    """Return the list of clue numerals eligible for Caesar/ROT
    promotion (LESSON-018).

    Each entry carries:
      ``value``        — int in [1, 25] (the candidate Caesar shift)
      ``token``        — original token string
      ``role``         — LESSON-018 role classifier result
      ``shift_source`` — "explicit_caesar_token" |
                          "clue_numeric_tag" |
                          "clue_numeric_free"

    De-duplicates by value (first occurrence wins) so a clue with
    repeated numerals doesn't produce duplicate Caesar specs.

    Filters: a numeral is eligible iff
      (1) its role is in ``_NUMERIC_CAESAR_ELIGIBLE_ROLES``, AND
      (2) NO OTHER occurrence of the same value in the clue has a
          stronger structural binding (route_width, grid_dimension,
          rail_depth, block_size, skip_step, object_count). This
          conservative filter prevents promotion of "five" in
          "five stones" even if "five" later appears as a free
          numeric in the same clue (which would be unusual but
          possible).
    """
    classifications = _classify_numeric_roles(clue_text)
    # Build map: value → set(roles seen in clue)
    roles_by_value: dict[int, set[str]] = {}
    for c in classifications:
        v = c["value"]
        if v is None:
            continue
        roles_by_value.setdefault(v, set()).add(c["role"])

    structural_roles: frozenset[str] = frozenset({
        "route_width", "grid_dimension", "rail_depth",
        "block_size", "skip_step", "object_count",
    })

    seen_values: set[int] = set()
    out: list[dict[str, Any]] = []
    for c in classifications:
        v = c["value"]
        if v is None:
            continue
        if v in seen_values:
            continue
        if c["role"] not in _NUMERIC_CAESAR_ELIGIBLE_ROLES:
            continue
        # Conservative filter: if this VALUE has any structural
        # binding elsewhere in the clue, don't promote it. The
        # exception is "explicit_caesar" — when an explicit Caesar
        # word names this value, structural appearances elsewhere
        # do not block the explicit binding.
        if c["role"] != "explicit_caesar":
            other_roles = roles_by_value.get(v, set())
            if other_roles & structural_roles:
                continue
        seen_values.add(v)
        if c["role"] == "explicit_caesar":
            shift_source = "explicit_caesar_token"
        elif c["role"] == "free_numeric_tag":
            shift_source = "clue_numeric_tag"
        else:  # ambiguous_numeric
            shift_source = "clue_numeric_free"
        out.append({
            "value": v,
            "token": c["token"],
            "role": c["role"],
            "shift_source": shift_source,
        })
    return out


def _expand_caesar_shifts_with_complement(
    promoted: Sequence[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Each promoted shift n produces both directions:

      as_given  — shift_value = n
      complement — shift_value = (26 - n) % 26  (skipped when self-
                  complement, i.e. n == 13 ⇒ same value)

    Caesar dispatch uses ``C = (P + shift) mod 26``. Without
    knowing whether the clue numeral describes the encrypt shift
    (P → C) or the decrypt shift (C → P), we emit both and let
    crib scoring decide. The 26 - n value is the corresponding
    inverse direction.
    """
    out: list[dict[str, Any]] = []
    for entry in promoted:
        v = int(entry["value"])
        out.append({
            **entry,
            "shift_value": v,
            "shift_direction": "as_given",
        })
        comp = (26 - v) % 26
        if comp == 0 or comp == v:
            # 0 is identity (skip); v == 13 self-complements (skip
            # to avoid duplicate).
            continue
        out.append({
            **entry,
            "shift_value": comp,
            "shift_direction": "complement",
        })
    return out


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
# multiprocessing startup (~1s/spec) — ~14 min/cycle at the worst
# case. Operators can lower the ceiling via --hcc-seeds N when they
# want a faster cycle.
#
# 2026-04-28 (LESSON-013): bumped from 5000 to 10000 to accommodate
# the enumerated columnar families:
#   * columnar_<sub> pair (~900 specs)
#   * i3_columnar_<sub> pair (~900 specs)
#   * caesar_columnar_atbash (~300 specs)
#   * columnar_<sub>_rail_fence 3-layer (~2100 specs — needed to
#     reach K4B-006's empirical 24/24 path)
# Total LESSON-013 contribution: ~4200 specs per triggered cycle.
# Combined with the legacy keyword path + LESSON-008/-009/-011
# trigger-driven families the catalogue stays under 10000. Per
# Colin's runtime policy (memory: feedback_do_not_cap_runtime.md),
# compute is not the constraint.
_DEFAULT_MAX_SPECS: int = 10000


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
    # 2026-04-28 (LESSON-008): block-reversal coverage fields. Empty
    # when the spec does not include a reverse_blocks layer; populated
    # otherwise so coverage analysis can answer "have we tested
    # block_size=5 with mode=reverse_partial in this family?".
    block_size: Optional[int] = None
    block_mode: str = ""              # "reverse_partial" | "truncate" | ""
    operation_source: str = ""        # "clue_numeral" | "clue_phrase" | "default_set" | ""
    # 2026-04-28 (LESSON-009): Caesar / ROT coverage fields. Empty
    # when the spec does not include a caesar layer; populated
    # otherwise so coverage analysis can answer "have we tested
    # shift=8 in this family?". ``operation_source`` (above) is
    # shared between LESSON-008 and LESSON-009 — it always describes
    # the provenance of whichever non-keyword numeric parameter
    # drives the spec (block_size for reverse_blocks, shift_value
    # for caesar). When a spec uses BOTH layers (e.g. caesar +
    # reverse_blocks), the operation_source reports the Caesar
    # shift's provenance and the block_size's provenance is encoded
    # in the spec extras.
    shift_value: Optional[int] = None
    # 2026-04-28 (LESSON-010): explicit role telemetry. The
    # ``role_assignment`` tuple is preserved as the canonical
    # symmetry-class key, but specs that involve a substitution +
    # transposition pipeline now also surface the per-role keywords
    # as named fields so a downstream attempt-artifact reader can
    # answer "did we test substitution key X with alphabet key Y
    # and transposition key Z?" without parsing the role_assignment
    # tuple.
    #
    #   substitution_keyword     — the keyword passed to the
    #                              substitution layer (vig/beau/var_beau)
    #   alphabet_keyword         — the alphabet_keyword resolved by
    #                              the alphabet_mode (clue word for
    #                              keyword_mixed; "" for AZ/KA;
    #                              reversed_az/ka constants for the
    #                              mirror modes)
    #   transposition_keyword    — the keyword passed to the
    #                              transposition layer (columnar /
    #                              myszkowski). "" for keywordless
    #                              transpositions (rail_fence / route)
    #                              and for caesar / atbash families.
    #   role_assignment_mode     — "pairwise" (legacy 2-role family
    #                              generator) or
    #                              "independent_three_role"
    #                              (LESSON-010 generator that
    #                              enumerates the full sub × alpha ×
    #                              trans triple). Other values: ""
    #                              (legacy / single-layer specs).
    #
    # Legacy specs leave all four fields at their safe empty defaults
    # so the historical catalog and gap analysis continue to work.
    substitution_keyword: str = ""
    alphabet_keyword: str = ""
    transposition_keyword: str = ""
    role_assignment_mode: str = ""
    # 2026-04-28 (LESSON-011): skip / step / stride modular route
    # telemetry. Empty when the spec does not include a skip_route
    # layer; populated otherwise so coverage analysis can answer
    # "have we tested skip_route(step=5, offset=3) in this family?".
    #
    #   route_mode  — "skip_route" when this spec uses the
    #                 LESSON-011 modular-walk transposition; ""
    #                 for legacy / non-skip-route specs.
    #   step        — int parameter passed to the skip_route layer.
    #                 None for non-skip-route specs.
    #   offset      — int parameter passed to the skip_route layer.
    #                 None for non-skip-route specs.
    #
    # ``operation_source`` (above) is shared with LESSON-008 /
    # LESSON-009: it always describes the provenance of whichever
    # numeric parameter drove the spec (block_size for
    # reverse_blocks, shift_value for caesar, the (step, offset)
    # pair for skip_route — when both come from the clue text the
    # source is "clue_numeral", otherwise "default_set" or "mixed"
    # if step is clue-derived but offset is default).
    route_mode: str = ""
    step: Optional[int] = None
    offset: Optional[int] = None
    # 2026-04-28 (LESSON-013): explicit columnar-permutation
    # telemetry. Empty when the spec does not include a columnar
    # layer; populated otherwise so coverage analysis can answer
    # "have we tested width=5 col_order=(4,1,3,0,2) in this
    # family?". The legacy ``role_assignment`` tuple still carries
    # ("columnar", keyword) when col_order is keyword-derived;
    # for enumerated permutations the role_assignment carries
    # ("columnar", f"width{W}_perm{idx}") so the symmetry-class
    # key remains unique. Legacy specs (no columnar layer) leave
    # all four fields at safe empty defaults.
    transposition_width: Optional[int] = None
    col_order: tuple[int, ...] = ()
    col_order_source: str = ""
    col_order_index: Optional[int] = None
    width_source: str = ""
    # 2026-04-28 (LESSON-014): width-only ragged boustrophedon
    # route telemetry. Empty when the spec does not include a
    # route_boustrophedon layer; populated otherwise so coverage
    # analysis can answer "did we test vigenere(ARCHIVE) followed
    # by ragged boustrophedon width 8 with vertical=True?".
    #
    #   route_mode (existing)  — set to "route_boustrophedon" or
    #                            "boustrophedon_width" when this spec
    #                            uses the LESSON-014 layer; "" for
    #                            non-LESSON-014 specs and "skip_route"
    #                            for LESSON-011 specs.
    #   route_width            — int width of the boustrophedon grid.
    #                            Implies rows = ceil(CT_LEN / width).
    #                            None for non-LESSON-014 specs.
    #   route_rows             — implied row count = ceil(CT_LEN /
    #                            route_width). None for non-LESSON-014
    #                            specs. Stored explicitly so attempt-
    #                            artifact readers do not have to
    #                            recompute.
    #   route_cols             — equals route_width. Stored explicitly
    #                            so the (rows, cols) telemetry pair is
    #                            symmetric with the existing ``route``
    #                            kind.
    #   route_ragged           — True when CT_LEN is not a multiple of
    #                            route_width (the standard case for
    #                            CT_LEN=97). False only when width
    #                            divides CT_LEN exactly. None for non-
    #                            LESSON-014 specs.
    #   route_direction        — "horizontal" (vertical=False) or
    #                            "vertical" (vertical=True). Mirrors
    #                            the dispatcher's ``vertical`` flag.
    #                            "" for non-LESSON-014 specs.
    #   route_width_source     — "phrase_bound_route_width",
    #                            "clue_keyword_length", "default_set"
    #                            — provenance of the width used.
    #                            Empty for non-LESSON-014 specs.
    #
    # The legacy ``width_source`` field describes columnar widths
    # (LESSON-013); ``route_width_source`` is a separate field so
    # three-layer specs that combine columnar AND route_boustrophedon
    # can carry both provenance values without ambiguity.
    route_width: Optional[int] = None
    route_rows: Optional[int] = None
    route_cols: Optional[int] = None
    route_ragged: Optional[bool] = None
    route_direction: str = ""
    route_width_source: str = ""
    # 2026-04-28 (LESSON-015): folded-strip / alternate-row reversal
    # telemetry. Empty when the spec does not include a row_reverse
    # layer; populated otherwise so coverage analysis can answer
    # "did we test vig(SHADOW) followed by row_reverse(width=10,
    # parity=odd)?".
    #
    #   row_reverse_width      — int width of each row
    #   row_reverse_parity     — "odd" / "even" / "both"
    #   row_reverse_source     — "phrase_bound_row_reverse_width" /
    #                            "clue_keyword_length" /
    #                            "default_set"
    #   row_reverse_ragged     — True when CT_LEN % width != 0;
    #                            False for exact divisors
    #   row_reverse_start_row  — 0 or 1 (parity offset)
    #
    # Self-inverse contract: applying the same (width, parity,
    # start_row) twice returns the identity. The dispatcher's
    # row_reverse translator asserts this invariant and refuses to
    # dispatch on violation.
    row_reverse_width: Optional[int] = None
    row_reverse_parity: str = ""
    row_reverse_source: str = ""
    row_reverse_ragged: Optional[bool] = None
    row_reverse_start_row: Optional[int] = None
    # 2026-04-29 (LESSON-016): diagonal grid-route telemetry. Empty
    # when the spec does not include a route(variant='diagonal')
    # layer; populated otherwise so downstream coverage analysis can
    # answer "did we test main-axis forward top_then_left at width
    # 10?". Reused fields:
    #   route_mode  — set to "route_diagonal"
    #   route_rows / route_cols / route_width / route_ragged —
    #                 populated as for other route variants
    # New fields:
    #   diagonal_axis        — "main" | "anti"
    #   diagonal_order       — "forward" | "reverse"
    #   diagonal_start_edge  — axis-constrained: top_then_left /
    #                          left_then_top / top_then_right /
    #                          right_then_top
    diagonal_axis: str = ""
    diagonal_order: str = ""
    diagonal_start_edge: str = ""
    # 2026-04-28 (LESSON-015 audit-hygiene): explicit identity flag.
    # ``row_reverse_identity=True`` means the (width, parity, start_row)
    # triple selects no row of length > 1, so the layer is the
    # identity permutation. This happens when the no-fold sentinel
    # ``width=CT_LEN + parity=odd + start_row=0`` is enumerated AND
    # for any other (width, parity, start_row) where every row whose
    # parity matches happens to be a single character.
    #
    # Why this matters: identity layers provide ZERO cipher work but
    # are still useful catalog points (they let substitution+row_reverse
    # cover substitution-alone-equivalent specs). Downstream analysis
    # — coverage rollups, bench postmortems, success-attribution
    # tooling — MUST distinguish "fold-style row reversal was in the
    # winning method" from "an identity wrapper happened to ride the
    # winning substitution." Without this flag a no-fold sentinel
    # win would be miscredited as evidence that folded-row reversal
    # is the missing capability.
    #
    # ``row_reverse_identity=False`` means the layer actually reverses
    # at least one multi-character row (the substantive case).
    # ``None`` is the default for specs that do not include a
    # row_reverse layer.
    row_reverse_identity: Optional[bool] = None
    # 2026-04-29 (LESSON-017): stratified bench-fast scheduling
    # telemetry. Set by the two-pass scheduler in
    # ``generate_layered_specs`` so attempt artifacts can answer
    # "was this spec retained because of its family quota guarantee
    # or because residual cap was still available?". Empty when
    # the spec did not pass through the LESSON-017 scheduler (e.g.
    # a future caller invoking _make_spec directly without going
    # through generate_layered_specs).
    #
    #   scheduling_pass    — "quota" | "residual" | ""
    #   family_quota       — the per-family minimum-exposure quota
    #                        in effect when this spec was scheduled
    #   family_quota_rank  — 1-indexed rank within the family among
    #                        quota-retained specs; 0 for residual
    #                        specs and for non-scheduled specs
    #   hcc_max_specs      — the max_specs cap that was applied
    #
    # Downstream attribution: a winning spec with
    # ``scheduling_pass="quota"`` indicates the family would have
    # been TRUNCATED under pre-LESSON-017 front-loaded scheduling;
    # ``scheduling_pass="residual"`` indicates the family was
    # already in the front of the catalog and would have survived
    # any reasonable cap.
    scheduling_pass: str = ""
    family_quota: Optional[int] = None
    family_quota_rank: Optional[int] = None
    hcc_max_specs: Optional[int] = None
    # 2026-04-29 (LESSON-018): numeric Caesar promotion telemetry.
    # Populated when a Caesar layer's shift_value came from a clue
    # numeral classified as eligible for promotion (free_numeric_tag,
    # ambiguous_numeric, or explicit_caesar). Empty when shift_value
    # came from the legacy default-shift set or when no Caesar layer
    # is present.
    #
    #   shift_source        — "clue_numeric_free" |
    #                          "clue_numeric_tag" |
    #                          "explicit_caesar_token" |
    #                          "default_set" | ""
    #   shift_token         — original token string ("seventeen", "17")
    #   shift_role          — classifier result for the source token
    #                          (free_numeric_tag, ambiguous_numeric,
    #                          explicit_caesar, etc.)
    #   shift_direction     — "as_given" | "complement" | ""
    #   numeric_trigger_without_caesar_word
    #                       — True when the Caesar layer was emitted
    #                          via numeric promotion (no explicit
    #                          shift/rotate/caesar/rot trigger word
    #                          in the clue); False when emitted via
    #                          the legacy explicit-trigger path; None
    #                          when no Caesar layer is present.
    shift_source: str = ""
    shift_token: str = ""
    shift_role: str = ""
    shift_direction: str = ""
    numeric_trigger_without_caesar_word: Optional[bool] = None

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
            "block_size": self.block_size,
            "block_mode": self.block_mode,
            "operation_source": self.operation_source,
            "shift_value": self.shift_value,
            "substitution_keyword": self.substitution_keyword,
            "alphabet_keyword": self.alphabet_keyword,
            "transposition_keyword": self.transposition_keyword,
            "role_assignment_mode": self.role_assignment_mode,
            "route_mode": self.route_mode,
            "step": self.step,
            "offset": self.offset,
            "transposition_width": self.transposition_width,
            "col_order": list(self.col_order),
            "col_order_source": self.col_order_source,
            "col_order_index": self.col_order_index,
            "width_source": self.width_source,
            # LESSON-014 fields. Always emitted (even when None /
            # empty) so attempt artifact readers can tell the
            # difference between "field absent in old data" and
            # "field present but inapplicable here".
            "route_width": self.route_width,
            "route_rows": self.route_rows,
            "route_cols": self.route_cols,
            "route_ragged": self.route_ragged,
            "route_direction": self.route_direction,
            "route_width_source": self.route_width_source,
            # LESSON-015 fields. Always emitted so attempt artifact
            # readers can tell "field absent in old data" from
            # "field present but inapplicable here".
            "row_reverse_width": self.row_reverse_width,
            "row_reverse_parity": self.row_reverse_parity,
            "row_reverse_source": self.row_reverse_source,
            "row_reverse_ragged": self.row_reverse_ragged,
            "row_reverse_start_row": self.row_reverse_start_row,
            "row_reverse_identity": self.row_reverse_identity,
            # LESSON-016 fields. Always emitted so attempt artifact
            # readers can tell "field absent in old data" from "field
            # present but inapplicable here".
            "diagonal_axis": self.diagonal_axis,
            "diagonal_order": self.diagonal_order,
            "diagonal_start_edge": self.diagonal_start_edge,
            # LESSON-017 scheduler telemetry. Always emitted.
            "scheduling_pass": self.scheduling_pass,
            "family_quota": self.family_quota,
            "family_quota_rank": self.family_quota_rank,
            "hcc_max_specs": self.hcc_max_specs,
            # LESSON-018 numeric-Caesar-promotion telemetry.
            "shift_source": self.shift_source,
            "shift_token": self.shift_token,
            "shift_role": self.shift_role,
            "shift_direction": self.shift_direction,
            "numeric_trigger_without_caesar_word": (
                self.numeric_trigger_without_caesar_word
            ),
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
        bs_raw = d.get("block_size")
        block_size = int(bs_raw) if isinstance(bs_raw, int) else None
        sh_raw = d.get("shift_value")
        shift_value = int(sh_raw) if isinstance(sh_raw, int) else None
        return cls(
            layer_family=str(d.get("layer_family", "")),
            layer_order=tuple(layer_order),
            role_assignment=role_tuple,
            alphabet=legacy_alphabet,
            n_layers=int(d.get("n_layers", len(layer_order))),
            extras=extras_tuple,
            alphabet_mode=str(d.get("alphabet_mode", legacy_alphabet)),
            alphabet_source=str(d.get("alphabet_source", "default")),
            block_size=block_size,
            block_mode=str(d.get("block_mode", "")),
            operation_source=str(d.get("operation_source", "")),
            shift_value=shift_value,
            substitution_keyword=str(d.get("substitution_keyword", "")),
            alphabet_keyword=str(d.get("alphabet_keyword", "")),
            transposition_keyword=str(d.get("transposition_keyword", "")),
            role_assignment_mode=str(d.get("role_assignment_mode", "")),
            route_mode=str(d.get("route_mode", "")),
            step=int(d["step"]) if isinstance(d.get("step"), int) else None,
            offset=(
                int(d["offset"]) if isinstance(d.get("offset"), int)
                else None
            ),
            transposition_width=(
                int(d["transposition_width"])
                if isinstance(d.get("transposition_width"), int)
                else None
            ),
            col_order=tuple(d.get("col_order") or ()),
            col_order_source=str(d.get("col_order_source", "")),
            col_order_index=(
                int(d["col_order_index"])
                if isinstance(d.get("col_order_index"), int)
                else None
            ),
            width_source=str(d.get("width_source", "")),
            # LESSON-014 fields. Lenient parsing so older ledger rows
            # that predate LESSON-014 read back as None / empty
            # without raising — those rows correctly describe specs
            # that did not include a route_boustrophedon layer.
            route_width=(
                int(d["route_width"])
                if isinstance(d.get("route_width"), int)
                else None
            ),
            route_rows=(
                int(d["route_rows"])
                if isinstance(d.get("route_rows"), int)
                else None
            ),
            route_cols=(
                int(d["route_cols"])
                if isinstance(d.get("route_cols"), int)
                else None
            ),
            route_ragged=(
                bool(d["route_ragged"])
                if isinstance(d.get("route_ragged"), bool)
                else None
            ),
            route_direction=str(d.get("route_direction", "")),
            route_width_source=str(d.get("route_width_source", "")),
            # LESSON-015 fields. Lenient parsing: older ledger rows
            # that predate LESSON-015 read back as None / empty.
            row_reverse_width=(
                int(d["row_reverse_width"])
                if isinstance(d.get("row_reverse_width"), int)
                else None
            ),
            row_reverse_parity=str(d.get("row_reverse_parity", "")),
            row_reverse_source=str(d.get("row_reverse_source", "")),
            row_reverse_ragged=(
                bool(d["row_reverse_ragged"])
                if isinstance(d.get("row_reverse_ragged"), bool)
                else None
            ),
            row_reverse_start_row=(
                int(d["row_reverse_start_row"])
                if isinstance(d.get("row_reverse_start_row"), int)
                else None
            ),
            row_reverse_identity=(
                bool(d["row_reverse_identity"])
                if isinstance(d.get("row_reverse_identity"), bool)
                else None
            ),
            # LESSON-016 fields. Lenient parsing: older ledger rows
            # that predate LESSON-016 read back as empty strings.
            diagonal_axis=str(d.get("diagonal_axis", "")),
            diagonal_order=str(d.get("diagonal_order", "")),
            diagonal_start_edge=str(d.get("diagonal_start_edge", "")),
            # LESSON-017 scheduler telemetry. Lenient parsing for
            # pre-LESSON-017 ledger rows.
            scheduling_pass=str(d.get("scheduling_pass", "")),
            family_quota=(
                int(d["family_quota"])
                if isinstance(d.get("family_quota"), int)
                else None
            ),
            family_quota_rank=(
                int(d["family_quota_rank"])
                if isinstance(d.get("family_quota_rank"), int)
                else None
            ),
            hcc_max_specs=(
                int(d["hcc_max_specs"])
                if isinstance(d.get("hcc_max_specs"), int)
                else None
            ),
            # LESSON-018 fields. Lenient parsing: pre-LESSON-018
            # ledger rows read back as empty strings / None.
            shift_source=str(d.get("shift_source", "")),
            shift_token=str(d.get("shift_token", "")),
            shift_role=str(d.get("shift_role", "")),
            shift_direction=str(d.get("shift_direction", "")),
            numeric_trigger_without_caesar_word=(
                bool(d["numeric_trigger_without_caesar_word"])
                if isinstance(
                    d.get("numeric_trigger_without_caesar_word"), bool,
                )
                else None
            ),
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
    max_keyword_mixed: int = 3,
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

    2026-04-28 (LESSON-010): default ``max_keyword_mixed`` bumped
    from 2 to 3 so the alphabet/tableau keyword can be drawn
    independently from a third clue word — the K4B-005 case where
    substitution + alphabet + transposition map to three distinct
    clue keywords. The cap remains explicit so callers can lower
    it when they want a narrower mode set.
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
    # Cardinals
    "two": 2, "three": 3, "four": 4, "five": 5, "six": 6,
    "seven": 7, "eight": 8, "nine": 9, "ten": 10,
    "eleven": 11, "twelve": 12, "thirteen": 13, "fourteen": 14,
    "fifteen": 15, "sixteen": 16, "seventeen": 17,
    "eighteen": 18, "nineteen": 19, "twenty": 20,
    # Ordinals (LESSON-011 added 2026-04-28). Clue text often uses
    # ordinal forms — "fifth step", "third pass" — so the
    # extractor must lift those to the same numeric values as the
    # corresponding cardinals.
    "second": 2, "third": 3, "fourth": 4, "fifth": 5, "sixth": 6,
    "seventh": 7, "eighth": 8, "ninth": 9, "tenth": 10,
    "eleventh": 11, "twelfth": 12, "thirteenth": 13,
    "fourteenth": 14, "fifteenth": 15, "sixteenth": 16,
    "seventeenth": 17, "eighteenth": 18, "nineteenth": 19,
    "twentieth": 20,
}

# Rail-fence depths default set when no clue numerals apply. The
# generator unions clue-derived depths with these so a clue-free
# payload still produces a useful enumeration.
_DEFAULT_RAIL_FENCE_DEPTHS_BASE: tuple[int, ...] = (3, 5)


# ============================================================================
# LESSON-012: Phrase-attached numeric prominence
# ============================================================================
#
# Anchor token taxonomy. Keys are parameter slots; values are the
# trigger phrases that bind a numeral to that slot. Multi-word
# phrases ("blocks of", "shift by") are matched verbatim before
# the numeral; single-word anchors match either before or after
# the numeral within an N-token window.
#
# A drift test in test_lesson_phrase_numeric_prominence_capability.py
# asserts these runtime constants match LESSON-012's
# tactic_parameters.anchor_to_parameter mapping.
_PHRASE_ANCHORS_BEFORE: dict[str, tuple[str, ...]] = {
    # parameter -> anchor tokens that appear BEFORE the numeral.
    # The numeral can be a digit literal, cardinal, or ordinal.
    # Order within each tuple is irrelevant — we test set
    # membership against the immediately-preceding 1-3 tokens.
    "step": (
        "step", "stepped", "stride",
        # "every Nth" / "every fifth" — phrase pattern matched
        # via _PHRASE_ANCHORS_PHRASES below.
    ),
    "offset": (
        "offset",
    ),
    "rail_depth": (
        "depth",
        # "N rails" / "N-rail" matched via
        # _PHRASE_ANCHORS_AFTER below.
    ),
    "block_size": (
        "block", "blocks", "group", "groups", "chunk", "chunks",
        # "blocks of N" / "groups of N" matched via
        # _PHRASE_ANCHORS_PHRASES below.
    ),
    "shift_value": (
        "shift", "shifted", "rotated", "rotate",
        # "rot 13" matches here via the BEFORE-anchor; the
        # numeric-suffix pattern "rot13" (no space) is handled
        # by ``_detect_caesar_trigger`` separately.
        "rot",
    ),
}

# Anchor tokens that appear AFTER the numeral (e.g. "four rails").
# Searched within a 2-token window so "five tick groups" matches
# block_size=5 via the "groups" anchor at distance 2.
_PHRASE_ANCHORS_AFTER: dict[str, tuple[str, ...]] = {
    "rail_depth": (
        "rails", "rail", "railfence", "rail-fence",
    ),
    "step": (
        # Both singular and plural so "every fifth step" and
        # "three steps from the start" both bind to the step
        # parameter. Disambiguation against block_size's "every"
        # phrase is handled in the parser body.
        "step", "steps",
    ),
    "block_size": (
        # "five tick groups" / "five groups" / "five blocks"
        "blocks", "block", "groups", "group", "chunks", "chunk",
    ),
}

# Multi-word anchor phrases. Matched as exact substrings (after
# lowercase + whitespace normalization) immediately before the
# numeral. Longer phrases checked first so "every nth" matches
# before "every".
_PHRASE_ANCHORS_PHRASES: dict[str, tuple[str, ...]] = {
    "step": (
        "every nth", "every n",
    ),
    "offset": (
        "offset of",
    ),
    "block_size": (
        "blocks of", "block of", "groups of",
        # "every N" alone is handled here too — it is a hand-
        # cipher idiom for block_size when no other anchor names
        # the same numeral.
        "every",
    ),
    "shift_value": (
        "shift by",
    ),
}

# Operation-source labels for phrase-bound provenance. These appear
# in CoverageVector.operation_source so attempt-artifact readers can
# tell whether a parameter came from a clue phrase ("phrase_bound_*"),
# from the legacy flat numeric extraction ("clue_numeral"), or from
# a default fallback ("default_set").
_PHRASE_BOUND_SOURCES: dict[str, str] = {
    "step": "phrase_bound_step",
    "offset": "phrase_bound_offset",
    "rail_depth": "phrase_bound_rail_depth",
    "block_size": "phrase_bound_block_size",
    "shift_value": "phrase_bound_shift_value",
}


def extract_phrase_bound_numerics(
    clue_text: str,
    *,
    ct_length: int = 97,
) -> dict[str, list[int]]:
    """Parse phrase-attached numerals from clue text (LESSON-012).

    Returns a dict ``{parameter: [int, ...]}`` keyed by the
    parameter slots ``step``, ``offset``, ``rail_depth``,
    ``block_size``, ``shift_value``. Each value list is in
    document order of the bound numeral, deduplicated, never
    empty for a parameter that has at least one phrase-bound
    occurrence in the clue.

    Numerals supported:
      * digit literals 0..ct_length-1
      * cardinals: two..twenty (via _NUMBER_WORDS)
      * ordinals: second..twentieth (via _NUMBER_WORDS;
        LESSON-011 added ordinals)

    Anchor matching rules:
      * BEFORE-anchors: check the 1-3 tokens immediately
        preceding the numeral; if any matches a parameter's
        BEFORE list, bind the numeral to that parameter.
      * AFTER-anchors: check the 1-2 tokens immediately
        following the numeral; if any matches an AFTER list,
        bind.
      * PHRASE-anchors: check whether the (lowercased,
        whitespace-normalized) substring immediately before the
        numeral ends with any phrase in that parameter's PHRASE
        list.
      * Multi-binding: a numeral that matches anchors for
        multiple parameters appears in each list (e.g. "every
        fifth step" — the phrase "every" maps to block_size AND
        the trailing "step" word maps to step). The downstream
        consumer picks whichever it needs and discards the rest.

    A clue with no anchor phrases returns ``{}``-equivalent (every
    list empty); callers fall back to the legacy flat extractor
    plus default sets.
    """
    bindings: dict[str, list[int]] = {
        "step": [],
        "offset": [],
        "rail_depth": [],
        "block_size": [],
        "shift_value": [],
    }
    if not isinstance(clue_text, str) or not clue_text:
        return bindings

    import re
    lower = clue_text.lower()

    # Tokenize into (token, start, end) triples covering BOTH word
    # tokens (alphanumeric, possibly with internal hyphens) and
    # numerals. We keep positions so PHRASE-anchor matching can
    # check the substring immediately before the numeral.
    tokens: list[tuple[str, int, int]] = []
    for m in re.finditer(r"[A-Za-z]+|\d+", lower):
        tokens.append((m.group(0), m.start(), m.end()))

    # Helper: numeric value of a single token, if any.
    def _numeric_of(tok: str) -> Optional[int]:
        if tok.isdigit():
            try:
                v = int(tok)
            except ValueError:
                return None
            return v if 0 <= v < ct_length else None
        return _NUMBER_WORDS.get(tok)

    # Index every numeric token's position in `tokens` along with
    # its value.
    numerics: list[tuple[int, int]] = []  # (token_index, value)
    for i, (tok, _s, _e) in enumerate(tokens):
        v = _numeric_of(tok)
        if v is not None:
            numerics.append((i, v))

    def _add(param: str, value: int) -> None:
        # Skip degenerate values per parameter contract:
        if param in ("step", "rail_depth") and value < 2:
            return
        if param == "shift_value" and not 1 <= value <= 25:
            return
        if param == "block_size" and value < 2:
            return
        if param == "offset" and not 0 <= value < ct_length:
            return
        if value not in bindings[param]:
            bindings[param].append(value)

    # Pre-compute set of token indices that are themselves numerics
    # so the AFTER lookahead can avoid crossing over a different
    # numeral. Without this guard "blocks of seven four rails" would
    # bind seven=>rails because the 2-token lookahead reaches "rails"
    # past "four". The anchor for "rails" is "four", not "seven".
    numeric_idxs: set[int] = {i for i, _ in numerics}

    for tok_idx, value in numerics:
        # --- AFTER-anchor check (up to 2-token lookahead, blocked
        # by intervening numerics) ---
        # Computed FIRST because "fifth step" should win over the
        # BEFORE-phrase "every fifth" — the noun the numeral
        # modifies (the closest noun anchor following) wins.
        after_params: set[str] = set()
        for j in (1, 2):
            if tok_idx + j >= len(tokens):
                break
            # If the intervening token at tok_idx+j-1 (for j=2) is
            # itself a numeric, this numeric belongs to that
            # numeric's anchor scope, not ours. Stop the lookahead.
            if j == 2 and (tok_idx + 1) in numeric_idxs:
                break
            next_tok = tokens[tok_idx + j][0]
            for param, anchors in _PHRASE_ANCHORS_AFTER.items():
                if next_tok in anchors:
                    after_params.add(param)
            # Stop at the first matching token; deeper lookahead
            # only fires when the immediate next token is a
            # filler (e.g. "five tick groups" — j=2 reaches
            # "groups").
            if after_params:
                break
        for param in after_params:
            _add(param, value)

        # --- BEFORE-anchor check (1-token lookback) ---
        before_params: set[str] = set()
        if tok_idx >= 1:
            prev_tok = tokens[tok_idx - 1][0]
            for param, anchors in _PHRASE_ANCHORS_BEFORE.items():
                if prev_tok in anchors:
                    before_params.add(param)
        for param in before_params:
            _add(param, value)

        # --- PHRASE-anchor check (multi-word lookback) ---
        # Disambiguation rule: when an AFTER-anchor for a
        # noun parameter (step/rail_depth/block_size) already
        # bound the numeral, the BEFORE-phrase "every" /
        # "every nth" does NOT also bind to block_size. The
        # AFTER-anchor wins because it names the noun the
        # numeral modifies. Without this rule "every fifth
        # step" would bind both step=5 (via the "step"
        # AFTER-anchor) AND block_size=5 (via the "every"
        # phrase), polluting the block_size lesson with
        # numerals that are semantically step values.
        if tok_idx >= 1:
            window_start = tokens[max(0, tok_idx - 4)][1]
            num_start = tokens[tok_idx][1]
            window = lower[window_start:num_start]
            window_norm = re.sub(r"\s+", " ", window).strip()
            for param, phrases in _PHRASE_ANCHORS_PHRASES.items():
                # AFTER-anchor for a different noun parameter
                # already claimed this numeral — skip the loose
                # "every" / "every nth" phrase binding so we
                # don't cross-contaminate.
                if param == "block_size" and after_params & {
                    "step", "rail_depth",
                }:
                    continue
                if param == "step" and after_params & {
                    "rail_depth", "block_size",
                }:
                    continue
                # Sort longest-first so "every nth" wins over
                # "every".
                for phrase in sorted(phrases, key=len, reverse=True):
                    if window_norm.endswith(phrase):
                        _add(param, value)
                        break

    return bindings


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
    """Combine phrase-bound + clue-derived depths with the safe
    default set.

    LESSON-012 ordering:
      1. Phrase-bound depths from ``extract_phrase_bound_numerics``
         (e.g. "four rails" → 4, "depth seven" → 7) — highest
         priority, never starved.
      2. Legacy flat clue numerals from ``_depths_from_clue_text``
         — fallback when no anchor phrase exists.
      3. ``_DEFAULT_RAIL_FENCE_DEPTHS_BASE`` — final fallback.

    Always returns a deterministic, deduplicated list with at least
    ``len(_DEFAULT_RAIL_FENCE_DEPTHS_BASE)`` entries.
    """
    out: list[int] = []
    seen: set[int] = set()
    # 1. Phrase-bound first
    bound = extract_phrase_bound_numerics(clue_text)
    for d in bound["rail_depth"]:
        if 2 <= d and d not in seen:
            seen.add(d)
            out.append(d)
    # 2. Legacy flat fallback (only when no phrase-bound depth fired,
    # or to add complementary numerals that weren't anchor-bound)
    for d in _depths_from_clue_text(clue_text):
        if d >= 2 and d not in seen:
            seen.add(d)
            out.append(d)
    # 3. Safe defaults
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


# ---------------------------------------------------------------------------
# LESSON-013: arbitrary columnar column-order enumeration
# ---------------------------------------------------------------------------
#
# Pre-LESSON-013 the columnar layer was only ever built via
# ``_keyword_columnar_layer`` whose col_order came from the keyword's
# stable rank (LESSON-004 + LESSON-005). Some hand ciphers use an
# explicit numeric column permutation (e.g. (4, 1, 3, 0, 2) for W=5)
# that no natural English keyword stable-ranks to. LESSON-013 adds an
# enumerated col_order path that runs alongside — never replacing —
# the keyword path.

# Default widths to enumerate when no clue-driven width applies.
_DEFAULT_COLUMNAR_WIDTHS: tuple[int, ...] = (3, 4, 5)

# Largest width we are willing to enumerate exhaustively. W >= 8 is
# left untouched; the keyword-derived path still produces specs for
# any keyword of any length >= 2, but the enumerated path stops at 7.
_MAX_ENUMERATED_WIDTH: int = 7

# Per-width permutation cap. W=2..5 are exhaustive; W=6 (720) and
# W=7 (5040) get truncated to the first 120 lexicographic entries so
# the dispatch universe stays bounded across (sub × alpha × order ×
# col_order) products.
_PER_WIDTH_PERM_CAP: dict[int, int] = {
    2: 2, 3: 6, 4: 24, 5: 120, 6: 120, 7: 120,
}

# Alphabet modes that the enumerated path is allowed to use. Restricted
# to AZ + KA — keyword_mixed already explodes via the keyword path and
# would multiply the enumerated universe without adding a meaningful
# new tactic. Real-K4 mode is unaffected because HCC is bench-only.
_LESSON_013_ALPHABET_MODES: tuple[AlphabetMode, ...] = (
    AlphabetMode("AZ", "AZ", None, "default"),
    AlphabetMode("KA", "KA", None, "default"),
)


def _columnar_widths_for_payload(
    clue_text: str,
    clue_keywords: Sequence[str],
) -> list[tuple[int, str]]:
    """Resolve the enumerated columnar widths for a clue payload.

    Returns ``[(width, source), ...]`` deduplicated and capped at
    ``_MAX_ENUMERATED_WIDTH``. Source is one of:
      * ``phrase_bound_step``  — LESSON-012 ``step`` slot (only)
      * ``clue_keyword_length`` — len of a clue keyword in [2, 7]
      * ``default_set``         — fallback ``_DEFAULT_COLUMNAR_WIDTHS``

    Critical: rail_depth, shift_value, block_size, and offset
    bindings from ``extract_phrase_bound_numerics`` are EXPLICITLY
    NOT pulled in. Those numerals describe rail-count or arithmetic
    shifts; using them as a transposition width would be a category
    error and would explode the universe with unrelated values.
    """
    out: list[tuple[int, str]] = []
    seen: set[int] = set()

    # Priority 1: Phrase-bound ``step`` slot (LESSON-012). Most clue-
    # relevant — when the clue says "step five" we MUST enumerate W=5.
    # Only the ``step`` slot is consulted; rail_depth, shift_value,
    # block_size, and offset bindings are EXPLICITLY skipped (they
    # describe rail-count or arithmetic shifts, not transposition
    # widths — using them would explode the universe with unrelated
    # numerals).
    if isinstance(clue_text, str) and clue_text:
        bound = extract_phrase_bound_numerics(clue_text)
        for w in bound.get("step", []):
            if 2 <= w <= _MAX_ENUMERATED_WIDTH and w not in seen:
                seen.add(w)
                out.append((w, "phrase_bound_step"))

    # Priority 2: Safe defaults {3, 4, 5}. Cover the small-W universe
    # before the long tail of clue-keyword lengths so the per-family
    # cap reaches W=5 reliably.
    for w in _DEFAULT_COLUMNAR_WIDTHS:
        if w not in seen:
            seen.add(w)
            out.append((w, "default_set"))

    # Priority 3: Clue keyword lengths in [2, 7]. Long tail; only fills
    # remaining budget after phrase-bound + defaults are covered.
    for kw in clue_keywords:
        if not isinstance(kw, str):
            continue
        upper = kw.upper().strip()
        if not upper.isalpha():
            continue
        w = len(upper)
        if 2 <= w <= _MAX_ENUMERATED_WIDTH and w not in seen:
            seen.add(w)
            out.append((w, "clue_keyword_length"))

    return out


def _enumerated_col_orders_for_width(
    width: int,
    *,
    dedup_against: Optional[Sequence[Sequence[int]]] = None,
) -> list[tuple[tuple[int, ...], int]]:
    """Return ``[(col_order_tuple, index), ...]`` for ``width``.

    For W in [2, 7] this yields all W! permutations of ``range(width)``
    in lexicographic order, capped at ``_PER_WIDTH_PERM_CAP[width]``.
    The returned ``index`` is the position in the *unfiltered*
    lexicographic enumeration (so the index is a stable identifier
    even when ``dedup_against`` removes some entries).

    ``dedup_against`` is an optional collection of col_order sequences
    (typically keyword-derived) that should be skipped — guarantees the
    enumerated path emits no specs the keyword path already covers.

    For W < 2 returns ``[]`` (degenerate; columnar(W=1) is identity).
    For W > ``_MAX_ENUMERATED_WIDTH`` returns ``[]`` (out of scope).
    """
    if not isinstance(width, int) or width < 2:
        return []
    if width > _MAX_ENUMERATED_WIDTH:
        return []
    cap = _PER_WIDTH_PERM_CAP.get(width, 0)
    if cap <= 0:
        return []
    skip: set[tuple[int, ...]] = set()
    # Always skip the identity permutation — columnar with col_order =
    # range(W) is a no-op transposition (lesson 004 violation; was the
    # K4B-001 root-cause bug). Callers may add additional dedup
    # entries via ``dedup_against``.
    skip.add(tuple(range(width)))
    if dedup_against is not None:
        for co in dedup_against:
            try:
                skip.add(tuple(int(x) for x in co))
            except (TypeError, ValueError):
                continue
    import itertools as _it
    out: list[tuple[tuple[int, ...], int]] = []
    for idx, perm in enumerate(_it.permutations(range(width))):
        if perm in skip:
            continue
        out.append((perm, idx))
        if len(out) >= cap:
            break
    return out


def _explicit_columnar_layer(
    width: int,
    col_order: Sequence[int],
) -> dict[str, Any]:
    """Build a columnar layer with an explicit width + col_order pair.

    Mirror of ``_keyword_columnar_layer`` but for col_orders that did
    not come from a keyword's stable rank. Validates that ``col_order``
    is a permutation of ``range(width)`` so no malformed specs reach
    the validator.
    """
    if not isinstance(width, int) or width < 2:
        raise ValueError(
            f"_explicit_columnar_layer: width {width!r} too small; "
            "need width >= 2"
        )
    co_list = [int(x) for x in col_order]
    if sorted(co_list) != list(range(width)):
        raise ValueError(
            f"_explicit_columnar_layer: col_order {col_order!r} is "
            f"not a permutation of range({width})"
        )
    return {
        "kind": "columnar",
        "alphabet": "AZ",
        "params": [
            {"name": "width", "values": [width]},
            {"name": "col_order", "values": [co_list]},
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


# ============================================================================
# LESSON-014: width-only ragged boustrophedon route
# ============================================================================
#
# A clue like "the artifact says ARCHIVE and shows a ragged eight-column
# grid with arrows down, up, down, up" describes a width-only
# boustrophedon: the ciphertext is laid into a grid of fixed width
# (here 8), where the final row may be short ("ragged"), and read in a
# serpentine pattern alternating direction by row (or by column, when
# the clue says "down, up, down, up"). The existing ``route`` kind
# requires explicit rows AND cols + a non-ragged grid; LESSON-014's
# ``route_boustrophedon`` kind takes only ``width``, which is the
# correct shape for clue language that names a column count without
# specifying rows.
#
# Trigger vocabulary, default widths, width-source priority, and family
# pairings are all owned by LESSON-014 in the registry. A drift test
# asserts the runtime constants below match the registry payload.

_ROUTE_BOUSTROPHEDON_TRIGGER_TOKENS: frozenset[str] = frozenset({
    "archive",
    "column", "columns", "col",
    "grid",
    "walk", "walks", "walking",
    "route", "routes",
    "path", "paths",
    "edge", "edges",
    "ragged",
    "artifact", "artifacts",
    "count", "counts",
    "serpentine",
    "boustrophedon",
    "snake", "snaking",
    "zigzag",
    "up", "down", "left", "right",
    "row", "rows",
})

# Direction-priority tokens. When ANY of these appears in the clue,
# the vertical=True variant is the priority direction; vertical=False
# is still emitted as the symmetry partner (LESSON-002).
_ROUTE_BOUSTROPHEDON_VERTICAL_TOKENS: frozenset[str] = frozenset({
    "down", "up",
    "vertical", "vertically",
    "columnwise",
})

_ROUTE_BOUSTROPHEDON_HORIZONTAL_TOKENS: frozenset[str] = frozenset({
    "left", "right",
    "horizontal", "horizontally",
    "rowwise",
})

# Default width set. Intentionally bounded to the small-grid range a
# hand cipher operator could realistically count off on a sheet of
# paper. K4-length CT is 97 chars; widths up to 12 leave the implied
# row count at >=9 which is still grid-shaped. Wider widths (>12) are
# reachable only via clue keyword length when the clue keyword is
# itself longer (capped at 16 to stay within hand-cipher plausibility).
_DEFAULT_ROUTE_BOUSTROPHEDON_WIDTHS: tuple[int, ...] = (
    3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
)

# Hard bounds on enumerated widths. ``min_width`` is 2 because width=1
# is identity (a single column read top-down). ``max_width`` caps the
# clue-keyword-length path so a pathological 30-letter "keyword" does
# not seed a 30-wide grid.
_ROUTE_BOUSTROPHEDON_MIN_WIDTH: int = 2
_ROUTE_BOUSTROPHEDON_MAX_WIDTH: int = 16
_ROUTE_BOUSTROPHEDON_MAX_KEYWORD_WIDTH: int = 12

# Phrase anchors that bind a numeral to ``route_width`` specifically.
# These are SEPARATE from the LESSON-012 phrase taxonomy because the
# LESSON-012 anchors do not include "column" / "wide" / "grid" /
# "row" — those are LESSON-014's concern. The lesson registry mirrors
# this list so a drift test asserts they stay in sync.
_ROUTE_WIDTH_PHRASE_ANCHORS_BEFORE: tuple[str, ...] = (
    "width", "wide",
    "column", "columns", "col", "cols",
    "grid",
    "row", "rows",
)
_ROUTE_WIDTH_PHRASE_ANCHORS_AFTER: tuple[str, ...] = (
    "wide",
    "column", "columns", "col", "cols",
    "grid",
    "row", "rows",
)
# Hyphenated patterns: "eight-column", "8-wide", "12-row". The numeral
# can be a digit literal, cardinal, or ordinal (any token resolved by
# ``_NUMBER_WORDS`` / ``int(token)``).
_ROUTE_WIDTH_HYPHEN_SUFFIXES: tuple[str, ...] = (
    "column", "columns", "col", "cols",
    "wide", "row", "rows",
)


def _route_boustrophedon_layer(
    width: int,
    *,
    vertical: bool = False,
) -> dict[str, Any]:
    """Build a route_boustrophedon layer dict (LESSON-014).

    The dispatcher computes ``rows = ceil(CT_LEN / width)`` and reuses
    ``serpentine_perm`` which trims positions beyond CT_LEN; the layer
    is therefore length-preserving and deterministic. ``vertical``
    selects between row-direction alternation (False) and
    column-direction alternation (True) — the latter matches clue
    language like "arrows down, up, down, up".
    """
    if not isinstance(width, int) or width < _ROUTE_BOUSTROPHEDON_MIN_WIDTH:
        raise ValueError(
            f"_route_boustrophedon_layer: width must be int >= "
            f"{_ROUTE_BOUSTROPHEDON_MIN_WIDTH}; got {width!r}"
        )
    return {
        "kind": "route_boustrophedon",
        "alphabet": "AZ",
        "params": [
            {"name": "width", "values": [width]},
            {"name": "vertical", "values": [bool(vertical)]},
        ],
    }


def _detect_route_boustrophedon_trigger(clue_text: str) -> bool:
    """Whole-word match for any LESSON-014 boustrophedon trigger token.

    Used by ``generate_layered_specs`` to gate emission of the
    route_boustrophedon family matrix. A clue text without any of these
    tokens leaves the historical catalog bit-identical (route_
    boustrophedon families are absent).
    """
    if not isinstance(clue_text, str) or not clue_text:
        return False
    lower = clue_text.lower()
    for token in _ROUTE_BOUSTROPHEDON_TRIGGER_TOKENS:
        idx = 0
        while True:
            pos = lower.find(token, idx)
            if pos < 0:
                break
            before_ok = pos == 0 or not lower[pos - 1].isalnum()
            after_pos = pos + len(token)
            after_ok = (
                after_pos >= len(lower) or not lower[after_pos].isalnum()
            )
            if before_ok and after_ok:
                return True
            idx = pos + 1
    return False


def _detect_route_vertical_priority(clue_text: str) -> bool:
    """True iff the clue text contains any LESSON-014 vertical-direction
    token. Used to select vertical=True as the priority direction;
    vertical=False is always emitted as the symmetry partner.
    """
    if not isinstance(clue_text, str) or not clue_text:
        return False
    lower = clue_text.lower()
    for token in _ROUTE_BOUSTROPHEDON_VERTICAL_TOKENS:
        # Word-boundary match. "down" inside "downfall" must NOT
        # trigger; "down" in "down, up, down, up" must trigger.
        idx = 0
        while True:
            pos = lower.find(token, idx)
            if pos < 0:
                break
            before_ok = pos == 0 or not lower[pos - 1].isalnum()
            after_pos = pos + len(token)
            after_ok = (
                after_pos >= len(lower) or not lower[after_pos].isalnum()
            )
            if before_ok and after_ok:
                return True
            idx = pos + 1
    return False


def _extract_phrase_bound_route_widths(
    clue_text: str,
    *,
    ct_length: int = 97,
) -> list[int]:
    """Parse phrase-attached numerals that bind to ``route_width``.

    Distinct from ``extract_phrase_bound_numerics`` (LESSON-012), which
    handles step / offset / rail_depth / block_size / shift_value
    parameters. LESSON-014 anchors are different — "width", "column",
    "grid", "row", "wide" — so the parser is a lightweight separate
    routine rather than a new slot in the LESSON-012 taxonomy. Keeping
    them separate prevents cross-contamination: a clue like "every
    fifth step through eight columns" must bind step=5 to skip_route
    AND width=8 to route_boustrophedon, not pollute either with the
    other's numeral.

    Anchor matching rules (case-insensitive, whole-word):
      * BEFORE-anchors: numeral immediately preceded by an anchor
        token (within 1 token).
      * AFTER-anchors: numeral immediately followed by an anchor
        token (within 2 tokens).
      * Hyphen forms: "eight-column", "8-wide", "12-row" — matched
        as adjacent token pairs separated by '-'.

    Returns a deduplicated list of ints in document order, each in the
    range [_ROUTE_BOUSTROPHEDON_MIN_WIDTH, _ROUTE_BOUSTROPHEDON_MAX_WIDTH].
    """
    if not isinstance(clue_text, str) or not clue_text:
        return []
    import re
    lower = clue_text.lower()

    # Tokenize: alphabetic tokens, digit tokens, and remember whether
    # adjacent tokens are joined by a hyphen so "eight-column" is
    # recognized as a hyphen pair.
    tokens: list[tuple[str, int, int]] = []  # (token, start, end)
    for m in re.finditer(r"[A-Za-z]+|\d+", lower):
        tokens.append((m.group(0), m.start(), m.end()))

    def _numeric_of(tok: str) -> Optional[int]:
        if tok.isdigit():
            try:
                v = int(tok)
            except ValueError:
                return None
            return v
        return _NUMBER_WORDS.get(tok)

    def _hyphen_between(tok_a_end: int, tok_b_start: int) -> bool:
        # Hyphen joining condition: every char between the two tokens
        # is whitespace, optional '-', and optional more whitespace.
        # We accept exactly one '-' separator because that is the
        # hyphenated-compound idiom; "eight column" without hyphen is
        # already handled by the AFTER-anchor branch.
        between = lower[tok_a_end:tok_b_start]
        return between == "-"

    found: list[int] = []
    seen: set[int] = set()

    def _accept(value: int) -> None:
        if value in seen:
            return
        if not (
            _ROUTE_BOUSTROPHEDON_MIN_WIDTH
            <= value
            <= _ROUTE_BOUSTROPHEDON_MAX_WIDTH
        ):
            return
        seen.add(value)
        found.append(value)

    for i, (tok, start, end) in enumerate(tokens):
        v = _numeric_of(tok)
        if v is None:
            continue

        # BEFORE-anchor: previous token in
        # _ROUTE_WIDTH_PHRASE_ANCHORS_BEFORE.
        if i >= 1:
            prev_tok = tokens[i - 1][0]
            if prev_tok in _ROUTE_WIDTH_PHRASE_ANCHORS_BEFORE:
                _accept(v)

        # AFTER-anchor: next 1-2 tokens. Stop after the first match;
        # do not cross over a different numeric token.
        for j in (1, 2):
            if i + j >= len(tokens):
                break
            if j == 2 and _numeric_of(tokens[i + 1][0]) is not None:
                break
            next_tok = tokens[i + j][0]
            if next_tok in _ROUTE_WIDTH_PHRASE_ANCHORS_AFTER:
                _accept(v)
                break
            if j == 2:
                # Don't re-check token at j=2 if the j=1 token was
                # not an anchor (i.e. it was a filler like "wide").
                # Fillers are fine; just keep scanning to j=2.
                continue

        # Hyphen-pair: "eight-column", "8-wide". The numeral token
        # ends at ``end``; if the next token starts immediately after
        # a single '-' and is in _ROUTE_WIDTH_HYPHEN_SUFFIXES, accept.
        if i + 1 < len(tokens):
            next_tok, next_start, _ = tokens[i + 1]
            if _hyphen_between(end, next_start) and (
                next_tok in _ROUTE_WIDTH_HYPHEN_SUFFIXES
            ):
                _accept(v)

    return found


def _route_boustrophedon_widths_for_payload(
    clue_text: str,
    clue_keywords: Sequence[str],
    *,
    ct_length: int = 97,
) -> list[tuple[int, str]]:
    """Resolve LESSON-014 width candidates with provenance.

    Priority (highest first):
      1. ``phrase_bound_route_width`` — anchor-bound numerals from
         ``_extract_phrase_bound_route_widths``. Never starved by
         downstream caps.
      2. ``clue_keyword_length`` — len of any clue keyword in
         [min_width, max_keyword_width]. The lesson permits any
         clue keyword to seed a width — the trigger detector has
         already flagged the clue as route-relevant, so any clue
         word's length is a plausible width hint. Excluding by
         semantic class would over-fit to specific challenges.
      3. ``default_set`` — ``_DEFAULT_ROUTE_BOUSTROPHEDON_WIDTHS``.

    Returns ``[(width, source), ...]`` deduplicated and bounded to
    ``[min_width, max_width]``. Width values that fall outside the
    range are silently dropped.

    EXCLUSIONS (LESSON-014 contract): rail_depth, shift_value,
    block_size, step, and offset bindings from
    ``extract_phrase_bound_numerics`` are NOT pulled in. Those
    numerals describe rail count / arithmetic shifts / block size /
    skip-route step+offset; using them as a route-boustrophedon
    width would be a category error and would explode the universe.
    """
    out: list[tuple[int, str]] = []
    seen: set[int] = set()

    def _emit(width: int, source: str) -> None:
        if width in seen:
            return
        if not (
            _ROUTE_BOUSTROPHEDON_MIN_WIDTH
            <= width
            <= _ROUTE_BOUSTROPHEDON_MAX_WIDTH
        ):
            return
        seen.add(width)
        out.append((width, source))

    # Priority 1: phrase-bound widths (highest priority, never starved).
    for w in _extract_phrase_bound_route_widths(
        clue_text, ct_length=ct_length,
    ):
        _emit(w, "phrase_bound_route_width")

    # Priority 2: clue keyword lengths in the keyword-width band.
    for kw in clue_keywords:
        if not isinstance(kw, str):
            continue
        upper = kw.upper().strip()
        if not upper.isalpha():
            continue
        w = len(upper)
        if (
            _ROUTE_BOUSTROPHEDON_MIN_WIDTH
            <= w
            <= _ROUTE_BOUSTROPHEDON_MAX_KEYWORD_WIDTH
        ):
            _emit(w, "clue_keyword_length")

    # Priority 3: safe default set.
    for w in _DEFAULT_ROUTE_BOUSTROPHEDON_WIDTHS:
        _emit(w, "default_set")

    return out


# ============================================================================
# LESSON-015: alternate-row reversal / folded-strip route
# ============================================================================
#
# A clue like "a dark strip gives SHADOW and a KRYPTOS alphabet with the
# far end folded back over the near end" describes a folded-strip
# transposition: split the text into rows of fixed width and reverse
# alternating rows in place. The result is length-preserving and
# self-inverse — applying the same (width, parity, start_row) twice
# returns the original text.
#
# Distinct from ``route_boustrophedon`` (LESSON-014): that kind reads
# the GRID in serpentine fashion via a single global permutation.
# ``row_reverse`` only reverses SELECTED rows in place; non-selected
# rows pass through verbatim.
#
# Trigger vocabulary, default widths, parity options, and width-source
# priority are all owned by LESSON-015 in the registry. A drift test
# asserts the runtime constants below match the registry payload.

_ROW_REVERSE_TRIGGER_TOKENS: frozenset[str] = frozenset({
    "fold", "folded", "unfold", "unfolded", "folding",
    "reverse", "reversed", "reversal",
    "row", "rows", "line", "lines",
    "strip", "strips", "wall", "panel",
    "boustrophedon", "serpentine", "zigzag",
    "alternate", "alternating",
})

# Multi-word phrase triggers (case-insensitive substring match).
_ROW_REVERSE_TRIGGER_PHRASES: tuple[str, ...] = (
    "every other",
    "left edge", "right edge",
    "read back", "turn back",
)

# Default width set per the user's spec, plus CT_LEN as the "no-fold"
# boundary case so the LESSON-015 catalog covers substitution-alone-
# equivalent specs (width=CT_LEN with parity=odd is identity because
# only row 0 exists, row 0 is even, parity=odd selects no rows).
_DEFAULT_ROW_REVERSE_WIDTHS: tuple[int, ...] = (
    5, 7, 8, 10, 12, 14, 16,
)

# Hard bounds. min=2 because width=1 reverses every single char
# (identity) and is degenerate. max=CT_LEN because any width >=
# CT_LEN packs all characters into a single row; widths above
# CT_LEN are equivalent to width=CT_LEN.
_ROW_REVERSE_MIN_WIDTH: int = 2
_ROW_REVERSE_MAX_WIDTH: int = 97  # equals CT_LEN; exact-match expected
_ROW_REVERSE_MAX_KEYWORD_WIDTH: int = 16

# Default parity options enumerated per (width × layer-order ×
# keyword × alphabet) tuple. ``both`` is reachable via the explicit-
# parity path but not enumerated by default — reversing every row is
# equivalent to a global reverse and dilutes LESSON-015's signal.
_DEFAULT_ROW_REVERSE_PARITIES: tuple[str, ...] = ("odd", "even")

# Phrase anchors that bind a numeral to ``row_reverse_width``.
# Distinct from LESSON-014's route-width anchors and LESSON-013's
# columnar-width anchors so the three lessons can co-exist on the
# same clue without cross-contaminating their width pools.
_ROW_REVERSE_PHRASE_ANCHORS_BEFORE: tuple[str, ...] = (
    "width", "wide",
    "row", "rows",
    "line", "lines",
    "strip", "strips",
    "wall", "panel",
)
_ROW_REVERSE_PHRASE_ANCHORS_AFTER: tuple[str, ...] = (
    "wide",
    "row", "rows",
    "line", "lines",
    "strip", "strips",
    "wall", "panel",
)
_ROW_REVERSE_HYPHEN_SUFFIXES: tuple[str, ...] = (
    "wide", "row", "rows",
    "line", "lines",
    "strip", "strips",
)


def _row_reverse_layer(
    width: int,
    parity: str,
    *,
    start_row: int = 0,
) -> dict[str, Any]:
    """Build a row_reverse layer dict (LESSON-015).

    The dispatcher partitions the text into rows of width ``width``,
    reverses rows whose 0-indexed row-index (offset by start_row)
    matches the parity selector, and keeps the remaining rows. The
    operation is self-inverse: applying the same (width, parity,
    start_row) twice returns the identity.
    """
    if not isinstance(width, int) or width < _ROW_REVERSE_MIN_WIDTH:
        raise ValueError(
            f"_row_reverse_layer: width must be int >= "
            f"{_ROW_REVERSE_MIN_WIDTH}; got {width!r}"
        )
    if parity not in ("odd", "even", "both"):
        raise ValueError(
            f"_row_reverse_layer: parity must be in "
            "{'odd', 'even', 'both'}; got " + repr(parity)
        )
    if not isinstance(start_row, int) or start_row not in (0, 1):
        raise ValueError(
            f"_row_reverse_layer: start_row must be 0 or 1; got "
            f"{start_row!r}"
        )
    return {
        "kind": "row_reverse",
        "alphabet": "AZ",
        "params": [
            {"name": "width", "values": [width]},
            {"name": "parity", "values": [parity]},
            {"name": "start_row", "values": [start_row]},
        ],
    }


def _detect_row_reverse_trigger(clue_text: str) -> bool:
    """Whole-word match for any LESSON-015 trigger token, plus
    multi-word phrase substring match. Returns True iff the
    operator's clue language suggests a folded-strip / alternate-
    row reversal.
    """
    if not isinstance(clue_text, str) or not clue_text:
        return False
    lower = clue_text.lower()
    # Multi-word phrases first (substring match — phrases are
    # specific enough that false-positives are unlikely).
    for phrase in _ROW_REVERSE_TRIGGER_PHRASES:
        if phrase in lower:
            return True
    # Single-token triggers with word-boundary checks.
    for token in _ROW_REVERSE_TRIGGER_TOKENS:
        idx = 0
        while True:
            pos = lower.find(token, idx)
            if pos < 0:
                break
            before_ok = pos == 0 or not lower[pos - 1].isalnum()
            after_pos = pos + len(token)
            after_ok = (
                after_pos >= len(lower) or not lower[after_pos].isalnum()
            )
            if before_ok and after_ok:
                return True
            idx = pos + 1
    return False


def _extract_phrase_bound_row_reverse_widths(
    clue_text: str,
    *,
    ct_length: int = 97,
) -> list[int]:
    """Parse phrase-attached numerals that bind to row_reverse width.

    Distinct from LESSON-012 / LESSON-014 anchor sets so the three
    lessons can co-exist without cross-contaminating their width
    pools. Anchor matching rules mirror LESSON-014's
    ``_extract_phrase_bound_route_widths``: BEFORE-anchors,
    AFTER-anchors, and hyphen pairs (e.g. "ten-wide", "8-row").

    Returns a deduplicated list of ints in document order, each in
    the range [_ROW_REVERSE_MIN_WIDTH, _ROW_REVERSE_MAX_WIDTH].
    """
    if not isinstance(clue_text, str) or not clue_text:
        return []
    import re
    lower = clue_text.lower()

    tokens: list[tuple[str, int, int]] = []
    for m in re.finditer(r"[A-Za-z]+|\d+", lower):
        tokens.append((m.group(0), m.start(), m.end()))

    def _numeric_of(tok: str) -> Optional[int]:
        if tok.isdigit():
            try:
                v = int(tok)
            except ValueError:
                return None
            return v
        return _NUMBER_WORDS.get(tok)

    def _hyphen_between(end: int, start: int) -> bool:
        return lower[end:start] == "-"

    found: list[int] = []
    seen: set[int] = set()

    def _accept(value: int) -> None:
        if value in seen:
            return
        if not (
            _ROW_REVERSE_MIN_WIDTH
            <= value
            <= _ROW_REVERSE_MAX_WIDTH
        ):
            return
        seen.add(value)
        found.append(value)

    for i, (tok, start, end) in enumerate(tokens):
        v = _numeric_of(tok)
        if v is None:
            continue
        # BEFORE-anchor.
        if i >= 1:
            prev_tok = tokens[i - 1][0]
            if prev_tok in _ROW_REVERSE_PHRASE_ANCHORS_BEFORE:
                _accept(v)
        # AFTER-anchor (1-2 token lookahead, blocked by intervening
        # numerics).
        for j in (1, 2):
            if i + j >= len(tokens):
                break
            if j == 2 and _numeric_of(tokens[i + 1][0]) is not None:
                break
            next_tok = tokens[i + j][0]
            if next_tok in _ROW_REVERSE_PHRASE_ANCHORS_AFTER:
                _accept(v)
                break
        # Hyphen pair: "ten-wide", "8-row".
        if i + 1 < len(tokens):
            next_tok, next_start, _ = tokens[i + 1]
            if _hyphen_between(end, next_start) and (
                next_tok in _ROW_REVERSE_HYPHEN_SUFFIXES
            ):
                _accept(v)

    return found


def _row_reverse_widths_for_payload(
    clue_text: str,
    clue_keywords: Sequence[str],
    *,
    ct_length: int = 97,
) -> list[tuple[int, str]]:
    """Resolve LESSON-015 width candidates with provenance.

    Priority (highest first):
      1. ``phrase_bound_row_reverse_width`` — anchor-bound numerals.
      2. ``clue_keyword_length`` — len of any clue keyword in
         [min_width, max_keyword_width].
      3. ``default_set`` — ``_DEFAULT_ROW_REVERSE_WIDTHS``.
      4. The ``ct_length`` "no-fold sentinel" is always appended
         last so the catalog can express substitution-alone-
         equivalent specs via width=CT_LEN + parity=odd. The
         sentinel never displaces a phrase-bound or keyword-
         derived width.

    EXCLUSIONS: rail_depth, shift_value, block_size, step, and
    offset bindings from LESSON-012 are NOT pulled in.
    """
    out: list[tuple[int, str]] = []
    seen: set[int] = set()

    def _emit(width: int, source: str) -> None:
        if width in seen:
            return
        if not (
            _ROW_REVERSE_MIN_WIDTH
            <= width
            <= _ROW_REVERSE_MAX_WIDTH
        ):
            return
        seen.add(width)
        out.append((width, source))

    # Priority 1: phrase-bound widths.
    for w in _extract_phrase_bound_row_reverse_widths(
        clue_text, ct_length=ct_length,
    ):
        _emit(w, "phrase_bound_row_reverse_width")

    # Priority 2: clue keyword lengths.
    for kw in clue_keywords:
        if not isinstance(kw, str):
            continue
        upper = kw.upper().strip()
        if not upper.isalpha():
            continue
        w = len(upper)
        if (
            _ROW_REVERSE_MIN_WIDTH
            <= w
            <= _ROW_REVERSE_MAX_KEYWORD_WIDTH
        ):
            _emit(w, "clue_keyword_length")

    # Priority 3: safe default set.
    for w in _DEFAULT_ROW_REVERSE_WIDTHS:
        _emit(w, "default_set")

    # Priority 4: no-fold sentinel. Always last so phrase-bound /
    # keyword-derived widths consume the per-family cap budget
    # first; the sentinel is a graceful fallback that lets
    # row_reverse(width=CT_LEN, parity=odd) act as identity, which
    # — when paired with a substitution layer — covers the
    # "substitution alone" case.
    _emit(ct_length, "default_set")

    return out


def _reverse_blocks_layer(
    block_size: int,
    block_mode: str = "reverse_partial",
) -> dict[str, Any]:
    """Build a reverse_blocks layer dict.

    LESSON-008 primitive. The dispatcher emits a ``transposition_full``
    perm that reverses each block of size ``block_size`` over the
    canonical 97-char K4-shaped CT. ``block_mode`` selects whether a
    trailing partial block is reversed (``reverse_partial``) or kept
    as identity (``truncate``).
    """
    if not isinstance(block_size, int) or block_size < 2:
        raise ValueError(
            f"_reverse_blocks_layer: block_size must be int >= 2; "
            f"got {block_size!r}"
        )
    if block_mode not in ("reverse_partial", "truncate"):
        raise ValueError(
            f"_reverse_blocks_layer: block_mode must be in "
            f"{{'reverse_partial', 'truncate'}}; got {block_mode!r}"
        )
    return {
        "kind": "reverse_blocks",
        "alphabet": "AZ",
        "params": [
            {"name": "block_size", "values": [block_size]},
            {"name": "block_mode", "values": [block_mode]},
        ],
    }


# ============================================================================
# LESSON-016: diagonal grid-route transposition
# ============================================================================
#
# Clue language such as "diagonal", "oblique", "slant", "cross",
# "lattice", "stones", "mason", "courses", or directional shorthand
# ("NW-SE", "NE-SW") describes a grid-route transposition that reads
# the ciphertext along diagonal stripes rather than rows or columns.
# Pre-LESSON-016, the HCC catalogue had no diagonal-route family;
# clue tokens like "diagonal" were consumed only as candidate keyword
# material (substitution / alphabet / transposition keys), missing
# the route operation the clue actually names.
#
# The general lesson: clue geometry words must instantiate route
# operations, not only keyword material.
#
# Supported via the existing ``route`` DSL kind with
# ``variant="diagonal"`` plus three params (axis, order,
# start_edge). The dispatcher dispatches through the kernel's
# ``diagonal_perm`` primitive.

_DIAGONAL_TRIGGER_TOKENS: frozenset[str] = frozenset({
    # Direct geometry vocabulary.
    "diagonal", "diagonals",
    "oblique", "obliques",
    "slant", "slants", "slanted", "slanting",
    "slash", "slashes",
    "backslash", "backslashes",
    "cross", "crosses", "crossed", "crossing",
    "lattice", "lattices",
    "rising", "falling",
    # Compass shorthand for diagonal directions.
    "nwse", "nesw",
    # Masonry / stone-grid vocabulary; common public-puzzle phrasing
    # for diagonal stone-course layouts.
    "mason", "masons", "masonry",
    "stone", "stones",
    "course", "courses",
})

# Multi-word phrase triggers (case-insensitive substring).
_DIAGONAL_TRIGGER_PHRASES: tuple[str, ...] = (
    "nw-se", "nw to se", "nw->se",
    "ne-sw", "ne to sw", "ne->sw",
    "rising diagonal", "falling diagonal",
    "alternating diagonals",
)

# Default rectangular grids that the audit and bench-fast HCC mode
# may enumerate for diagonal routes. Each (rows, cols) pair has
# rows*cols >= CT_LEN (97) so the dispatcher rows*cols guard does
# not reject them; ragged trimming is handled by the kernel
# primitive.
_DEFAULT_DIAGONAL_GRIDS: tuple[tuple[int, int], ...] = (
    (10, 10),    # 100 cells, ragged 3
    (13, 8),     # 104 cells, ragged 7 — cols matches LESSON-014's
                 #   8-column case
    (8, 13),     # transpose
    (7, 14),     # 98 cells, ragged 1
    (14, 7),     # transpose
    (12, 9),     # 108 cells
    (9, 12),     # transpose
    (11, 10),    # 110 cells (covers cols=10 grids)
    (10, 11),
)

# Cap the number of (axis, order, start_edge) variants enumerated
# per grid in the substitution-paired families. The full cartesian
# is 2*2*2 = 8 per grid; capping at 4 picks the canonical set
# (main/anti × forward/reverse with the natural top_then_*
# start_edge for each axis) and skips the inverted start_edge to
# bound the universe. The alone family enumerates all 8.
_DIAGONAL_PAIR_VARIANT_CAP: int = 4


def _diagonal_route_layer(
    rows: int, cols: int,
    *,
    axis: str = "main",
    order: str = "forward",
    start_edge: str = "top_then_left",
) -> dict[str, Any]:
    """Build a route layer dict for the diagonal variant.

    The dispatcher's ``route`` translator validates rows*cols >=
    CT_LEN and the (axis, order, start_edge) whitelist; this builder
    rejects only obvious shape errors so the dispatcher remains the
    single source of truth for cipher-semantic validation.
    """
    if not isinstance(rows, int) or rows < 1:
        raise ValueError(
            f"_diagonal_route_layer: rows must be int >= 1; got {rows!r}"
        )
    if not isinstance(cols, int) or cols < 1:
        raise ValueError(
            f"_diagonal_route_layer: cols must be int >= 1; got {cols!r}"
        )
    if axis not in ("main", "anti"):
        raise ValueError(
            f"_diagonal_route_layer: axis must be 'main' or 'anti'; "
            f"got {axis!r}"
        )
    return {
        "kind": "route",
        "alphabet": "AZ",
        "params": [
            {"name": "variant", "values": ["diagonal"]},
            {"name": "rows", "values": [rows]},
            {"name": "cols", "values": [cols]},
            {"name": "diagonal_axis", "values": [axis]},
            {"name": "diagonal_order", "values": [order]},
            {"name": "diagonal_start_edge", "values": [start_edge]},
        ],
    }


def _detect_diagonal_trigger(clue_text: str) -> bool:
    """Return True iff the clue text contains any LESSON-016 trigger
    token (single-word, word-boundary) or trigger phrase (substring).
    """
    if not isinstance(clue_text, str) or not clue_text:
        return False
    lower = clue_text.lower()
    for phrase in _DIAGONAL_TRIGGER_PHRASES:
        if phrase in lower:
            return True
    for token in _DIAGONAL_TRIGGER_TOKENS:
        idx = 0
        while True:
            pos = lower.find(token, idx)
            if pos < 0:
                break
            before_ok = pos == 0 or not lower[pos - 1].isalnum()
            after_pos = pos + len(token)
            after_ok = (
                after_pos >= len(lower) or not lower[after_pos].isalnum()
            )
            if before_ok and after_ok:
                return True
            idx = pos + 1
    return False


def _diagonal_grids_for_payload(
    clue_text: str,
    clue_keywords: Sequence[str],
    *,
    ct_length: int = 97,
) -> list[tuple[tuple[int, int], str]]:
    """Resolve diagonal-route grids with provenance.

    Priority:
      1. ``phrase_bound_diagonal_width`` — width-anchor numerals
         from LESSON-014's ``_extract_phrase_bound_route_widths``
         (e.g. "ten-wide grid"). For each phrase-bound width W,
         emit (ceil(CT_LEN/W), W).
      2. ``clue_keyword_length`` — len(clue_keyword) used as a
         cols dimension when in [3, 16] (the diagonal route gains
         no resolution from very small or very large widths).
      3. ``default_set`` — ``_DEFAULT_DIAGONAL_GRIDS``.

    Returns a deduplicated list of ((rows, cols), source) entries.
    LESSON-014's row/route/column phrase anchors are reused so a
    single clue numeral binding ("ten-wide") feeds both lessons
    consistently.
    """
    out: list[tuple[tuple[int, int], str]] = []
    seen: set[tuple[int, int]] = set()

    def _emit(rows: int, cols: int, source: str) -> None:
        if rows < 1 or cols < 1 or rows * cols < ct_length:
            return
        key = (rows, cols)
        if key in seen:
            return
        seen.add(key)
        out.append((key, source))

    # Priority 1: phrase-bound widths. Reuse LESSON-014's parser so
    # a clue with "ten-wide grid" produces both an 8-column
    # boustrophedon AND a 10-column diagonal candidate without
    # duplicating the phrase taxonomy.
    if isinstance(clue_text, str) and clue_text:
        for w in _extract_phrase_bound_route_widths(
            clue_text, ct_length=ct_length,
        ):
            if 3 <= w <= 16:
                rows = (ct_length + w - 1) // w
                _emit(rows, w, "phrase_bound_diagonal_width")

    # Priority 2: clue keyword lengths.
    for kw in clue_keywords:
        if not isinstance(kw, str):
            continue
        upper = kw.upper().strip()
        if not upper.isalpha():
            continue
        w = len(upper)
        if 3 <= w <= 16:
            rows = (ct_length + w - 1) // w
            _emit(rows, w, "clue_keyword_length")

    # Priority 3: default grids.
    for rows, cols in _DEFAULT_DIAGONAL_GRIDS:
        _emit(rows, cols, "default_set")

    return out


def _diagonal_variant_combinations(
    *, cap: Optional[int] = None,
) -> list[tuple[str, str, str]]:
    """Return the canonical (axis, order, start_edge) variant list
    for diagonal routes. Order:

      1. main forward top_then_left (canonical NW->SE downward)
      2. anti forward top_then_right (canonical NE->SW downward)
      3. main reverse top_then_left
      4. anti reverse top_then_right
      5. main forward left_then_top (inverted within-diagonal)
      6. anti forward right_then_top
      7. main reverse left_then_top
      8. anti reverse right_then_top

    A ``cap`` truncates at the front so substitution-paired
    families enumerate the canonical 4 by default.
    """
    full: list[tuple[str, str, str]] = [
        ("main", "forward", "top_then_left"),
        ("anti", "forward", "top_then_right"),
        ("main", "reverse", "top_then_left"),
        ("anti", "reverse", "top_then_right"),
        ("main", "forward", "left_then_top"),
        ("anti", "forward", "right_then_top"),
        ("main", "reverse", "left_then_top"),
        ("anti", "reverse", "right_then_top"),
    ]
    if cap is None or cap >= len(full):
        return full
    if cap < 1:
        return []
    return full[:cap]


def _detect_block_reversal_trigger(clue_text: str) -> bool:
    """Case-insensitive whole-word/phrase match for any block-reversal
    trigger token. Returns True iff the operator's clue language
    suggests a fixed-size block reversal is in play.

    Uses simple word-boundary checks for single tokens and substring
    checks for multi-word phrases. Multi-word phrases are listed
    verbatim in ``_BLOCK_REVERSAL_TRIGGER_TOKENS`` (e.g. "small
    group", "route before", "before key").
    """
    if not isinstance(clue_text, str) or not clue_text:
        return False
    lower = clue_text.lower()
    for token in _BLOCK_REVERSAL_TRIGGER_TOKENS:
        if " " in token:
            # Phrase match — substring is enough; the phrases are
            # specific enough that false-positives are unlikely.
            if token in lower:
                return True
            continue
        # Single-word match with neighbour-character word boundary.
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


def _detect_shift_trigger(clue_text: str) -> bool:
    """Whole-word match for shift / rotation trigger language used by
    LESSON-008 to gate the three-layer sandwiches that include Atbash
    or a Caesar shift.
    """
    if not isinstance(clue_text, str) or not clue_text:
        return False
    lower = clue_text.lower()
    for token in _SHIFT_TRIGGER_TOKENS:
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


def _block_sizes_for_payload(clue_text: str) -> list[tuple[int, str]]:
    """Return the (block_size, operation_source) list for the payload.

    LESSON-012 ordering:
      ``phrase_bound_block_size`` — anchor-bound numerals from
                         ``extract_phrase_bound_numerics``
                         (e.g. "blocks of seven" → 7, "five
                         groups" → 5). Never starved.
      ``clue_numeral``    — legacy flat extraction from
                            ``_depths_from_clue_text`` for any
                            digit-literal / spelled numeral that
                            is NOT phrase-bound to a different
                            parameter slot.
      ``default_set``     — ``_DEFAULT_BLOCK_SIZES`` final fallback.
    """
    out: list[tuple[int, str]] = []
    seen: set[int] = set()
    bound = extract_phrase_bound_numerics(clue_text)
    # 1. Phrase-bound first (priority, cannot be starved)
    for d in bound["block_size"]:
        if d >= 2 and d not in seen:
            seen.add(d)
            out.append((d, "phrase_bound_block_size"))
    # Cross-contamination filter: numerals already bound to other
    # specific parameters (rail_depth / step / offset / shift_value)
    # should NOT also be promoted as block_size from the legacy
    # flat extractor. Without this filter "four rails, three steps"
    # would flood block_size with 3, 4 — polluting the
    # reverse_blocks family with numerals that the clue
    # semantically attached to other parameters.
    other_param_bound: set[int] = set()
    for k in ("step", "offset", "rail_depth", "shift_value"):
        for v in bound[k]:
            other_param_bound.add(v)
    # 2. Legacy flat fallback (filtered)
    for d in _depths_from_clue_text(clue_text):
        if d < 2 or d in seen or d in other_param_bound:
            continue
        seen.add(d)
        out.append((d, "clue_numeral"))
    for d in _DEFAULT_BLOCK_SIZES:
        if d in seen:
            continue
        seen.add(d)
        out.append((d, "default_set"))
    return out


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


# ---------------------------------------------------------------------------
# LESSON-013 family generators
# ---------------------------------------------------------------------------
#
# Per-family spec cap. Bounded so 7 LESSON-013 families combined
# (3 columnar_<sub> + 3 i3_columnar_<sub> + 1 caesar_columnar_atbash)
# stay under ~2100 specs of the global ``_DEFAULT_MAX_SPECS = 5000``
# cap, leaving room for skip_route / quagmire / sandwiches.
#
# At 300 per family with the canonical iteration (width → sub_kw →
# alphabet_mode → col_order → both layer orders) the W=5 enumeration
# reaches lex index ~120 for the first (sub_kw, alphabet_mode) pair
# before the cap fires. This is enough to ensure K4B-006's
# col_order=(4,1,3,0,2) at lex index 106 is emitted under the first
# sub_kw + first alphabet_mode in BOTH layer orderings (~254 specs
# from start: 40 from W=3 enumeration + 2×107 W=5 specs to reach
# idx 106). Reducing to 250 starves the canary; raising past 360
# starts to crowd skip_route at the global cap.
_LESSON_013_PER_FAMILY_CAP: int = 300


def _gen_enumerated_columnar_pair_family(
    *,
    bench_slug: str,
    sub_kind: str,
    keyword_a: str,
    keyword_b: str,
    clue_text: str,
    clue_keywords: Sequence[str],
    alphabet_modes: Optional[Sequence[AlphabetMode]] = None,
    per_family_cap: int = _LESSON_013_PER_FAMILY_CAP,
) -> list[GeneratedSpec]:
    """LESSON-013: 2-layer ``columnar_<sub>`` family with ENUMERATED
    column orderings instead of (or in addition to) the keyword-derived
    col_order produced by the legacy ``_gen_keyword_pair_family``.

    Width selection priority (LESSON-012 + LESSON-013):
      1. ``phrase_bound_step`` (LESSON-012 ``step`` slot only)
      2. ``clue_keyword_length`` (clue keywords of length 2..7)
      3. ``default_set`` ({3, 4, 5})

    For each (width, source) the col_orders enumerate ALL
    ``min(W!, _PER_WIDTH_PERM_CAP[W])`` permutations of ``range(W)``,
    deduplicated against any keyword-stable-rank col_order produced
    by a clue keyword of the same length. The keyword-derived path
    in ``_gen_keyword_pair_family`` is preserved bit-for-bit and
    runs in parallel, so legacy behaviour is unchanged.

    Coverage_vector telemetry (new fields populated):
      * ``transposition_width``  — int width of the columnar grid
      * ``col_order``            — explicit permutation tuple
      * ``col_order_source``     — ``"enumerated_permutation"``
      * ``col_order_index``      — index into the W! lex list
      * ``width_source``         — ``"phrase_bound_step"`` etc.

    The family_label stays ``columnar_<sub>`` so coverage analysis
    treats the enumerated and keyword-derived specs as members of
    the same family. The role_assignment uses the synthetic
    transposition role ``("columnar", f"W{width}_co{idx}")`` so two
    enumerated specs at different col_orders never collide on the
    symmetry-class key.
    """
    if sub_kind not in _SUBSTITUTION_KEYWORD_KINDS:
        raise ValueError(
            f"_gen_enumerated_columnar_pair_family: unsupported "
            f"sub_kind {sub_kind!r}"
        )
    sub_kws_raw = [keyword_a, keyword_b]
    sub_kws: list[str] = []
    seen_sub: set[str] = set()
    for kw in sub_kws_raw:
        if not isinstance(kw, str):
            continue
        u = kw.upper().strip()
        if u and u.isalpha() and u not in seen_sub and len(u) >= 2:
            seen_sub.add(u)
            sub_kws.append(u)
    if not sub_kws:
        return []

    family_label = f"columnar_{sub_kind}"
    if alphabet_modes is None:
        alphabet_modes = _LESSON_013_ALPHABET_MODES

    # Build (width, source) list. Phrase-bound widths come first so
    # the per-family cap can never starve them out.
    widths = _columnar_widths_for_payload(clue_text, clue_keywords)
    if not widths:
        return []

    # For each width, the keyword-derived path of _gen_keyword_pair_
    # family already covers col_orders for clue keywords whose length
    # equals that width. We dedupe those out so the enumerated path
    # never emits a duplicate of the keyword path.
    def _keyword_co_set_for_width(w: int) -> list[list[int]]:
        out: list[list[int]] = []
        seen_local: set[tuple[int, ...]] = set()
        for kw in clue_keywords or []:
            if not isinstance(kw, str):
                continue
            u = kw.upper().strip()
            if u.isalpha() and len(u) == w:
                co = _keyword_to_col_order(u)
                t = tuple(co)
                if t not in seen_local:
                    seen_local.add(t)
                    out.append(co)
        return out

    out: list[GeneratedSpec] = []
    for width, width_source in widths:
        if len(out) >= per_family_cap:
            break
        col_orders = _enumerated_col_orders_for_width(
            width, dedup_against=_keyword_co_set_for_width(width),
        )
        if not col_orders:
            continue
        for sub_kw in sub_kws:
            if len(out) >= per_family_cap:
                break
            for mode in alphabet_modes:
                if len(out) >= per_family_cap:
                    break
                sub_layer = _keyword_substitution_layer(
                    sub_kind, sub_kw,
                    alphabet=mode.dsl_alphabet,
                    alphabet_keyword=mode.alphabet_keyword,
                )
                for co_tuple, co_idx in col_orders:
                    if len(out) >= per_family_cap:
                        break
                    trans_layer = _explicit_columnar_layer(
                        width, list(co_tuple),
                    )
                    trans_role_value = (
                        f"W{width}_co{co_idx}"
                    )
                    role = (
                        (sub_kind, sub_kw),
                        ("columnar", trans_role_value),
                    )
                    cov_common = dict(
                        layer_family=family_label,
                        role_assignment=role,
                        alphabet=mode.mode_label,
                        n_layers=2,
                        alphabet_mode=mode.mode_label,
                        alphabet_source=mode.source,
                        substitution_keyword=sub_kw,
                        alphabet_keyword=mode.alphabet_keyword or "",
                        transposition_keyword="",
                        role_assignment_mode="enumerated_columnar",
                        transposition_width=width,
                        col_order=co_tuple,
                        col_order_source="enumerated_permutation",
                        col_order_index=co_idx,
                        width_source=width_source,
                    )
                    # Order 1: substitution first
                    out.append(_make_spec(
                        bench_slug=bench_slug,
                        family_label=family_label,
                        pipeline=[sub_layer, trans_layer],
                        coverage=CoverageVector(
                            layer_order=(sub_kind, "columnar"),
                            **cov_common,
                        ),
                        notes=(
                            f"L013 {sub_kind}({sub_kw}, "
                            f"alpha={mode.mode_label}) ∘ "
                            f"columnar(W={width}, co={co_tuple}) "
                            "[sub-first]"
                        ),
                    ))
                    if len(out) >= per_family_cap:
                        break
                    # Order 2: transposition first
                    out.append(_make_spec(
                        bench_slug=bench_slug,
                        family_label=family_label,
                        pipeline=[trans_layer, sub_layer],
                        coverage=CoverageVector(
                            layer_order=("columnar", sub_kind),
                            **cov_common,
                        ),
                        notes=(
                            f"L013 columnar(W={width}, co={co_tuple}) "
                            f"∘ {sub_kind}({sub_kw}, "
                            f"alpha={mode.mode_label}) "
                            "[trans-first]"
                        ),
                    ))
    return out


def _gen_enumerated_columnar_i3_family(
    *,
    bench_slug: str,
    sub_kind: str,
    clue_keywords: Sequence[str],
    clue_text: str,
    alphabet_modes: Optional[Sequence[AlphabetMode]] = None,
    role_pool_size: int = 3,
    per_family_cap: int = _LESSON_013_PER_FAMILY_CAP,
) -> list[GeneratedSpec]:
    """LESSON-013 + LESSON-010: i3 columnar family with ENUMERATED
    col_orders. The substitution_keyword and alphabet_keyword roles
    iterate independently (LESSON-010 contract); the columnar trans
    layer uses an enumerated col_order rather than a keyword stable
    rank so the role_assignment_mode is ``enumerated_columnar`` —
    NOT ``independent_three_role``.

    Family_label stays ``i3_columnar_<sub>``. Coverage_vector telemetry
    is identical to ``_gen_enumerated_columnar_pair_family`` but
    populates ``substitution_keyword``, ``alphabet_keyword`` from the
    independent role enumeration.
    """
    if sub_kind not in _SUBSTITUTION_KEYWORD_KINDS:
        raise ValueError(
            f"_gen_enumerated_columnar_i3_family: unsupported sub_kind "
            f"{sub_kind!r}"
        )
    pool: list[str] = []
    seen_pool: set[str] = set()
    for kw in clue_keywords:
        if not isinstance(kw, str):
            continue
        u = kw.upper().strip()
        if u and u.isalpha() and u not in seen_pool and len(u) >= 2:
            seen_pool.add(u)
            pool.append(u)
            if len(pool) >= role_pool_size:
                break
    if len(pool) < 2:
        return []

    family_label = f"i3_columnar_{sub_kind}"
    if alphabet_modes is None:
        alphabet_modes = _LESSON_013_ALPHABET_MODES

    widths = _columnar_widths_for_payload(clue_text, clue_keywords)
    if not widths:
        return []

    out: list[GeneratedSpec] = []
    for width, width_source in widths:
        if len(out) >= per_family_cap:
            break
        # Dedup against keyword-stable-rank col_orders produced by
        # the i3 keyword path for this width.
        keyword_co: list[list[int]] = []
        seen_co: set[tuple[int, ...]] = set()
        for kw in pool:
            if len(kw) == width:
                co = _keyword_to_col_order(kw)
                t = tuple(co)
                if t not in seen_co:
                    seen_co.add(t)
                    keyword_co.append(co)
        col_orders = _enumerated_col_orders_for_width(
            width, dedup_against=keyword_co,
        )
        if not col_orders:
            continue
        for kw_sub in pool:
            if len(out) >= per_family_cap:
                break
            for mode in alphabet_modes:
                if len(out) >= per_family_cap:
                    break
                sub_layer = _keyword_substitution_layer(
                    sub_kind, kw_sub,
                    alphabet=mode.dsl_alphabet,
                    alphabet_keyword=mode.alphabet_keyword,
                )
                alphabet_kw_text = mode.alphabet_keyword or ""
                for co_tuple, co_idx in col_orders:
                    if len(out) >= per_family_cap:
                        break
                    trans_layer = _explicit_columnar_layer(
                        width, list(co_tuple),
                    )
                    trans_role_value = (
                        f"W{width}_co{co_idx}"
                    )
                    role = (
                        (sub_kind, kw_sub),
                        ("columnar", trans_role_value),
                    )
                    cov_common = dict(
                        layer_family=family_label,
                        role_assignment=role,
                        alphabet=mode.mode_label,
                        n_layers=2,
                        alphabet_mode=mode.mode_label,
                        alphabet_source=mode.source,
                        substitution_keyword=kw_sub,
                        alphabet_keyword=alphabet_kw_text,
                        transposition_keyword="",
                        role_assignment_mode="enumerated_columnar",
                        transposition_width=width,
                        col_order=co_tuple,
                        col_order_source="enumerated_permutation",
                        col_order_index=co_idx,
                        width_source=width_source,
                    )
                    out.append(_make_spec(
                        bench_slug=bench_slug,
                        family_label=family_label,
                        pipeline=[sub_layer, trans_layer],
                        coverage=CoverageVector(
                            layer_order=(sub_kind, "columnar"),
                            **cov_common,
                        ),
                        notes=(
                            f"L013 i3 {sub_kind}(sub={kw_sub}, "
                            f"alpha={mode.mode_label}) ∘ columnar"
                            f"(W={width}, co={co_tuple}) [sub-first]"
                        ),
                    ))
                    if len(out) >= per_family_cap:
                        break
                    out.append(_make_spec(
                        bench_slug=bench_slug,
                        family_label=family_label,
                        pipeline=[trans_layer, sub_layer],
                        coverage=CoverageVector(
                            layer_order=("columnar", sub_kind),
                            **cov_common,
                        ),
                        notes=(
                            f"L013 i3 columnar(W={width}, "
                            f"co={co_tuple}) ∘ {sub_kind}"
                            f"(sub={kw_sub}, alpha={mode.mode_label}) "
                            "[trans-first]"
                        ),
                    ))
    return out


def _gen_enumerated_caesar_columnar_atbash_family(
    *,
    bench_slug: str,
    shifts: Sequence[tuple[int, str]],
    clue_text: str,
    clue_keywords: Sequence[str],
    per_family_cap: int = _LESSON_013_PER_FAMILY_CAP,
) -> list[GeneratedSpec]:
    """LESSON-013 + LESSON-009: 3-layer ``caesar_columnar_atbash``
    sandwich with ENUMERATED col_orders. Mirrors
    ``_gen_caesar_three_layer_family(trans_kind="columnar", ...)`` but
    swaps the keyword-stable-rank columnar layer for an enumerated
    columnar layer.

    Emits all four canonical 3-layer orderings per (shift × width ×
    col_order). Family_label stays ``caesar_columnar_atbash``.
    """
    if not shifts:
        return []
    family_label = "caesar_columnar_atbash"
    atbash_layer = {"kind": "atbash", "alphabet": "AZ", "params": []}

    widths = _columnar_widths_for_payload(clue_text, clue_keywords)
    if not widths:
        return []

    out: list[GeneratedSpec] = []
    for width, width_source in widths:
        if len(out) >= per_family_cap:
            break
        keyword_co: list[list[int]] = []
        seen_co: set[tuple[int, ...]] = set()
        for kw in clue_keywords or []:
            if not isinstance(kw, str):
                continue
            u = kw.upper().strip()
            if u.isalpha() and len(u) == width:
                co = _keyword_to_col_order(u)
                t = tuple(co)
                if t not in seen_co:
                    seen_co.add(t)
                    keyword_co.append(co)
        col_orders = _enumerated_col_orders_for_width(
            width, dedup_against=keyword_co,
        )
        if not col_orders:
            continue
        for shift, op_source in shifts:
            if shift == 0:
                continue
            if len(out) >= per_family_cap:
                break
            caesar_layer = _caesar_layer(shift)
            for co_tuple, co_idx in col_orders:
                if len(out) >= per_family_cap:
                    break
                trans_layer = _explicit_columnar_layer(
                    width, list(co_tuple),
                )
                trans_role_value = f"W{width}_co{co_idx}"
                role = (
                    ("caesar_shift", str(shift)),
                    ("columnar", trans_role_value),
                )
                extras = (
                    ("caesar_shift", shift),
                    ("transposition_width", width),
                    ("col_order_index", co_idx),
                )
                cov_common = dict(
                    layer_family=family_label,
                    role_assignment=role,
                    alphabet="AZ",
                    n_layers=3,
                    extras=extras,
                    shift_value=shift,
                    operation_source=op_source,
                    transposition_width=width,
                    col_order=co_tuple,
                    col_order_source="enumerated_permutation",
                    col_order_index=co_idx,
                    width_source=width_source,
                    role_assignment_mode="enumerated_columnar",
                )
                # 1. caesar ∘ columnar ∘ atbash
                out.append(_make_spec(
                    bench_slug=bench_slug,
                    family_label=family_label,
                    pipeline=[caesar_layer, trans_layer, atbash_layer],
                    coverage=CoverageVector(
                        layer_order=("caesar", "columnar", "atbash"),
                        **cov_common,
                    ),
                    notes=(
                        f"L013 caesar({shift}) ∘ columnar"
                        f"(W={width}, co={co_tuple}) ∘ atbash"
                    ),
                    compute_budget_minutes=3,
                ))
                if len(out) >= per_family_cap:
                    break
                # 2. atbash ∘ columnar ∘ caesar
                out.append(_make_spec(
                    bench_slug=bench_slug,
                    family_label=family_label,
                    pipeline=[atbash_layer, trans_layer, caesar_layer],
                    coverage=CoverageVector(
                        layer_order=("atbash", "columnar", "caesar"),
                        **cov_common,
                    ),
                    notes=(
                        f"L013 atbash ∘ columnar(W={width}, "
                        f"co={co_tuple}) ∘ caesar({shift})"
                    ),
                    compute_budget_minutes=3,
                ))
                if len(out) >= per_family_cap:
                    break
                # 3. columnar ∘ caesar ∘ atbash
                out.append(_make_spec(
                    bench_slug=bench_slug,
                    family_label=family_label,
                    pipeline=[trans_layer, caesar_layer, atbash_layer],
                    coverage=CoverageVector(
                        layer_order=("columnar", "caesar", "atbash"),
                        **cov_common,
                    ),
                    notes=(
                        f"L013 columnar(W={width}, co={co_tuple}) "
                        f"∘ caesar({shift}) ∘ atbash"
                    ),
                    compute_budget_minutes=3,
                ))
                if len(out) >= per_family_cap:
                    break
                # 4. atbash ∘ caesar ∘ columnar
                out.append(_make_spec(
                    bench_slug=bench_slug,
                    family_label=family_label,
                    pipeline=[atbash_layer, caesar_layer, trans_layer],
                    coverage=CoverageVector(
                        layer_order=("atbash", "caesar", "columnar"),
                        **cov_common,
                    ),
                    notes=(
                        f"L013 atbash ∘ caesar({shift}) ∘ columnar"
                        f"(W={width}, co={co_tuple})"
                    ),
                    compute_budget_minutes=3,
                ))
    return out


# Per-family cap for the 3-layer columnar+sub+rail_fence family.
# The iteration order is
#   width → sub_kw → alpha → depth → col_order → ordering
# so the (first sub_kw, first alpha, first depth) tuple reaches its
# full W=5 enumeration before any other tuple starts. With the
# K4B-006 clue (3 widths × 3 depths × 2 sub_kws × 2 alphas × 6
# orderings, full universe ~27720 per family), the spec count to
# reach K4B-006's empirical winning config (W=5, co_idx=106,
# sub_kw=MIRROR, alpha=AZ, depth=4, ordering=(columnar, sub,
# rail_fence)) is:
#   W=3 enumerated for all (sub_kw, alpha, depth) tuples = 360
#   + W=5, MIRROR, AZ, depth=4, idx=0..106 × 6 orderings = 642
#   = 1002 specs
# Cap at 1200 to leave margin while still bounding the per-family
# universe under the global 10000 cap.
_LESSON_013_RAIL_FENCE_CAP: int = 1200


def _gen_enumerated_columnar_sub_rail_fence_family(
    *,
    bench_slug: str,
    sub_kind: str,
    keyword_a: str,
    keyword_b: str,
    rail_fence_depths: Sequence[int],
    clue_text: str,
    clue_keywords: Sequence[str],
    per_family_cap: int = _LESSON_013_RAIL_FENCE_CAP,
) -> list[GeneratedSpec]:
    """LESSON-013 + rail-fence 3-layer sandwich.

    Emits 3-layer specs of shape ``columnar(W, co) + <sub>(kw, alpha)
    + rail_fence(d)`` in every meaningful layer ordering. The
    columnar layer uses an ENUMERATED col_order (LESSON-013), the
    substitution uses a clue keyword, and the rail-fence uses one of
    the resolved depth candidates.

    Family_label: ``columnar_<sub>_rail_fence`` (NEW family, not a
    re-use of an existing label). The lesson registry's
    ``applies_to_families`` field grew to include this label so the
    drift test stays in sync.

    Layer orderings emitted: all 6 permutations of (columnar, sub,
    rail_fence). The K4B-006 winning ordering is
    ``(columnar, sub, rail_fence)`` — the first ordering in the
    deterministic enumeration.

    Universe per family with the default cap:
      widths × col_orders × sub_kws × alpha_modes × depths × orderings
      capped at ``_LESSON_013_RAIL_FENCE_CAP``.

    Real-K4 mode is unaffected (HCC bench-only via
    ``ProblemContext``).
    """
    if sub_kind not in _SUBSTITUTION_KEYWORD_KINDS:
        raise ValueError(
            f"_gen_enumerated_columnar_sub_rail_fence_family: "
            f"unsupported sub_kind {sub_kind!r}"
        )
    sub_kws_raw = [keyword_a, keyword_b]
    sub_kws: list[str] = []
    seen_sub: set[str] = set()
    for kw in sub_kws_raw:
        if not isinstance(kw, str):
            continue
        u = kw.upper().strip()
        if u and u.isalpha() and u not in seen_sub and len(u) >= 2:
            seen_sub.add(u)
            sub_kws.append(u)
    if not sub_kws:
        return []
    depths = [int(d) for d in rail_fence_depths if isinstance(d, int) and d >= 2]
    if not depths:
        return []

    family_label = f"columnar_{sub_kind}_rail_fence"
    alphabet_modes = _LESSON_013_ALPHABET_MODES

    widths = _columnar_widths_for_payload(clue_text, clue_keywords)
    if not widths:
        return []

    # Six canonical orderings, ENUMERATING all 3! permutations so the
    # K4B-006 (columnar, sub, rail_fence) ordering is reached.
    from itertools import permutations as _perm
    layer_orderings = list(_perm(("columnar", sub_kind, "rail_fence")))

    out: list[GeneratedSpec] = []
    for width, width_source in widths:
        if len(out) >= per_family_cap:
            break
        keyword_co: list[list[int]] = []
        seen_co: set[tuple[int, ...]] = set()
        for kw in clue_keywords or []:
            if not isinstance(kw, str):
                continue
            u = kw.upper().strip()
            if u.isalpha() and len(u) == width:
                co = _keyword_to_col_order(u)
                t = tuple(co)
                if t not in seen_co:
                    seen_co.add(t)
                    keyword_co.append(co)
        col_orders = _enumerated_col_orders_for_width(
            width, dedup_against=keyword_co,
        )
        if not col_orders:
            continue
        for sub_kw in sub_kws:
            if len(out) >= per_family_cap:
                break
            for mode in alphabet_modes:
                if len(out) >= per_family_cap:
                    break
                sub_layer = _keyword_substitution_layer(
                    sub_kind, sub_kw,
                    alphabet=mode.dsl_alphabet,
                    alphabet_keyword=mode.alphabet_keyword,
                )
                for depth in depths:
                    if len(out) >= per_family_cap:
                        break
                    rf_layer = _rail_fence_layer(depth)
                    for co_tuple, co_idx in col_orders:
                        if len(out) >= per_family_cap:
                            break
                        col_layer = _explicit_columnar_layer(
                            width, list(co_tuple),
                        )
                        layer_lookup = {
                            "columnar": col_layer,
                            sub_kind: sub_layer,
                            "rail_fence": rf_layer,
                        }
                        trans_role_value = f"W{width}_co{co_idx}"
                        role = (
                            (sub_kind, sub_kw),
                            ("columnar", trans_role_value),
                            ("rail_fence", str(depth)),
                        )
                        extras = (
                            ("transposition_width", width),
                            ("col_order_index", co_idx),
                            ("rail_fence_depth", depth),
                        )
                        for ordering in layer_orderings:
                            if len(out) >= per_family_cap:
                                break
                            pipeline = [
                                layer_lookup[k] for k in ordering
                            ]
                            cov = CoverageVector(
                                layer_family=family_label,
                                layer_order=ordering,
                                role_assignment=role,
                                alphabet=mode.mode_label,
                                n_layers=3,
                                alphabet_mode=mode.mode_label,
                                alphabet_source=mode.source,
                                substitution_keyword=sub_kw,
                                alphabet_keyword=mode.alphabet_keyword or "",
                                transposition_keyword="",
                                role_assignment_mode="enumerated_columnar",
                                transposition_width=width,
                                col_order=co_tuple,
                                col_order_source="enumerated_permutation",
                                col_order_index=co_idx,
                                width_source=width_source,
                                extras=extras,
                            )
                            out.append(_make_spec(
                                bench_slug=bench_slug,
                                family_label=family_label,
                                pipeline=pipeline,
                                coverage=cov,
                                notes=(
                                    f"L013 columnar(W={width}, "
                                    f"co={co_tuple}) ∘ {sub_kind}"
                                    f"({sub_kw}, alpha={mode.mode_label}) "
                                    f"∘ rail_fence({depth}) order={ordering}"
                                ),
                                compute_budget_minutes=3,
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


def _gen_reverse_blocks_alone_family(
    *,
    bench_slug: str,
    block_sizes: Sequence[tuple[int, str]],
    block_modes: Sequence[str] = ("reverse_partial", "truncate"),
) -> list[GeneratedSpec]:
    """LESSON-008: reverse_blocks as a single-layer transposition.

    Emits one spec per (block_size, block_mode) pair so the operator
    can observe which combinations the kernel scoring is closest on
    BEFORE composing with a substitution layer. No keywords involved
    — pure permutation.
    """
    family_label = "reverse_blocks"
    out: list[GeneratedSpec] = []
    for block_size, op_source in block_sizes:
        for mode in block_modes:
            layer = _reverse_blocks_layer(block_size, mode)
            cov = CoverageVector(
                layer_family=family_label,
                layer_order=("reverse_blocks",),
                role_assignment=(),
                alphabet="AZ", n_layers=1,
                extras=(("block_size", block_size), ("block_mode", mode)),
                alphabet_mode="AZ",
                alphabet_source="default",
                block_size=block_size,
                block_mode=mode,
                operation_source=op_source,
            )
            out.append(_make_spec(
                bench_slug=bench_slug, family_label=family_label,
                pipeline=[layer], coverage=cov,
                notes=(
                    f"reverse_blocks(size={block_size}, mode={mode}) "
                    f"[op_source={op_source}]"
                ),
                crib_alignment="post_transposition",
            ))
    return out


def _gen_reverse_blocks_substitution_family(
    *,
    bench_slug: str,
    sub_kind: str,                # vigenere | beaufort | variant_beaufort
    keyword_a: str,
    keyword_b: str,
    block_sizes: Sequence[tuple[int, str]],
    alphabet_modes: Optional[Sequence[AlphabetMode]] = None,
    block_modes: Sequence[str] = ("reverse_partial", "truncate"),
) -> list[GeneratedSpec]:
    """LESSON-008: reverse_blocks paired with a keyword substitution.

    Emits BOTH layer orders (sub-first / trans-first) per (keyword,
    block_size, block_mode, alphabet_mode) tuple. Like
    ``_gen_keywordless_trans_pair_family`` the role-permutation
    collapses to "which keyword is the sub keyword?", because the
    transposition is keyword-free.
    """
    if sub_kind not in _SUBSTITUTION_KEYWORD_KINDS:
        raise ValueError(f"unsupported sub_kind {sub_kind!r}")
    family_label = f"reverse_blocks_{sub_kind}"
    if alphabet_modes is None:
        alphabet_modes = (AlphabetMode("AZ", "AZ", None, "default"),)

    out: list[GeneratedSpec] = []
    for kw in (keyword_a, keyword_b):
        if not isinstance(kw, str) or len(kw) < 1:
            continue
        for mode in alphabet_modes:
            sub_layer = _keyword_substitution_layer(
                sub_kind, kw,
                alphabet=mode.dsl_alphabet,
                alphabet_keyword=mode.alphabet_keyword,
            )
            for block_size, op_source in block_sizes:
                for bmode in block_modes:
                    rb_layer = _reverse_blocks_layer(block_size, bmode)
                    role = ((sub_kind, kw),)
                    extras = (
                        ("block_size", block_size),
                        ("block_mode", bmode),
                    )
                    # Order 1: substitution first
                    out.append(_make_spec(
                        bench_slug=bench_slug,
                        family_label=family_label,
                        pipeline=[sub_layer, rb_layer],
                        coverage=CoverageVector(
                            layer_family=family_label,
                            layer_order=(sub_kind, "reverse_blocks"),
                            role_assignment=role,
                            alphabet=mode.mode_label, n_layers=2,
                            extras=extras,
                            alphabet_mode=mode.mode_label,
                            alphabet_source=mode.source,
                            block_size=block_size,
                            block_mode=bmode,
                            operation_source=op_source,
                        ),
                        notes=(
                            f"{sub_kind}({kw}, alpha={mode.mode_label}) ∘ "
                            f"reverse_blocks({block_size}, {bmode}) "
                            "[sub-first]"
                        ),
                    ))
                    # Order 2: reverse_blocks first
                    out.append(_make_spec(
                        bench_slug=bench_slug,
                        family_label=family_label,
                        pipeline=[rb_layer, sub_layer],
                        coverage=CoverageVector(
                            layer_family=family_label,
                            layer_order=("reverse_blocks", sub_kind),
                            role_assignment=role,
                            alphabet=mode.mode_label, n_layers=2,
                            extras=extras,
                            alphabet_mode=mode.mode_label,
                            alphabet_source=mode.source,
                            block_size=block_size,
                            block_mode=bmode,
                            operation_source=op_source,
                        ),
                        notes=(
                            f"reverse_blocks({block_size}, {bmode}) ∘ "
                            f"{sub_kind}({kw}, alpha={mode.mode_label}) "
                            "[trans-first]"
                        ),
                    ))
    return out


def _gen_reverse_blocks_atbash_family(
    *,
    bench_slug: str,
    block_sizes: Sequence[tuple[int, str]],
    block_modes: Sequence[str] = ("reverse_partial", "truncate"),
) -> list[GeneratedSpec]:
    """LESSON-008: reverse_blocks paired with parameter-free Atbash.

    Atbash takes no parameters, so there is no role-permutation; only
    the layer-order flip matters. Emits 2 specs per
    (block_size, block_mode).
    """
    family_label = "reverse_blocks_atbash"
    atbash_layer = {"kind": "atbash", "alphabet": "AZ", "params": []}
    out: list[GeneratedSpec] = []
    for block_size, op_source in block_sizes:
        for bmode in block_modes:
            rb_layer = _reverse_blocks_layer(block_size, bmode)
            extras = (("block_size", block_size), ("block_mode", bmode))
            # atbash + reverse_blocks
            out.append(_make_spec(
                bench_slug=bench_slug, family_label=family_label,
                pipeline=[atbash_layer, rb_layer],
                coverage=CoverageVector(
                    layer_family=family_label,
                    layer_order=("atbash", "reverse_blocks"),
                    role_assignment=(),
                    alphabet="AZ", n_layers=2,
                    extras=extras,
                    block_size=block_size, block_mode=bmode,
                    operation_source=op_source,
                ),
                notes=(
                    f"atbash ∘ reverse_blocks({block_size}, {bmode}) "
                    "[atbash-first]"
                ),
            ))
            # reverse_blocks + atbash
            out.append(_make_spec(
                bench_slug=bench_slug, family_label=family_label,
                pipeline=[rb_layer, atbash_layer],
                coverage=CoverageVector(
                    layer_family=family_label,
                    layer_order=("reverse_blocks", "atbash"),
                    role_assignment=(),
                    alphabet="AZ", n_layers=2,
                    extras=extras,
                    block_size=block_size, block_mode=bmode,
                    operation_source=op_source,
                ),
                notes=(
                    f"reverse_blocks({block_size}, {bmode}) ∘ atbash "
                    "[trans-first]"
                ),
            ))
    return out


def _gen_reverse_blocks_caesar_family(
    *,
    bench_slug: str,
    block_sizes: Sequence[tuple[int, str]],
    shifts: Sequence[int] = _DEFAULT_REV_BLOCKS_CAESAR_SHIFTS,
    block_modes: Sequence[str] = ("reverse_partial", "truncate"),
) -> list[GeneratedSpec]:
    """LESSON-008: reverse_blocks paired with a Caesar shift.

    Caesar is implemented as a single-letter Vigenere keyword
    (shift k → keyword=chr(A+k)) so the existing dispatcher path
    handles it without a new DSL kind. The family_label preserves
    "caesar" so coverage analysis can answer "have we tested
    reverse_blocks ∘ caesar(shift=5)?".
    """
    family_label = "reverse_blocks_caesar"
    out: list[GeneratedSpec] = []
    for shift in shifts:
        if shift == 0 or not 1 <= shift <= 25:
            continue
        kw = _shift_to_keyword(shift)
        # Caesar uses canonical AZ — KA / mirrored modes are
        # collapsed because a single-letter shift over a non-AZ
        # alphabet is just a different shift constant; no extra
        # information is exposed.
        sub_layer = _keyword_substitution_layer(
            "vigenere", kw, alphabet="AZ", alphabet_keyword=None,
        )
        for block_size, op_source in block_sizes:
            for bmode in block_modes:
                rb_layer = _reverse_blocks_layer(block_size, bmode)
                role = (("caesar_shift", str(shift)),)
                extras = (
                    ("block_size", block_size),
                    ("block_mode", bmode),
                    ("caesar_shift", shift),
                )
                # caesar + reverse_blocks
                out.append(_make_spec(
                    bench_slug=bench_slug, family_label=family_label,
                    pipeline=[sub_layer, rb_layer],
                    coverage=CoverageVector(
                        layer_family=family_label,
                        layer_order=("caesar", "reverse_blocks"),
                        role_assignment=role,
                        alphabet="AZ", n_layers=2,
                        extras=extras,
                        block_size=block_size, block_mode=bmode,
                        operation_source=op_source,
                    ),
                    notes=(
                        f"caesar(shift={shift}) ∘ "
                        f"reverse_blocks({block_size}, {bmode}) "
                        "[caesar-first]"
                    ),
                ))
                # reverse_blocks + caesar
                out.append(_make_spec(
                    bench_slug=bench_slug, family_label=family_label,
                    pipeline=[rb_layer, sub_layer],
                    coverage=CoverageVector(
                        layer_family=family_label,
                        layer_order=("reverse_blocks", "caesar"),
                        role_assignment=role,
                        alphabet="AZ", n_layers=2,
                        extras=extras,
                        block_size=block_size, block_mode=bmode,
                        operation_source=op_source,
                    ),
                    notes=(
                        f"reverse_blocks({block_size}, {bmode}) ∘ "
                        f"caesar(shift={shift}) [trans-first]"
                    ),
                ))
    return out


def _gen_reverse_blocks_three_layer_family(
    *,
    bench_slug: str,
    sub_kind: str,                # vigenere | beaufort | variant_beaufort
    sandwich_partner: str,        # "atbash" | "caesar"
    keyword_a: str,
    keyword_b: str,
    block_sizes: Sequence[tuple[int, str]],
    shifts: Sequence[int] = _DEFAULT_REV_BLOCKS_CAESAR_SHIFTS,
    block_modes: Sequence[str] = ("reverse_partial",),
    alphabet_modes: Optional[Sequence[AlphabetMode]] = None,
) -> list[GeneratedSpec]:
    """LESSON-008 three-layer sandwich: ``sub`` ∘ ``reverse_blocks`` ∘
    ``partner`` where partner is Atbash or Caesar(shift). Only fires
    when the clue pack carries BOTH a block-reversal trigger AND a
    shift / rotation trigger; the caller is responsible for that gate.

    To keep the universe bounded, three-layer sandwiches default to
    a single ``block_mode`` ("reverse_partial") and a small Caesar
    shift set when partner=="caesar". Substitution alphabets follow
    the standard ``alphabet_modes``.
    """
    if sub_kind not in _SUBSTITUTION_KEYWORD_KINDS:
        raise ValueError(f"unsupported sub_kind {sub_kind!r}")
    if sandwich_partner not in ("atbash", "caesar"):
        raise ValueError(
            f"sandwich_partner must be in {{'atbash', 'caesar'}}; "
            f"got {sandwich_partner!r}"
        )
    family_label = f"{sub_kind}_reverse_blocks_{sandwich_partner}"
    if alphabet_modes is None:
        alphabet_modes = (AlphabetMode("AZ", "AZ", None, "default"),)

    if sandwich_partner == "atbash":
        partner_specs: list[tuple[dict[str, Any], int]] = [
            ({"kind": "atbash", "alphabet": "AZ", "params": []}, 0),
        ]
    else:  # caesar
        partner_specs = []
        for s in shifts:
            if s == 0 or not 1 <= s <= 25:
                continue
            partner_specs.append((
                _keyword_substitution_layer(
                    "vigenere", _shift_to_keyword(s),
                    alphabet="AZ", alphabet_keyword=None,
                ),
                s,
            ))

    out: list[GeneratedSpec] = []
    for kw in (keyword_a, keyword_b):
        if not isinstance(kw, str) or len(kw) < 1:
            continue
        for mode in alphabet_modes:
            sub_layer = _keyword_substitution_layer(
                sub_kind, kw,
                alphabet=mode.dsl_alphabet,
                alphabet_keyword=mode.alphabet_keyword,
            )
            for block_size, op_source in block_sizes:
                for bmode in block_modes:
                    rb_layer = _reverse_blocks_layer(block_size, bmode)
                    for partner_layer, shift_value in partner_specs:
                        if sandwich_partner == "atbash":
                            role = ((sub_kind, kw),)
                            partner_label = "atbash"
                        else:
                            role = (
                                (sub_kind, kw),
                                ("caesar_shift", str(shift_value)),
                            )
                            partner_label = f"caesar({shift_value})"
                        extras = (
                            ("block_size", block_size),
                            ("block_mode", bmode),
                        )
                        if sandwich_partner == "caesar":
                            extras = extras + (
                                ("caesar_shift", shift_value),
                            )
                        out.append(_make_spec(
                            bench_slug=bench_slug,
                            family_label=family_label,
                            pipeline=[sub_layer, rb_layer, partner_layer],
                            coverage=CoverageVector(
                                layer_family=family_label,
                                layer_order=(
                                    sub_kind, "reverse_blocks",
                                    sandwich_partner,
                                ),
                                role_assignment=role,
                                alphabet=mode.mode_label, n_layers=3,
                                extras=extras,
                                alphabet_mode=mode.mode_label,
                                alphabet_source=mode.source,
                                block_size=block_size,
                                block_mode=bmode,
                                operation_source=op_source,
                            ),
                            notes=(
                                f"{sub_kind}({kw}, alpha={mode.mode_label}) "
                                f"∘ reverse_blocks({block_size}, {bmode}) "
                                f"∘ {partner_label}"
                            ),
                            compute_budget_minutes=3,
                        ))
    return out


def _gen_caesar_alone_family(
    *,
    bench_slug: str,
    shifts: Sequence[tuple[int, str]],
) -> list[GeneratedSpec]:
    """LESSON-009: canonical Caesar / ROT layer alone.

    Emits one spec per shift value. Shift 0 is excluded (identity).
    The coverage_vector carries shift_value + operation_source so
    telemetry distinguishes Caesar(8) from a 1-letter Vigenere(I).
    """
    family_label = "caesar"
    out: list[GeneratedSpec] = []
    for shift, op_source in shifts:
        if shift == 0:
            continue
        layer = _caesar_layer(shift)
        cov = CoverageVector(
            layer_family=family_label,
            layer_order=("caesar",),
            role_assignment=(("caesar_shift", str(shift)),),
            alphabet="AZ", n_layers=1,
            extras=(("caesar_shift", shift),),
            shift_value=shift,
            operation_source=op_source,
        )
        out.append(_make_spec(
            bench_slug=bench_slug, family_label=family_label,
            pipeline=[layer], coverage=cov,
            notes=(
                f"caesar(shift={shift}) [op_source={op_source}]"
            ),
            crib_alignment="direct_positional",
        ))
    return out


def _gen_caesar_keyword_transposition_family(
    *,
    bench_slug: str,
    trans_kind: str,                  # "columnar" | "myszkowski"
    keyword_a: str,
    keyword_b: str,
    shifts: Sequence[tuple[int, str]],
) -> list[GeneratedSpec]:
    """LESSON-009: Caesar + keyword transposition in BOTH layer orders.

    For trans_kind in {columnar, myszkowski}, emits one spec per
    (keyword × shift × layer_order) tuple. The transposition keyword
    is clue-derived (caller passes ``keyword_a`` / ``keyword_b`` from
    the clue extraction); Caesar shift values come from the
    LESSON-009 ``_caesar_shifts_for_payload`` enumeration. Layer
    family label = ``caesar_<trans_kind>`` so coverage analysis
    answers "have we tested caesar(8) + columnar(RIVET) in both
    orders?".
    """
    if trans_kind not in ("columnar", "myszkowski"):
        raise ValueError(
            f"_gen_caesar_keyword_transposition_family: unsupported "
            f"trans_kind {trans_kind!r}; expected columnar / myszkowski"
        )
    family_label = f"caesar_{trans_kind}"

    def _trans_layer(kw: str) -> dict[str, Any]:
        if trans_kind == "columnar":
            return _keyword_columnar_layer(kw)
        return _keyword_myszkowski_layer(kw)

    out: list[GeneratedSpec] = []
    for kw in (keyword_a, keyword_b):
        if not isinstance(kw, str) or len(kw) < 2:
            continue
        trans_layer = _trans_layer(kw)
        for shift, op_source in shifts:
            if shift == 0:
                continue
            caesar_layer = _caesar_layer(shift)
            role = (
                ("caesar_shift", str(shift)),
                (trans_kind, kw),
            )
            extras = (("caesar_shift", shift),)
            # Order 1: Caesar first
            out.append(_make_spec(
                bench_slug=bench_slug, family_label=family_label,
                pipeline=[caesar_layer, trans_layer],
                coverage=CoverageVector(
                    layer_family=family_label,
                    layer_order=("caesar", trans_kind),
                    role_assignment=role,
                    alphabet="AZ", n_layers=2,
                    extras=extras,
                    shift_value=shift,
                    operation_source=op_source,
                ),
                notes=(
                    f"caesar(shift={shift}) ∘ {trans_kind}({kw}) "
                    "[caesar-first]"
                ),
            ))
            # Order 2: Transposition first
            out.append(_make_spec(
                bench_slug=bench_slug, family_label=family_label,
                pipeline=[trans_layer, caesar_layer],
                coverage=CoverageVector(
                    layer_family=family_label,
                    layer_order=(trans_kind, "caesar"),
                    role_assignment=role,
                    alphabet="AZ", n_layers=2,
                    extras=extras,
                    shift_value=shift,
                    operation_source=op_source,
                ),
                notes=(
                    f"{trans_kind}({kw}) ∘ caesar(shift={shift}) "
                    "[trans-first]"
                ),
            ))
    return out


def _gen_caesar_keywordless_transposition_family(
    *,
    bench_slug: str,
    trans_kind: str,                  # "rail_fence" | "route"
    shifts: Sequence[tuple[int, str]],
    rail_fence_depths: Sequence[int] = (3, 5),
    route_grids: Sequence[tuple[int, int]] = ((7, 14), (10, 10)),
) -> list[GeneratedSpec]:
    """LESSON-009: Caesar + keywordless transposition (rail_fence /
    route) in BOTH layer orders.

    Rail-fence iterates depth from the resolved depth set (clue
    numerals + safe defaults). Route iterates the project default
    grids (7×14, 10×10) at the serpentine variant.
    """
    if trans_kind not in ("rail_fence", "route"):
        raise ValueError(
            f"_gen_caesar_keywordless_transposition_family: "
            f"unsupported trans_kind {trans_kind!r}"
        )
    family_label = f"caesar_{trans_kind}"

    if trans_kind == "rail_fence":
        trans_specs = [
            (
                _rail_fence_layer(depth),
                (("rail_fence_depth", depth),),
            )
            for depth in rail_fence_depths
        ]
    else:  # route
        trans_specs = [
            (
                _route_layer(variant="serpentine", rows=r, cols=c),
                (("route_rows", r), ("route_cols", c)),
            )
            for r, c in route_grids
        ]

    out: list[GeneratedSpec] = []
    for trans_layer, trans_extras in trans_specs:
        for shift, op_source in shifts:
            if shift == 0:
                continue
            caesar_layer = _caesar_layer(shift)
            role = (("caesar_shift", str(shift)),)
            extras = (("caesar_shift", shift),) + trans_extras
            # Order 1: Caesar first
            out.append(_make_spec(
                bench_slug=bench_slug, family_label=family_label,
                pipeline=[caesar_layer, trans_layer],
                coverage=CoverageVector(
                    layer_family=family_label,
                    layer_order=("caesar", trans_kind),
                    role_assignment=role,
                    alphabet="AZ", n_layers=2,
                    extras=extras,
                    shift_value=shift,
                    operation_source=op_source,
                ),
                notes=(
                    f"caesar(shift={shift}) ∘ {trans_kind}{trans_extras} "
                    "[caesar-first]"
                ),
            ))
            # Order 2: Transposition first
            out.append(_make_spec(
                bench_slug=bench_slug, family_label=family_label,
                pipeline=[trans_layer, caesar_layer],
                coverage=CoverageVector(
                    layer_family=family_label,
                    layer_order=(trans_kind, "caesar"),
                    role_assignment=role,
                    alphabet="AZ", n_layers=2,
                    extras=extras,
                    shift_value=shift,
                    operation_source=op_source,
                ),
                notes=(
                    f"{trans_kind}{trans_extras} ∘ caesar(shift={shift}) "
                    "[trans-first]"
                ),
            ))
    return out


def _gen_caesar_atbash_family(
    *,
    bench_slug: str,
    shifts: Sequence[tuple[int, str]],
) -> list[GeneratedSpec]:
    """LESSON-009: Caesar + Atbash (parameter-free) in BOTH orders."""
    family_label = "caesar_atbash"
    atbash_layer = {"kind": "atbash", "alphabet": "AZ", "params": []}
    out: list[GeneratedSpec] = []
    for shift, op_source in shifts:
        if shift == 0:
            continue
        caesar_layer = _caesar_layer(shift)
        role = (("caesar_shift", str(shift)),)
        extras = (("caesar_shift", shift),)
        # caesar + atbash
        out.append(_make_spec(
            bench_slug=bench_slug, family_label=family_label,
            pipeline=[caesar_layer, atbash_layer],
            coverage=CoverageVector(
                layer_family=family_label,
                layer_order=("caesar", "atbash"),
                role_assignment=role,
                alphabet="AZ", n_layers=2,
                extras=extras,
                shift_value=shift,
                operation_source=op_source,
            ),
            notes=f"caesar(shift={shift}) ∘ atbash [caesar-first]",
        ))
        # atbash + caesar
        out.append(_make_spec(
            bench_slug=bench_slug, family_label=family_label,
            pipeline=[atbash_layer, caesar_layer],
            coverage=CoverageVector(
                layer_family=family_label,
                layer_order=("atbash", "caesar"),
                role_assignment=role,
                alphabet="AZ", n_layers=2,
                extras=extras,
                shift_value=shift,
                operation_source=op_source,
            ),
            notes=f"atbash ∘ caesar(shift={shift}) [atbash-first]",
        ))
    return out


def _gen_caesar_three_layer_family(
    *,
    bench_slug: str,
    trans_kind: str,
    keyword: str,
    shifts: Sequence[tuple[int, str]],
    rail_fence_depth: Optional[int] = None,
    route_grid: Optional[tuple[int, int]] = None,
) -> list[GeneratedSpec]:
    """LESSON-009: three-layer sandwiches over Caesar + transposition
    + Atbash, in all four meaningful orderings.

    Orderings:
      1. caesar    ∘ transposition ∘ atbash
      2. atbash    ∘ transposition ∘ caesar
      3. transposition ∘ caesar    ∘ atbash
      4. atbash    ∘ caesar         ∘ transposition

    For keyword transpositions (columnar, myszkowski) the keyword is
    clue-derived. For keywordless transpositions (rail_fence, route)
    the caller passes the depth or grid via the optional params.
    """
    if trans_kind == "columnar":
        if not isinstance(keyword, str) or len(keyword) < 2:
            return []
        trans_layer = _keyword_columnar_layer(keyword)
        trans_role = (trans_kind, keyword)
        trans_extras: tuple[tuple[str, Any], ...] = ()
    elif trans_kind == "myszkowski":
        if not isinstance(keyword, str) or len(keyword) < 2:
            return []
        trans_layer = _keyword_myszkowski_layer(keyword)
        trans_role = (trans_kind, keyword)
        trans_extras = ()
    elif trans_kind == "rail_fence":
        depth = int(rail_fence_depth or 3)
        trans_layer = _rail_fence_layer(depth)
        trans_role = (trans_kind, str(depth))
        trans_extras = (("rail_fence_depth", depth),)
    elif trans_kind == "route":
        rows, cols = route_grid or (7, 14)
        trans_layer = _route_layer(variant="serpentine", rows=rows, cols=cols)
        trans_role = (trans_kind, f"{rows}x{cols}")
        trans_extras = (("route_rows", rows), ("route_cols", cols))
    else:
        raise ValueError(
            f"_gen_caesar_three_layer_family: unsupported trans_kind "
            f"{trans_kind!r}"
        )

    family_label = f"caesar_{trans_kind}_atbash"
    atbash_layer = {"kind": "atbash", "alphabet": "AZ", "params": []}

    out: list[GeneratedSpec] = []
    for shift, op_source in shifts:
        if shift == 0:
            continue
        caesar_layer = _caesar_layer(shift)
        role = (
            ("caesar_shift", str(shift)),
            trans_role,
        )
        extras = (("caesar_shift", shift),) + trans_extras
        # 1. caesar ∘ transposition ∘ atbash
        out.append(_make_spec(
            bench_slug=bench_slug, family_label=family_label,
            pipeline=[caesar_layer, trans_layer, atbash_layer],
            coverage=CoverageVector(
                layer_family=family_label,
                layer_order=("caesar", trans_kind, "atbash"),
                role_assignment=role,
                alphabet="AZ", n_layers=3,
                extras=extras,
                shift_value=shift,
                operation_source=op_source,
            ),
            notes=(
                f"caesar({shift}) ∘ {trans_kind}{trans_extras} ∘ atbash"
            ),
            compute_budget_minutes=3,
        ))
        # 2. atbash ∘ transposition ∘ caesar
        out.append(_make_spec(
            bench_slug=bench_slug, family_label=family_label,
            pipeline=[atbash_layer, trans_layer, caesar_layer],
            coverage=CoverageVector(
                layer_family=family_label,
                layer_order=("atbash", trans_kind, "caesar"),
                role_assignment=role,
                alphabet="AZ", n_layers=3,
                extras=extras,
                shift_value=shift,
                operation_source=op_source,
            ),
            notes=(
                f"atbash ∘ {trans_kind}{trans_extras} ∘ caesar({shift})"
            ),
            compute_budget_minutes=3,
        ))
        # 3. transposition ∘ caesar ∘ atbash
        out.append(_make_spec(
            bench_slug=bench_slug, family_label=family_label,
            pipeline=[trans_layer, caesar_layer, atbash_layer],
            coverage=CoverageVector(
                layer_family=family_label,
                layer_order=(trans_kind, "caesar", "atbash"),
                role_assignment=role,
                alphabet="AZ", n_layers=3,
                extras=extras,
                shift_value=shift,
                operation_source=op_source,
            ),
            notes=(
                f"{trans_kind}{trans_extras} ∘ caesar({shift}) ∘ atbash"
            ),
            compute_budget_minutes=3,
        ))
        # 4. atbash ∘ caesar ∘ transposition
        out.append(_make_spec(
            bench_slug=bench_slug, family_label=family_label,
            pipeline=[atbash_layer, caesar_layer, trans_layer],
            coverage=CoverageVector(
                layer_family=family_label,
                layer_order=("atbash", "caesar", trans_kind),
                role_assignment=role,
                alphabet="AZ", n_layers=3,
                extras=extras,
                shift_value=shift,
                operation_source=op_source,
            ),
            notes=(
                f"atbash ∘ caesar({shift}) ∘ {trans_kind}{trans_extras}"
            ),
            compute_budget_minutes=3,
        ))
    return out


# ----------------------------------------------------------------------------
# LESSON-018: numeric Caesar promotion family generators
# ----------------------------------------------------------------------------
#
# These generators run when ``_detect_numeric_caesar_promotion``
# returns non-empty AND ``_detect_caesar_trigger`` returns False (so
# we don't double-emit Caesar specs already covered by the legacy
# explicit-trigger path). The matrix is deliberately small:
#
#   - caesar alone (1 spec per shift)
#   - caesar + route_boustrophedon (both layer orders) when the
#     boustrophedon trigger also fired
#   - caesar + route_diagonal (both layer orders) when the
#     diagonal trigger also fired
#   - caesar + row_reverse (both layer orders) when the row_reverse
#     trigger also fired
#
# A shift n produces both n and (26 - n) % 26 entries (skipping
# self-complement n=13 and the identity 0). All emitted specs
# carry ``numeric_trigger_without_caesar_word=True`` plus the
# LESSON-018 telemetry fields.


def _coverage_kwargs_from_promoted(
    p: dict[str, Any],
    *,
    numeric_only: bool,
) -> dict[str, Any]:
    """Build the LESSON-018 telemetry kwargs for a CoverageVector.

    ``p`` is a single entry from
    ``_expand_caesar_shifts_with_complement`` (so it carries
    shift_value, shift_direction, role, token, shift_source,
    value).
    """
    return {
        "shift_value": int(p["shift_value"]),
        "shift_source": str(p["shift_source"]),
        "shift_token": str(p["token"]),
        "shift_role": str(p["role"]),
        "shift_direction": str(p["shift_direction"]),
        "numeric_trigger_without_caesar_word": bool(numeric_only),
    }


def _gen_numeric_caesar_alone_family(
    *,
    bench_slug: str,
    promoted_shifts: Sequence[dict[str, Any]],
    numeric_only: bool,
) -> list[GeneratedSpec]:
    """Emit caesar-alone specs from numerically-promoted shifts.

    Each promoted shift produces ONE spec. Shift 0 is excluded.
    The coverage_vector carries the LESSON-018 telemetry plus the
    legacy ``shift_value`` + ``operation_source`` fields so
    downstream rollups continue to work.
    """
    family_label = "caesar"
    out: list[GeneratedSpec] = []
    for p in promoted_shifts:
        shift = int(p["shift_value"])
        if shift == 0:
            continue
        layer = _caesar_layer(shift)
        cov_kwargs = _coverage_kwargs_from_promoted(
            p, numeric_only=numeric_only,
        )
        cov = CoverageVector(
            layer_family=family_label,
            layer_order=("caesar",),
            role_assignment=(("caesar_shift", str(shift)),),
            alphabet="AZ", n_layers=1,
            extras=(("caesar_shift", shift),),
            operation_source="numeric_caesar_trigger",
            **cov_kwargs,
        )
        out.append(_make_spec(
            bench_slug=bench_slug, family_label=family_label,
            pipeline=[layer], coverage=cov,
            notes=(
                f"caesar(shift={shift}) "
                f"[numeric_promotion={p['shift_source']}, "
                f"token={p['token']}, dir={p['shift_direction']}]"
            ),
            crib_alignment="direct_positional",
        ))
    return out


def _gen_numeric_caesar_route_pair_family(
    *,
    bench_slug: str,
    route_partner_kind: str,            # "route_boustrophedon" |
                                         # "route_diagonal" |
                                         # "row_reverse"
    route_layer_factory,                 # callable() → list[layer dict]
                                         # (each entry: a route layer
                                         # ready for spec emission)
    route_partner_extras_factory,        # callable(layer) → tuple[(k, v), ...]
    promoted_shifts: Sequence[dict[str, Any]],
    numeric_only: bool,
    coverage_extras_factory=None,        # callable(layer) → dict
                                         # (extra fields for CV)
) -> list[GeneratedSpec]:
    """Generic emitter: caesar + <route_partner> in BOTH layer orders.

    The factory pattern decouples this from the specific route
    family generators. Caller supplies a ``route_layer_factory()``
    that returns one or more route layer dicts; for each route
    layer × promoted shift, we emit both [caesar, route] and
    [route, caesar] specs.
    """
    family_label = f"caesar_{route_partner_kind}"
    out: list[GeneratedSpec] = []
    route_layers = list(route_layer_factory())
    for p in promoted_shifts:
        shift = int(p["shift_value"])
        if shift == 0:
            continue
        caesar_layer = _caesar_layer(shift)
        cov_telemetry = _coverage_kwargs_from_promoted(
            p, numeric_only=numeric_only,
        )
        for route_layer in route_layers:
            partner_extras = route_partner_extras_factory(route_layer)
            extras = (
                ("caesar_shift", shift),
            ) + partner_extras
            extra_cov = (
                coverage_extras_factory(route_layer)
                if coverage_extras_factory else {}
            )
            common = {
                "layer_family": family_label,
                "role_assignment": (("caesar_shift", str(shift)),),
                "alphabet": "AZ", "n_layers": 2,
                "extras": extras,
                "operation_source": "numeric_caesar_trigger",
                **cov_telemetry,
                **extra_cov,
            }
            # Order 1: caesar first.
            out.append(_make_spec(
                bench_slug=bench_slug, family_label=family_label,
                pipeline=[caesar_layer, route_layer],
                coverage=CoverageVector(
                    layer_order=("caesar", route_partner_kind),
                    **common,
                ),
                notes=(
                    f"caesar({shift}) ∘ {route_partner_kind} "
                    f"[caesar-first, numeric_promotion="
                    f"{p['shift_source']}, dir={p['shift_direction']}]"
                ),
            ))
            # Order 2: route first.
            out.append(_make_spec(
                bench_slug=bench_slug, family_label=family_label,
                pipeline=[route_layer, caesar_layer],
                coverage=CoverageVector(
                    layer_order=(route_partner_kind, "caesar"),
                    **common,
                ),
                notes=(
                    f"{route_partner_kind} ∘ caesar({shift}) "
                    f"[route-first, numeric_promotion="
                    f"{p['shift_source']}, dir={p['shift_direction']}]"
                ),
            ))
    return out


# ----------------------------------------------------------------------------
# LESSON-019: role-complete numeric-route-columnar three-layer composition
# ----------------------------------------------------------------------------
#
# Pre-LESSON-019 the controller had each role detector independently:
#   - LESSON-018 promoted clue numerals to Caesar/ROT shifts,
#   - LESSON-014 / LESSON-016 enumerated route_boustrophedon /
#     route_diagonal layers from clue widths and grid wording,
#   - the legacy keyword logic enumerated columnar layers from clue
#     keywords.
# But when ALL THREE role classes fired on the same clue, no family
# generator emitted a three-layer composition combining them. This
# is the role-complete composition gap LESSON-019 closes.
#
# The generator is purely additive over the existing role detectors:
# it does NOT introduce any new primitive, does NOT widen any
# detector vocabulary, and does NOT touch real-K4 mode (HCC is
# bench-mode only via _collect_hcc_seeds).
#
# Cardinality bound on a multi-trigger clue:
#   N_shifts (≤ ~4 from LESSON-018: as_given + complement, dedup'd)
#   × N_route_layers (≤ ~8 — bounded by route_layer_factory caller)
#   × N_columnar_keywords (≤ 2 — keyword_a, keyword_b)
#   × 6 layer-order permutations
# Per route partner: ≤ 4 × 8 × 2 × 6 = 384 specs in the worst case;
# realistic K4B clues land at 96-192. The LESSON-017 stratified
# scheduler classifies LESSON-019 families as three_layer_sandwich
# (quota=40 each) so per-family retention stays bounded regardless
# of the upstream cardinality.


# Decryption-order layer-order permutations for the role-complete
# three-layer composition. Six distinct orderings cover all valid
# encrypt/decrypt-direction interpretations of "caesar + route +
# columnar" without privileging one. The route_kind placeholder is
# substituted with the concrete route_partner_kind at emission
# time.
_LESSON_019_LAYER_ORDERS: tuple[tuple[str, str, str], ...] = (
    ("caesar",   "<route>",  "columnar"),  # caesar → route → columnar
    ("caesar",   "columnar", "<route>"),   # caesar → columnar → route
    ("<route>",  "caesar",   "columnar"),  # route  → caesar → columnar
    ("<route>",  "columnar", "caesar"),    # route  → columnar → caesar
    ("columnar", "caesar",   "<route>"),   # columnar → caesar → route
    ("columnar", "<route>",  "caesar"),    # columnar → route → caesar
)


def _resolve_lesson_019_layer_orders(
    route_partner_kind: str,
) -> tuple[tuple[str, str, str], ...]:
    """Substitute the concrete route partner kind into
    ``_LESSON_019_LAYER_ORDERS`` to get the actual ordering tuples.
    """
    return tuple(
        tuple(
            route_partner_kind if seg == "<route>" else seg
            for seg in order
        )
        for order in _LESSON_019_LAYER_ORDERS
    )


def _gen_numeric_caesar_route_columnar_family(
    *,
    bench_slug: str,
    route_partner_kind: str,             # "route_boustrophedon" |
                                         # "route_diagonal"
    route_layer_factory,                 # callable() → list[layer dict]
    route_partner_extras_factory,        # callable(layer) → tuple[(k, v), ...]
    coverage_extras_factory,             # callable(layer) → dict
    promoted_shifts: Sequence[dict[str, Any]],
    columnar_keywords: Sequence[str],
    numeric_only: bool = True,
) -> list[GeneratedSpec]:
    """LESSON-019: caesar + route + columnar three-layer family.

    Emits one spec per (promoted_shift, route_layer, columnar_keyword,
    layer_order) tuple. Six layer-order permutations cover all
    decrypt-direction interpretations of the role triple. Caller is
    expected to pre-cap ``route_layer_factory`` output and
    ``columnar_keywords`` so the cartesian universe stays bounded;
    the LESSON-017 scheduler enforces a final per-family quota.

    Required role triple:
      - numeric Caesar/ROT shift (from LESSON-018 promotion)
      - route layer (from LESSON-014 boustrophedon or LESSON-016
        diagonal generators)
      - columnar keyword (length >= 2 — single-character keywords
        produce degenerate column orders and are silently skipped)

    All emitted specs carry:
      - layer_family = "caesar_<route_partner_kind>_columnar"
      - layer_order  = one of six permutations
      - operation_source = "numeric_route_columnar_composition"
      - role_assignment_mode = "numeric_route_columnar_three_role"
      - LESSON-018 numeric-promotion telemetry (shift_*,
        numeric_trigger_without_caesar_word)
      - route telemetry from coverage_extras_factory (route_mode,
        route_width, route_rows, route_cols, route_width_source, ...)
      - transposition_keyword + col_order from the columnar keyword
    """
    if route_partner_kind not in (
        "route_boustrophedon", "route_diagonal",
    ):
        raise ValueError(
            f"unsupported route_partner_kind {route_partner_kind!r}"
        )
    family_label = f"caesar_{route_partner_kind}_columnar"
    out: list[GeneratedSpec] = []
    route_layers = list(route_layer_factory())
    if not route_layers:
        return []
    # Filter columnar keywords to those usable as a column order.
    cleaned_kws: list[str] = []
    seen_kw: set[str] = set()
    for kw in columnar_keywords:
        if not isinstance(kw, str):
            continue
        upper = kw.upper().strip()
        if not upper.isalpha() or len(upper) < 2:
            continue
        if upper in seen_kw:
            continue
        seen_kw.add(upper)
        cleaned_kws.append(upper)
    if not cleaned_kws:
        return []
    layer_orders = _resolve_lesson_019_layer_orders(route_partner_kind)
    for p in promoted_shifts:
        shift = int(p["shift_value"])
        if shift == 0:
            continue
        caesar_layer = _caesar_layer(shift)
        cov_telemetry = _coverage_kwargs_from_promoted(
            p, numeric_only=numeric_only,
        )
        for route_layer in route_layers:
            partner_extras = route_partner_extras_factory(route_layer)
            extra_cov = coverage_extras_factory(route_layer)
            for kw in cleaned_kws:
                col_layer = _keyword_columnar_layer(kw)
                col_order = _keyword_to_col_order(kw)
                col_extras = (
                    ("columnar_keyword", kw),
                    ("columnar_width", len(kw)),
                    ("columnar_col_order", tuple(col_order)),
                )
                extras = (
                    ("caesar_shift", shift),
                ) + partner_extras + col_extras
                role_assignment = (
                    ("caesar_shift", str(shift)),
                    (route_partner_kind, ""),
                    ("columnar", kw),
                )
                # Layer kind → layer dict. Used to assemble the
                # pipeline once per layer_order.
                layer_for_kind = {
                    "caesar":   caesar_layer,
                    "columnar": col_layer,
                    route_partner_kind: route_layer,
                }
                for layer_order in layer_orders:
                    pipeline = [layer_for_kind[k] for k in layer_order]
                    common = {
                        "layer_family": family_label,
                        "layer_order": layer_order,
                        "role_assignment": role_assignment,
                        "role_assignment_mode": (
                            "numeric_route_columnar_three_role"
                        ),
                        "alphabet": "AZ", "n_layers": 3,
                        "extras": extras,
                        "operation_source": (
                            "numeric_route_columnar_composition"
                        ),
                        "transposition_keyword": kw,
                        "col_order": tuple(col_order),
                        "col_order_source": "clue_keyword",
                        **cov_telemetry,
                        **extra_cov,
                    }
                    cov = CoverageVector(**common)
                    out.append(_make_spec(
                        bench_slug=bench_slug,
                        family_label=family_label,
                        pipeline=pipeline,
                        coverage=cov,
                        notes=(
                            f"caesar({shift}) ∘ {route_partner_kind} ∘ "
                            f"columnar({kw}) "
                            f"[order={'-'.join(layer_order)}, "
                            f"numeric_promotion={p['shift_source']}, "
                            f"dir={p['shift_direction']}]"
                        ),
                    ))
    return out


def _gen_independent_three_role_keyword_family(
    *,
    bench_slug: str,
    sub_kind: str,                  # vigenere | beaufort | variant_beaufort
    trans_kind: str,                # columnar | myszkowski
    clue_keywords: Sequence[str],
    alphabet_modes: Optional[Sequence[AlphabetMode]] = None,
    role_pool_size: int = 3,
    allow_self_pairs: bool = True,
) -> list[GeneratedSpec]:
    """LESSON-010: substitution + keyword-transposition with the
    three role slots (substitution_keyword, alphabet_keyword,
    transposition_keyword) enumerated INDEPENDENTLY from the clue
    pool.

    The pre-LESSON-010 ``_gen_keyword_pair_family`` iterated only
    pairwise role swaps ``(kw_sub, kw_trans) ∈ {(A,B), (B,A)}`` —
    which forces the transposition keyword to be the OTHER of the
    first two clue words and ties the alphabet keyword (when
    ``alphabet_mode == keyword_mixed``) to whichever clue word the
    AlphabetMode points to. With three clue words {A, B, C} this
    misses any candidate where all three roles use distinct
    keywords (e.g. K4B-005's intended ``vig(TUNNEL,
    alphabet_keyword=KRYPTOS) ∘ columnar(TOWER)``).

    This generator emits the full
    ``(sub_keyword × alphabet_mode × trans_keyword)`` cartesian
    product, capped at the first ``role_pool_size`` clue keywords
    (default 3). Self-pairs are admitted by default because some
    hand ciphers reuse the same keyword across multiple roles.

    Coverage_vector telemetry:
      ``substitution_keyword``  — populated
      ``alphabet_keyword``      — populated (may be "" for AZ/KA)
      ``transposition_keyword`` — populated
      ``role_assignment_mode``  — "independent_three_role"

    Universe per family with default knobs and no mirror trigger:
      role_pool_size (3) × alphabet_modes (5: AZ + KA + 3 keyword_mixed)
                        × role_pool_size (3) × layer_orders (2)
        = 90 specs / family
    With mirror trigger (+2 alphabet modes):
        = 3 × 7 × 3 × 2 = 126 specs / family
    """
    if sub_kind not in _SUBSTITUTION_KEYWORD_KINDS:
        raise ValueError(
            f"_gen_independent_three_role_keyword_family: unsupported "
            f"sub_kind {sub_kind!r}"
        )
    if trans_kind not in _KEYWORD_TRANSPOSITION_KINDS:
        raise ValueError(
            f"_gen_independent_three_role_keyword_family: unsupported "
            f"trans_kind {trans_kind!r}"
        )
    pool: list[str] = []
    seen: set[str] = set()
    for kw in clue_keywords:
        if not isinstance(kw, str):
            continue
        upper = kw.upper().strip()
        if not upper.isalpha() or upper in seen:
            continue
        seen.add(upper)
        pool.append(upper)
        if len(pool) >= role_pool_size:
            break
    # Need at least 2 keywords for a meaningful enumeration; with 1
    # keyword the legacy pair family is a strict superset of what
    # this generator could emit. Caller is expected to skip the i3
    # family when len(pool) < 2.
    if len(pool) < 2:
        return []

    family_label = f"i3_{trans_kind}_{sub_kind}"
    if alphabet_modes is None:
        alphabet_modes = (AlphabetMode("AZ", "AZ", None, "default"),)

    def _trans_layer(kw: str) -> dict[str, Any]:
        if trans_kind == "columnar":
            return _keyword_columnar_layer(kw)
        return _keyword_myszkowski_layer(kw)

    out: list[GeneratedSpec] = []
    for kw_sub in pool:
        for kw_trans in pool:
            if not allow_self_pairs and kw_sub == kw_trans:
                continue
            for mode in alphabet_modes:
                sub_layer = _keyword_substitution_layer(
                    sub_kind, kw_sub,
                    alphabet=mode.dsl_alphabet,
                    alphabet_keyword=mode.alphabet_keyword,
                )
                trans_layer = _trans_layer(kw_trans)
                # role_assignment encodes the full triple so the
                # symmetry-class key + slug both reflect the
                # independent role assignment.
                # role_assignment stays as the canonical keyword-swap
                # tuple ``((sub, kw_sub), (trans, kw_trans))`` so the
                # legacy "all role values are clue words" invariant
                # still holds. The independent alphabet axis lives
                # in the explicit ``alphabet_keyword`` field below.
                role = (
                    (sub_kind, kw_sub),
                    (trans_kind, kw_trans),
                )
                alphabet_kw_text = mode.alphabet_keyword or ""
                # Order 1: substitution first
                out.append(_make_spec(
                    bench_slug=bench_slug, family_label=family_label,
                    pipeline=[sub_layer, trans_layer],
                    coverage=CoverageVector(
                        layer_family=family_label,
                        layer_order=(sub_kind, trans_kind),
                        role_assignment=role,
                        alphabet=mode.mode_label,
                        n_layers=2,
                        alphabet_mode=mode.mode_label,
                        alphabet_source=mode.source,
                        substitution_keyword=kw_sub,
                        alphabet_keyword=alphabet_kw_text,
                        transposition_keyword=kw_trans,
                        role_assignment_mode="independent_three_role",
                    ),
                    notes=(
                        f"i3 {sub_kind}(sub={kw_sub}, alpha={mode.mode_label}/"
                        f"{mode.source}) ∘ {trans_kind}(trans={kw_trans}) "
                        "[sub-first]"
                    ),
                ))
                # Order 2: transposition first
                out.append(_make_spec(
                    bench_slug=bench_slug, family_label=family_label,
                    pipeline=[trans_layer, sub_layer],
                    coverage=CoverageVector(
                        layer_family=family_label,
                        layer_order=(trans_kind, sub_kind),
                        role_assignment=role,
                        alphabet=mode.mode_label,
                        n_layers=2,
                        alphabet_mode=mode.mode_label,
                        alphabet_source=mode.source,
                        substitution_keyword=kw_sub,
                        alphabet_keyword=alphabet_kw_text,
                        transposition_keyword=kw_trans,
                        role_assignment_mode="independent_three_role",
                    ),
                    notes=(
                        f"i3 {trans_kind}(trans={kw_trans}) ∘ "
                        f"{sub_kind}(sub={kw_sub}, alpha={mode.mode_label}/"
                        f"{mode.source}) [trans-first]"
                    ),
                ))
    return out


def _gen_independent_three_role_keywordless_family(
    *,
    bench_slug: str,
    sub_kind: str,                  # vigenere | beaufort | variant_beaufort
    trans_kind: str,                # rail_fence | route
    clue_keywords: Sequence[str],
    extra_params: dict[str, Any],
    alphabet_modes: Optional[Sequence[AlphabetMode]] = None,
    role_pool_size: int = 3,
) -> list[GeneratedSpec]:
    """LESSON-010 keywordless variant. The transposition is keyword-
    free (rail_fence depth, route variant + grid) so only the
    substitution_keyword × alphabet_keyword × layer_order axes
    matter for role independence. The transposition's
    ``transposition_keyword`` field is recorded as "" since there
    is no keyword to swap.

    This is the LESSON-010 path the existing ``_gen_keywordless_
    trans_pair_family`` already approximated (it iterated each clue
    word as the substitution keyword separately). The new generator
    is structurally distinct so coverage analysis can audit the
    independent role choice via the explicit telemetry fields.
    """
    if sub_kind not in _SUBSTITUTION_KEYWORD_KINDS:
        raise ValueError(
            f"_gen_independent_three_role_keywordless_family: "
            f"unsupported sub_kind {sub_kind!r}"
        )
    if trans_kind not in _KEYWORDLESS_TRANSPOSITION_KINDS:
        raise ValueError(
            f"_gen_independent_three_role_keywordless_family: "
            f"unsupported trans_kind {trans_kind!r}"
        )
    pool: list[str] = []
    seen: set[str] = set()
    for kw in clue_keywords:
        if not isinstance(kw, str):
            continue
        upper = kw.upper().strip()
        if not upper.isalpha() or upper in seen:
            continue
        seen.add(upper)
        pool.append(upper)
        if len(pool) >= role_pool_size:
            break
    if not pool:
        return []

    family_label = f"i3_{trans_kind}_{sub_kind}"
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

    if alphabet_modes is None:
        alphabet_modes = (AlphabetMode("AZ", "AZ", None, "default"),)

    out: list[GeneratedSpec] = []
    for kw_sub in pool:
        for mode in alphabet_modes:
            sub_layer = _keyword_substitution_layer(
                sub_kind, kw_sub,
                alphabet=mode.dsl_alphabet,
                alphabet_keyword=mode.alphabet_keyword,
            )
            # role_assignment stays as the canonical keyword tuple
            # ``((sub, kw_sub),)``; alphabet axis carried in the
            # explicit ``alphabet_keyword`` field below.
            role = (
                (sub_kind, kw_sub),
            )
            alphabet_kw_text = mode.alphabet_keyword or ""
            # Order 1: substitution first
            out.append(_make_spec(
                bench_slug=bench_slug, family_label=family_label,
                pipeline=[sub_layer, trans_layer],
                coverage=CoverageVector(
                    layer_family=family_label,
                    layer_order=(sub_kind, trans_kind),
                    role_assignment=role,
                    alphabet=mode.mode_label, n_layers=2,
                    extras=extras_tuple,
                    alphabet_mode=mode.mode_label,
                    alphabet_source=mode.source,
                    substitution_keyword=kw_sub,
                    alphabet_keyword=alphabet_kw_text,
                    transposition_keyword="",
                    role_assignment_mode="independent_three_role",
                ),
                notes=(
                    f"i3 {sub_kind}(sub={kw_sub}, alpha={mode.mode_label}/"
                    f"{mode.source}) ∘ {trans_kind}({extra_params}) [sub-first]"
                ),
            ))
            # Order 2: transposition first
            out.append(_make_spec(
                bench_slug=bench_slug, family_label=family_label,
                pipeline=[trans_layer, sub_layer],
                coverage=CoverageVector(
                    layer_family=family_label,
                    layer_order=(trans_kind, sub_kind),
                    role_assignment=role,
                    alphabet=mode.mode_label, n_layers=2,
                    extras=extras_tuple,
                    alphabet_mode=mode.mode_label,
                    alphabet_source=mode.source,
                    substitution_keyword=kw_sub,
                    alphabet_keyword=alphabet_kw_text,
                    transposition_keyword="",
                    role_assignment_mode="independent_three_role",
                ),
                notes=(
                    f"i3 {trans_kind}({extra_params}) ∘ "
                    f"{sub_kind}(sub={kw_sub}, alpha={mode.mode_label}/"
                    f"{mode.source}) [trans-first]"
                ),
            ))
    return out


def _gen_skip_route_alone_family(
    *,
    bench_slug: str,
    pairs: Sequence[tuple[int, int, str]],
) -> list[GeneratedSpec]:
    """LESSON-011: skip_route as a single-layer transposition.

    Emits one spec per (step, offset) pair. Coverage_vector carries
    route_mode='skip_route' + step + offset + operation_source so
    downstream readers can audit the exact modular walk that was
    tested.
    """
    family_label = "skip_route"
    out: list[GeneratedSpec] = []
    for step, offset, op_source in pairs:
        layer = _skip_route_layer(step, offset)
        cov = CoverageVector(
            layer_family=family_label,
            layer_order=("skip_route",),
            role_assignment=(),
            alphabet="AZ", n_layers=1,
            extras=(("step", step), ("offset", offset)),
            route_mode="skip_route",
            step=step, offset=offset,
            operation_source=op_source,
        )
        out.append(_make_spec(
            bench_slug=bench_slug, family_label=family_label,
            pipeline=[layer], coverage=cov,
            notes=(
                f"skip_route(step={step}, offset={offset}) "
                f"[op_source={op_source}]"
            ),
            crib_alignment="post_transposition",
        ))
    return out


def _gen_skip_route_substitution_family(
    *,
    bench_slug: str,
    sub_kind: str,                  # vigenere | beaufort | variant_beaufort
    keyword_a: str,
    keyword_b: str,
    pairs: Sequence[tuple[int, int, str]],
    alphabet_modes: Optional[Sequence[AlphabetMode]] = None,
) -> list[GeneratedSpec]:
    """LESSON-011: skip_route paired with a keyword substitution in
    BOTH layer orders. Emits one spec per (keyword × alphabet_mode
    × (step, offset) × layer_order) tuple. Caller is expected to
    pre-cap ``pairs`` so the universe stays bounded.
    """
    if sub_kind not in _SUBSTITUTION_KEYWORD_KINDS:
        raise ValueError(f"unsupported sub_kind {sub_kind!r}")
    family_label = f"skip_route_{sub_kind}"
    if alphabet_modes is None:
        alphabet_modes = (AlphabetMode("AZ", "AZ", None, "default"),)

    out: list[GeneratedSpec] = []
    for kw in (keyword_a, keyword_b):
        if not isinstance(kw, str) or len(kw) < 1:
            continue
        for mode in alphabet_modes:
            sub_layer = _keyword_substitution_layer(
                sub_kind, kw,
                alphabet=mode.dsl_alphabet,
                alphabet_keyword=mode.alphabet_keyword,
            )
            for step, offset, op_source in pairs:
                sk_layer = _skip_route_layer(step, offset)
                role = ((sub_kind, kw),)
                extras = (("step", step), ("offset", offset))
                # Order 1: substitution first
                out.append(_make_spec(
                    bench_slug=bench_slug, family_label=family_label,
                    pipeline=[sub_layer, sk_layer],
                    coverage=CoverageVector(
                        layer_family=family_label,
                        layer_order=(sub_kind, "skip_route"),
                        role_assignment=role,
                        alphabet=mode.mode_label, n_layers=2,
                        extras=extras,
                        alphabet_mode=mode.mode_label,
                        alphabet_source=mode.source,
                        substitution_keyword=kw,
                        alphabet_keyword=mode.alphabet_keyword or "",
                        route_mode="skip_route",
                        step=step, offset=offset,
                        operation_source=op_source,
                    ),
                    notes=(
                        f"{sub_kind}({kw}, alpha={mode.mode_label}) ∘ "
                        f"skip_route({step}, {offset}) [sub-first]"
                    ),
                ))
                # Order 2: skip_route first
                out.append(_make_spec(
                    bench_slug=bench_slug, family_label=family_label,
                    pipeline=[sk_layer, sub_layer],
                    coverage=CoverageVector(
                        layer_family=family_label,
                        layer_order=("skip_route", sub_kind),
                        role_assignment=role,
                        alphabet=mode.mode_label, n_layers=2,
                        extras=extras,
                        alphabet_mode=mode.mode_label,
                        alphabet_source=mode.source,
                        substitution_keyword=kw,
                        alphabet_keyword=mode.alphabet_keyword or "",
                        route_mode="skip_route",
                        step=step, offset=offset,
                        operation_source=op_source,
                    ),
                    notes=(
                        f"skip_route({step}, {offset}) ∘ "
                        f"{sub_kind}({kw}, alpha={mode.mode_label}) "
                        "[trans-first]"
                    ),
                ))
    return out


def _gen_skip_route_caesar_family(
    *,
    bench_slug: str,
    pairs: Sequence[tuple[int, int, str]],
    shifts: Sequence[int] = _DEFAULT_REV_BLOCKS_CAESAR_SHIFTS,
) -> list[GeneratedSpec]:
    """LESSON-011: skip_route + canonical Caesar in BOTH orders.

    Uses the smaller LESSON-008 default shift set (1, 3, 13) to
    keep the (caesar_shift × skip_route step × offset) universe
    bounded; LESSON-009 already exercises the full Caesar shift
    space against the keyed transpositions independently.
    """
    family_label = "skip_route_caesar"
    out: list[GeneratedSpec] = []
    for shift in shifts:
        if shift == 0 or not 1 <= shift <= 25:
            continue
        caesar_layer = _caesar_layer(shift)
        for step, offset, op_source in pairs:
            sk_layer = _skip_route_layer(step, offset)
            role = (("caesar_shift", str(shift)),)
            extras = (
                ("caesar_shift", shift),
                ("step", step), ("offset", offset),
            )
            # caesar + skip_route
            out.append(_make_spec(
                bench_slug=bench_slug, family_label=family_label,
                pipeline=[caesar_layer, sk_layer],
                coverage=CoverageVector(
                    layer_family=family_label,
                    layer_order=("caesar", "skip_route"),
                    role_assignment=role,
                    alphabet="AZ", n_layers=2,
                    extras=extras,
                    shift_value=shift,
                    route_mode="skip_route",
                    step=step, offset=offset,
                    operation_source=op_source,
                ),
                notes=(
                    f"caesar({shift}) ∘ skip_route({step}, {offset}) "
                    "[caesar-first]"
                ),
            ))
            # skip_route + caesar
            out.append(_make_spec(
                bench_slug=bench_slug, family_label=family_label,
                pipeline=[sk_layer, caesar_layer],
                coverage=CoverageVector(
                    layer_family=family_label,
                    layer_order=("skip_route", "caesar"),
                    role_assignment=role,
                    alphabet="AZ", n_layers=2,
                    extras=extras,
                    shift_value=shift,
                    route_mode="skip_route",
                    step=step, offset=offset,
                    operation_source=op_source,
                ),
                notes=(
                    f"skip_route({step}, {offset}) ∘ caesar({shift}) "
                    "[trans-first]"
                ),
            ))
    return out


def _gen_skip_route_atbash_family(
    *,
    bench_slug: str,
    pairs: Sequence[tuple[int, int, str]],
) -> list[GeneratedSpec]:
    """LESSON-011: skip_route + parameter-free Atbash in BOTH orders."""
    family_label = "skip_route_atbash"
    atbash_layer = {"kind": "atbash", "alphabet": "AZ", "params": []}
    out: list[GeneratedSpec] = []
    for step, offset, op_source in pairs:
        sk_layer = _skip_route_layer(step, offset)
        extras = (("step", step), ("offset", offset))
        # atbash + skip_route
        out.append(_make_spec(
            bench_slug=bench_slug, family_label=family_label,
            pipeline=[atbash_layer, sk_layer],
            coverage=CoverageVector(
                layer_family=family_label,
                layer_order=("atbash", "skip_route"),
                role_assignment=(),
                alphabet="AZ", n_layers=2,
                extras=extras,
                route_mode="skip_route",
                step=step, offset=offset,
                operation_source=op_source,
            ),
            notes=(
                f"atbash ∘ skip_route({step}, {offset}) [atbash-first]"
            ),
        ))
        # skip_route + atbash
        out.append(_make_spec(
            bench_slug=bench_slug, family_label=family_label,
            pipeline=[sk_layer, atbash_layer],
            coverage=CoverageVector(
                layer_family=family_label,
                layer_order=("skip_route", "atbash"),
                role_assignment=(),
                alphabet="AZ", n_layers=2,
                extras=extras,
                route_mode="skip_route",
                step=step, offset=offset,
                operation_source=op_source,
            ),
            notes=(
                f"skip_route({step}, {offset}) ∘ atbash [trans-first]"
            ),
        ))
    return out


def _gen_skip_route_rail_fence_family(
    *,
    bench_slug: str,
    pairs: Sequence[tuple[int, int, str]],
    rail_fence_depths: Sequence[int],
) -> list[GeneratedSpec]:
    """LESSON-011: skip_route + rail_fence in BOTH orders.

    Pure-transposition pair: skip_route(step, offset) composed with
    rail_fence(depth). No keyword roles, so the family is bounded
    by the (step × offset × depth × layer_order) cartesian.
    """
    family_label = "skip_route_rail_fence"
    out: list[GeneratedSpec] = []
    for depth in rail_fence_depths:
        rf_layer = _rail_fence_layer(int(depth))
        for step, offset, op_source in pairs:
            sk_layer = _skip_route_layer(step, offset)
            extras = (
                ("step", step), ("offset", offset),
                ("rail_fence_depth", int(depth)),
            )
            # rail_fence + skip_route
            out.append(_make_spec(
                bench_slug=bench_slug, family_label=family_label,
                pipeline=[rf_layer, sk_layer],
                coverage=CoverageVector(
                    layer_family=family_label,
                    layer_order=("rail_fence", "skip_route"),
                    role_assignment=(),
                    alphabet="AZ", n_layers=2,
                    extras=extras,
                    route_mode="skip_route",
                    step=step, offset=offset,
                    operation_source=op_source,
                ),
                notes=(
                    f"rail_fence({depth}) ∘ skip_route({step}, {offset}) "
                    "[rail-first]"
                ),
            ))
            # skip_route + rail_fence
            out.append(_make_spec(
                bench_slug=bench_slug, family_label=family_label,
                pipeline=[sk_layer, rf_layer],
                coverage=CoverageVector(
                    layer_family=family_label,
                    layer_order=("skip_route", "rail_fence"),
                    role_assignment=(),
                    alphabet="AZ", n_layers=2,
                    extras=extras,
                    route_mode="skip_route",
                    step=step, offset=offset,
                    operation_source=op_source,
                ),
                notes=(
                    f"skip_route({step}, {offset}) ∘ rail_fence({depth}) "
                    "[skip-first]"
                ),
            ))
    return out


def _gen_skip_route_three_layer_family(
    *,
    bench_slug: str,
    sub_kind: str,                  # vigenere | beaufort | variant_beaufort
    sandwich_partner: str,          # "rail_fence" | "atbash" | "caesar"
    keyword_a: str,
    keyword_b: str,
    pairs: Sequence[tuple[int, int, str]],
    rail_fence_depth: int = 4,
    caesar_shifts: Sequence[int] = (1, 3, 13),
    alphabet_modes: Optional[Sequence[AlphabetMode]] = None,
) -> list[GeneratedSpec]:
    """LESSON-011 three-layer sandwich:
    sub ∘ skip_route ∘ partner.

    Partner kinds:
      "rail_fence" — sub ∘ skip_route ∘ rail_fence in 4 orderings:
         sub_first   → sub ∘ skip ∘ fence,   fence_first → fence ∘ skip ∘ sub
         skip_first  → skip ∘ sub ∘ fence,   skip_last   → fence ∘ sub ∘ skip
      "atbash"     — sub ∘ skip_route ∘ atbash in 2 layer orderings
                     (atbash is parameter-free; reduces to 2 not 4).
      "caesar"     — sub ∘ skip_route ∘ caesar(shift) in 2 layer
                     orderings × len(caesar_shifts).

    To keep the universe bounded, ``pairs`` is expected to be the
    pre-capped (step, offset) list from
    ``_skip_route_pairs_for_payload(cap=...)``.
    """
    if sub_kind not in _SUBSTITUTION_KEYWORD_KINDS:
        raise ValueError(f"unsupported sub_kind {sub_kind!r}")
    if sandwich_partner not in ("rail_fence", "atbash", "caesar"):
        raise ValueError(
            f"sandwich_partner must be in "
            f"{{'rail_fence', 'atbash', 'caesar'}}; got "
            f"{sandwich_partner!r}"
        )
    family_label = f"{sub_kind}_skip_route_{sandwich_partner}"
    if alphabet_modes is None:
        alphabet_modes = (AlphabetMode("AZ", "AZ", None, "default"),)

    if sandwich_partner == "rail_fence":
        partner_layers: list[tuple[dict[str, Any], dict[str, Any]]] = [
            (
                _rail_fence_layer(int(rail_fence_depth)),
                {"rail_fence_depth": int(rail_fence_depth)},
            ),
        ]
    elif sandwich_partner == "atbash":
        partner_layers = [
            ({"kind": "atbash", "alphabet": "AZ", "params": []}, {}),
        ]
    else:  # caesar
        partner_layers = [
            (_caesar_layer(s), {"caesar_shift": s})
            for s in caesar_shifts if 1 <= s <= 25
        ]

    out: list[GeneratedSpec] = []
    for kw in (keyword_a, keyword_b):
        if not isinstance(kw, str) or len(kw) < 1:
            continue
        for mode in alphabet_modes:
            sub_layer = _keyword_substitution_layer(
                sub_kind, kw,
                alphabet=mode.dsl_alphabet,
                alphabet_keyword=mode.alphabet_keyword,
            )
            for step, offset, op_source in pairs:
                sk_layer = _skip_route_layer(step, offset)
                for partner_layer, partner_extras in partner_layers:
                    role: tuple[tuple[str, str], ...] = (
                        (sub_kind, kw),
                    )
                    if sandwich_partner == "caesar":
                        role = role + (
                            (
                                "caesar_shift",
                                str(partner_extras.get("caesar_shift")),
                            ),
                        )
                    extras = (
                        ("step", step), ("offset", offset),
                    )
                    for k, v in partner_extras.items():
                        extras = extras + ((k, v),)

                    if sandwich_partner == "rail_fence":
                        # 4 orderings for rail_fence
                        orderings: list[tuple[
                            tuple[str, str, str], list[dict[str, Any]],
                        ]] = [
                            (
                                (sub_kind, "skip_route", "rail_fence"),
                                [sub_layer, sk_layer, partner_layer],
                            ),
                            (
                                ("rail_fence", "skip_route", sub_kind),
                                [partner_layer, sk_layer, sub_layer],
                            ),
                            (
                                ("skip_route", sub_kind, "rail_fence"),
                                [sk_layer, sub_layer, partner_layer],
                            ),
                            (
                                ("rail_fence", sub_kind, "skip_route"),
                                [partner_layer, sub_layer, sk_layer],
                            ),
                        ]
                    else:
                        # 2 orderings for atbash / caesar
                        orderings = [
                            (
                                (sub_kind, "skip_route",
                                 sandwich_partner),
                                [sub_layer, sk_layer, partner_layer],
                            ),
                            (
                                (sandwich_partner, "skip_route",
                                 sub_kind),
                                [partner_layer, sk_layer, sub_layer],
                            ),
                        ]

                    for layer_order, pipeline in orderings:
                        cov = CoverageVector(
                            layer_family=family_label,
                            layer_order=layer_order,
                            role_assignment=role,
                            alphabet=mode.mode_label, n_layers=3,
                            extras=extras,
                            alphabet_mode=mode.mode_label,
                            alphabet_source=mode.source,
                            substitution_keyword=kw,
                            alphabet_keyword=(
                                mode.alphabet_keyword or ""
                            ),
                            route_mode="skip_route",
                            step=step, offset=offset,
                            operation_source=op_source,
                        )
                        if sandwich_partner == "caesar":
                            cov = CoverageVector(
                                **{
                                    **cov.to_dict(),
                                    "shift_value": int(
                                        partner_extras["caesar_shift"]
                                    ),
                                }
                            ) if False else CoverageVector(
                                layer_family=cov.layer_family,
                                layer_order=cov.layer_order,
                                role_assignment=cov.role_assignment,
                                alphabet=cov.alphabet,
                                n_layers=cov.n_layers,
                                extras=cov.extras,
                                alphabet_mode=cov.alphabet_mode,
                                alphabet_source=cov.alphabet_source,
                                substitution_keyword=cov.substitution_keyword,
                                alphabet_keyword=cov.alphabet_keyword,
                                route_mode=cov.route_mode,
                                step=cov.step, offset=cov.offset,
                                operation_source=cov.operation_source,
                                shift_value=int(
                                    partner_extras["caesar_shift"]
                                ),
                            )
                        out.append(_make_spec(
                            bench_slug=bench_slug,
                            family_label=family_label,
                            pipeline=pipeline, coverage=cov,
                            notes=(
                                f"{sub_kind}({kw}, alpha={mode.mode_label}) "
                                f"× skip_route({step}, {offset}) × "
                                f"{sandwich_partner}{partner_extras} "
                                f"[order={'/'.join(layer_order)}]"
                            ),
                            compute_budget_minutes=3,
                        ))
    return out


# ----------------------------------------------------------------------------
# LESSON-014: route_boustrophedon family generators
# ----------------------------------------------------------------------------


def _route_boustrophedon_route_metadata(
    width: int, vertical: bool, *, ct_length: int = 97,
) -> tuple[int, int, bool, str]:
    """Compute (rows, cols, ragged, direction) for a width / vertical
    pair. Centralized so every LESSON-014 generator emits identical
    telemetry.
    """
    rows = (ct_length + width - 1) // width
    cols = width
    ragged = (ct_length % width) != 0
    direction = "vertical" if vertical else "horizontal"
    return rows, cols, ragged, direction


def _route_boustrophedon_extras(
    width: int, vertical: bool, *, ct_length: int = 97,
) -> tuple[tuple[str, Any], ...]:
    """Standard ``extras`` tuple for a LESSON-014 spec. Mirrors the
    coverage-vector telemetry so two specs with identical
    (width, vertical) share an extras hash regardless of family.
    """
    rows, cols, ragged, direction = _route_boustrophedon_route_metadata(
        width, vertical, ct_length=ct_length,
    )
    return (
        ("route_width", width),
        ("route_rows", rows),
        ("route_cols", cols),
        ("route_ragged", ragged),
        ("route_direction", direction),
        ("vertical", vertical),
    )


def _gen_route_boustrophedon_alone_family(
    *,
    bench_slug: str,
    widths: Sequence[tuple[int, str]],
    directions: Sequence[bool] = (False, True),
    ct_length: int = 97,
) -> list[GeneratedSpec]:
    """LESSON-014: route_boustrophedon as a single-layer transposition.

    Emits one spec per (width, vertical) pair. ``widths`` is the
    provenance-tagged width list from
    ``_route_boustrophedon_widths_for_payload``; ``directions``
    enumerates both vertical=False and vertical=True per LESSON-002
    (layer-order inversion is degenerate for a one-layer family, so
    direction enumeration is the analogous symmetry control here).
    """
    family_label = "route_boustrophedon"
    out: list[GeneratedSpec] = []
    for width, source in widths:
        for vertical in directions:
            layer = _route_boustrophedon_layer(width, vertical=vertical)
            rows, cols, ragged, direction = (
                _route_boustrophedon_route_metadata(
                    width, vertical, ct_length=ct_length,
                )
            )
            cov = CoverageVector(
                layer_family=family_label,
                layer_order=("route_boustrophedon",),
                role_assignment=(),
                alphabet="AZ", n_layers=1,
                extras=_route_boustrophedon_extras(
                    width, vertical, ct_length=ct_length,
                ),
                route_mode="route_boustrophedon",
                operation_source=source,
                route_width=width,
                route_rows=rows,
                route_cols=cols,
                route_ragged=ragged,
                route_direction=direction,
                route_width_source=source,
            )
            out.append(_make_spec(
                bench_slug=bench_slug, family_label=family_label,
                pipeline=[layer], coverage=cov,
                notes=(
                    f"route_boustrophedon(width={width}, "
                    f"vertical={vertical}) "
                    f"[width_source={source}, rows={rows}, "
                    f"ragged={ragged}]"
                ),
                crib_alignment="post_transposition",
            ))
    return out


def _gen_route_boustrophedon_substitution_family(
    *,
    bench_slug: str,
    sub_kind: str,                  # vigenere | beaufort | variant_beaufort
    keyword_a: str,
    keyword_b: str,
    widths: Sequence[tuple[int, str]],
    directions: Sequence[bool] = (False, True),
    alphabet_modes: Optional[Sequence[AlphabetMode]] = None,
    ct_length: int = 97,
) -> list[GeneratedSpec]:
    """LESSON-014: route_boustrophedon paired with a keyword
    substitution in BOTH layer orders (LESSON-002).

    Emits one spec per (keyword × alphabet_mode × (width, direction)
    × layer_order) tuple. Caller is expected to pre-cap ``widths`` if
    the universe gets too large.
    """
    if sub_kind not in _SUBSTITUTION_KEYWORD_KINDS:
        raise ValueError(f"unsupported sub_kind {sub_kind!r}")
    family_label = f"route_boustrophedon_{sub_kind}"
    if alphabet_modes is None:
        alphabet_modes = (AlphabetMode("AZ", "AZ", None, "default"),)

    out: list[GeneratedSpec] = []
    for kw in (keyword_a, keyword_b):
        if not isinstance(kw, str) or len(kw) < 1:
            continue
        for mode in alphabet_modes:
            sub_layer = _keyword_substitution_layer(
                sub_kind, kw,
                alphabet=mode.dsl_alphabet,
                alphabet_keyword=mode.alphabet_keyword,
            )
            for width, source in widths:
                for vertical in directions:
                    rb_layer = _route_boustrophedon_layer(
                        width, vertical=vertical,
                    )
                    rows, cols, ragged, direction = (
                        _route_boustrophedon_route_metadata(
                            width, vertical, ct_length=ct_length,
                        )
                    )
                    role = ((sub_kind, kw),)
                    extras = _route_boustrophedon_extras(
                        width, vertical, ct_length=ct_length,
                    )
                    # Order 1: substitution first
                    out.append(_make_spec(
                        bench_slug=bench_slug,
                        family_label=family_label,
                        pipeline=[sub_layer, rb_layer],
                        coverage=CoverageVector(
                            layer_family=family_label,
                            layer_order=(sub_kind, "route_boustrophedon"),
                            role_assignment=role,
                            alphabet=mode.mode_label, n_layers=2,
                            extras=extras,
                            alphabet_mode=mode.mode_label,
                            alphabet_source=mode.source,
                            substitution_keyword=kw,
                            alphabet_keyword=mode.alphabet_keyword or "",
                            route_mode="route_boustrophedon",
                            operation_source=source,
                            route_width=width,
                            route_rows=rows,
                            route_cols=cols,
                            route_ragged=ragged,
                            route_direction=direction,
                            route_width_source=source,
                        ),
                        notes=(
                            f"{sub_kind}({kw}, alpha={mode.mode_label}) ∘ "
                            f"route_boustrophedon({width}, "
                            f"vertical={vertical}) [sub-first, "
                            f"width_source={source}]"
                        ),
                    ))
                    # Order 2: route_boustrophedon first
                    out.append(_make_spec(
                        bench_slug=bench_slug,
                        family_label=family_label,
                        pipeline=[rb_layer, sub_layer],
                        coverage=CoverageVector(
                            layer_family=family_label,
                            layer_order=("route_boustrophedon", sub_kind),
                            role_assignment=role,
                            alphabet=mode.mode_label, n_layers=2,
                            extras=extras,
                            alphabet_mode=mode.mode_label,
                            alphabet_source=mode.source,
                            substitution_keyword=kw,
                            alphabet_keyword=mode.alphabet_keyword or "",
                            route_mode="route_boustrophedon",
                            operation_source=source,
                            route_width=width,
                            route_rows=rows,
                            route_cols=cols,
                            route_ragged=ragged,
                            route_direction=direction,
                            route_width_source=source,
                        ),
                        notes=(
                            f"route_boustrophedon({width}, "
                            f"vertical={vertical}) ∘ "
                            f"{sub_kind}({kw}, alpha={mode.mode_label}) "
                            f"[trans-first, width_source={source}]"
                        ),
                    ))
    return out


def _gen_route_boustrophedon_caesar_family(
    *,
    bench_slug: str,
    widths: Sequence[tuple[int, str]],
    directions: Sequence[bool] = (False, True),
    shifts: Sequence[int] = _DEFAULT_REV_BLOCKS_CAESAR_SHIFTS,
    ct_length: int = 97,
) -> list[GeneratedSpec]:
    """LESSON-014: route_boustrophedon + canonical Caesar in BOTH
    orders. Uses the smaller LESSON-008 default shift set so the
    (caesar_shift × width × direction × order) universe stays bounded.
    """
    family_label = "route_boustrophedon_caesar"
    out: list[GeneratedSpec] = []
    for shift in shifts:
        if shift == 0 or not 1 <= shift <= 25:
            continue
        caesar_layer = _caesar_layer(shift)
        for width, source in widths:
            for vertical in directions:
                rb_layer = _route_boustrophedon_layer(
                    width, vertical=vertical,
                )
                rows, cols, ragged, direction = (
                    _route_boustrophedon_route_metadata(
                        width, vertical, ct_length=ct_length,
                    )
                )
                role = (("caesar_shift", str(shift)),)
                extras = _route_boustrophedon_extras(
                    width, vertical, ct_length=ct_length,
                ) + (("caesar_shift", shift),)
                # caesar + route_boustrophedon
                out.append(_make_spec(
                    bench_slug=bench_slug, family_label=family_label,
                    pipeline=[caesar_layer, rb_layer],
                    coverage=CoverageVector(
                        layer_family=family_label,
                        layer_order=("caesar", "route_boustrophedon"),
                        role_assignment=role,
                        alphabet="AZ", n_layers=2,
                        extras=extras,
                        shift_value=shift,
                        route_mode="route_boustrophedon",
                        operation_source=source,
                        route_width=width,
                        route_rows=rows,
                        route_cols=cols,
                        route_ragged=ragged,
                        route_direction=direction,
                        route_width_source=source,
                    ),
                    notes=(
                        f"caesar({shift}) ∘ route_boustrophedon("
                        f"{width}, vertical={vertical}) [caesar-first]"
                    ),
                ))
                # route_boustrophedon + caesar
                out.append(_make_spec(
                    bench_slug=bench_slug, family_label=family_label,
                    pipeline=[rb_layer, caesar_layer],
                    coverage=CoverageVector(
                        layer_family=family_label,
                        layer_order=("route_boustrophedon", "caesar"),
                        role_assignment=role,
                        alphabet="AZ", n_layers=2,
                        extras=extras,
                        shift_value=shift,
                        route_mode="route_boustrophedon",
                        operation_source=source,
                        route_width=width,
                        route_rows=rows,
                        route_cols=cols,
                        route_ragged=ragged,
                        route_direction=direction,
                        route_width_source=source,
                    ),
                    notes=(
                        f"route_boustrophedon({width}, "
                        f"vertical={vertical}) ∘ caesar({shift}) "
                        "[trans-first]"
                    ),
                ))
    return out


def _gen_route_boustrophedon_atbash_family(
    *,
    bench_slug: str,
    widths: Sequence[tuple[int, str]],
    directions: Sequence[bool] = (False, True),
    ct_length: int = 97,
) -> list[GeneratedSpec]:
    """LESSON-014: route_boustrophedon + parameter-free Atbash in
    BOTH orders.
    """
    family_label = "route_boustrophedon_atbash"
    atbash_layer = {"kind": "atbash", "alphabet": "AZ", "params": []}
    out: list[GeneratedSpec] = []
    for width, source in widths:
        for vertical in directions:
            rb_layer = _route_boustrophedon_layer(
                width, vertical=vertical,
            )
            rows, cols, ragged, direction = (
                _route_boustrophedon_route_metadata(
                    width, vertical, ct_length=ct_length,
                )
            )
            extras = _route_boustrophedon_extras(
                width, vertical, ct_length=ct_length,
            )
            # atbash + route_boustrophedon
            out.append(_make_spec(
                bench_slug=bench_slug, family_label=family_label,
                pipeline=[atbash_layer, rb_layer],
                coverage=CoverageVector(
                    layer_family=family_label,
                    layer_order=("atbash", "route_boustrophedon"),
                    role_assignment=(),
                    alphabet="AZ", n_layers=2,
                    extras=extras,
                    route_mode="route_boustrophedon",
                    operation_source=source,
                    route_width=width,
                    route_rows=rows,
                    route_cols=cols,
                    route_ragged=ragged,
                    route_direction=direction,
                    route_width_source=source,
                ),
                notes=(
                    f"atbash ∘ route_boustrophedon({width}, "
                    f"vertical={vertical}) [atbash-first]"
                ),
            ))
            # route_boustrophedon + atbash
            out.append(_make_spec(
                bench_slug=bench_slug, family_label=family_label,
                pipeline=[rb_layer, atbash_layer],
                coverage=CoverageVector(
                    layer_family=family_label,
                    layer_order=("route_boustrophedon", "atbash"),
                    role_assignment=(),
                    alphabet="AZ", n_layers=2,
                    extras=extras,
                    route_mode="route_boustrophedon",
                    operation_source=source,
                    route_width=width,
                    route_rows=rows,
                    route_cols=cols,
                    route_ragged=ragged,
                    route_direction=direction,
                    route_width_source=source,
                ),
                notes=(
                    f"route_boustrophedon({width}, "
                    f"vertical={vertical}) ∘ atbash [trans-first]"
                ),
            ))
    return out


def _gen_route_boustrophedon_rail_fence_family(
    *,
    bench_slug: str,
    widths: Sequence[tuple[int, str]],
    rail_fence_depths: Sequence[int],
    directions: Sequence[bool] = (False, True),
    ct_length: int = 97,
) -> list[GeneratedSpec]:
    """LESSON-014: route_boustrophedon + rail_fence in BOTH orders.

    Pure-transposition pair. No keyword roles, so the family is bounded
    by the (width × direction × depth × layer_order) cartesian.
    """
    family_label = "route_boustrophedon_rail_fence"
    out: list[GeneratedSpec] = []
    for depth in rail_fence_depths:
        rf_layer = _rail_fence_layer(int(depth))
        for width, source in widths:
            for vertical in directions:
                rb_layer = _route_boustrophedon_layer(
                    width, vertical=vertical,
                )
                rows, cols, ragged, direction = (
                    _route_boustrophedon_route_metadata(
                        width, vertical, ct_length=ct_length,
                    )
                )
                extras = _route_boustrophedon_extras(
                    width, vertical, ct_length=ct_length,
                ) + (("rail_fence_depth", int(depth)),)
                # rail_fence + route_boustrophedon
                out.append(_make_spec(
                    bench_slug=bench_slug, family_label=family_label,
                    pipeline=[rf_layer, rb_layer],
                    coverage=CoverageVector(
                        layer_family=family_label,
                        layer_order=("rail_fence", "route_boustrophedon"),
                        role_assignment=(),
                        alphabet="AZ", n_layers=2,
                        extras=extras,
                        route_mode="route_boustrophedon",
                        operation_source=source,
                        route_width=width,
                        route_rows=rows,
                        route_cols=cols,
                        route_ragged=ragged,
                        route_direction=direction,
                        route_width_source=source,
                    ),
                    notes=(
                        f"rail_fence({depth}) ∘ route_boustrophedon("
                        f"{width}, vertical={vertical}) [rail-first]"
                    ),
                ))
                # route_boustrophedon + rail_fence
                out.append(_make_spec(
                    bench_slug=bench_slug, family_label=family_label,
                    pipeline=[rb_layer, rf_layer],
                    coverage=CoverageVector(
                        layer_family=family_label,
                        layer_order=("route_boustrophedon", "rail_fence"),
                        role_assignment=(),
                        alphabet="AZ", n_layers=2,
                        extras=extras,
                        route_mode="route_boustrophedon",
                        operation_source=source,
                        route_width=width,
                        route_rows=rows,
                        route_cols=cols,
                        route_ragged=ragged,
                        route_direction=direction,
                        route_width_source=source,
                    ),
                    notes=(
                        f"route_boustrophedon({width}, "
                        f"vertical={vertical}) ∘ rail_fence({depth}) "
                        "[rb-first]"
                    ),
                ))
    return out


def _gen_route_boustrophedon_three_layer_family(
    *,
    bench_slug: str,
    sub_kind: str,                  # vigenere | beaufort | variant_beaufort
    sandwich_partner: str,          # "rail_fence" | "columnar"
    keyword_a: str,
    keyword_b: str,
    widths: Sequence[tuple[int, str]],
    directions: Sequence[bool] = (False, True),
    rail_fence_depth: int = 4,
    columnar_keyword: Optional[str] = None,
    alphabet_modes: Optional[Sequence[AlphabetMode]] = None,
    ct_length: int = 97,
) -> list[GeneratedSpec]:
    """LESSON-014 three-layer sandwich:
    sub ∘ route_boustrophedon ∘ partner (and rotations).

    Partner kinds:
      "rail_fence" — sub ∘ rb ∘ rail_fence in 4 layer orderings:
         sub_first   → sub ∘ rb ∘ fence
         fence_first → fence ∘ rb ∘ sub
         rb_middle   → sub ∘ fence ∘ rb is NOT generated (mirrored
                       by fence_first when keyword roles flip);
                       instead the four canonical orderings closing
                       the symmetry class are used (cf. LESSON-011's
                       rail_fence three-layer).
      "columnar"   — sub ∘ rb ∘ columnar in 2 layer orderings:
         sub_first   → sub ∘ rb ∘ columnar
         col_first   → columnar ∘ rb ∘ sub
         The columnar keyword is taken from ``columnar_keyword`` when
         provided, else from ``keyword_b``. col_order derives from
         the keyword stable rank (LESSON-004 / LESSON-005). The
         enumerated col_order path (LESSON-013) is exercised by the
         dedicated columnar+sub pair family; this sandwich keeps the
         keyword path so the universe stays bounded.

    To keep the universe bounded, callers are expected to pre-cap
    ``widths`` and ``directions``.
    """
    if sub_kind not in _SUBSTITUTION_KEYWORD_KINDS:
        raise ValueError(f"unsupported sub_kind {sub_kind!r}")
    if sandwich_partner not in ("rail_fence", "columnar"):
        raise ValueError(
            f"sandwich_partner must be in {{'rail_fence', 'columnar'}}; "
            f"got {sandwich_partner!r}"
        )
    family_label = f"{sub_kind}_route_boustrophedon_{sandwich_partner}"
    if alphabet_modes is None:
        alphabet_modes = (AlphabetMode("AZ", "AZ", None, "default"),)

    if sandwich_partner == "rail_fence":
        partner_layer = _rail_fence_layer(int(rail_fence_depth))
        partner_extras: tuple[tuple[str, Any], ...] = (
            ("rail_fence_depth", int(rail_fence_depth)),
        )
        partner_role: tuple[tuple[str, str], ...] = ()
    else:  # columnar
        kw_for_col = (
            columnar_keyword
            if isinstance(columnar_keyword, str) and len(columnar_keyword) >= 2
            else keyword_b
        )
        if not (isinstance(kw_for_col, str) and len(kw_for_col) >= 2):
            return []  # no usable columnar keyword; family inactive
        partner_layer = _keyword_columnar_layer(kw_for_col)
        col_order = _keyword_to_col_order(kw_for_col)
        partner_extras = (
            ("columnar_keyword", kw_for_col),
            ("columnar_width", len(kw_for_col)),
            ("columnar_col_order", tuple(col_order)),
        )
        partner_role = (("columnar", kw_for_col),)

    out: list[GeneratedSpec] = []
    for kw in (keyword_a, keyword_b):
        if not isinstance(kw, str) or len(kw) < 1:
            continue
        for mode in alphabet_modes:
            sub_layer = _keyword_substitution_layer(
                sub_kind, kw,
                alphabet=mode.dsl_alphabet,
                alphabet_keyword=mode.alphabet_keyword,
            )
            for width, source in widths:
                for vertical in directions:
                    rb_layer = _route_boustrophedon_layer(
                        width, vertical=vertical,
                    )
                    rows, cols, ragged, direction = (
                        _route_boustrophedon_route_metadata(
                            width, vertical, ct_length=ct_length,
                        )
                    )
                    extras = (
                        _route_boustrophedon_extras(
                            width, vertical, ct_length=ct_length,
                        )
                        + partner_extras
                    )
                    role: tuple[tuple[str, str], ...] = (
                        (sub_kind, kw),
                    ) + partner_role

                    if sandwich_partner == "rail_fence":
                        # 4 orderings, mirroring LESSON-011's rail_fence
                        # three-layer pattern.
                        orderings: list[tuple[
                            tuple[str, str, str], list[dict[str, Any]],
                        ]] = [
                            (
                                (sub_kind, "route_boustrophedon",
                                 "rail_fence"),
                                [sub_layer, rb_layer, partner_layer],
                            ),
                            (
                                ("rail_fence", "route_boustrophedon",
                                 sub_kind),
                                [partner_layer, rb_layer, sub_layer],
                            ),
                            (
                                ("route_boustrophedon", sub_kind,
                                 "rail_fence"),
                                [rb_layer, sub_layer, partner_layer],
                            ),
                            (
                                ("rail_fence", sub_kind,
                                 "route_boustrophedon"),
                                [partner_layer, sub_layer, rb_layer],
                            ),
                        ]
                    else:  # columnar — 2 layer-order rotations
                        orderings = [
                            (
                                (sub_kind, "route_boustrophedon",
                                 "columnar"),
                                [sub_layer, rb_layer, partner_layer],
                            ),
                            (
                                ("columnar", "route_boustrophedon",
                                 sub_kind),
                                [partner_layer, rb_layer, sub_layer],
                            ),
                        ]

                    for layer_order, pipeline in orderings:
                        cov_kwargs: dict[str, Any] = dict(
                            layer_family=family_label,
                            layer_order=layer_order,
                            role_assignment=role,
                            alphabet=mode.mode_label, n_layers=3,
                            extras=extras,
                            alphabet_mode=mode.mode_label,
                            alphabet_source=mode.source,
                            substitution_keyword=kw,
                            alphabet_keyword=(
                                mode.alphabet_keyword or ""
                            ),
                            route_mode="route_boustrophedon",
                            operation_source=source,
                            route_width=width,
                            route_rows=rows,
                            route_cols=cols,
                            route_ragged=ragged,
                            route_direction=direction,
                            route_width_source=source,
                        )
                        if sandwich_partner == "columnar":
                            cov_kwargs["transposition_keyword"] = (
                                kw_for_col
                            )
                            cov_kwargs["transposition_width"] = (
                                len(kw_for_col)
                            )
                            cov_kwargs["col_order"] = tuple(col_order)
                            cov_kwargs["col_order_source"] = (
                                "keyword_stable_rank"
                            )
                            cov_kwargs["width_source"] = (
                                "clue_keyword_length"
                            )
                        cov = CoverageVector(**cov_kwargs)
                        out.append(_make_spec(
                            bench_slug=bench_slug,
                            family_label=family_label,
                            pipeline=pipeline, coverage=cov,
                            notes=(
                                f"{sub_kind}({kw}, alpha="
                                f"{mode.mode_label}) × "
                                f"route_boustrophedon({width}, "
                                f"vertical={vertical}) × "
                                f"{sandwich_partner}{partner_extras} "
                                f"[order={'/'.join(layer_order)}]"
                            ),
                            compute_budget_minutes=3,
                        ))
    return out


# ----------------------------------------------------------------------------
# Standalone single-layer substitution family (audit-hygiene 2026-04-28)
# ----------------------------------------------------------------------------
#
# Pre-2026-04-28 the HCC catalog never emitted single-layer
# substitution specs — every Vigenere / Beaufort / Variant Beaufort
# always paired with a transposition partner. That coverage gap was
# observed on K4B-008 (single-layer ``vigenere(SHADOW, mirrored_KA)``
# is the intended decryption) where the controller could only reach
# the answer through an identity ``row_reverse(width=CT_LEN,
# parity=odd)`` wrapper riding the substitution layer.
#
# This generator emits standalone substitution specs as a always-on
# default family — one spec per (sub_kind × clue_keyword × alphabet_
# mode) — so single-layer-substitution challenges no longer require
# an identity-wrapper workaround. The coverage_vector clearly marks
# ``layer_family="standalone_<sub_kind>"`` and ``n_layers=1`` so
# downstream attribution distinguishes "single-layer substitution
# was the intended cipher" from "two-layer pipeline reached the
# answer".


def _gen_standalone_substitution_family(
    *,
    bench_slug: str,
    sub_kind: str,                  # vigenere | beaufort | variant_beaufort
    clue_keywords: Sequence[str],
    alphabet_modes: Optional[Sequence[AlphabetMode]] = None,
) -> list[GeneratedSpec]:
    """Emit single-layer substitution specs across (keyword × alphabet
    mode). One spec per (clue_keyword × alphabet_mode); the family is
    deliberately keyword-driven so a clue pack containing N keywords
    and M alphabet modes produces exactly N×M specs (≤ a few dozen
    for typical clue packs).

    The family is ALWAYS emitted — it does not require a trigger word.
    Single-layer substitution is a fundamental cipher class that any
    coverage-complete catalog should include independent of clue
    triggers; the prior absence was a real coverage gap, not an
    intentional gate.
    """
    if sub_kind not in _SUBSTITUTION_KEYWORD_KINDS:
        raise ValueError(f"unsupported sub_kind {sub_kind!r}")
    family_label = f"standalone_{sub_kind}"
    if alphabet_modes is None:
        alphabet_modes = (AlphabetMode("AZ", "AZ", None, "default"),)

    out: list[GeneratedSpec] = []
    seen_keys: set[tuple[str, str, str]] = set()
    for kw in clue_keywords:
        if not isinstance(kw, str):
            continue
        upper = kw.upper().strip()
        if not upper.isalpha() or not upper:
            continue
        for mode in alphabet_modes:
            # Dedup on (keyword, alphabet_mode_label, alphabet_source)
            # so two AlphabetMode entries with the same shape (which
            # can happen if a caller passes a redundant override list)
            # never produce duplicate specs.
            key = (upper, mode.mode_label, mode.source)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            sub_layer = _keyword_substitution_layer(
                sub_kind, upper,
                alphabet=mode.dsl_alphabet,
                alphabet_keyword=mode.alphabet_keyword,
            )
            cov = CoverageVector(
                layer_family=family_label,
                layer_order=(sub_kind,),
                role_assignment=((sub_kind, upper),),
                alphabet=mode.mode_label, n_layers=1,
                alphabet_mode=mode.mode_label,
                alphabet_source=mode.source,
                substitution_keyword=upper,
                alphabet_keyword=mode.alphabet_keyword or "",
            )
            out.append(_make_spec(
                bench_slug=bench_slug, family_label=family_label,
                pipeline=[sub_layer], coverage=cov,
                notes=(
                    f"standalone {sub_kind}({upper}, alpha="
                    f"{mode.mode_label}, src={mode.source}) "
                    "[single-layer substitution]"
                ),
                # Single-layer substitution is the simplest dispatch
                # shape; the kernel evaluates one config in
                # microseconds, so the budget is overwhelmingly
                # multiprocessing startup. 1 minute is plenty.
                compute_budget_minutes=1,
                crib_alignment="direct_positional",
            ))
    return out


# ----------------------------------------------------------------------------
# LESSON-015: row_reverse family generators
# ----------------------------------------------------------------------------


def _row_reverse_metadata(
    width: int, *, ct_length: int = 97,
) -> bool:
    """Return ``ragged`` flag (True iff width does not divide
    CT_LEN). Centralized so every LESSON-015 generator emits
    consistent ragged telemetry.
    """
    return (ct_length % width) != 0


def _row_reverse_is_identity(
    width: int,
    parity: str,
    start_row: int,
    *,
    ct_length: int = 97,
) -> bool:
    """Return True iff the (width, parity, start_row) triple selects
    no row of length > 1 — i.e. the row_reverse perm is the identity
    permutation.

    This is the "no-fold" check. The audit-hygiene contract is that
    every emitted row_reverse spec carries
    ``row_reverse_identity = _row_reverse_is_identity(...)`` so
    downstream analysis can distinguish substantive folded-row
    reversal from identity wrappers that ride a substitution layer
    just to surface a substitution-alone-equivalent spec.

    Cases:
      - parity="both": every row is reversed; identity iff ALL rows
        have length <= 1 (effectively impossible for our widths).
      - parity="odd"/"even": identity iff every selected row has
        length <= 1.

    The canonical no-fold sentinel ``width=CT_LEN, parity=odd,
    start_row=0`` matches: only row 0 exists (length CT_LEN), but
    parity=odd selects only ODD-indexed rows, so no row is
    reversed → identity.
    """
    if not isinstance(width, int) or width < 1:
        return False
    if parity not in ("odd", "even", "both"):
        return False
    if start_row not in (0, 1):
        return False
    n_rows = (ct_length + width - 1) // width
    for row_idx in range(n_rows):
        # Replicate the dispatcher's parity logic exactly.
        effective_idx = row_idx - start_row
        if parity == "both":
            should_reverse = True
        elif parity == "odd":
            should_reverse = (effective_idx % 2) == 1
        else:  # "even"
            should_reverse = (effective_idx % 2) == 0
        if not should_reverse:
            continue
        # This row is selected. Is its reversal the identity?
        # A single-character row reversed in place is the identity;
        # any row of length >= 2 produces a non-identity perm.
        row_start = row_idx * width
        row_len = min(width, ct_length - row_start)
        if row_len > 1:
            return False
    return True


def _row_reverse_extras(
    width: int, parity: str, start_row: int, *, ct_length: int = 97,
) -> tuple[tuple[str, Any], ...]:
    """Standard ``extras`` tuple for a LESSON-015 spec."""
    return (
        ("row_reverse_width", width),
        ("row_reverse_parity", parity),
        ("row_reverse_start_row", start_row),
        ("row_reverse_ragged", _row_reverse_metadata(
            width, ct_length=ct_length,
        )),
        ("row_reverse_identity", _row_reverse_is_identity(
            width, parity, start_row, ct_length=ct_length,
        )),
    )


def _gen_row_reverse_alone_family(
    *,
    bench_slug: str,
    widths: Sequence[tuple[int, str]],
    parities: Sequence[str] = _DEFAULT_ROW_REVERSE_PARITIES,
    start_rows: Sequence[int] = (0,),
    ct_length: int = 97,
) -> list[GeneratedSpec]:
    """LESSON-015: row_reverse as a single-layer transposition.

    Emits one spec per (width, parity, start_row) triple. ``widths``
    is the provenance-tagged width list from
    ``_row_reverse_widths_for_payload``.
    """
    family_label = "row_reverse"
    out: list[GeneratedSpec] = []
    for width, source in widths:
        for parity in parities:
            for start_row in start_rows:
                layer = _row_reverse_layer(
                    width, parity, start_row=start_row,
                )
                ragged = _row_reverse_metadata(
                    width, ct_length=ct_length,
                )
                cov = CoverageVector(
                    layer_family=family_label,
                    layer_order=("row_reverse",),
                    role_assignment=(),
                    alphabet="AZ", n_layers=1,
                    extras=_row_reverse_extras(
                        width, parity, start_row, ct_length=ct_length,
                    ),
                    operation_source=source,
                    row_reverse_width=width,
                    row_reverse_parity=parity,
                    row_reverse_source=source,
                    row_reverse_ragged=ragged,
                    row_reverse_start_row=start_row,
                    row_reverse_identity=_row_reverse_is_identity(
                        width, parity, start_row, ct_length=ct_length,
                    ),
                )
                out.append(_make_spec(
                    bench_slug=bench_slug, family_label=family_label,
                    pipeline=[layer], coverage=cov,
                    notes=(
                        f"row_reverse(width={width}, parity={parity}, "
                        f"start_row={start_row}) "
                        f"[width_source={source}, ragged={ragged}]"
                    ),
                    crib_alignment="post_transposition",
                ))
    return out


def _gen_row_reverse_substitution_family(
    *,
    bench_slug: str,
    sub_kind: str,                  # vigenere | beaufort | variant_beaufort
    keyword_a: str,
    keyword_b: str,
    widths: Sequence[tuple[int, str]],
    parities: Sequence[str] = _DEFAULT_ROW_REVERSE_PARITIES,
    start_rows: Sequence[int] = (0,),
    alphabet_modes: Optional[Sequence[AlphabetMode]] = None,
    ct_length: int = 97,
) -> list[GeneratedSpec]:
    """LESSON-015: row_reverse paired with a keyword substitution in
    BOTH layer orders (LESSON-002).
    """
    if sub_kind not in _SUBSTITUTION_KEYWORD_KINDS:
        raise ValueError(f"unsupported sub_kind {sub_kind!r}")
    family_label = f"row_reverse_{sub_kind}"
    if alphabet_modes is None:
        alphabet_modes = (AlphabetMode("AZ", "AZ", None, "default"),)

    out: list[GeneratedSpec] = []
    for kw in (keyword_a, keyword_b):
        if not isinstance(kw, str) or len(kw) < 1:
            continue
        for mode in alphabet_modes:
            sub_layer = _keyword_substitution_layer(
                sub_kind, kw,
                alphabet=mode.dsl_alphabet,
                alphabet_keyword=mode.alphabet_keyword,
            )
            for width, source in widths:
                for parity in parities:
                    for start_row in start_rows:
                        rr_layer = _row_reverse_layer(
                            width, parity, start_row=start_row,
                        )
                        ragged = _row_reverse_metadata(
                            width, ct_length=ct_length,
                        )
                        role = ((sub_kind, kw),)
                        extras = _row_reverse_extras(
                            width, parity, start_row,
                            ct_length=ct_length,
                        )
                        # Order 1: substitution first
                        out.append(_make_spec(
                            bench_slug=bench_slug,
                            family_label=family_label,
                            pipeline=[sub_layer, rr_layer],
                            coverage=CoverageVector(
                                layer_family=family_label,
                                layer_order=(sub_kind, "row_reverse"),
                                role_assignment=role,
                                alphabet=mode.mode_label, n_layers=2,
                                extras=extras,
                                alphabet_mode=mode.mode_label,
                                alphabet_source=mode.source,
                                substitution_keyword=kw,
                                alphabet_keyword=(
                                    mode.alphabet_keyword or ""
                                ),
                                operation_source=source,
                                row_reverse_width=width,
                                row_reverse_parity=parity,
                                row_reverse_source=source,
                                row_reverse_ragged=ragged,
                                row_reverse_start_row=start_row,
                                row_reverse_identity=(
                                    _row_reverse_is_identity(
                                        width, parity, start_row,
                                        ct_length=ct_length,
                                    )
                                ),
                            ),
                            notes=(
                                f"{sub_kind}({kw}, alpha="
                                f"{mode.mode_label}) ∘ "
                                f"row_reverse({width}, {parity}, "
                                f"start={start_row}) "
                                f"[sub-first, src={source}]"
                            ),
                        ))
                        # Order 2: row_reverse first
                        out.append(_make_spec(
                            bench_slug=bench_slug,
                            family_label=family_label,
                            pipeline=[rr_layer, sub_layer],
                            coverage=CoverageVector(
                                layer_family=family_label,
                                layer_order=("row_reverse", sub_kind),
                                role_assignment=role,
                                alphabet=mode.mode_label, n_layers=2,
                                extras=extras,
                                alphabet_mode=mode.mode_label,
                                alphabet_source=mode.source,
                                substitution_keyword=kw,
                                alphabet_keyword=(
                                    mode.alphabet_keyword or ""
                                ),
                                operation_source=source,
                                row_reverse_width=width,
                                row_reverse_parity=parity,
                                row_reverse_source=source,
                                row_reverse_ragged=ragged,
                                row_reverse_start_row=start_row,
                                row_reverse_identity=(
                                    _row_reverse_is_identity(
                                        width, parity, start_row,
                                        ct_length=ct_length,
                                    )
                                ),
                            ),
                            notes=(
                                f"row_reverse({width}, {parity}, "
                                f"start={start_row}) ∘ "
                                f"{sub_kind}({kw}, alpha="
                                f"{mode.mode_label}) "
                                f"[trans-first, src={source}]"
                            ),
                        ))
    return out


def _gen_row_reverse_caesar_family(
    *,
    bench_slug: str,
    widths: Sequence[tuple[int, str]],
    parities: Sequence[str] = _DEFAULT_ROW_REVERSE_PARITIES,
    shifts: Sequence[int] = _DEFAULT_REV_BLOCKS_CAESAR_SHIFTS,
    ct_length: int = 97,
) -> list[GeneratedSpec]:
    """LESSON-015: row_reverse + canonical Caesar in BOTH orders."""
    family_label = "row_reverse_caesar"
    out: list[GeneratedSpec] = []
    for shift in shifts:
        if shift == 0 or not 1 <= shift <= 25:
            continue
        caesar_layer = _caesar_layer(shift)
        for width, source in widths:
            for parity in parities:
                rr_layer = _row_reverse_layer(width, parity)
                ragged = _row_reverse_metadata(
                    width, ct_length=ct_length,
                )
                role = (("caesar_shift", str(shift)),)
                extras = _row_reverse_extras(
                    width, parity, 0, ct_length=ct_length,
                ) + (("caesar_shift", shift),)
                out.append(_make_spec(
                    bench_slug=bench_slug, family_label=family_label,
                    pipeline=[caesar_layer, rr_layer],
                    coverage=CoverageVector(
                        layer_family=family_label,
                        layer_order=("caesar", "row_reverse"),
                        role_assignment=role,
                        alphabet="AZ", n_layers=2,
                        extras=extras,
                        shift_value=shift,
                        operation_source=source,
                        row_reverse_width=width,
                        row_reverse_parity=parity,
                        row_reverse_source=source,
                        row_reverse_ragged=ragged,
                        row_reverse_start_row=0,
                        row_reverse_identity=_row_reverse_is_identity(
                            width, parity, 0, ct_length=ct_length,
                        ),
                    ),
                    notes=(
                        f"caesar({shift}) ∘ row_reverse({width}, "
                        f"{parity}) [caesar-first]"
                    ),
                ))
                out.append(_make_spec(
                    bench_slug=bench_slug, family_label=family_label,
                    pipeline=[rr_layer, caesar_layer],
                    coverage=CoverageVector(
                        layer_family=family_label,
                        layer_order=("row_reverse", "caesar"),
                        role_assignment=role,
                        alphabet="AZ", n_layers=2,
                        extras=extras,
                        shift_value=shift,
                        operation_source=source,
                        row_reverse_width=width,
                        row_reverse_parity=parity,
                        row_reverse_source=source,
                        row_reverse_ragged=ragged,
                        row_reverse_start_row=0,
                        row_reverse_identity=_row_reverse_is_identity(
                            width, parity, 0, ct_length=ct_length,
                        ),
                    ),
                    notes=(
                        f"row_reverse({width}, {parity}) ∘ "
                        f"caesar({shift}) [trans-first]"
                    ),
                ))
    return out


def _gen_row_reverse_atbash_family(
    *,
    bench_slug: str,
    widths: Sequence[tuple[int, str]],
    parities: Sequence[str] = _DEFAULT_ROW_REVERSE_PARITIES,
    ct_length: int = 97,
) -> list[GeneratedSpec]:
    """LESSON-015: row_reverse + Atbash in BOTH orders."""
    family_label = "row_reverse_atbash"
    atbash_layer = {"kind": "atbash", "alphabet": "AZ", "params": []}
    out: list[GeneratedSpec] = []
    for width, source in widths:
        for parity in parities:
            rr_layer = _row_reverse_layer(width, parity)
            ragged = _row_reverse_metadata(width, ct_length=ct_length)
            extras = _row_reverse_extras(
                width, parity, 0, ct_length=ct_length,
            )
            out.append(_make_spec(
                bench_slug=bench_slug, family_label=family_label,
                pipeline=[atbash_layer, rr_layer],
                coverage=CoverageVector(
                    layer_family=family_label,
                    layer_order=("atbash", "row_reverse"),
                    role_assignment=(),
                    alphabet="AZ", n_layers=2,
                    extras=extras,
                    operation_source=source,
                    row_reverse_width=width,
                    row_reverse_parity=parity,
                    row_reverse_source=source,
                    row_reverse_ragged=ragged,
                    row_reverse_start_row=0,
                    row_reverse_identity=_row_reverse_is_identity(
                        width, parity, 0, ct_length=ct_length,
                    ),
                ),
                notes=(
                    f"atbash ∘ row_reverse({width}, {parity}) "
                    "[atbash-first]"
                ),
            ))
            out.append(_make_spec(
                bench_slug=bench_slug, family_label=family_label,
                pipeline=[rr_layer, atbash_layer],
                coverage=CoverageVector(
                    layer_family=family_label,
                    layer_order=("row_reverse", "atbash"),
                    role_assignment=(),
                    alphabet="AZ", n_layers=2,
                    extras=extras,
                    operation_source=source,
                    row_reverse_width=width,
                    row_reverse_parity=parity,
                    row_reverse_source=source,
                    row_reverse_ragged=ragged,
                    row_reverse_start_row=0,
                    row_reverse_identity=_row_reverse_is_identity(
                        width, parity, 0, ct_length=ct_length,
                    ),
                ),
                notes=(
                    f"row_reverse({width}, {parity}) ∘ atbash "
                    "[trans-first]"
                ),
            ))
    return out


def _gen_row_reverse_rail_fence_family(
    *,
    bench_slug: str,
    widths: Sequence[tuple[int, str]],
    rail_fence_depths: Sequence[int],
    parities: Sequence[str] = _DEFAULT_ROW_REVERSE_PARITIES,
    ct_length: int = 97,
) -> list[GeneratedSpec]:
    """LESSON-015: row_reverse + rail_fence in BOTH orders."""
    family_label = "row_reverse_rail_fence"
    out: list[GeneratedSpec] = []
    for depth in rail_fence_depths:
        rf_layer = _rail_fence_layer(int(depth))
        for width, source in widths:
            for parity in parities:
                rr_layer = _row_reverse_layer(width, parity)
                ragged = _row_reverse_metadata(
                    width, ct_length=ct_length,
                )
                extras = _row_reverse_extras(
                    width, parity, 0, ct_length=ct_length,
                ) + (("rail_fence_depth", int(depth)),)
                out.append(_make_spec(
                    bench_slug=bench_slug, family_label=family_label,
                    pipeline=[rf_layer, rr_layer],
                    coverage=CoverageVector(
                        layer_family=family_label,
                        layer_order=("rail_fence", "row_reverse"),
                        role_assignment=(),
                        alphabet="AZ", n_layers=2,
                        extras=extras,
                        operation_source=source,
                        row_reverse_width=width,
                        row_reverse_parity=parity,
                        row_reverse_source=source,
                        row_reverse_ragged=ragged,
                        row_reverse_start_row=0,
                        row_reverse_identity=_row_reverse_is_identity(
                            width, parity, 0, ct_length=ct_length,
                        ),
                    ),
                    notes=(
                        f"rail_fence({depth}) ∘ row_reverse("
                        f"{width}, {parity}) [rail-first]"
                    ),
                ))
                out.append(_make_spec(
                    bench_slug=bench_slug, family_label=family_label,
                    pipeline=[rr_layer, rf_layer],
                    coverage=CoverageVector(
                        layer_family=family_label,
                        layer_order=("row_reverse", "rail_fence"),
                        role_assignment=(),
                        alphabet="AZ", n_layers=2,
                        extras=extras,
                        operation_source=source,
                        row_reverse_width=width,
                        row_reverse_parity=parity,
                        row_reverse_source=source,
                        row_reverse_ragged=ragged,
                        row_reverse_start_row=0,
                        row_reverse_identity=_row_reverse_is_identity(
                            width, parity, 0, ct_length=ct_length,
                        ),
                    ),
                    notes=(
                        f"row_reverse({width}, {parity}) ∘ "
                        f"rail_fence({depth}) [rr-first]"
                    ),
                ))
    return out


def _gen_row_reverse_route_three_layer_family(
    *,
    bench_slug: str,
    sub_kind: str,                  # vigenere | beaufort | variant_beaufort
    route_partner: str,             # "route" | "route_boustrophedon"
    keyword_a: str,
    keyword_b: str,
    widths: Sequence[tuple[int, str]],
    parities: Sequence[str] = _DEFAULT_ROW_REVERSE_PARITIES,
    route_grid: tuple[int, int] = (10, 10),
    route_boustrophedon_widths: Sequence[int] = (8, 10),
    alphabet_modes: Optional[Sequence[AlphabetMode]] = None,
    ct_length: int = 97,
) -> list[GeneratedSpec]:
    """LESSON-015 three-layer: substitution + route + row_reverse
    (and rotations).

    ``route_partner`` selects the ``route`` kind (variant=
    serpentine, fixed grid) or the LESSON-014 ``route_boustrophedon``
    kind. Both peel orders for the row_reverse position are
    enumerated:
      sub + route + row_reverse
      row_reverse + route + sub
      sub + row_reverse + route
      route + row_reverse + sub
    """
    if sub_kind not in _SUBSTITUTION_KEYWORD_KINDS:
        raise ValueError(f"unsupported sub_kind {sub_kind!r}")
    if route_partner not in ("route", "route_boustrophedon"):
        raise ValueError(
            f"route_partner must be in {{'route', 'route_boustrophedon'}}; "
            f"got {route_partner!r}"
        )
    family_label = f"{sub_kind}_{route_partner}_row_reverse"
    if alphabet_modes is None:
        alphabet_modes = (AlphabetMode("AZ", "AZ", None, "default"),)

    if route_partner == "route":
        rows, cols = route_grid
        route_layers: list[tuple[dict[str, Any], dict[str, Any]]] = [
            (
                _route_layer(variant="serpentine", rows=rows, cols=cols),
                {"route_rows": rows, "route_cols": cols,
                 "route_variant": "serpentine"},
            ),
        ]
    else:  # route_boustrophedon
        route_layers = [
            (
                _route_boustrophedon_layer(rb_width, vertical=False),
                {"route_boustrophedon_width": rb_width,
                 "route_boustrophedon_vertical": False},
            )
            for rb_width in route_boustrophedon_widths
        ]

    out: list[GeneratedSpec] = []
    for kw in (keyword_a, keyword_b):
        if not isinstance(kw, str) or len(kw) < 1:
            continue
        for mode in alphabet_modes:
            sub_layer = _keyword_substitution_layer(
                sub_kind, kw,
                alphabet=mode.dsl_alphabet,
                alphabet_keyword=mode.alphabet_keyword,
            )
            for width, source in widths:
                for parity in parities:
                    rr_layer = _row_reverse_layer(width, parity)
                    ragged = _row_reverse_metadata(
                        width, ct_length=ct_length,
                    )
                    rr_extras = _row_reverse_extras(
                        width, parity, 0, ct_length=ct_length,
                    )
                    for route_layer, route_extras in route_layers:
                        extras = rr_extras + tuple(
                            route_extras.items()
                        )
                        role: tuple[tuple[str, str], ...] = (
                            (sub_kind, kw),
                        )
                        # 4 layer orderings closing the symmetry
                        # class.
                        orderings: list[tuple[
                            tuple[str, str, str], list[dict[str, Any]],
                        ]] = [
                            (
                                (sub_kind, route_partner, "row_reverse"),
                                [sub_layer, route_layer, rr_layer],
                            ),
                            (
                                ("row_reverse", route_partner, sub_kind),
                                [rr_layer, route_layer, sub_layer],
                            ),
                            (
                                (sub_kind, "row_reverse", route_partner),
                                [sub_layer, rr_layer, route_layer],
                            ),
                            (
                                (route_partner, "row_reverse", sub_kind),
                                [route_layer, rr_layer, sub_layer],
                            ),
                        ]
                        for layer_order, pipeline in orderings:
                            cov_kwargs: dict[str, Any] = dict(
                                layer_family=family_label,
                                layer_order=layer_order,
                                role_assignment=role,
                                alphabet=mode.mode_label, n_layers=3,
                                extras=extras,
                                alphabet_mode=mode.mode_label,
                                alphabet_source=mode.source,
                                substitution_keyword=kw,
                                alphabet_keyword=(
                                    mode.alphabet_keyword or ""
                                ),
                                operation_source=source,
                                row_reverse_width=width,
                                row_reverse_parity=parity,
                                row_reverse_source=source,
                                row_reverse_ragged=ragged,
                                row_reverse_start_row=0,
                                row_reverse_identity=(
                                    _row_reverse_is_identity(
                                        width, parity, 0,
                                        ct_length=ct_length,
                                    )
                                ),
                            )
                            if route_partner == "route_boustrophedon":
                                rb_width = route_extras[
                                    "route_boustrophedon_width"
                                ]
                                rb_rows = (
                                    ct_length + rb_width - 1
                                ) // rb_width
                                cov_kwargs["route_mode"] = (
                                    "route_boustrophedon"
                                )
                                cov_kwargs["route_width"] = rb_width
                                cov_kwargs["route_rows"] = rb_rows
                                cov_kwargs["route_cols"] = rb_width
                                cov_kwargs["route_ragged"] = (
                                    (ct_length % rb_width) != 0
                                )
                                cov_kwargs["route_direction"] = (
                                    "horizontal"
                                )
                            cov = CoverageVector(**cov_kwargs)
                            out.append(_make_spec(
                                bench_slug=bench_slug,
                                family_label=family_label,
                                pipeline=pipeline, coverage=cov,
                                notes=(
                                    f"{sub_kind}({kw}, alpha="
                                    f"{mode.mode_label}) × "
                                    f"{route_partner}{route_extras} "
                                    f"× row_reverse({width}, "
                                    f"{parity}) "
                                    f"[order={'/'.join(layer_order)}]"
                                ),
                                compute_budget_minutes=3,
                            ))
    return out


# ----------------------------------------------------------------------------
# LESSON-016: diagonal grid-route family generators
# ----------------------------------------------------------------------------


def _diagonal_extras(
    rows: int, cols: int, axis: str, order: str, start_edge: str,
    *, ct_length: int = 97,
) -> tuple[tuple[str, Any], ...]:
    """Standard ``extras`` tuple for a LESSON-016 spec."""
    return (
        ("route_rows", rows),
        ("route_cols", cols),
        ("route_width", cols),
        ("route_ragged", (rows * cols) > ct_length),
        ("diagonal_axis", axis),
        ("diagonal_order", order),
        ("diagonal_start_edge", start_edge),
    )


def _gen_diagonal_alone_family(
    *,
    bench_slug: str,
    grids: Sequence[tuple[tuple[int, int], str]],
    variants: Optional[Sequence[tuple[str, str, str]]] = None,
    ct_length: int = 97,
) -> list[GeneratedSpec]:
    """LESSON-016: diagonal route as a single-layer transposition.

    Emits one spec per (grid × variant) combination. Variants
    enumerate the canonical 8 (axis × order × start_edge) tuples
    by default; callers may pass a smaller pre-capped list.
    """
    if variants is None:
        variants = _diagonal_variant_combinations()
    family_label = "route_diagonal"
    out: list[GeneratedSpec] = []
    for (rows, cols), source in grids:
        ragged = (rows * cols) > ct_length
        for axis, order, start_edge in variants:
            layer = _diagonal_route_layer(
                rows, cols, axis=axis, order=order, start_edge=start_edge,
            )
            cov = CoverageVector(
                layer_family=family_label,
                layer_order=("route_diagonal",),
                role_assignment=(),
                alphabet="AZ", n_layers=1,
                extras=_diagonal_extras(
                    rows, cols, axis, order, start_edge,
                    ct_length=ct_length,
                ),
                operation_source=source,
                route_mode="route_diagonal",
                route_width=cols,
                route_rows=rows,
                route_cols=cols,
                route_ragged=ragged,
                route_direction=axis,
                route_width_source=source,
                diagonal_axis=axis,
                diagonal_order=order,
                diagonal_start_edge=start_edge,
            )
            out.append(_make_spec(
                bench_slug=bench_slug, family_label=family_label,
                pipeline=[layer], coverage=cov,
                notes=(
                    f"route_diagonal(rows={rows}, cols={cols}, "
                    f"axis={axis}, order={order}, "
                    f"start_edge={start_edge}) "
                    f"[width_source={source}, ragged={ragged}]"
                ),
                crib_alignment="post_transposition",
            ))
    return out


def _gen_diagonal_substitution_family(
    *,
    bench_slug: str,
    sub_kind: str,                   # vigenere | beaufort | variant_beaufort
    keyword_a: str,
    keyword_b: str,
    grids: Sequence[tuple[tuple[int, int], str]],
    variants: Optional[Sequence[tuple[str, str, str]]] = None,
    alphabet_modes: Optional[Sequence[AlphabetMode]] = None,
    ct_length: int = 97,
) -> list[GeneratedSpec]:
    """LESSON-016: diagonal route paired with a keyword substitution
    in BOTH layer orders (LESSON-002).
    """
    if sub_kind not in _SUBSTITUTION_KEYWORD_KINDS:
        raise ValueError(f"unsupported sub_kind {sub_kind!r}")
    if variants is None:
        variants = _diagonal_variant_combinations(
            cap=_DIAGONAL_PAIR_VARIANT_CAP,
        )
    family_label = f"route_diagonal_{sub_kind}"
    if alphabet_modes is None:
        alphabet_modes = (AlphabetMode("AZ", "AZ", None, "default"),)

    out: list[GeneratedSpec] = []
    for kw in (keyword_a, keyword_b):
        if not isinstance(kw, str) or len(kw) < 1:
            continue
        for mode in alphabet_modes:
            sub_layer = _keyword_substitution_layer(
                sub_kind, kw,
                alphabet=mode.dsl_alphabet,
                alphabet_keyword=mode.alphabet_keyword,
            )
            for (rows, cols), source in grids:
                ragged = (rows * cols) > ct_length
                for axis, order, start_edge in variants:
                    diag_layer = _diagonal_route_layer(
                        rows, cols,
                        axis=axis, order=order, start_edge=start_edge,
                    )
                    role = ((sub_kind, kw),)
                    extras = _diagonal_extras(
                        rows, cols, axis, order, start_edge,
                        ct_length=ct_length,
                    )
                    common_kwargs = dict(
                        layer_family=family_label,
                        role_assignment=role,
                        alphabet=mode.mode_label, n_layers=2,
                        extras=extras,
                        alphabet_mode=mode.mode_label,
                        alphabet_source=mode.source,
                        substitution_keyword=kw,
                        alphabet_keyword=mode.alphabet_keyword or "",
                        operation_source=source,
                        route_mode="route_diagonal",
                        route_width=cols,
                        route_rows=rows,
                        route_cols=cols,
                        route_ragged=ragged,
                        route_direction=axis,
                        route_width_source=source,
                        diagonal_axis=axis,
                        diagonal_order=order,
                        diagonal_start_edge=start_edge,
                    )
                    # Order 1: substitution first.
                    out.append(_make_spec(
                        bench_slug=bench_slug,
                        family_label=family_label,
                        pipeline=[sub_layer, diag_layer],
                        coverage=CoverageVector(
                            layer_order=(sub_kind, "route_diagonal"),
                            **common_kwargs,
                        ),
                        notes=(
                            f"{sub_kind}({kw}, alpha={mode.mode_label}) "
                            f"∘ route_diagonal({rows}x{cols}, {axis}, "
                            f"{order}, {start_edge}) [sub-first]"
                        ),
                    ))
                    # Order 2: route first.
                    out.append(_make_spec(
                        bench_slug=bench_slug,
                        family_label=family_label,
                        pipeline=[diag_layer, sub_layer],
                        coverage=CoverageVector(
                            layer_order=("route_diagonal", sub_kind),
                            **common_kwargs,
                        ),
                        notes=(
                            f"route_diagonal({rows}x{cols}, {axis}, "
                            f"{order}, {start_edge}) ∘ "
                            f"{sub_kind}({kw}, alpha={mode.mode_label}) "
                            "[route-first]"
                        ),
                    ))
    return out


def _gen_diagonal_rail_fence_family(
    *,
    bench_slug: str,
    grids: Sequence[tuple[tuple[int, int], str]],
    rail_fence_depths: Sequence[int],
    variants: Optional[Sequence[tuple[str, str, str]]] = None,
    ct_length: int = 97,
) -> list[GeneratedSpec]:
    """LESSON-016: diagonal route + rail_fence in BOTH layer orders.
    Pure-transposition pair; no keyword roles.
    """
    if variants is None:
        variants = _diagonal_variant_combinations(
            cap=_DIAGONAL_PAIR_VARIANT_CAP,
        )
    family_label = "route_diagonal_rail_fence"
    out: list[GeneratedSpec] = []
    for depth in rail_fence_depths:
        rf_layer = _rail_fence_layer(int(depth))
        for (rows, cols), source in grids:
            ragged = (rows * cols) > ct_length
            for axis, order, start_edge in variants:
                diag_layer = _diagonal_route_layer(
                    rows, cols,
                    axis=axis, order=order, start_edge=start_edge,
                )
                extras = _diagonal_extras(
                    rows, cols, axis, order, start_edge,
                    ct_length=ct_length,
                ) + (("rail_fence_depth", int(depth)),)
                common_kwargs = dict(
                    layer_family=family_label,
                    role_assignment=(),
                    alphabet="AZ", n_layers=2,
                    extras=extras,
                    operation_source=source,
                    route_mode="route_diagonal",
                    route_width=cols,
                    route_rows=rows,
                    route_cols=cols,
                    route_ragged=ragged,
                    route_direction=axis,
                    route_width_source=source,
                    diagonal_axis=axis,
                    diagonal_order=order,
                    diagonal_start_edge=start_edge,
                )
                out.append(_make_spec(
                    bench_slug=bench_slug, family_label=family_label,
                    pipeline=[rf_layer, diag_layer],
                    coverage=CoverageVector(
                        layer_order=("rail_fence", "route_diagonal"),
                        **common_kwargs,
                    ),
                    notes=(
                        f"rail_fence({depth}) ∘ route_diagonal("
                        f"{rows}x{cols}, {axis}, {order}, "
                        f"{start_edge}) [rail-first]"
                    ),
                ))
                out.append(_make_spec(
                    bench_slug=bench_slug, family_label=family_label,
                    pipeline=[diag_layer, rf_layer],
                    coverage=CoverageVector(
                        layer_order=("route_diagonal", "rail_fence"),
                        **common_kwargs,
                    ),
                    notes=(
                        f"route_diagonal({rows}x{cols}, {axis}, "
                        f"{order}, {start_edge}) ∘ rail_fence({depth}) "
                        "[route-first]"
                    ),
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


# ============================================================================
# LESSON-017: stratified HCC bench-fast family quotas
# ============================================================================
#
# Pre-LESSON-017 the validation tail truncated the spec stream from
# the front: ``if len(validated) >= max_specs: break``. On clues
# that fired many learned triggers (e.g. K4B-009 fired LESSON-014
# boustrophedon + LESSON-015 row_reverse + LESSON-016 diagonal
# simultaneously), 8,250 specs out of 18,250 were dropped — and
# 23 entire families received zero dispatched specs.
#
# LESSON-017 replaces front-truncation with a deterministic two-pass
# scheduler:
#
#   Pass 1 (quota): walk the original spec stream once. For each
#     spec, retain it if its family has not yet hit its per-family
#     quota AND total retained < max_specs. The quota guarantees
#     bounded minimum exposure for every triggered family.
#
#   Pass 2 (residual): walk the same stream again. For each spec
#     not retained in pass 1, retain it if total retained <
#     max_specs. Pass 2 preserves the legacy emission-order fill
#     beyond the quota guarantees.
#
# Output ordering: pass 1 specs first (in their original emission
# order), then pass 2 specs (in their original emission order).
# This preserves the K4B-001 cap-preservation invariant — at very
# small caps (e.g. cap=4), the first 4 emitted specs are
# columnar_vigenere, all retained by quota, all in the front of the
# catalog. Larger caps get the full stratification benefit.
#
# Determinism: identical inputs (clue, keyword pool, max_specs)
# produce identical scheduling output. The quota table is a fixed
# module constant; the pass walks are fixed-order; no random
# sampling.

# Per-family quota classes. The classifier reads layer_family by
# substring patterns; an unmatched family falls into the default
# bucket. Conservative values: total quota budget across all 57
# triggered families on K4B-009-shape clues sums to ~5500-6000,
# leaving 4000-4500 for residual fill at cap=10000.
_LESSON_017_FAMILY_QUOTAS: dict[str, int] = {
    # Front-of-catalog legacy keyword-pair families. Higher quota
    # protects the K4B-001 / K4B-006 critical paths against
    # cap-pressure on multi-trigger clues. Quota=200 means each of
    # these families gets ~200 specs in the catalog before residual
    # fill kicks in.
    "front_of_catalog": 200,

    # Triggered route / row-reverse / diagonal families. Quota=80
    # gives each LESSON-014 / LESSON-015 / LESSON-016 family enough
    # exposure to surface its symmetry classes (axis × order ×
    # start_edge × keyword × alphabet) without monopolizing the
    # cap.
    "trigger_route": 80,

    # Three-layer sandwiches that combine multiple lessons.
    # Quota=40 — these emit ~480-960 specs each at full scale; 40
    # is a conservative guarantee that does NOT starve them while
    # leaving budget for everything else.
    "three_layer_sandwich": 40,

    # Catch-all for smaller / less-common families (rail_fence_*,
    # myszkowski_*, quagmire, route_*, route_boustrophedon (alone),
    # row_reverse (alone), atbash combinations, caesar
    # combinations).
    "default": 40,
}

# Patterns that classify a layer_family into a quota class. First
# match wins; order matters. Substring match against the family
# label.
_LESSON_017_FAMILY_CLASSIFIERS: tuple[tuple[str, str], ...] = (
    # Three-layer sandwiches (LESSON-013, LESSON-014, LESSON-015,
    # LESSON-016 cross-products). Identified by THREE
    # underscore-separated segments where the middle segment is a
    # transposition kind. Recognized exemplars below; pattern is
    # by exact-prefix match.
    ("three_layer_sandwich", "vigenere_route_boustrophedon_row_reverse"),
    ("three_layer_sandwich", "beaufort_route_boustrophedon_row_reverse"),
    ("three_layer_sandwich", "variant_beaufort_route_boustrophedon_row_reverse"),
    ("three_layer_sandwich", "vigenere_route_boustrophedon_rail_fence"),
    ("three_layer_sandwich", "beaufort_route_boustrophedon_rail_fence"),
    ("three_layer_sandwich", "variant_beaufort_route_boustrophedon_rail_fence"),
    ("three_layer_sandwich", "vigenere_route_boustrophedon_columnar"),
    ("three_layer_sandwich", "beaufort_route_boustrophedon_columnar"),
    ("three_layer_sandwich", "variant_beaufort_route_boustrophedon_columnar"),
    ("three_layer_sandwich", "vigenere_route_row_reverse"),
    ("three_layer_sandwich", "beaufort_route_row_reverse"),
    ("three_layer_sandwich", "variant_beaufort_route_row_reverse"),
    ("three_layer_sandwich", "vigenere_skip_route_rail_fence"),
    ("three_layer_sandwich", "beaufort_skip_route_rail_fence"),
    ("three_layer_sandwich", "variant_beaufort_skip_route_rail_fence"),
    ("three_layer_sandwich", "vigenere_skip_route_atbash"),
    ("three_layer_sandwich", "beaufort_skip_route_atbash"),
    ("three_layer_sandwich", "variant_beaufort_skip_route_atbash"),
    ("three_layer_sandwich", "vigenere_skip_route_caesar"),
    ("three_layer_sandwich", "beaufort_skip_route_caesar"),
    ("three_layer_sandwich", "variant_beaufort_skip_route_caesar"),
    ("three_layer_sandwich", "vigenere_reverse_blocks_atbash"),
    ("three_layer_sandwich", "beaufort_reverse_blocks_atbash"),
    ("three_layer_sandwich", "variant_beaufort_reverse_blocks_atbash"),
    ("three_layer_sandwich", "vigenere_reverse_blocks_caesar"),
    ("three_layer_sandwich", "beaufort_reverse_blocks_caesar"),
    ("three_layer_sandwich", "variant_beaufort_reverse_blocks_caesar"),
    ("three_layer_sandwich", "vigenere_rail_fence_beaufort"),
    ("three_layer_sandwich", "beaufort_rail_fence_vigenere"),
    # LESSON-013 enumerated columnar three-layer.
    ("front_of_catalog", "columnar_vigenere_rail_fence"),
    ("front_of_catalog", "columnar_beaufort_rail_fence"),
    ("front_of_catalog", "columnar_variant_beaufort_rail_fence"),
    # Caesar three-layer sandwiches.
    ("three_layer_sandwich", "caesar_columnar_atbash"),
    ("three_layer_sandwich", "caesar_myszkowski_atbash"),
    ("three_layer_sandwich", "caesar_rail_fence_atbash"),
    ("three_layer_sandwich", "caesar_route_atbash"),
    # LESSON-019: role-complete numeric-route-columnar three-layer
    # composition. Two route-partner variants; both classified as
    # three_layer_sandwich (quota=40 each) so per-family retention
    # matches the other LESSON-013/-014 sandwich families.
    ("three_layer_sandwich", "caesar_route_boustrophedon_columnar"),
    ("three_layer_sandwich", "caesar_route_diagonal_columnar"),
    # Front-of-catalog (legacy keyword-pair, i3, standalone).
    ("front_of_catalog", "i3_columnar_"),
    ("front_of_catalog", "i3_myszkowski_"),
    ("front_of_catalog", "i3_rail_fence_"),
    ("front_of_catalog", "i3_route_"),
    ("front_of_catalog", "columnar_vigenere"),
    ("front_of_catalog", "columnar_beaufort"),
    ("front_of_catalog", "columnar_variant_beaufort"),
    ("front_of_catalog", "myszkowski_vigenere"),
    ("front_of_catalog", "myszkowski_beaufort"),
    ("front_of_catalog", "rail_fence_vigenere"),
    ("front_of_catalog", "rail_fence_beaufort"),
    ("front_of_catalog", "route_vigenere"),
    ("front_of_catalog", "route_beaufort"),
    ("front_of_catalog", "standalone_vigenere"),
    ("front_of_catalog", "standalone_beaufort"),
    ("front_of_catalog", "standalone_variant_beaufort"),
    # Triggered route / row_reverse / diagonal pair families.
    ("trigger_route", "route_boustrophedon_vigenere"),
    ("trigger_route", "route_boustrophedon_beaufort"),
    ("trigger_route", "route_boustrophedon_variant_beaufort"),
    ("trigger_route", "route_boustrophedon_caesar"),
    ("trigger_route", "route_boustrophedon_atbash"),
    ("trigger_route", "route_boustrophedon_rail_fence"),
    ("trigger_route", "route_diagonal_vigenere"),
    ("trigger_route", "route_diagonal_beaufort"),
    ("trigger_route", "route_diagonal_variant_beaufort"),
    ("trigger_route", "route_diagonal_rail_fence"),
    ("trigger_route", "row_reverse_vigenere"),
    ("trigger_route", "row_reverse_beaufort"),
    ("trigger_route", "row_reverse_variant_beaufort"),
    ("trigger_route", "row_reverse_caesar"),
    ("trigger_route", "row_reverse_atbash"),
    ("trigger_route", "row_reverse_rail_fence"),
    ("trigger_route", "skip_route_vigenere"),
    ("trigger_route", "skip_route_beaufort"),
    ("trigger_route", "skip_route_variant_beaufort"),
    ("trigger_route", "skip_route_caesar"),
    ("trigger_route", "skip_route_atbash"),
    ("trigger_route", "skip_route_rail_fence"),
    ("trigger_route", "reverse_blocks_vigenere"),
    ("trigger_route", "reverse_blocks_beaufort"),
    ("trigger_route", "reverse_blocks_variant_beaufort"),
    ("trigger_route", "reverse_blocks_caesar"),
    ("trigger_route", "reverse_blocks_atbash"),
    ("trigger_route", "caesar_columnar"),
    ("trigger_route", "caesar_myszkowski"),
    ("trigger_route", "caesar_rail_fence"),
    ("trigger_route", "caesar_route"),
    ("trigger_route", "caesar_atbash"),
    # Default catch-all (alone families and Quagmire).
)


def _quota_for_family(family_label: str) -> int:
    """Return the per-family quota for a given layer_family label.

    First-match-wins prefix lookup against
    ``_LESSON_017_FAMILY_CLASSIFIERS``; falls back to the
    ``"default"`` quota for unrecognised families.
    """
    for quota_class, prefix in _LESSON_017_FAMILY_CLASSIFIERS:
        if family_label.startswith(prefix):
            return _LESSON_017_FAMILY_QUOTAS.get(
                quota_class, _LESSON_017_FAMILY_QUOTAS["default"],
            )
    return _LESSON_017_FAMILY_QUOTAS["default"]


def _stratified_schedule(
    specs: Sequence[GeneratedSpec],
    max_specs: int,
) -> list[GeneratedSpec]:
    """Two-pass deterministic scheduler.

    Walks the input spec stream twice. Pass 1 retains up to
    each family's quota; pass 2 fills residual capacity. The
    output preserves emission order WITHIN each pass.

    Side effect: each retained spec's ``coverage`` is replaced with
    a copy carrying scheduling-telemetry fields (scheduling_pass,
    family_quota, family_quota_rank, hcc_max_specs). The original
    GeneratedSpec is not mutated; ``dataclasses.replace`` produces
    a fresh frozen copy.

    Determinism: identical input + max_specs produces identical
    output (same order, same telemetry).
    """
    import dataclasses

    if max_specs < 0:
        raise ValueError(f"max_specs must be >= 0; got {max_specs}")
    if max_specs == 0:
        return []

    # Pass 1: quota.
    family_counts: dict[str, int] = {}
    pass1: list[GeneratedSpec] = []
    pass1_indices: set[int] = set()
    for i, gs in enumerate(specs):
        if len(pass1) >= max_specs:
            break
        fam = gs.coverage.layer_family
        quota = _quota_for_family(fam)
        seen = family_counts.get(fam, 0)
        if seen >= quota:
            continue
        family_counts[fam] = seen + 1
        new_cov = dataclasses.replace(
            gs.coverage,
            scheduling_pass="quota",
            family_quota=quota,
            family_quota_rank=seen + 1,
            hcc_max_specs=max_specs,
        )
        new_gs = dataclasses.replace(gs, coverage=new_cov)
        pass1.append(new_gs)
        pass1_indices.add(i)

    # Pass 2: residual.
    pass2: list[GeneratedSpec] = []
    remaining_budget = max_specs - len(pass1)
    if remaining_budget > 0:
        for i, gs in enumerate(specs):
            if len(pass2) >= remaining_budget:
                break
            if i in pass1_indices:
                continue
            fam = gs.coverage.layer_family
            new_cov = dataclasses.replace(
                gs.coverage,
                scheduling_pass="residual",
                family_quota=_quota_for_family(fam),
                family_quota_rank=0,
                hcc_max_specs=max_specs,
            )
            new_gs = dataclasses.replace(gs, coverage=new_cov)
            pass2.append(new_gs)

    # Final ordering: pass 1 first, then pass 2 — both in original
    # emission order. Pass 1 first preserves the K4B-001
    # cap-preservation invariant (small caps keep front-of-catalog
    # families at the front).
    return pass1 + pass2


def coverage_audit_summary(
    specs: Sequence[GeneratedSpec],
    *,
    total_generated_before_cap: Optional[int] = None,
) -> dict[str, Any]:
    """Lightweight summary of an HCC catalog after scheduling.

    Returns a dict with:
      total_retained, total_dropped, total_generated_before_cap (when
      provided by caller), retained_by_family, dropped_by_family
      (only when total_generated_before_cap is supplied), and
      retained_by_scheduling_pass (the LESSON-017 split).

    Designed for quick read-only audits of a generator pass; the
    caller is expected to pass the FULL pre-cap stream length when
    they have it (e.g. by re-running ``generate_layered_specs`` at
    a high max_specs).
    """
    from collections import Counter

    retained = list(specs)
    by_family: Counter[str] = Counter()
    by_pass: Counter[str] = Counter()
    for gs in retained:
        fam = gs.coverage.layer_family
        by_family[fam] += 1
        sp = gs.coverage.scheduling_pass or "<unscheduled>"
        by_pass[sp] += 1
    out: dict[str, Any] = {
        "total_retained": len(retained),
        "retained_by_family": dict(by_family),
        "retained_by_scheduling_pass": dict(by_pass),
    }
    if total_generated_before_cap is not None:
        out["total_generated_before_cap"] = int(total_generated_before_cap)
        out["total_dropped"] = int(
            max(0, total_generated_before_cap - len(retained))
        )
    return out


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
        # 2026-04-28 audit-hygiene: standalone single-layer
        # substitution families are part of the default catalogue
        # (no trigger required). Closes the coverage gap observed
        # on K4B-008 where a single-layer Vigenere + mirrored_KA
        # answer was previously only reachable through an identity
        # row_reverse wrapper.
        "standalone_vigenere",
        "standalone_beaufort",
        "standalone_variant_beaufort",
    }
    if include_three_layer:
        default_families |= {
            "vigenere_rail_fence_beaufort",
            "beaufort_rail_fence_vigenere",
            # LESSON-013: 3-layer ``columnar_<sub>_rail_fence``
            # sandwich with enumerated col_orders.
            "columnar_vigenere_rail_fence",
            "columnar_beaufort_rail_fence",
            "columnar_variant_beaufort_rail_fence",
        }
    # 2026-04-28 (LESSON-010): the i3_* family labels are part of the
    # default catalogue when there are 2+ clue keywords. Adding them
    # to ``default_families`` keeps the gating uniform (a caller
    # passing ``families={"i3_columnar_vigenere"}`` activates only
    # that family; passing ``families=None`` activates everything).
    if len(cleaned) >= 2:
        default_families |= {
            "i3_columnar_vigenere",
            "i3_columnar_beaufort",
            "i3_columnar_variant_beaufort",
            "i3_myszkowski_vigenere",
            "i3_myszkowski_beaufort",
            "i3_rail_fence_vigenere",
            "i3_rail_fence_beaufort",
            "i3_route_vigenere",
            "i3_route_beaufort",
        }
    # 2026-04-28 (LESSON-008): block-reversal families fire only when
    # the clue pack carries a block-reversal trigger token. The lesson
    # is GENERALIZED — when triggered, we add the family set to the
    # default allow-list so the operator gets the full coverage matrix
    # without having to opt in. When NOT triggered, the family set is
    # absent and the historical catalogue is preserved bit-for-bit.
    block_reversal_triggered = _detect_block_reversal_trigger(clue_text)
    shift_triggered = _detect_shift_trigger(clue_text)
    # 2026-04-28 (LESSON-009): Caesar / ROT trigger. The Caesar
    # vocabulary is wider than the LESSON-008 shift-trigger set
    # (adds: shift, shifted, offset, step, caesar, rot, additive,
    # subtractive); a clue with any of these tokens activates the
    # Caesar + transposition + Atbash family matrix.
    caesar_triggered = _detect_caesar_trigger(clue_text)
    if block_reversal_triggered:
        default_families |= {
            "reverse_blocks",
            "reverse_blocks_vigenere",
            "reverse_blocks_beaufort",
            "reverse_blocks_variant_beaufort",
            "reverse_blocks_caesar",
            "reverse_blocks_atbash",
        }
        if include_three_layer and shift_triggered:
            # Three-layer sandwiches fire only when BOTH triggers
            # are present. The shift trigger gates the partner kind
            # (Atbash / Caesar); without it the sandwich would be a
            # generic two-layer pair already covered above.
            default_families |= {
                "vigenere_reverse_blocks_atbash",
                "beaufort_reverse_blocks_atbash",
                "variant_beaufort_reverse_blocks_atbash",
                "vigenere_reverse_blocks_caesar",
                "beaufort_reverse_blocks_caesar",
                "variant_beaufort_reverse_blocks_caesar",
            }
    # 2026-04-28 (LESSON-009): Caesar / ROT family matrix.
    if caesar_triggered:
        default_families |= {
            "caesar",
            "caesar_columnar",
            "caesar_myszkowski",
            "caesar_rail_fence",
            "caesar_route",
            "caesar_atbash",
        }
        if include_three_layer:
            default_families |= {
                "caesar_columnar_atbash",
                "caesar_myszkowski_atbash",
                "caesar_rail_fence_atbash",
                "caesar_route_atbash",
            }
    # 2026-04-28 (LESSON-015): folded-strip / alternate-row reversal
    # trigger. Detected before LESSON-014 / LESSON-011 because clue
    # language like "fold" / "reverse" / "row" overlaps with the other
    # transposition triggers; we add row_reverse families ALONGSIDE
    # those (not instead).
    row_reverse_triggered = _detect_row_reverse_trigger(clue_text)
    if row_reverse_triggered:
        default_families |= {
            "row_reverse",
            "row_reverse_vigenere",
            "row_reverse_beaufort",
            "row_reverse_variant_beaufort",
            "row_reverse_caesar",
            "row_reverse_atbash",
            "row_reverse_rail_fence",
        }
        if include_three_layer:
            default_families |= {
                "vigenere_route_row_reverse",
                "beaufort_route_row_reverse",
                "variant_beaufort_route_row_reverse",
                "vigenere_route_boustrophedon_row_reverse",
                "beaufort_route_boustrophedon_row_reverse",
                "variant_beaufort_route_boustrophedon_row_reverse",
            }

    # 2026-04-29 (LESSON-016): diagonal grid-route trigger. Detected
    # alongside (not instead of) other route triggers — the same
    # clue can fire boustrophedon AND diagonal families, and the
    # generator is purely additive.
    diagonal_triggered = _detect_diagonal_trigger(clue_text)
    if diagonal_triggered:
        default_families |= {
            "route_diagonal",
            "route_diagonal_vigenere",
            "route_diagonal_beaufort",
            "route_diagonal_variant_beaufort",
            "route_diagonal_rail_fence",
        }

    # 2026-04-28 (LESSON-014): width-only ragged boustrophedon route
    # trigger. Detected before the LESSON-011 trigger because clue
    # language like "route" appears in BOTH lessons' vocabularies; we
    # gate on the LESSON-014 detector to add boustrophedon families
    # ALONGSIDE skip_route families (not instead).
    boustrophedon_triggered = _detect_route_boustrophedon_trigger(clue_text)
    boustrophedon_vertical_priority = (
        _detect_route_vertical_priority(clue_text)
        if boustrophedon_triggered else False
    )
    if boustrophedon_triggered:
        default_families |= {
            "route_boustrophedon",
            "route_boustrophedon_vigenere",
            "route_boustrophedon_beaufort",
            "route_boustrophedon_variant_beaufort",
            "route_boustrophedon_caesar",
            "route_boustrophedon_atbash",
            "route_boustrophedon_rail_fence",
        }
        if include_three_layer:
            default_families |= {
                "vigenere_route_boustrophedon_rail_fence",
                "beaufort_route_boustrophedon_rail_fence",
                "variant_beaufort_route_boustrophedon_rail_fence",
                "vigenere_route_boustrophedon_columnar",
                "beaufort_route_boustrophedon_columnar",
                "variant_beaufort_route_boustrophedon_columnar",
            }

    # 2026-04-28 (LESSON-011): skip / step / stride route trigger.
    skip_route_triggered = _detect_skip_route_trigger(clue_text)
    if skip_route_triggered:
        default_families |= {
            "skip_route",
            "skip_route_vigenere",
            "skip_route_beaufort",
            "skip_route_variant_beaufort",
            "skip_route_caesar",
            "skip_route_atbash",
            "skip_route_rail_fence",
        }
        if include_three_layer:
            default_families |= {
                "vigenere_skip_route_rail_fence",
                "beaufort_skip_route_rail_fence",
                "variant_beaufort_skip_route_rail_fence",
            }
            # Three-layer atbash / caesar sandwiches fire only
            # when the corresponding trigger is also present.
            if shift_triggered or caesar_triggered:
                default_families |= {
                    "vigenere_skip_route_atbash",
                    "beaufort_skip_route_atbash",
                    "variant_beaufort_skip_route_atbash",
                }
            if caesar_triggered:
                default_families |= {
                    "vigenere_skip_route_caesar",
                    "beaufort_skip_route_caesar",
                    "variant_beaufort_skip_route_caesar",
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

    # --- LESSON-013: enumerated columnar pair families ---------------
    # Fires immediately after the legacy keyword-pair generator so
    # the per-family cap is filled while we still have global
    # _DEFAULT_MAX_SPECS budget. Family_label stays
    # ``columnar_<sub>`` (same coverage class as the legacy path).
    enumerated_columnar_pair_specs: list[tuple[str, str]] = [
        ("columnar_vigenere",         "vigenere"),
        ("columnar_beaufort",         "beaufort"),
        ("columnar_variant_beaufort", "variant_beaufort"),
    ]
    for label, sub_kind in enumerated_columnar_pair_specs:
        if label not in active:
            continue
        out.extend(_gen_enumerated_columnar_pair_family(
            bench_slug=bench_slug,
            sub_kind=sub_kind,
            keyword_a=keyword_a, keyword_b=keyword_b,
            clue_text=clue_text, clue_keywords=cleaned,
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

    # --- LESSON-010: independent three-role keyword assignment -------
    # When the clue pool has 2+ keywords, also emit the i3 family
    # variants that enumerate substitution_keyword × alphabet_keyword
    # × transposition_keyword INDEPENDENTLY across the first three
    # clue keywords. The pre-LESSON-010 pair-family generators above
    # tied (kw_sub, kw_trans) to (A, B) / (B, A) and tied alphabet_
    # keyword to whichever clue word the AlphabetMode points to;
    # this missed any candidate where all three roles use distinct
    # clue keywords (e.g. K4B-005's intended vig(TUNNEL,
    # alphabet_keyword=KRYPTOS) ∘ columnar(TOWER)).
    #
    # Real-K4 mode is unaffected because HCC is bench-mode only via
    # _collect_hcc_seeds; the LESSON-010 entry in the registry is
    # still visible to the LLM theorist as a generalized tactic.
    if len(cleaned) >= 2:
        i3_keyword_pair_specs: list[tuple[str, str, str]] = [
            ("i3_columnar_vigenere",         "vigenere",         "columnar"),
            ("i3_columnar_beaufort",         "beaufort",         "columnar"),
            ("i3_columnar_variant_beaufort", "variant_beaufort", "columnar"),
            ("i3_myszkowski_vigenere",       "vigenere",         "myszkowski"),
            ("i3_myszkowski_beaufort",       "beaufort",         "myszkowski"),
        ]
        for label, sub_kind, trans_kind in i3_keyword_pair_specs:
            # i3 family is gated by its own ``i3_*`` label only; a
            # caller passing ``families={"columnar_vigenere"}``
            # activates the legacy pair family, while
            # ``families={"i3_columnar_vigenere"}`` activates only
            # the LESSON-010 family. Both fire under the default
            # ``families=None`` (full catalogue).
            if label not in active:
                continue
            out.extend(_gen_independent_three_role_keyword_family(
                bench_slug=bench_slug,
                sub_kind=sub_kind, trans_kind=trans_kind,
                clue_keywords=cleaned,
                alphabet_modes=alphabet_modes,
            ))
        # --- LESSON-013: enumerated col_orders in i3 columnar -----
        # Family_label stays ``i3_columnar_<sub>`` (same coverage
        # class). Only fires for trans_kind == "columnar".
        for label, sub_kind, trans_kind in i3_keyword_pair_specs:
            if trans_kind != "columnar":
                continue
            if label not in active:
                continue
            out.extend(_gen_enumerated_columnar_i3_family(
                bench_slug=bench_slug,
                sub_kind=sub_kind,
                clue_keywords=cleaned,
                clue_text=clue_text,
            ))
        i3_keywordless_pairs: list[tuple[str, str, str]] = [
            ("i3_rail_fence_vigenere", "vigenere", "rail_fence"),
            ("i3_rail_fence_beaufort", "beaufort", "rail_fence"),
            ("i3_route_vigenere",      "vigenere", "route"),
            ("i3_route_beaufort",      "beaufort", "route"),
        ]
        for label, sub_kind, trans_kind in i3_keywordless_pairs:
            if label not in active:
                continue
            if trans_kind == "rail_fence":
                for depth in rail_fence_depths:
                    out.extend(
                        _gen_independent_three_role_keywordless_family(
                            bench_slug=bench_slug,
                            sub_kind=sub_kind, trans_kind=trans_kind,
                            clue_keywords=cleaned,
                            extra_params={"depth": depth},
                            alphabet_modes=alphabet_modes,
                        )
                    )
            else:  # route
                for rows, cols in _DEFAULT_ROUTE_GRIDS:
                    out.extend(
                        _gen_independent_three_role_keywordless_family(
                            bench_slug=bench_slug,
                            sub_kind=sub_kind, trans_kind=trans_kind,
                            clue_keywords=cleaned,
                            extra_params={
                                "variant": "serpentine",
                                "rows": rows, "cols": cols,
                            },
                            alphabet_modes=alphabet_modes,
                        )
                    )

    # --- Standalone single-layer substitution families (audit-hygiene) ---
    # 2026-04-28: always-on (no trigger required). Emitted AFTER the
    # legacy keyword-pair / i3 keyword-pair families so K4B-001-style
    # cap-preservation invariants (small caps keep columnar_vigenere
    # at the front of the catalogue) remain intact, but BEFORE the
    # quagmire single-layer family and all trigger-driven families
    # so single-layer substitution coverage is robust against budget
    # truncation. ~3 sub_kinds × clue_keywords × alphabet_modes
    # ≈ 100 specs total at typical clue pack sizes.
    for sub_kind, label in (
        ("vigenere", "standalone_vigenere"),
        ("beaufort", "standalone_beaufort"),
        ("variant_beaufort", "standalone_variant_beaufort"),
    ):
        if label in active:
            out.extend(_gen_standalone_substitution_family(
                bench_slug=bench_slug,
                sub_kind=sub_kind,
                clue_keywords=cleaned,
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

    # --- LESSON-008: reverse_blocks families ---------------------------
    # Trigger-driven (block_reversal_triggered set above). When the
    # clue pack contains no block-reversal trigger token, every
    # ``reverse_blocks_*`` family above is absent from ``active`` and
    # the entire block here is a no-op. Real-K4 mode receives the
    # lesson registry entry but has empty HCC seed lists (HCC is
    # bench-mode only via _collect_hcc_seeds), so the families fire
    # only on bench challenges whose clue pack triggers them.
    if block_reversal_triggered:
        block_sizes = _block_sizes_for_payload(clue_text)
        if "reverse_blocks" in active:
            out.extend(_gen_reverse_blocks_alone_family(
                bench_slug=bench_slug,
                block_sizes=block_sizes,
            ))
        # Substitution-paired families: emit only ``reverse_partial``
        # block mode by default. The alone family above already tests
        # both modes, so this avoids doubling the substitution-paired
        # spec count while keeping coverage of both modes per family.
        for sub_kind, label in (
            ("vigenere", "reverse_blocks_vigenere"),
            ("beaufort", "reverse_blocks_beaufort"),
            ("variant_beaufort", "reverse_blocks_variant_beaufort"),
        ):
            if label in active:
                out.extend(_gen_reverse_blocks_substitution_family(
                    bench_slug=bench_slug,
                    sub_kind=sub_kind,
                    keyword_a=keyword_a, keyword_b=keyword_b,
                    block_sizes=block_sizes,
                    alphabet_modes=alphabet_modes,
                    block_modes=("reverse_partial",),
                ))
        if "reverse_blocks_atbash" in active:
            out.extend(_gen_reverse_blocks_atbash_family(
                bench_slug=bench_slug,
                block_sizes=block_sizes,
                block_modes=("reverse_partial", "truncate"),
            ))
        if "reverse_blocks_caesar" in active:
            out.extend(_gen_reverse_blocks_caesar_family(
                bench_slug=bench_slug,
                block_sizes=block_sizes,
                block_modes=("reverse_partial",),
            ))
        if include_three_layer and shift_triggered:
            for sub_kind in ("vigenere", "beaufort", "variant_beaufort"):
                atbash_label = f"{sub_kind}_reverse_blocks_atbash"
                caesar_label = f"{sub_kind}_reverse_blocks_caesar"
                if atbash_label in active:
                    out.extend(_gen_reverse_blocks_three_layer_family(
                        bench_slug=bench_slug,
                        sub_kind=sub_kind,
                        sandwich_partner="atbash",
                        keyword_a=keyword_a, keyword_b=keyword_c,
                        block_sizes=block_sizes,
                        alphabet_modes=alphabet_modes,
                    ))
                if caesar_label in active:
                    out.extend(_gen_reverse_blocks_three_layer_family(
                        bench_slug=bench_slug,
                        sub_kind=sub_kind,
                        sandwich_partner="caesar",
                        keyword_a=keyword_a, keyword_b=keyword_c,
                        block_sizes=block_sizes,
                        alphabet_modes=alphabet_modes,
                    ))

    # --- LESSON-009: Caesar / ROT composition families -----------------
    # Trigger-driven (caesar_triggered set above). When the clue pack
    # contains no Caesar / ROT trigger token, every ``caesar*`` family
    # above is absent from ``active`` and the entire block here is a
    # no-op. Real-K4 mode receives the lesson registry entry but has
    # empty HCC seed lists (HCC is bench-mode only via
    # _collect_hcc_seeds), so the families fire only on bench
    # challenges whose clue pack triggers them.
    if caesar_triggered:
        caesar_shifts = _caesar_shifts_for_payload(clue_text)
        if "caesar" in active:
            out.extend(_gen_caesar_alone_family(
                bench_slug=bench_slug,
                shifts=caesar_shifts,
            ))
        if "caesar_columnar" in active:
            out.extend(_gen_caesar_keyword_transposition_family(
                bench_slug=bench_slug,
                trans_kind="columnar",
                keyword_a=keyword_a, keyword_b=keyword_b,
                shifts=caesar_shifts,
            ))
        if "caesar_myszkowski" in active:
            out.extend(_gen_caesar_keyword_transposition_family(
                bench_slug=bench_slug,
                trans_kind="myszkowski",
                keyword_a=keyword_a, keyword_b=keyword_b,
                shifts=caesar_shifts,
            ))
        if "caesar_rail_fence" in active:
            out.extend(_gen_caesar_keywordless_transposition_family(
                bench_slug=bench_slug,
                trans_kind="rail_fence",
                shifts=caesar_shifts,
                rail_fence_depths=tuple(rail_fence_depths),
            ))
        if "caesar_route" in active:
            out.extend(_gen_caesar_keywordless_transposition_family(
                bench_slug=bench_slug,
                trans_kind="route",
                shifts=caesar_shifts,
                route_grids=_DEFAULT_ROUTE_GRIDS,
            ))
        if "caesar_atbash" in active:
            out.extend(_gen_caesar_atbash_family(
                bench_slug=bench_slug,
                shifts=caesar_shifts,
            ))
        if include_three_layer:
            # Use the first rail-fence depth + first route grid from
            # the resolved sets so three-layer sandwiches enumerate
            # the most-clue-relevant params without multiplying the
            # universe by every candidate.
            sw_depth = (
                rail_fence_depths[0] if rail_fence_depths else 3
            )
            sw_grid = _DEFAULT_ROUTE_GRIDS[0]
            for label, trans_kind, kw_for_trans, kwargs in [
                ("caesar_columnar_atbash", "columnar", keyword_a, {}),
                ("caesar_columnar_atbash", "columnar", keyword_b, {}),
                ("caesar_myszkowski_atbash", "myszkowski", keyword_a, {}),
                ("caesar_myszkowski_atbash", "myszkowski", keyword_b, {}),
                ("caesar_rail_fence_atbash", "rail_fence", "",
                 {"rail_fence_depth": sw_depth}),
                ("caesar_route_atbash", "route", "",
                 {"route_grid": sw_grid}),
            ]:
                if label not in active:
                    continue
                out.extend(_gen_caesar_three_layer_family(
                    bench_slug=bench_slug,
                    trans_kind=trans_kind,
                    keyword=kw_for_trans,
                    shifts=caesar_shifts,
                    **kwargs,
                ))
            # --- LESSON-013: enumerated col_orders in caesar+col+atbash
            # Only the columnar variant gets enumerated; rail_fence /
            # route / myszkowski sandwiches keep their existing shape.
            # Family_label stays ``caesar_columnar_atbash``.
            if "caesar_columnar_atbash" in active:
                out.extend(
                    _gen_enumerated_caesar_columnar_atbash_family(
                        bench_slug=bench_slug,
                        shifts=caesar_shifts,
                        clue_text=clue_text,
                        clue_keywords=cleaned,
                    )
                )

    # --- LESSON-013: 3-layer columnar+sub+rail_fence sandwich --------
    # Closes K4B-006's empirical 24/24 path that the 2-layer
    # columnar+sub cannot reach (probe_all_col_orders.py confirmed
    # 24/24 requires the rail-fence layer). Wired AFTER LESSON-009
    # so the trigger-driven caesar* families fire first under tight
    # budgets — the new family's per-family cap is large
    # (~1200 specs × 3 sub_kinds = 3600 specs total) and would
    # starve caesar otherwise.
    if include_three_layer:
        enumerated_columnar_rf_specs: list[tuple[str, str]] = [
            ("columnar_vigenere_rail_fence",         "vigenere"),
            ("columnar_beaufort_rail_fence",         "beaufort"),
            ("columnar_variant_beaufort_rail_fence", "variant_beaufort"),
        ]
        for label, sub_kind in enumerated_columnar_rf_specs:
            if label not in active:
                continue
            out.extend(
                _gen_enumerated_columnar_sub_rail_fence_family(
                    bench_slug=bench_slug,
                    sub_kind=sub_kind,
                    keyword_a=keyword_a, keyword_b=keyword_b,
                    rail_fence_depths=rail_fence_depths,
                    clue_text=clue_text,
                    clue_keywords=cleaned,
                )
            )

    # --- LESSON-011: skip / step / stride route families ---------------
    # Trigger-driven (skip_route_triggered set above). When the clue
    # pack contains no skip-route trigger token, every ``skip_route*``
    # family is absent from ``active`` and this block is a no-op.
    # Real-K4 mode is unaffected because HCC is bench-mode only via
    # _collect_hcc_seeds; the LESSON-011 entry remains visible to
    # the LLM theorist as a generalized tactic.
    if skip_route_triggered:
        # Full pair enumeration for the alone family (the universe
        # stays small even at the default).
        sk_pairs_full = _skip_route_pairs_for_payload(clue_text)
        # Capped pair list for the (sub × alpha × order × pair)
        # combinatorics. The cap guarantees the combined LESSON-011
        # universe stays bounded under O(few thousand) specs even
        # when block_reversal / caesar / mirror triggers also fire.
        sk_pairs_capped = _skip_route_pairs_for_payload(
            clue_text, cap=_SKIP_ROUTE_PAIR_CAP,
        )
        if "skip_route" in active:
            out.extend(_gen_skip_route_alone_family(
                bench_slug=bench_slug,
                pairs=sk_pairs_full,
            ))
        for sub_kind, label in (
            ("vigenere", "skip_route_vigenere"),
            ("beaufort", "skip_route_beaufort"),
            ("variant_beaufort", "skip_route_variant_beaufort"),
        ):
            if label in active:
                out.extend(_gen_skip_route_substitution_family(
                    bench_slug=bench_slug,
                    sub_kind=sub_kind,
                    keyword_a=keyword_a, keyword_b=keyword_b,
                    pairs=sk_pairs_capped,
                    alphabet_modes=alphabet_modes,
                ))
        if "skip_route_caesar" in active:
            out.extend(_gen_skip_route_caesar_family(
                bench_slug=bench_slug,
                pairs=sk_pairs_capped,
            ))
        if "skip_route_atbash" in active:
            out.extend(_gen_skip_route_atbash_family(
                bench_slug=bench_slug,
                pairs=sk_pairs_capped,
            ))
        if "skip_route_rail_fence" in active:
            out.extend(_gen_skip_route_rail_fence_family(
                bench_slug=bench_slug,
                pairs=sk_pairs_capped,
                rail_fence_depths=tuple(rail_fence_depths),
            ))
        if include_three_layer:
            sw_depth = (
                rail_fence_depths[0] if rail_fence_depths else 3
            )
            # Three-layer sandwiches use a smaller (step, offset)
            # cap so (sub × alpha × pair × layer-orders) stays
            # bounded across the catalog.
            sk_pairs_three = _skip_route_pairs_for_payload(
                clue_text, cap=_SKIP_ROUTE_THREE_LAYER_PAIR_CAP,
            )
            for sub_kind in ("vigenere", "beaufort", "variant_beaufort"):
                rf_label = f"{sub_kind}_skip_route_rail_fence"
                atb_label = f"{sub_kind}_skip_route_atbash"
                cae_label = f"{sub_kind}_skip_route_caesar"
                if rf_label in active:
                    out.extend(_gen_skip_route_three_layer_family(
                        bench_slug=bench_slug,
                        sub_kind=sub_kind,
                        sandwich_partner="rail_fence",
                        keyword_a=keyword_a, keyword_b=keyword_b,
                        pairs=sk_pairs_three,
                        rail_fence_depth=sw_depth,
                        alphabet_modes=alphabet_modes,
                    ))
                if atb_label in active:
                    out.extend(_gen_skip_route_three_layer_family(
                        bench_slug=bench_slug,
                        sub_kind=sub_kind,
                        sandwich_partner="atbash",
                        keyword_a=keyword_a, keyword_b=keyword_b,
                        pairs=sk_pairs_three,
                        alphabet_modes=alphabet_modes,
                    ))
                if cae_label in active:
                    out.extend(_gen_skip_route_three_layer_family(
                        bench_slug=bench_slug,
                        sub_kind=sub_kind,
                        sandwich_partner="caesar",
                        keyword_a=keyword_a, keyword_b=keyword_b,
                        pairs=sk_pairs_three,
                        caesar_shifts=(
                            _SKIP_ROUTE_THREE_LAYER_CAESAR_SHIFTS
                        ),
                        alphabet_modes=alphabet_modes,
                    ))

    # --- LESSON-016: diagonal grid-route families ---------------------
    # Trigger-driven (diagonal_triggered set above). When the clue
    # pack contains no diagonal trigger token, every
    # ``route_diagonal*`` family is absent from ``active`` and this
    # block is a no-op. Real-K4 mode is unaffected because HCC is
    # bench-mode only via _collect_hcc_seeds; the LESSON-016 entry
    # remains visible to the LLM theorist as a generalized tactic.
    #
    # Placement note: emitted BEFORE LESSON-014 (boustrophedon) and
    # LESSON-015 (row_reverse), AFTER LESSON-011 (skip_route). On
    # K4B-009-shaped clues that fire BOTH diagonal and boustrophedon
    # triggers, this ordering keeps LESSON-016 inside the
    # _DEFAULT_MAX_SPECS=10000 bench-fast cap rather than being
    # truncated by LESSON-014's ~5000 specs.
    if diagonal_triggered:
        diag_grids = _diagonal_grids_for_payload(
            clue_text, cleaned,
        )
        # Cap the grid list for substitution-paired families so the
        # (sub × alpha × grid × variant × layer-orders) cartesian
        # stays bounded at bench-fast scale.
        diag_grids_capped = diag_grids[:8]
        if "route_diagonal" in active:
            out.extend(_gen_diagonal_alone_family(
                bench_slug=bench_slug,
                grids=diag_grids,
            ))
        for sub_kind, label in (
            ("vigenere", "route_diagonal_vigenere"),
            ("beaufort", "route_diagonal_beaufort"),
            ("variant_beaufort", "route_diagonal_variant_beaufort"),
        ):
            if label in active:
                out.extend(_gen_diagonal_substitution_family(
                    bench_slug=bench_slug,
                    sub_kind=sub_kind,
                    keyword_a=keyword_a, keyword_b=keyword_b,
                    grids=diag_grids_capped,
                    alphabet_modes=alphabet_modes,
                ))
        if "route_diagonal_rail_fence" in active:
            out.extend(_gen_diagonal_rail_fence_family(
                bench_slug=bench_slug,
                grids=diag_grids_capped,
                rail_fence_depths=tuple(rail_fence_depths),
            ))

    # --- LESSON-018: numeric Caesar/ROT promotion ---------------------
    # Placement note: emitted BEFORE LESSON-014 / -015 / -016 so the
    # ~74-spec LESSON-018 block lands in the LESSON-017 quota pass
    # (pass 1) even at smaller bench-fast caps. The block was
    # originally at the end of generate_layered_specs; on K4B-009-
    # shape clues the LESSON-014 / -015 emissions consumed the cap
    # before LESSON-018 specs were reached.
    if not caesar_triggered:
        promoted_raw = _detect_numeric_caesar_promotion(clue_text)
        if promoted_raw:
            promoted_shifts = _expand_caesar_shifts_with_complement(
                promoted_raw,
            )
            # caesar alone — ALWAYS emit when promotion fires.
            out.extend(_gen_numeric_caesar_alone_family(
                bench_slug=bench_slug,
                promoted_shifts=promoted_shifts,
                numeric_only=True,
            ))
            # caesar + route_boustrophedon, only if boustrophedon
            # trigger also fired (so cross-trigger composition is
            # plausible).
            if boustrophedon_triggered:
                rb_widths_for_caesar = (8, 10)

                def _rb_layer_factory() -> list[dict[str, Any]]:
                    layers: list[dict[str, Any]] = []
                    for w in rb_widths_for_caesar:
                        for vert in (False, True):
                            layers.append(_route_boustrophedon_layer(
                                w, vertical=vert,
                            ))
                    return layers

                def _rb_extras(layer: dict[str, Any]) -> tuple[tuple[str, Any], ...]:
                    params = {p["name"]: p["values"][0] for p in layer.get("params", [])}
                    width = params.get("width")
                    return (
                        ("rb_width", width),
                        ("rb_vertical", params.get("vertical", False)),
                    )

                def _rb_cov_extras(layer: dict[str, Any]) -> dict[str, Any]:
                    params = {p["name"]: p["values"][0] for p in layer.get("params", [])}
                    width = int(params.get("width"))
                    vert = bool(params.get("vertical", False))
                    rows = (97 + width - 1) // width
                    return {
                        "route_mode": "route_boustrophedon",
                        "route_rows": rows,
                        "route_cols": width,
                        "route_width": width,
                        "route_ragged": (97 % width) != 0,
                        "route_direction": "vertical" if vert else "horizontal",
                        "route_width_source": "default_set",
                    }

                out.extend(_gen_numeric_caesar_route_pair_family(
                    bench_slug=bench_slug,
                    route_partner_kind="route_boustrophedon",
                    route_layer_factory=_rb_layer_factory,
                    route_partner_extras_factory=_rb_extras,
                    promoted_shifts=promoted_shifts,
                    numeric_only=True,
                    coverage_extras_factory=_rb_cov_extras,
                ))
            # caesar + route_diagonal.
            if diagonal_triggered:
                # Use the canonical 4 variants × 2 grid sizes as a
                # bounded matrix (8 route layers × 2*N shifts × 2
                # layer orders). At 1 shift n=17 with complement n=9,
                # this produces 8 × 2 × 2 = 32 specs — well within
                # bench-fast scale.
                diag_grids_for_caesar = ((10, 10), (13, 8))
                diag_variants_for_caesar = [
                    ("main", "forward", "top_then_left"),
                    ("anti", "forward", "top_then_right"),
                    ("main", "reverse", "top_then_left"),
                    ("anti", "reverse", "top_then_right"),
                ]

                def _diag_layer_factory() -> list[dict[str, Any]]:
                    layers: list[dict[str, Any]] = []
                    for rows, cols in diag_grids_for_caesar:
                        for axis, order, start_edge in diag_variants_for_caesar:
                            layers.append(_diagonal_route_layer(
                                rows, cols,
                                axis=axis, order=order,
                                start_edge=start_edge,
                            ))
                    return layers

                def _diag_extras(layer: dict[str, Any]) -> tuple[tuple[str, Any], ...]:
                    params = {p["name"]: p["values"][0] for p in layer.get("params", [])}
                    return (
                        ("diag_rows", params.get("rows")),
                        ("diag_cols", params.get("cols")),
                        ("diag_axis", params.get("diagonal_axis")),
                        ("diag_order", params.get("diagonal_order")),
                        ("diag_start_edge", params.get("diagonal_start_edge")),
                    )

                def _diag_cov_extras(layer: dict[str, Any]) -> dict[str, Any]:
                    params = {p["name"]: p["values"][0] for p in layer.get("params", [])}
                    rows = int(params["rows"])
                    cols = int(params["cols"])
                    return {
                        "route_mode": "route_diagonal",
                        "route_rows": rows,
                        "route_cols": cols,
                        "route_width": cols,
                        "route_ragged": (rows * cols) > 97,
                        "route_direction": str(params["diagonal_axis"]),
                        "diagonal_axis": str(params["diagonal_axis"]),
                        "diagonal_order": str(params["diagonal_order"]),
                        "diagonal_start_edge": str(
                            params["diagonal_start_edge"]
                        ),
                    }

                out.extend(_gen_numeric_caesar_route_pair_family(
                    bench_slug=bench_slug,
                    route_partner_kind="route_diagonal",
                    route_layer_factory=_diag_layer_factory,
                    route_partner_extras_factory=_diag_extras,
                    promoted_shifts=promoted_shifts,
                    numeric_only=True,
                    coverage_extras_factory=_diag_cov_extras,
                ))
            # caesar + row_reverse.
            if row_reverse_triggered:
                rr_widths_for_caesar = (8, 10, 12)
                rr_parities_for_caesar = ("odd", "even")

                def _rr_layer_factory() -> list[dict[str, Any]]:
                    layers: list[dict[str, Any]] = []
                    for w in rr_widths_for_caesar:
                        for parity in rr_parities_for_caesar:
                            layers.append(_row_reverse_layer(
                                w, parity, start_row=0,
                            ))
                    return layers

                def _rr_extras(layer: dict[str, Any]) -> tuple[tuple[str, Any], ...]:
                    params = {p["name"]: p["values"][0] for p in layer.get("params", [])}
                    return (
                        ("rr_width", params.get("width")),
                        ("rr_parity", params.get("parity")),
                    )

                def _rr_cov_extras(layer: dict[str, Any]) -> dict[str, Any]:
                    params = {p["name"]: p["values"][0] for p in layer.get("params", [])}
                    w = int(params["width"])
                    parity = str(params["parity"])
                    return {
                        "row_reverse_width": w,
                        "row_reverse_parity": parity,
                        "row_reverse_source": "default_set",
                        "row_reverse_ragged": (97 % w) != 0,
                        "row_reverse_start_row": 0,
                        "row_reverse_identity": _row_reverse_is_identity(
                            w, parity, 0,
                        ),
                    }

                out.extend(_gen_numeric_caesar_route_pair_family(
                    bench_slug=bench_slug,
                    route_partner_kind="row_reverse",
                    route_layer_factory=_rr_layer_factory,
                    route_partner_extras_factory=_rr_extras,
                    promoted_shifts=promoted_shifts,
                    numeric_only=True,
                    coverage_extras_factory=_rr_cov_extras,
                ))

            # --- LESSON-019: role-complete numeric + route + columnar
            # three-layer composition. Fires only when ALL THREE role
            # classes are present: a numeric Caesar/ROT shift
            # (LESSON-018 promotion), a route trigger (boustrophedon
            # OR diagonal), and at least one columnar keyword (clue
            # pool ``cleaned`` has length >= 1 and a usable keyword
            # of length >= 2). Each route partner emits its own
            # bounded family so the LESSON-017 scheduler can apply
            # per-family quotas independently.
            #
            # The same factories used inside the LESSON-018 cross-
            # product blocks are re-instantiated here against the
            # canonical bounded route-layer matrices (top-2 widths
            # for boustrophedon; (10,10)+(13,8) × 4 axis variants
            # for diagonal). Columnar keyword pool is bounded to
            # ``[keyword_a, keyword_b]`` (deduplicated, len>=2 only)
            # so the cartesian universe stays inside three_layer_
            # sandwich quota policy.
            l019_columnar_keywords: list[str] = []
            for _kw in (keyword_a, keyword_b):
                if (
                    isinstance(_kw, str)
                    and _kw.isalpha()
                    and len(_kw) >= 2
                    and _kw not in l019_columnar_keywords
                ):
                    l019_columnar_keywords.append(_kw)
            if l019_columnar_keywords:
                if boustrophedon_triggered:
                    l019_rb_widths = (8, 10)

                    def _l019_rb_layer_factory() -> list[dict[str, Any]]:
                        layers: list[dict[str, Any]] = []
                        for w in l019_rb_widths:
                            for vert in (False, True):
                                layers.append(_route_boustrophedon_layer(
                                    w, vertical=vert,
                                ))
                        return layers

                    def _l019_rb_extras(
                        layer: dict[str, Any],
                    ) -> tuple[tuple[str, Any], ...]:
                        params = {
                            p["name"]: p["values"][0]
                            for p in layer.get("params", [])
                        }
                        return (
                            ("rb_width", params.get("width")),
                            ("rb_vertical", params.get("vertical", False)),
                        )

                    def _l019_rb_cov_extras(
                        layer: dict[str, Any],
                    ) -> dict[str, Any]:
                        params = {
                            p["name"]: p["values"][0]
                            for p in layer.get("params", [])
                        }
                        width = int(params.get("width"))
                        vert = bool(params.get("vertical", False))
                        rows = (97 + width - 1) // width
                        return {
                            "route_mode": "route_boustrophedon",
                            "route_rows": rows,
                            "route_cols": width,
                            "route_width": width,
                            "route_ragged": (97 % width) != 0,
                            "route_direction": (
                                "vertical" if vert else "horizontal"
                            ),
                            "route_width_source": "default_set",
                        }

                    out.extend(
                        _gen_numeric_caesar_route_columnar_family(
                            bench_slug=bench_slug,
                            route_partner_kind="route_boustrophedon",
                            route_layer_factory=_l019_rb_layer_factory,
                            route_partner_extras_factory=_l019_rb_extras,
                            coverage_extras_factory=_l019_rb_cov_extras,
                            promoted_shifts=promoted_shifts,
                            columnar_keywords=l019_columnar_keywords,
                            numeric_only=True,
                        )
                    )
                if diagonal_triggered:
                    l019_diag_grids = ((10, 10), (13, 8))
                    l019_diag_variants = [
                        ("main", "forward", "top_then_left"),
                        ("anti", "forward", "top_then_right"),
                        ("main", "reverse", "top_then_left"),
                        ("anti", "reverse", "top_then_right"),
                    ]

                    def _l019_diag_layer_factory() -> list[dict[str, Any]]:
                        layers: list[dict[str, Any]] = []
                        for rows, cols in l019_diag_grids:
                            for axis, order, start_edge in (
                                l019_diag_variants
                            ):
                                layers.append(_diagonal_route_layer(
                                    rows, cols,
                                    axis=axis, order=order,
                                    start_edge=start_edge,
                                ))
                        return layers

                    def _l019_diag_extras(
                        layer: dict[str, Any],
                    ) -> tuple[tuple[str, Any], ...]:
                        params = {
                            p["name"]: p["values"][0]
                            for p in layer.get("params", [])
                        }
                        return (
                            ("diag_rows", params.get("rows")),
                            ("diag_cols", params.get("cols")),
                            ("diag_axis", params.get("diagonal_axis")),
                            ("diag_order", params.get("diagonal_order")),
                            ("diag_start_edge",
                             params.get("diagonal_start_edge")),
                        )

                    def _l019_diag_cov_extras(
                        layer: dict[str, Any],
                    ) -> dict[str, Any]:
                        params = {
                            p["name"]: p["values"][0]
                            for p in layer.get("params", [])
                        }
                        rows = int(params["rows"])
                        cols = int(params["cols"])
                        return {
                            "route_mode": "route_diagonal",
                            "route_rows": rows,
                            "route_cols": cols,
                            "route_width": cols,
                            "route_ragged": (rows * cols) > 97,
                            "route_direction": str(params["diagonal_axis"]),
                            "route_width_source": "default_set",
                            "diagonal_axis": str(params["diagonal_axis"]),
                            "diagonal_order": str(params["diagonal_order"]),
                            "diagonal_start_edge": str(
                                params["diagonal_start_edge"]
                            ),
                        }

                    out.extend(
                        _gen_numeric_caesar_route_columnar_family(
                            bench_slug=bench_slug,
                            route_partner_kind="route_diagonal",
                            route_layer_factory=_l019_diag_layer_factory,
                            route_partner_extras_factory=_l019_diag_extras,
                            coverage_extras_factory=_l019_diag_cov_extras,
                            promoted_shifts=promoted_shifts,
                            columnar_keywords=l019_columnar_keywords,
                            numeric_only=True,
                        )
                    )

    # --- LESSON-014: width-only ragged boustrophedon families ---------
    # Trigger-driven (boustrophedon_triggered set above). When the
    # clue pack contains no boustrophedon trigger token, every
    # ``route_boustrophedon*`` family is absent from ``active`` and
    # this block is a no-op. Real-K4 mode is unaffected because HCC
    # is bench-mode only via _collect_hcc_seeds; the LESSON-014
    # entry remains visible to the LLM theorist as a generalized
    # tactic.
    if boustrophedon_triggered:
        rb_widths_full = _route_boustrophedon_widths_for_payload(
            clue_text, cleaned,
        )
        # Direction priority (LESSON-014): if the clue contains a
        # vertical-direction token (down/up/vertical/columnwise),
        # the vertical=True variant is enumerated FIRST (in the
        # tuple) so it gets priority under the per-family cap;
        # vertical=False is still emitted as the symmetry partner.
        if boustrophedon_vertical_priority:
            rb_directions: tuple[bool, ...] = (True, False)
        else:
            rb_directions = (False, True)
        # Cap the substitution-paired and three-layer width lists so
        # the (sub × alpha × widths × directions × order) cartesian
        # stays bounded. Phrase-bound widths come first by
        # construction in _route_boustrophedon_widths_for_payload, so
        # truncation never starves a clue-prominent width.
        rb_widths_capped = rb_widths_full[
            :_ROUTE_BOUSTROPHEDON_PAIR_WIDTH_CAP
        ]
        rb_widths_three = rb_widths_full[
            :_ROUTE_BOUSTROPHEDON_THREE_LAYER_WIDTH_CAP
        ]

        if "route_boustrophedon" in active:
            out.extend(_gen_route_boustrophedon_alone_family(
                bench_slug=bench_slug,
                widths=rb_widths_full,
                directions=rb_directions,
            ))
        for sub_kind, label in (
            ("vigenere", "route_boustrophedon_vigenere"),
            ("beaufort", "route_boustrophedon_beaufort"),
            ("variant_beaufort", "route_boustrophedon_variant_beaufort"),
        ):
            if label in active:
                out.extend(
                    _gen_route_boustrophedon_substitution_family(
                        bench_slug=bench_slug,
                        sub_kind=sub_kind,
                        keyword_a=keyword_a, keyword_b=keyword_b,
                        widths=rb_widths_capped,
                        directions=rb_directions,
                        alphabet_modes=alphabet_modes,
                    )
                )
        if "route_boustrophedon_caesar" in active:
            out.extend(_gen_route_boustrophedon_caesar_family(
                bench_slug=bench_slug,
                widths=rb_widths_capped,
                directions=rb_directions,
            ))
        if "route_boustrophedon_atbash" in active:
            out.extend(_gen_route_boustrophedon_atbash_family(
                bench_slug=bench_slug,
                widths=rb_widths_capped,
                directions=rb_directions,
            ))
        if "route_boustrophedon_rail_fence" in active:
            out.extend(_gen_route_boustrophedon_rail_fence_family(
                bench_slug=bench_slug,
                widths=rb_widths_capped,
                rail_fence_depths=tuple(rail_fence_depths),
                directions=rb_directions,
            ))
        if include_three_layer:
            sw_depth = (
                rail_fence_depths[0] if rail_fence_depths else 3
            )
            for sub_kind in (
                "vigenere", "beaufort", "variant_beaufort",
            ):
                rf_label = (
                    f"{sub_kind}_route_boustrophedon_rail_fence"
                )
                col_label = (
                    f"{sub_kind}_route_boustrophedon_columnar"
                )
                if rf_label in active:
                    out.extend(
                        _gen_route_boustrophedon_three_layer_family(
                            bench_slug=bench_slug,
                            sub_kind=sub_kind,
                            sandwich_partner="rail_fence",
                            keyword_a=keyword_a, keyword_b=keyword_b,
                            widths=rb_widths_three,
                            directions=rb_directions,
                            rail_fence_depth=sw_depth,
                            alphabet_modes=alphabet_modes,
                        )
                    )
                if col_label in active and len(cleaned) >= 2:
                    out.extend(
                        _gen_route_boustrophedon_three_layer_family(
                            bench_slug=bench_slug,
                            sub_kind=sub_kind,
                            sandwich_partner="columnar",
                            keyword_a=keyword_a, keyword_b=keyword_b,
                            columnar_keyword=keyword_b,
                            widths=rb_widths_three,
                            directions=rb_directions,
                            alphabet_modes=alphabet_modes,
                        )
                    )

    # --- LESSON-015: alternate-row reversal / folded-strip families ---
    # Trigger-driven (row_reverse_triggered set above). When the clue
    # pack contains no row_reverse trigger token, every ``row_reverse*``
    # family is absent from ``active`` and this block is a no-op.
    # Real-K4 mode is unaffected because HCC is bench-mode only via
    # _collect_hcc_seeds; the LESSON-015 entry remains visible to the
    # LLM theorist as a generalized tactic.
    if row_reverse_triggered:
        rr_widths_full = _row_reverse_widths_for_payload(
            clue_text, cleaned,
        )
        # Ensure the no-fold sentinel (width=CT_LEN) survives the
        # per-family cap. The sentinel is appended LAST by the width
        # resolver so phrase-bound and keyword-derived widths fill
        # the cap first; we then explicitly merge the sentinel into
        # the capped list. Without this, substitution+row_reverse
        # families miss the substitution-alone-equivalent path.
        def _capped_with_sentinel(
            full: Sequence[tuple[int, str]], cap: int,
        ) -> list[tuple[int, str]]:
            out_list = list(full[:cap])
            keys = {w for w, _ in out_list}
            for w, src in full:
                if w == 97 and w not in keys:
                    out_list.append((w, src))
                    break
            return out_list

        rr_widths_capped = _capped_with_sentinel(
            rr_widths_full, _ROW_REVERSE_PAIR_WIDTH_CAP,
        )
        rr_widths_three = _capped_with_sentinel(
            rr_widths_full, _ROW_REVERSE_THREE_LAYER_WIDTH_CAP,
        )
        rr_parities = _DEFAULT_ROW_REVERSE_PARITIES

        if "row_reverse" in active:
            out.extend(_gen_row_reverse_alone_family(
                bench_slug=bench_slug,
                widths=rr_widths_full,
                parities=rr_parities,
            ))
        for sub_kind, label in (
            ("vigenere", "row_reverse_vigenere"),
            ("beaufort", "row_reverse_beaufort"),
            ("variant_beaufort", "row_reverse_variant_beaufort"),
        ):
            if label in active:
                out.extend(_gen_row_reverse_substitution_family(
                    bench_slug=bench_slug,
                    sub_kind=sub_kind,
                    keyword_a=keyword_a, keyword_b=keyword_b,
                    widths=rr_widths_capped,
                    parities=rr_parities,
                    alphabet_modes=alphabet_modes,
                ))
        if "row_reverse_caesar" in active:
            out.extend(_gen_row_reverse_caesar_family(
                bench_slug=bench_slug,
                widths=rr_widths_capped,
                parities=rr_parities,
            ))
        if "row_reverse_atbash" in active:
            out.extend(_gen_row_reverse_atbash_family(
                bench_slug=bench_slug,
                widths=rr_widths_capped,
                parities=rr_parities,
            ))
        if "row_reverse_rail_fence" in active:
            out.extend(_gen_row_reverse_rail_fence_family(
                bench_slug=bench_slug,
                widths=rr_widths_capped,
                rail_fence_depths=tuple(rail_fence_depths),
                parities=rr_parities,
            ))
        if include_three_layer:
            sw_route_grid = _DEFAULT_ROUTE_GRIDS[0]
            for sub_kind in (
                "vigenere", "beaufort", "variant_beaufort",
            ):
                route_label = f"{sub_kind}_route_row_reverse"
                rb_label = (
                    f"{sub_kind}_route_boustrophedon_row_reverse"
                )
                if route_label in active:
                    out.extend(
                        _gen_row_reverse_route_three_layer_family(
                            bench_slug=bench_slug,
                            sub_kind=sub_kind,
                            route_partner="route",
                            keyword_a=keyword_a, keyword_b=keyword_b,
                            widths=rr_widths_three,
                            parities=rr_parities,
                            route_grid=sw_route_grid,
                            alphabet_modes=alphabet_modes,
                        )
                    )
                if rb_label in active:
                    out.extend(
                        _gen_row_reverse_route_three_layer_family(
                            bench_slug=bench_slug,
                            sub_kind=sub_kind,
                            route_partner="route_boustrophedon",
                            keyword_a=keyword_a, keyword_b=keyword_b,
                            widths=rr_widths_three,
                            parities=rr_parities,
                            route_boustrophedon_widths=(8, 10),
                            alphabet_modes=alphabet_modes,
                        )
                    )

    # Validate every emitted spec; drop the ones the dispatcher would
    # reject. This is a belt-and-suspenders check — the family
    # generators already produce dispatcher-shaped specs, but a future
    # kernel-side enforcement change could invalidate one of them and
    # we want fail-closed silence rather than cascading dispatch
    # failures inside the worker.
    #
    # 2026-04-29 (LESSON-017): validation runs on the FULL emitted
    # stream (no front-truncation). The cap is then applied by the
    # stratified two-pass scheduler so triggered families are not
    # starved of dispatched specs when many lessons fire on the
    # same clue.
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
    # LESSON-017: stratified scheduling (two-pass: quota then residual).
    # When ``len(validated) <= max_specs`` the scheduler still runs so
    # every retained spec carries scheduling_pass telemetry.
    return _stratified_schedule(validated, max_specs)


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
