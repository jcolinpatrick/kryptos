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
_DEFAULT_MAX_SPECS: int = 5000


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
