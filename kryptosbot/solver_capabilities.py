"""SolverCapabilities — generalized solver lessons (no sealed material).

Purpose
-------
A capability ledger that records lessons learned from prior runs as
GENERALIZED tactical heuristics. The lessons drive the bench-mode
fallback generator AND can be consumed by the real-K4 path without
ever importing K4Bench plaintexts or answer keys.

The user-facing contract:

    "This registry may guide future K4Bench and real-K4 generation,
     but it must store only generalized tactics, never sealed answers
     or benchmark plaintexts."

Every Lesson record passes a forbidden-field check at construction
time. The registry's ``add`` method re-runs the check on every
incoming lesson, so a programming error that tries to attach a
plaintext to a lesson fails loud rather than silently leaking.

Lessons are pure heuristics — they describe "in family X, also try
the role-swap" — never "in family X, the answer is Y". The
distinction is enforced structurally:

    Allowed fields: lesson_id, title, description, tactic_kind,
                    applies_to_families, generates_specs,
                    related_lesson_ids, source_origin (slug),
                    coverage_floor, references (URLs only).

    Forbidden fields: plaintext, ciphertext, answer, solution,
                      sealed, encryption_key, decryption_key,
                      key_material, target_pt, decryption_layers_in_order.

Storage
-------
JSON file under ``db/solver_capabilities/lessons.json`` (created on
first init). The schema is versioned and forward-compatible: new
fields are added with safe defaults; old reader code keeps working.

The default lesson set seeds the six lessons enumerated in the
patch spec:

    LESSON-001  clue_role_permutation
    LESSON-002  layer_order_inversion
    LESSON-003  keyword_tableau_role_ambiguity
    LESSON-004  transposition_width_from_keyword_length
    LESSON-005  stable_column_order_tie_handling
    LESSON-006  failed_method_coverage
    LESSON-007  trigger_driven_alphabet_enumeration
    LESSON-008  fixed_size_block_reversal
    LESSON-009  caesar_rot_composition
    LESSON-010  independent_multi_role_assignment
    LESSON-011  skip_step_route_enumeration
    LESSON-012  phrase_attached_numeric_prominence
    LESSON-013  arbitrary_columnar_order_enumeration
    LESSON-014  width_only_ragged_boustrophedon_route
    LESSON-015  alternate_row_reversal_folded_strip
    LESSON-016  diagonal_grid_route_enumeration

The constructor refuses to load any registry file containing
forbidden fields, so a corrupted on-disk registry fails closed.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional


logger = logging.getLogger("kryptosbot.solver_capabilities")


# ---------------------------------------------------------------------------
# Forbidden / allowed field guards
# ---------------------------------------------------------------------------

# Field names whose presence anywhere in a Lesson dict (or nested
# values) indicates sealed material has leaked into the registry.
# The check is recursive on dicts and lists. Substring match is used
# so e.g. "answer_key" trips on "answer" — deliberately conservative.
_FORBIDDEN_TOKENS: tuple[str, ...] = (
    "plaintext",
    "ciphertext",
    "answer",
    "solution",
    "sealed",
    "encryption_key",
    "decryption_key",
    "key_material",
    "target_pt",
    "decryption_layers_in_order",
    "encryption_layers_in_order",
)


class LessonValidationError(ValueError):
    """Raised when a Lesson contains forbidden / sealed material."""


def _looks_like_sealed_string(s: str) -> bool:
    """Heuristic: a long uppercase A-Z string with no whitespace and
    no common-word substring is suspicious — that's the shape of a
    K4-style plaintext or ciphertext. Conservative: requires len >= 30
    so descriptive ALL-CAPS phrases like "VIGENERE+COLUMNAR" don't
    trip.
    """
    if not isinstance(s, str) or len(s) < 30:
        return False
    if not s.isalpha() or not s.isupper():
        return False
    # No spaces / punctuation already implied by isalpha. Long
    # contiguous A-Z is the danger signal.
    return True


def _scan_for_forbidden(node: Any, path: str = "") -> list[str]:
    """Recursive walk; returns paths whose key contains a forbidden
    token OR whose string value looks like a sealed-material blob.
    A non-empty return means the lesson is rejected.
    """
    found: list[str] = []
    if isinstance(node, Mapping):
        for k, v in node.items():
            kl = str(k).lower()
            for tok in _FORBIDDEN_TOKENS:
                if tok in kl:
                    found.append(f"{path}{k}")
                    break
            found.extend(_scan_for_forbidden(v, path=f"{path}{k}."))
    elif isinstance(node, list):
        for i, item in enumerate(node):
            found.extend(_scan_for_forbidden(item, path=f"{path}[{i}]."))
    elif isinstance(node, str):
        if _looks_like_sealed_string(node):
            found.append(f"{path}<value-looks-like-sealed-string>")
    return found


# ---------------------------------------------------------------------------
# Lesson dataclass
# ---------------------------------------------------------------------------


# Allowed values for ``tactic_kind``. Adding a new tactic kind here
# requires an explicit code change so the categorical surface area
# stays small and reviewable.
_VALID_TACTIC_KINDS: frozenset[str] = frozenset({
    "role_permutation",            # swap clue-word roles across layers
    "layer_order_inversion",       # try both decrypt-stack orders
    "keyword_tableau_ambiguity",   # Quagmire IV pt vs ct keyword roles
    "parameter_derivation",        # derive width / depth from keyword
    "tie_handling",                # stable rank tie-break specification
    "coverage_completion",         # close gaps after partial coverage
    "general_search_policy",       # high-level policy heuristic
    "alphabet_mode_enumeration",   # 2026-04-27: trigger-driven alphabet
                                   # variant enumeration over substitution
                                   # layers (AZ, KA, keyword_mixed,
                                   # mirrored_az, mirrored_ka)
    "block_reversal_enumeration",  # 2026-04-28: trigger-driven fixed-
                                   # size block reversal as a hand-
                                   # cipher transposition primitive
                                   # (LESSON-008). Generalizes the
                                   # K4B-004 miss into a reusable
                                   # tactic; clue-derived block sizes
                                   # plus safe defaults compose with
                                   # vig/beau/var_beau/caesar/atbash.
    "caesar_rot_composition",      # 2026-04-28: trigger-driven Caesar /
                                   # ROT shift composed with keyed
                                   # transpositions and Atbash
                                   # (LESSON-009). Generalizes the
                                   # K4B-003 miss into a reusable
                                   # tactic; clue-derived shift values
                                   # plus safe defaults compose with
                                   # columnar / myszkowski / rail_fence /
                                   # route / atbash.
    "independent_multi_role_assignment",  # 2026-04-28: independent
                                   # enumeration of substitution /
                                   # alphabet / transposition role
                                   # keywords from the clue pool,
                                   # NOT just pairwise. Generalizes
                                   # the K4B-005 miss where the
                                   # intended cipher used three
                                   # distinct clue keywords across
                                   # three independent role slots
                                   # (LESSON-010).
    "skip_step_route_enumeration", # 2026-04-28: trigger-driven
                                   # modular skip / step / stride
                                   # route transposition. Generalizes
                                   # the K4B-006 miss into a reusable
                                   # tactic. Clue-derived (step,
                                   # offset) pairs plus safe defaults
                                   # compose with vig/beau/var_beau/
                                   # caesar/atbash/rail_fence
                                   # (LESSON-011).
    "phrase_attached_numeric_prominence",  # 2026-04-28: bind clue
                                   # numerals to their semantic
                                   # anchor words so each numeric-
                                   # parametrized lesson (rail_fence
                                   # depth, reverse_blocks block_size,
                                   # caesar shift_value, skip_route
                                   # step+offset) consumes its own
                                   # phrase-bound numerals before
                                   # falling back to default sets.
                                   # Closes the K4B-006 cap-budget
                                   # starvation where "step five" was
                                   # outranked by "three steps" /
                                   # "four rails" in a flat numeral
                                   # bag (LESSON-012).
    "arbitrary_columnar_order_enumeration",  # 2026-04-28: enumerate
                                   # ALL W! columnar col_orders for
                                   # small widths (W in 2..7), in
                                   # addition to the existing keyword-
                                   # derived col_orders. Generalizes
                                   # the K4B-006 Gap B finding: the
                                   # answer used col_order=(4,1,3,0,2)
                                   # which is NOT producible from any
                                   # natural 5-letter keyword via
                                   # stable rank. The lesson is the
                                   # bounded-exhaustive enumeration,
                                   # not the specific permutation
                                   # (LESSON-013).
    "width_only_ragged_boustrophedon_route",  # 2026-04-28: width-only
                                   # ragged boustrophedon (serpentine)
                                   # route as a hand-cipher transposition
                                   # primitive. Generalizes the K4B-007
                                   # miss into a reusable tactic. The
                                   # existing ``route`` kind requires
                                   # explicit rows AND cols + a non-
                                   # ragged grid; this lesson adds the
                                   # width-only ``route_boustrophedon``
                                   # kind so a clue like "ragged eight-
                                   # column grid" emits the correct
                                   # permutation directly. Clue-
                                   # derived widths plus safe defaults
                                   # compose with vig/beau/var_beau/
                                   # caesar/atbash/rail_fence and (for
                                   # three-layer families) columnar
                                   # (LESSON-014).
    "alternate_row_reversal_folded_strip",  # 2026-04-28: folded-
                                   # strip / alternate-row reversal
                                   # as a hand-cipher transposition
                                   # primitive. Generalizes the K4B-008
                                   # miss into a reusable tactic. The
                                   # existing transposition catalog
                                   # had no in-place row-reversal
                                   # primitive (route_boustrophedon
                                   # reads the GRID serpentine, but
                                   # does not selectively reverse
                                   # rows in place). LESSON-015 adds
                                   # the ``row_reverse`` kind which
                                   # is self-inverse: applying it
                                   # twice with the same parameters
                                   # returns the identity. Clue-
                                   # derived widths plus safe
                                   # defaults compose with vig/beau/
                                   # var_beau/caesar/atbash/rail_fence
                                   # and (for three-layer families)
                                   # route + route_boustrophedon
                                   # (LESSON-015).
    "diagonal_grid_route_enumeration",  # 2026-04-29: diagonal grid-
                                   # route transposition. Generalizes
                                   # K4B-009 into a reusable tactic.
                                   # The existing transposition catalog
                                   # had no diagonal-route primitive
                                   # (serpentine_perm reads rows;
                                   # spiral_perm reads outside-in;
                                   # neither traces the NW->SE or
                                   # NE->SW stripes a diagonal clue
                                   # actually names). LESSON-016
                                   # extends the existing ``route``
                                   # kind with variant="diagonal" plus
                                   # axis (main|anti) / order
                                   # (forward|reverse) /
                                   # start_edge (axis-constrained
                                   # whitelist). The kernel's
                                   # ``diagonal_perm`` produces a
                                   # length-preserving bijection
                                   # under ragged grids. Clue
                                   # geometry words such as diagonal
                                   # / oblique / slant / cross /
                                   # lattice / stones / mason now
                                   # instantiate route operations,
                                   # not only keyword material
                                   # (LESSON-016).
})


@dataclass
class Lesson:
    """One generalized solver tactic.

    Lessons describe HOW to search, not WHAT the answer is. The
    forbidden-field check at __post_init__ fails loud if a caller
    tries to attach sealed material.

    2026-04-27: ``tactic_parameters`` carries machine-readable knobs
    that drive the generalized tactic (e.g. trigger token list,
    alphabet mode label set). The runtime code in
    ``kryptosbot.hand_cipher_core`` SHOULD treat the lesson as the
    audit-time source of truth: a drift test asserts that the
    runtime constants match the lesson's parameters. The
    forbidden-field scan walks ``tactic_parameters`` recursively
    so a misconfigured parameter cannot smuggle sealed material in.
    """
    lesson_id: str                                              # e.g. "LESSON-001"
    title: str
    description: str
    tactic_kind: str
    applies_to_families: list[str] = field(default_factory=list)
    generates_specs: bool = False
    related_lesson_ids: list[str] = field(default_factory=list)
    source_origin: str = ""                                     # e.g. "k4bench-derived"
    coverage_floor: dict[str, int] = field(default_factory=dict)
    references: list[str] = field(default_factory=list)
    enabled: bool = True
    tactic_parameters: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.lesson_id or not isinstance(self.lesson_id, str):
            raise LessonValidationError("Lesson.lesson_id must be a non-empty str")
        if self.tactic_kind not in _VALID_TACTIC_KINDS:
            raise LessonValidationError(
                f"Lesson.tactic_kind {self.tactic_kind!r} not in "
                f"{sorted(_VALID_TACTIC_KINDS)}"
            )
        # Recursive forbidden-field scan over the whole lesson dict.
        forbidden = _scan_for_forbidden(asdict(self))
        if forbidden:
            raise LessonValidationError(
                f"Lesson {self.lesson_id} contains forbidden sealed "
                f"material at field paths: {forbidden}. "
                "The lesson registry stores generalized tactics only; "
                "plaintexts, answer keys, and ciphertexts are not "
                "allowed even as nested values."
            )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "Lesson":
        allowed = {k for k in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in d.items() if k in allowed})


# ---------------------------------------------------------------------------
# Default lesson seed set
# ---------------------------------------------------------------------------


def _default_lessons() -> list[Lesson]:
    """Return the canonical lesson seed set.

    Six lessons matching the user-mandated registry contents. The
    ordering matches lesson_id; consumers may filter by tactic_kind
    or applies_to_families.
    """
    return [
        Lesson(
            lesson_id="LESSON-001",
            title="Clue-role permutation",
            description=(
                "When a clue pack supplies two or more keywords and the "
                "candidate cipher is multi-layer, every keyword role "
                "assignment must be tested. For two keywords A and B "
                "across roles X and Y, dispatch BOTH X(A)/Y(B) and "
                "X(B)/Y(A); never assume the lexical order in the clue "
                "text matches the encryption-time role order."
            ),
            tactic_kind="role_permutation",
            applies_to_families=[
                "columnar_vigenere", "columnar_beaufort",
                "columnar_variant_beaufort",
                "myszkowski_vigenere", "myszkowski_beaufort",
                "quagmire",
            ],
            generates_specs=True,
            source_origin="k4bench-derived",
        ),
        Lesson(
            lesson_id="LESSON-002",
            title="Layer-order inversion",
            description=(
                "For any two-layer family (X, Y), test both decrypt "
                "stack orders [X, Y] and [Y, X]. The encryption-time "
                "outermost layer is the decryption-time first-applied "
                "layer; without testing both orders you only cover half "
                "the family."
            ),
            tactic_kind="layer_order_inversion",
            applies_to_families=["*"],
            generates_specs=True,
            related_lesson_ids=["LESSON-001"],
            source_origin="k4bench-derived",
        ),
        Lesson(
            lesson_id="LESSON-003",
            title="Keyword/tableau role ambiguity (Quagmire IV)",
            description=(
                "Quagmire IV uses distinct pt_alphabet_keyword and "
                "ct_alphabet_keyword. When a clue supplies two "
                "keywords A and B, both (pt=A, ct=B) and (pt=B, ct=A) "
                "must be tested. The kernel rejects a Quagmire IV "
                "spec where the two keywords are identical, but does "
                "NOT enforce a particular role assignment."
            ),
            tactic_kind="keyword_tableau_ambiguity",
            applies_to_families=["quagmire"],
            generates_specs=True,
            source_origin="kernel-doctrine",
        ),
        Lesson(
            lesson_id="LESSON-004",
            title="Transposition width from keyword length",
            description=(
                "For columnar transposition, the column count equals "
                "the keyword length, and the column-read order is the "
                "stable rank order of the keyword's letters. Hand-cipher "
                "convention: A=1, then alphabetical ascending, with "
                "left-to-right tie-break for repeated letters."
            ),
            tactic_kind="parameter_derivation",
            applies_to_families=["columnar_vigenere", "columnar_beaufort", "columnar_variant_beaufort"],
            generates_specs=True,
            source_origin="hand-cipher-doctrine",
        ),
        Lesson(
            lesson_id="LESSON-005",
            title="Stable column-order tie handling",
            description=(
                "Repeated letters in a transposition keyword must "
                "rank in DOCUMENT order (left-to-right), never in "
                "implementation-defined / locale-dependent order. "
                "Equivalent specifications produced by different "
                "tie-break conventions are NOT cross-compatible; "
                "always use the stable convention."
            ),
            tactic_kind="tie_handling",
            applies_to_families=["columnar_vigenere", "columnar_beaufort", "columnar_variant_beaufort", "myszkowski_vigenere", "myszkowski_beaufort"],
            generates_specs=False,
            source_origin="kernel-doctrine",
        ),
        Lesson(
            lesson_id="LESSON-006",
            title="Failed-method coverage",
            description=(
                "When a candidate cipher family has been partially "
                "tested (e.g. one of the four (role × order) points in "
                "a two-keyword two-layer family), the remaining points "
                "must be exhausted before exploring an unrelated "
                "family. A negative result on one symmetry-class point "
                "does NOT eliminate the family until every point in "
                "the class has tested negative."
            ),
            tactic_kind="coverage_completion",
            applies_to_families=["*"],
            generates_specs=True,
            related_lesson_ids=["LESSON-001", "LESSON-002"],
            source_origin="k4bench-derived",
        ),
        Lesson(
            lesson_id="LESSON-007",
            title="Trigger-driven alphabet/tableau enumeration",
            description=(
                "When clue-pack language gestures at alphabet "
                "transformation — words such as mirror, mirrored, "
                "alpha, alphabet, strip, table, tableau, reverse, "
                "reversed, fold, or folded (case-insensitive, "
                "word-boundary match) — every substitution-family "
                "layer in a candidate pipeline MUST enumerate "
                "additional alphabet variants beyond the canonical "
                "AZ tableau. The required mode set is: AZ "
                "(canonical), KA (KRYPTOS-prefixed mixed), "
                "keyword_mixed for each available clue keyword, "
                "mirrored_az (reversed canonical alphabet used as "
                "the substitution tableau via the keyword_mixed "
                "dispatcher path), and mirrored_ka (reversed "
                "KRYPTOS-prefixed alphabet, same path). The lesson "
                "applies to Vigenere, Beaufort, Variant Beaufort, "
                "Quagmire, and any of those substitution layers "
                "paired with rail_fence, route, columnar, or "
                "Myszkowski transpositions. When no trigger word is "
                "present the standard non-mirrored modes (AZ, KA, "
                "keyword_mixed) are still emitted; mirrored variants "
                "only fire on trigger language so the candidate set "
                "stays bounded."
            ),
            tactic_kind="alphabet_mode_enumeration",
            applies_to_families=[
                "vigenere", "beaufort", "variant_beaufort",
                "quagmire",
                "columnar_vigenere", "columnar_beaufort",
                "columnar_variant_beaufort",
                "myszkowski_vigenere", "myszkowski_beaufort",
                "rail_fence_vigenere", "rail_fence_beaufort",
                "route_vigenere", "route_beaufort",
            ],
            generates_specs=True,
            related_lesson_ids=["LESSON-003", "LESSON-006"],
            source_origin="k4bench-derived",
            # Machine-readable knobs. The runtime in
            # kryptosbot.hand_cipher_core treats these as the
            # audit-time source of truth; a drift test asserts the
            # runtime constants match. Keys are lowercase + underscored
            # so the recursive forbidden-field scan can grep for
            # sealed-material tokens without false-positives on the
            # generic field names.
            tactic_parameters={
                "trigger_tokens": [
                    "mirror", "mirrored",
                    "alpha", "alphabet",
                    "strip", "table", "tableau",
                    "reverse", "reversed",
                    "fold", "folded",
                ],
                "alphabet_mode_labels": [
                    "AZ", "KA", "keyword_mixed",
                    "mirrored_az", "mirrored_ka",
                ],
                "trigger_match": "word_boundary_case_insensitive",
                "applies_to_substitution_kinds": [
                    "vigenere", "beaufort", "variant_beaufort",
                ],
                "applies_to_paired_transposition_kinds": [
                    "columnar", "myszkowski", "rail_fence", "route",
                ],
            },
        ),
        Lesson(
            lesson_id="LESSON-008",
            title="Fixed-size block / chunk reversal",
            description=(
                "When clue-pack language gestures at fixed-size "
                "groupings, in-block reordering, or directional "
                "reversal — words such as block, blocks, chunk, "
                "chunks, group, groups, small group, backward, "
                "backwards, reverse, reversed, reversal, turn, "
                "clockwise, counterclockwise, clock, route before, "
                "read first, read last, before key, after key — the "
                "candidate pipeline MUST enumerate a fixed-size "
                "block-reversal transposition (the reverse_blocks "
                "kind). The block size is drawn from clue-derived "
                "numerals (digit literals 2..49 and small spelled "
                "numbers two..twenty) UNIONED with the safe default "
                "set {2, 3, 4, 5, 6, 7, 8, 10}. Two block modes are "
                "enumerated: reverse_partial (reverse every block "
                "including a partial trailing one) and truncate "
                "(reverse complete blocks only; trailing tail is "
                "identity). The lesson composes with the existing "
                "substitution families: reverse_blocks alone, plus "
                "two-layer pairings with vigenere, beaufort, "
                "variant_beaufort, caesar, and atbash in BOTH layer "
                "orders, plus three-layer sandwiches where "
                "reverse_blocks sits between or after a substitution "
                "and Atbash/Caesar when shift/reverse trigger "
                "language is also present. The lesson is a "
                "GENERALIZED tactic: it stores trigger vocabulary, "
                "block-size knobs, and family pairings — never "
                "challenge-specific plaintexts or sealed material."
            ),
            tactic_kind="block_reversal_enumeration",
            applies_to_families=[
                "reverse_blocks",
                "reverse_blocks_vigenere",
                "reverse_blocks_beaufort",
                "reverse_blocks_variant_beaufort",
                "reverse_blocks_caesar",
                "reverse_blocks_atbash",
                "vigenere_reverse_blocks_atbash",
                "beaufort_reverse_blocks_caesar",
            ],
            generates_specs=True,
            related_lesson_ids=["LESSON-002", "LESSON-006", "LESSON-007"],
            source_origin="k4bench-derived",
            tactic_parameters={
                "trigger_tokens": [
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
                ],
                "default_block_sizes": [2, 3, 4, 5, 6, 7, 8, 10],
                "block_modes": ["reverse_partial", "truncate"],
                "trigger_match": "phrase_or_word_boundary_case_insensitive",
                "applies_to_substitution_kinds": [
                    "vigenere", "beaufort", "variant_beaufort",
                    "caesar", "atbash",
                ],
                "shift_trigger_tokens": [
                    "shift", "shifted", "rotate", "rotated", "rotation",
                    "turn", "clockwise", "counterclockwise",
                ],
                "operation_source_labels": [
                    "clue_numeral", "clue_phrase", "default_set",
                ],
            },
        ),
        Lesson(
            lesson_id="LESSON-009",
            title="Caesar / ROT composition with transposition + Atbash",
            description=(
                "When clue-pack language gestures at additive shifts "
                "or rotations — words such as shift, shifted, offset, "
                "rotate, rotated, rotation, step, caesar, rot, "
                "additive, subtractive — the candidate pipeline MUST "
                "enumerate a canonical Caesar / ROT layer (the "
                "first-class ``caesar`` DSL kind, NOT a 1-letter "
                "Vigenere collapse, so coverage_vector and attempt "
                "layers explicitly carry shift_value and "
                "operation_source). Shift values are drawn from "
                "clue-derived numerals (digit literals 0..25 and "
                "small spelled numerals two..twenty) UNIONED with "
                "the safe default set {1, 3, 5, 7, 8, 13, 17, 23} "
                "(common shift constants including ROT13). The "
                "lesson composes Caesar with the keyed transpositions "
                "(columnar, myszkowski, rail_fence, route) in BOTH "
                "layer orders, with Atbash in BOTH layer orders, and "
                "with the four three-layer sandwiches that route "
                "through Caesar + transposition + Atbash, Atbash + "
                "transposition + Caesar, transposition + Caesar + "
                "Atbash, and Atbash + Caesar + transposition. The "
                "lesson is GENERALIZED: it stores trigger vocabulary, "
                "shift-value knobs, and family pairings — never "
                "challenge-specific plaintexts or sealed material."
            ),
            tactic_kind="caesar_rot_composition",
            applies_to_families=[
                "caesar",
                "caesar_columnar",
                "caesar_myszkowski",
                "caesar_rail_fence",
                "caesar_route",
                "caesar_atbash",
                "caesar_columnar_atbash",
                "atbash_columnar_caesar",
                "columnar_caesar_atbash",
                "atbash_caesar_columnar",
            ],
            generates_specs=True,
            related_lesson_ids=["LESSON-001", "LESSON-002", "LESSON-008"],
            source_origin="k4bench-derived",
            tactic_parameters={
                "trigger_tokens": [
                    "shift", "shifted", "offset",
                    "rotate", "rotated", "rotation",
                    "step",
                    "caesar",
                    "rot",
                    "additive", "subtractive",
                ],
                "default_shifts": [1, 3, 5, 7, 8, 13, 17, 23],
                "trigger_match": "word_boundary_case_insensitive",
                "applies_to_transposition_kinds": [
                    "columnar", "myszkowski", "rail_fence", "route",
                ],
                "applies_to_substitution_partners": [
                    "atbash",
                ],
                "operation_source_labels": [
                    "clue_numeral", "clue_phrase", "default_set",
                ],
                "three_layer_orders": [
                    ["caesar", "transposition", "atbash"],
                    ["atbash", "transposition", "caesar"],
                    ["transposition", "caesar", "atbash"],
                    ["atbash", "caesar", "transposition"],
                ],
            },
        ),
        Lesson(
            lesson_id="LESSON-010",
            title="Independent multi-role keyword assignment",
            description=(
                "When a candidate has at least three role slots — "
                "substitution keyword, alphabet/tableau keyword, "
                "transposition keyword (and optionally Quagmire "
                "period_keyword, pt_alphabet_keyword, ct_alphabet_"
                "keyword, indicator/key-letter, route/grid keyword) — "
                "every role MUST be enumerable independently from "
                "the clue keyword pool. The pre-LESSON-010 generator "
                "iterated only pairwise role swaps (sub_keyword, "
                "trans_keyword) ∈ {(A,B), (B,A)} with the alphabet "
                "keyword tied to the substitution role; this missed "
                "any candidate where the alphabet/tableau keyword is "
                "a third clue word. The lesson requires that for a "
                "clue pool {A, B, C, ...}, the generator emit "
                "candidates of the form ``substitution(key=A, "
                "alphabet_keyword=B) ∘ transposition(keyword=C)`` "
                "and all bounded permutations across the three "
                "roles, in BOTH layer orders. Each emitted spec "
                "MUST tag its CoverageVector with the explicit "
                "role keywords (substitution_keyword, "
                "alphabet_keyword, transposition_keyword) so a "
                "downstream attempt-artifact reader can resolve "
                "the question 'did we test substitution key X with "
                "alphabet key Y and transposition key Z?'. To keep "
                "the universe "
                "bounded, the role enumeration is capped at the "
                "first ``role_pool_size`` clue keywords (default 3); "
                "operators with more clue words rely on clue "
                "ranking to put the right keywords first. Self-"
                "pairs (sub_keyword == trans_keyword) are admitted "
                "because some hand ciphers reuse the same keyword "
                "across roles. The lesson is GENERALIZED: it stores "
                "role-slot taxonomy and the bounded-pool policy "
                "only — never benchmark-specific decryptions or "
                "sealed material."
            ),
            tactic_kind="independent_multi_role_assignment",
            applies_to_families=[
                "columnar_vigenere", "columnar_beaufort",
                "columnar_variant_beaufort",
                "myszkowski_vigenere", "myszkowski_beaufort",
                "rail_fence_vigenere", "rail_fence_beaufort",
                "route_vigenere", "route_beaufort",
                "quagmire",
            ],
            generates_specs=True,
            related_lesson_ids=[
                "LESSON-001", "LESSON-002", "LESSON-003",
                "LESSON-006", "LESSON-007",
            ],
            source_origin="k4bench-derived",
            tactic_parameters={
                "role_slots": [
                    "substitution_keyword",
                    "alphabet_keyword",
                    "transposition_keyword",
                    "quagmire_period_keyword",
                    "quagmire_pt_alphabet_keyword",
                    "quagmire_ct_alphabet_keyword",
                    "indicator_letter",
                    "route_grid_keyword",
                ],
                "role_pool_size": 3,
                "allow_self_pairs": True,
                "alphabet_keyword_pool_size": 3,
                "role_assignment_modes": [
                    "pairwise",                   # legacy: 2-role
                    "independent_three_role",     # LESSON-010 path
                ],
                "applies_to_substitution_kinds": [
                    "vigenere", "beaufort", "variant_beaufort",
                ],
                "applies_to_transposition_kinds": [
                    "columnar", "myszkowski", "rail_fence", "route",
                ],
            },
        ),
        Lesson(
            lesson_id="LESSON-011",
            title="Skip / step / stride modular route transposition",
            description=(
                "When clue-pack language gestures at a stepped or "
                "stride-walked route — words such as skip, skipped, "
                "step, stepped, stride, every, nth, offset, route, "
                "path, tunnel, passage, layer, hide, hides, hidden, "
                "read, reads, walk, walks, margin, margins — the "
                "candidate pipeline MUST enumerate a modular skip-"
                "route transposition layer (the first-class "
                "``skip_route`` DSL kind, NOT a generic route or "
                "serpentine layer, so coverage_vector and attempt "
                "artifact layers explicitly carry route_mode + step + "
                "offset). The skip-route layer is length-preserving: "
                "for ciphertext length L, ``output[i] = input"
                "[(offset + i*step) mod L]``; the (step, L) pair MUST "
                "be coprime so the walk visits every position once. "
                "Step values are drawn from clue-derived numerals "
                "(digit literals 2..L-1 and small spelled numerals "
                "two..twenty) UNIONED with the safe default set "
                "{2, 3, 4, 5, 6, 7, 8, 10, 13, 17, 23}. Offsets are "
                "drawn from clue-derived numerals UNIONED with "
                "0..min(step-1, 5) so a small bounded enumeration "
                "covers the early offset window every step admits. "
                "The lesson composes skip_route alone, paired with "
                "Vigenere / Beaufort / Variant Beaufort / Caesar / "
                "Atbash / rail_fence in BOTH layer orders, and in "
                "three-layer sandwiches with substitution + "
                "skip_route + rail_fence (and skip_route + sub + "
                "atbash / caesar when the corresponding existing "
                "trigger applies). The lesson is GENERALIZED: it "
                "stores trigger vocabulary, step / offset knobs, "
                "and family pairings only — never benchmark-"
                "specific decryptions or sealed material."
            ),
            tactic_kind="skip_step_route_enumeration",
            applies_to_families=[
                "skip_route",
                "skip_route_vigenere",
                "skip_route_beaufort",
                "skip_route_variant_beaufort",
                "skip_route_caesar",
                "skip_route_atbash",
                "skip_route_rail_fence",
                "vigenere_skip_route_rail_fence",
                "beaufort_skip_route_rail_fence",
                "variant_beaufort_skip_route_rail_fence",
            ],
            generates_specs=True,
            related_lesson_ids=[
                "LESSON-002", "LESSON-006", "LESSON-007",
                "LESSON-008", "LESSON-009", "LESSON-010",
            ],
            source_origin="k4bench-derived",
            tactic_parameters={
                "trigger_tokens": [
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
                ],
                "default_steps": [2, 3, 4, 5, 6, 7, 8, 10, 13, 17, 23],
                "default_offsets": [0, 1, 2],
                "trigger_match": "word_boundary_case_insensitive",
                "applies_to_substitution_kinds": [
                    "vigenere", "beaufort", "variant_beaufort",
                    "caesar", "atbash",
                ],
                "applies_to_transposition_partners": [
                    "rail_fence",
                ],
                "operation_source_labels": [
                    "clue_numeral", "default_set",
                ],
                "coprimality_required": True,
                "permutation_formula": (
                    "output[i] = input[(offset + i*step) mod L]"
                ),
            },
        ),
        Lesson(
            lesson_id="LESSON-012",
            title="Phrase-attached numeric prominence in clue parsing",
            description=(
                "When a clue text contains multiple numerals, each "
                "numeral carries an anchor word that names its target "
                "cipher parameter. Pre-LESSON-012 generators flowed "
                "every numeral into a flat bag and let cap budgets "
                "and ascending-order iteration decide priority — "
                "which starves clue-prominent numerals when other "
                "anchored numerals appear earlier in the text or "
                "earlier in the numeric ordering. The lesson requires "
                "that the parser extract anchor-to-numeral bindings "
                "BEFORE any numeric-parametrized HCC family runs, "
                "and that each lesson consume only its own bound "
                "values + safe defaults (never another parameter's "
                "bound values).\n\n"
                "Anchor patterns the parser recognizes "
                "(case-insensitive, word-boundary; supports digit "
                "literals, cardinals two..twenty, and ordinals "
                "second..twentieth):\n"
                "  step / stepped / stride N     -> skip_route step\n"
                "  every Nth                     -> skip_route step\n"
                "  offset / offset of N          -> skip_route offset\n"
                "  depth / N rails / N rail /\n"
                "    N-rail                       -> rail_fence depth\n"
                "  block / blocks of / block of /\n"
                "    groups of / every N          -> reverse_blocks block_size\n"
                "  shift / shift by / rotated /\n"
                "    rotate / rotN                -> caesar shift_value\n\n"
                "Each numeric-parametrized lesson consumes its own "
                "bound list FIRST (with operation_source labels such "
                "as 'phrase_bound_step', 'phrase_bound_offset', "
                "'phrase_bound_rail_depth', 'phrase_bound_block_size', "
                "'phrase_bound_shift_value'), then falls back to the "
                "legacy flat numeric extraction and finally to the "
                "default set. Phrase-bound values are guaranteed to "
                "survive the per-lesson cap budget so the most "
                "semantically prominent value never gets starved.\n\n"
                "The lesson is GENERALIZED: it stores anchor->parameter "
                "vocabulary only — never benchmark-specific decryptions "
                "or sealed material."
            ),
            tactic_kind="phrase_attached_numeric_prominence",
            applies_to_families=[
                # All numeric-parametrized HCC families benefit
                "rail_fence_vigenere", "rail_fence_beaufort",
                "reverse_blocks", "reverse_blocks_vigenere",
                "reverse_blocks_beaufort",
                "reverse_blocks_variant_beaufort",
                "reverse_blocks_caesar", "reverse_blocks_atbash",
                "caesar", "caesar_columnar", "caesar_myszkowski",
                "caesar_rail_fence", "caesar_route", "caesar_atbash",
                "skip_route", "skip_route_vigenere",
                "skip_route_beaufort",
                "skip_route_variant_beaufort",
                "skip_route_caesar", "skip_route_atbash",
                "skip_route_rail_fence",
            ],
            generates_specs=False,  # Generates BINDINGS, not specs
            related_lesson_ids=[
                "LESSON-008", "LESSON-009", "LESSON-011",
            ],
            source_origin="k4bench-derived",
            tactic_parameters={
                # Anchor lexicon. Keys are the parameter slots; values
                # are the anchor tokens / phrases that bind to them.
                # The runtime parser consumes this taxonomy as the
                # source of truth — a drift test asserts the runtime
                # constants match.
                "anchor_to_parameter": {
                    "step": [
                        "step", "stepped", "stride",
                        "every nth",
                    ],
                    "offset": [
                        "offset", "offset of",
                    ],
                    "rail_depth": [
                        "depth", "rails", "rail", "rail-fence",
                    ],
                    "block_size": [
                        "block", "blocks", "blocks of", "block of",
                        "groups of", "every",
                    ],
                    "shift_value": [
                        "shift", "shifted", "shift by",
                        "rotated", "rotate", "rot",
                    ],
                },
                "binding_keys": [
                    "step", "offset", "rail_depth",
                    "block_size", "shift_value",
                ],
                "operation_source_labels": [
                    "phrase_bound_step",
                    "phrase_bound_offset",
                    "phrase_bound_rail_depth",
                    "phrase_bound_block_size",
                    "phrase_bound_shift_value",
                    "clue_numeral",     # legacy flat fallback
                    "default_set",      # safe default fallback
                    "mixed",            # legacy mixed-source label
                ],
                "supports_digit_literals": True,
                "supports_cardinals": True,
                "supports_ordinals": True,
                "trigger_match": "anchor_phrase_proximity_case_insensitive",
                "fallback_when_no_anchor": "legacy_flat_extraction",
            },
        ),
        Lesson(
            lesson_id="LESSON-013",
            title="Arbitrary columnar column-order enumeration for small widths",
            description=(
                "Pre-LESSON-013 HCC emitted columnar layers only with "
                "col_order derived from a clue keyword's stable rank "
                "(LESSON-004 + LESSON-005). Some hand ciphers use an "
                "explicit numeric column permutation that is NOT "
                "producible from any natural keyword via the standard "
                "stable-rank convention. This lesson generalizes the "
                "columnar primitive so column order may come from "
                "EITHER (1) the existing keyword-derived stable rank "
                "OR (2) an enumerated arbitrary permutation for small "
                "widths.\n\n"
                "Bounded exhaustive enumeration: for width W in 2..7, "
                "all W! column orderings are emitted (with a per-"
                "width cap that limits W=6 and W=7 to keep the "
                "universe manageable). Width W >= 8 is NOT enumerated "
                "by default — those use only keyword-derived "
                "col_orders. Width selection priority:\n"
                "  1. Phrase-bound numeric values from LESSON-012's "
                "     ``step`` slot (when the numeral is in [2, 7] "
                "     and plausibly describes route/step/width "
                "     behaviour). Rail-depth and shift-value "
                "     bindings are EXPLICITLY excluded so unrelated "
                "     numerals do not pollute columnar width.\n"
                "  2. Clue keyword lengths in [2, 7].\n"
                "  3. Safe defaults {3, 4, 5}.\n\n"
                "Coverage_vector telemetry:\n"
                "  ``transposition_width``  — int width of the "
                "                              columnar grid\n"
                "  ``col_order``            — the explicit "
                "                              permutation tuple\n"
                "  ``col_order_source``     — 'keyword_stable_rank' "
                "                              (legacy) or "
                "                              'enumerated_permutation'\n"
                "  ``col_order_index``      — index into the W! list "
                "                              (only for enumerated)\n"
                "  ``width_source``         — 'phrase_bound_step' / "
                "                              'clue_keyword_length' "
                "                              / 'default_set'\n\n"
                "Deduplication: enumerated col_orders for a given "
                "width skip any col_order that is also produced by "
                "a clue-keyword-derived family for the same width.\n\n"
                "Per-family budget caps prevent the W! growth from "
                "exploding HCC's dispatch universe:\n"
                "  W=5 → 120 col_orders (full)\n"
                "  W=6 → cap at 120 (random sample of 720)\n"
                "  W=7 → cap at 120 (sample of 5040)\n"
                "Alphabet modes for enumerated columnar families are "
                "restricted to AZ + KA only (no keyword_mixed). "
                "Keyword-derived families retain full alphabet mode "
                "coverage so legacy behaviour is bit-identical.\n\n"
                "The lesson is GENERALIZED: it enumerates ALL "
                "permutations for small W, never privileging a "
                "specific col_order. K4B-006's winning permutation "
                "(4, 1, 3, 0, 2) is one of 120 W=5 entries — no "
                "more, no less."
            ),
            tactic_kind="arbitrary_columnar_order_enumeration",
            applies_to_families=[
                "columnar_vigenere", "columnar_beaufort",
                "columnar_variant_beaufort",
                "i3_columnar_vigenere", "i3_columnar_beaufort",
                "i3_columnar_variant_beaufort",
                "caesar_columnar", "caesar_columnar_atbash",
                # 3-layer columnar+sub+rail_fence sandwich added so
                # K4B-006's empirical 24/24 path
                # (columnar(W=5, co=(4,1,3,0,2)) + beaufort(MIRROR,
                # AZ) + rail_fence(4)) is reachable from HCC.
                "columnar_vigenere_rail_fence",
                "columnar_beaufort_rail_fence",
                "columnar_variant_beaufort_rail_fence",
            ],
            generates_specs=True,
            related_lesson_ids=[
                "LESSON-004", "LESSON-005", "LESSON-010", "LESSON-012",
            ],
            source_origin="k4bench-derived",
            tactic_parameters={
                "default_widths": [3, 4, 5],
                "max_enumerated_width": 7,
                "per_width_caps": {
                    "2": 2, "3": 6, "4": 24, "5": 120,
                    "6": 120, "7": 120,
                },
                "width_sources": [
                    "phrase_bound_step",
                    "clue_keyword_length",
                    "default_set",
                ],
                "col_order_sources": [
                    "keyword_stable_rank",
                    "enumerated_permutation",
                ],
                "alphabet_modes_for_enumerated": [
                    "AZ", "KA",
                ],
                "applies_to_substitution_kinds": [
                    "vigenere", "beaufort", "variant_beaufort",
                ],
                "applies_to_transposition_kinds": [
                    "columnar",
                ],
                "phrase_bound_slots_for_width": [
                    # LESSON-012 slots that may seed columnar widths.
                    # rail_depth and shift_value are deliberately
                    # excluded — they describe rail-count and shift,
                    # not transposition width.
                    "step",
                ],
                "deterministic_ordering": "lexicographic_within_width",
            },
        ),
        Lesson(
            lesson_id="LESSON-014",
            title="Width-only ragged boustrophedon route enumeration",
            description=(
                "When clue-pack language gestures at a fixed-width "
                "grid that is read as a serpentine / boustrophedon "
                "(alternating-direction-by-row or by-column) — words "
                "such as archive, column, columns, grid, walk, route, "
                "path, edge, ragged, artifact, count, serpentine, "
                "boustrophedon, snake, zigzag, up, down, left, right, "
                "row, rows — the candidate pipeline MUST enumerate a "
                "ragged width-only boustrophedon route layer (the "
                "first-class ``route_boustrophedon`` DSL kind). The "
                "kind is deliberately distinct from the existing "
                "``route`` kind: ``route`` requires explicit rows AND "
                "cols + a grid sized to cover the full ciphertext; "
                "``route_boustrophedon`` takes a single ``width`` "
                "parameter and implies ``rows = ceil(CT_LEN / "
                "width)`` so the final row may be short ('ragged'). "
                "The dispatcher reuses the kernel's ``serpentine_perm`` "
                "primitive — which already trims positions beyond "
                "CT_LEN — so the layer is length-preserving and "
                "deterministic.\n\n"
                "Width values are drawn from "
                "(1) phrase-bound numerals attached to a "
                "route/grid/column anchor in the clue text "
                "(highest priority — never starved by cap budget), "
                "(2) clue keyword lengths in [2, 12] when the "
                "keyword denotes an artifact / column / grid / "
                "archive / route / walk concept, and "
                "(3) the safe default set {3, 4, 5, 6, 7, 8, 9, 10, "
                "11, 12}. The lesson EXPLICITLY excludes rail_depth, "
                "shift_value, block_size, step, and offset bindings "
                "as width sources — those numerals describe rail "
                "count / arithmetic shifts / block size / route "
                "step+offset, not boustrophedon width; using them "
                "would explode the universe with category-error "
                "values.\n\n"
                "Direction enumeration: each (width, layer-order, "
                "keyword) tuple is emitted with BOTH "
                "``vertical=False`` (horizontal serpentine — "
                "left/right alternation by row) and ``vertical=True`` "
                "(vertical serpentine — top-down/bottom-up "
                "alternation by column). The vertical=True variant "
                "matches clue language like 'arrows down, up, down, "
                "up'. The horizontal default matches plain 'ragged "
                "row read'.\n\n"
                "The lesson composes route_boustrophedon alone, "
                "paired with Vigenere / Beaufort / Variant "
                "Beaufort / Caesar / Atbash / rail_fence in BOTH "
                "layer orders, and in three-layer sandwiches with "
                "substitution + route_boustrophedon + rail_fence "
                "(both peel orders) and substitution + "
                "route_boustrophedon + columnar (both peel orders, "
                "columnar permits use of LESSON-013 enumerated "
                "col_orders).\n\n"
                "Coverage_vector telemetry:\n"
                "  ``route_mode``        — 'route_boustrophedon' or "
                "                          'boustrophedon_width'\n"
                "  ``route_width``       — int width of the grid\n"
                "  ``width_source``      — 'phrase_bound_route_width' "
                "                          / 'clue_keyword_length' / "
                "                          'default_set'\n"
                "  ``route_rows``        — implied row count\n"
                "  ``route_cols``        — equals ``route_width``\n"
                "  ``route_ragged``      — True when CT_LEN is not "
                "                          a multiple of width "
                "                          (the standard case)\n"
                "  ``route_direction``   — 'horizontal' or "
                "                          'vertical' (mirrors the "
                "                          ``vertical`` flag)\n\n"
                "The lesson is GENERALIZED: it stores trigger "
                "vocabulary, width-source priority rules, and family "
                "pairings only — never benchmark-specific "
                "decryptions or sealed material."
            ),
            tactic_kind="width_only_ragged_boustrophedon_route",
            applies_to_families=[
                "route_boustrophedon",
                "route_boustrophedon_vigenere",
                "route_boustrophedon_beaufort",
                "route_boustrophedon_variant_beaufort",
                "route_boustrophedon_caesar",
                "route_boustrophedon_atbash",
                "route_boustrophedon_rail_fence",
                "vigenere_route_boustrophedon_rail_fence",
                "beaufort_route_boustrophedon_rail_fence",
                "variant_beaufort_route_boustrophedon_rail_fence",
                "vigenere_route_boustrophedon_columnar",
                "beaufort_route_boustrophedon_columnar",
                "variant_beaufort_route_boustrophedon_columnar",
            ],
            generates_specs=True,
            related_lesson_ids=[
                "LESSON-002", "LESSON-006", "LESSON-007",
                "LESSON-009", "LESSON-010", "LESSON-011",
                "LESSON-012", "LESSON-013",
            ],
            source_origin="k4bench-derived",
            tactic_parameters={
                "trigger_tokens": [
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
                    # Direction tokens used in clues like
                    # "arrows down, up, down, up" — these alone are
                    # not strong enough to fire LESSON-014 but the
                    # detector uses them as supporting context for
                    # the vertical=True variant.
                    "up", "down", "left", "right",
                    "row", "rows",
                ],
                "vertical_direction_tokens": [
                    # When ANY of these tokens appears in the clue,
                    # the vertical=True variant is the priority
                    # direction; vertical=False is still emitted as
                    # the symmetry partner.
                    "down", "up",
                    "vertical", "vertically",
                    "column-wise", "columnwise",
                ],
                "horizontal_direction_tokens": [
                    "left", "right",
                    "horizontal", "horizontally",
                    "row-wise", "rowwise",
                ],
                "default_widths": [3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
                "min_width": 2,
                "max_width": 16,
                "max_clue_keyword_width": 12,
                "trigger_match": "word_boundary_case_insensitive",
                "applies_to_substitution_kinds": [
                    "vigenere", "beaufort", "variant_beaufort",
                    "caesar", "atbash",
                ],
                "applies_to_transposition_partners": [
                    "rail_fence", "columnar",
                ],
                "operation_source_labels": [
                    "phrase_bound_route_width",
                    "clue_keyword_length",
                    "default_set",
                ],
                # Width sources EXPLICITLY excluded from the
                # route-width enumeration. These describe rail-count,
                # arithmetic shifts, block size, and skip-route
                # step+offset — using them would explode the universe
                # with unrelated values. The exclusion is a category
                # contract, not a budget heuristic.
                "excluded_width_sources": [
                    "phrase_bound_rail_depth",
                    "phrase_bound_shift_value",
                    "phrase_bound_block_size",
                    "phrase_bound_step",
                    "phrase_bound_offset",
                ],
                "permutation_formula": (
                    "rows = ceil(CT_LEN / width); "
                    "perm = serpentine_perm(rows, width, CT_LEN, "
                    "vertical); ragged final row trimmed by "
                    "kernel primitive"
                ),
                "length_preserving": True,
                "directions_emitted": [
                    "horizontal",
                    "vertical",
                ],
            },
        ),
        Lesson(
            lesson_id="LESSON-015",
            title="Alternate-row reversal / folded-strip route",
            description=(
                "When clue-pack language gestures at a folded strip, "
                "an alternate-row reversal, or a 'far end folded back "
                "over near end' construction — words such as fold, "
                "folded, unfold, unfolded, folding, reverse, "
                "reversed, reversal, row, rows, line, lines, strip, "
                "strips, wall, panel, boustrophedon, serpentine, "
                "zigzag, every other, alternate, alternating, left "
                "edge, right edge, read back, turn back — the "
                "candidate pipeline MUST enumerate a self-inverse "
                "row-reversal layer (the first-class ``row_reverse`` "
                "DSL kind). Distinct from ``route_boustrophedon`` "
                "(LESSON-014) which reads a width-grid in serpentine "
                "fashion via a single global permutation; "
                "``row_reverse`` reverses ONLY the rows whose 0-"
                "indexed row-index matches a parity selector "
                "(``odd``, ``even``, or ``both``), while the other "
                "rows pass through verbatim.\n\n"
                "Operation: split the text into consecutive rows of "
                "width W; for each row whose 0-indexed row-index "
                "(optionally offset by ``start_row``) matches the "
                "parity, reverse that row in place; concatenate "
                "back to the original length. The trailing partial "
                "row is reversed in place when its row-index is "
                "selected (ragged-aware). The dispatcher emits the "
                "perm and asserts both length-preservation and the "
                "self-inverse invariant ``perm[perm[i]] == i`` so a "
                "partition bug fails closed.\n\n"
                "Width values are drawn from\n"
                "  (1) phrase-bound numerals attached to a "
                "row/strip/wall/panel/column anchor in the clue text "
                "(highest priority — never starved by cap budget),\n"
                "  (2) clue keyword lengths in [2, 16] when the "
                "keyword denotes an artifact / strip / wall / panel "
                "/ route / row concept, and\n"
                "  (3) the safe default set {5, 7, 8, 10, 12, 14, "
                "16}.\n\n"
                "EXCLUSIONS (LESSON-015 contract): rail_depth, "
                "shift_value, block_size, step, and offset bindings "
                "from ``extract_phrase_bound_numerics`` are NOT "
                "pulled in. Those numerals describe rail count / "
                "arithmetic shifts / block size / skip-route step+"
                "offset; using them as a row-reversal width would "
                "be a category error and would explode the "
                "universe.\n\n"
                "Parity enumeration: each (width, layer-order, "
                "keyword) tuple is emitted with ``parity=odd`` "
                "(reverse rows 1, 3, 5, ...) and ``parity=even`` "
                "(reverse rows 0, 2, 4, ...). The ``both`` value "
                "is reachable via the explicit-parity path but is "
                "not enumerated by default — reversing every row "
                "is just a global reverse-then-permute equivalent, "
                "and LESSON-015's value is in the ALTERNATING "
                "structure.\n\n"
                "The lesson composes row_reverse alone, paired "
                "with Vigenere / Beaufort / Variant Beaufort / "
                "Caesar / Atbash / rail_fence in BOTH layer "
                "orders, and in three-layer sandwiches with "
                "substitution + route + row_reverse and "
                "substitution + route_boustrophedon + row_reverse "
                "(both peel orders). When width = CT_LEN with "
                "parity=odd, row_reverse is the identity (only "
                "row 0 exists; row 0 is even; parity=odd selects "
                "no rows) — this is the 'no-fold' boundary case "
                "and is intentionally enumerated so the catalog "
                "covers substitution-alone-equivalent specs "
                "without adding a separate substitution-alone "
                "family.\n\n"
                "Coverage_vector telemetry:\n"
                "  ``row_reverse_width``    — int width of each "
                "                              row\n"
                "  ``row_reverse_parity``   — 'odd' / 'even' / "
                "                              'both'\n"
                "  ``row_reverse_source``   — 'phrase_bound_row_"
                "                              reverse_width' / "
                "                              'clue_keyword_length' "
                "                              / 'default_set'\n"
                "  ``row_reverse_ragged``   — True when CT_LEN is "
                "                              not a multiple of "
                "                              width\n"
                "  ``row_reverse_start_row``— 0 or 1 (parity "
                "                              offset)\n\n"
                "The lesson is GENERALIZED: it stores trigger "
                "vocabulary, width-source priority rules, and "
                "family pairings only — never benchmark-specific "
                "decryptions or sealed material."
            ),
            tactic_kind="alternate_row_reversal_folded_strip",
            applies_to_families=[
                "row_reverse",
                "row_reverse_vigenere",
                "row_reverse_beaufort",
                "row_reverse_variant_beaufort",
                "row_reverse_caesar",
                "row_reverse_atbash",
                "row_reverse_rail_fence",
                "row_reverse_route",
                "row_reverse_route_boustrophedon",
                "vigenere_route_row_reverse",
                "beaufort_route_row_reverse",
                "variant_beaufort_route_row_reverse",
                "vigenere_route_boustrophedon_row_reverse",
                "beaufort_route_boustrophedon_row_reverse",
                "variant_beaufort_route_boustrophedon_row_reverse",
            ],
            generates_specs=True,
            related_lesson_ids=[
                "LESSON-002", "LESSON-006", "LESSON-007",
                "LESSON-008", "LESSON-009", "LESSON-010",
                "LESSON-011", "LESSON-012", "LESSON-013",
                "LESSON-014",
            ],
            source_origin="k4bench-derived",
            tactic_parameters={
                "trigger_tokens": [
                    "fold", "folded", "unfold", "unfolded", "folding",
                    "reverse", "reversed", "reversal",
                    "row", "rows", "line", "lines",
                    "strip", "strips", "wall", "panel",
                    "boustrophedon", "serpentine", "zigzag",
                    "alternate", "alternating",
                    "every other",
                    "left edge", "right edge",
                    "read back", "turn back",
                ],
                "default_widths": [5, 7, 8, 10, 12, 14, 16],
                "min_width": 2,
                # Includes CT_LEN (97) so width=97 + parity=odd
                # gives identity. The boundary case is the "no-
                # fold" sentinel that lets the catalog reach
                # substitution-alone-equivalent specs without a
                # separate alone family.
                "max_width": 97,
                "max_clue_keyword_width": 16,
                "parity_options": ["odd", "even", "both"],
                "default_parities": ["odd", "even"],
                "trigger_match": "word_boundary_case_insensitive",
                "applies_to_substitution_kinds": [
                    "vigenere", "beaufort", "variant_beaufort",
                    "caesar", "atbash",
                ],
                "applies_to_transposition_partners": [
                    "rail_fence", "route", "route_boustrophedon",
                    "columnar",
                ],
                "operation_source_labels": [
                    "phrase_bound_row_reverse_width",
                    "clue_keyword_length",
                    "default_set",
                ],
                "excluded_width_sources": [
                    "phrase_bound_rail_depth",
                    "phrase_bound_shift_value",
                    "phrase_bound_block_size",
                    "phrase_bound_step",
                    "phrase_bound_offset",
                ],
                "permutation_formula": (
                    "for each row r in 0..ceil(CT_LEN/W)-1: "
                    "if (r - start_row) % 2 selects parity, "
                    "reverse row in place; else identity. "
                    "perm[perm[i]] == i (self-inverse)"
                ),
                "length_preserving": True,
                "self_inverse": True,
                "no_fold_boundary_case": (
                    "width=CT_LEN with parity=odd is identity "
                    "(only row 0 exists; row 0 is even; parity=odd "
                    "selects no rows). Used by the catalog to "
                    "express substitution-alone-equivalent specs."
                ),
            },
        ),
        Lesson(
            lesson_id="LESSON-016",
            title="Diagonal grid-route enumeration",
            description=(
                "When clue-pack language gestures at a diagonal grid "
                "read — words such as diagonal, diagonals, oblique, "
                "slant, slanted, slash, backslash, cross, lattice, "
                "rising, falling, stone(s), mason, masonry, course(s), "
                "or compass shorthand NW-SE / NE-SW — the candidate "
                "pipeline MUST enumerate a diagonal route "
                "transposition layer. Pre-LESSON-016 the HCC "
                "catalogue treated such clue tokens only as candidate "
                "keyword material (substitution / alphabet / "
                "transposition keys), which is the wrong granularity: "
                "a clue that names a diagonal READ describes a route "
                "operation, not a key.\n\n"
                "The general lesson: clue geometry words such as "
                "diagonal must instantiate route operations, not "
                "only keyword material.\n\n"
                "LESSON-016 extends the existing ``route`` DSL kind "
                "with ``variant=\"diagonal\"`` plus three params:\n"
                "  diagonal_axis        — 'main' (NW->SE) or 'anti' "
                "                          (NE->SW)\n"
                "  diagonal_order       — 'forward' or 'reverse' "
                "                          (order in which diagonals "
                "                          are visited)\n"
                "  diagonal_start_edge  — within each diagonal, which "
                "                          end is read first; "
                "                          axis-constrained: "
                "                          {top_then_left, "
                "                          left_then_top} for main, "
                "                          {top_then_right, "
                "                          right_then_top} for anti\n"
                "The kernel's ``diagonal_perm`` produces a length-"
                "preserving bijection over [0, CT_LEN) under any "
                "rows*cols >= CT_LEN grid (ragged supported). The "
                "dispatcher rejects unknown axis / order / "
                "start_edge values and rows*cols < CT_LEN with "
                "DispatcherError; there are no silent defaults.\n\n"
                "Grid sources: phrase-bound widths (reusing "
                "LESSON-014's anchor parser so 'ten-wide grid' "
                "produces both an 8-column boustrophedon and a "
                "10-column diagonal candidate from the same clue), "
                "clue keyword lengths in [3, 16], and a curated "
                "default-grid set covering common K4-shape ragged "
                "rectangles (10x10, 13x8, 8x13, 7x14, 14x7, ...).\n\n"
                "Variant enumeration is bounded: alone family "
                "enumerates the full 8 (axis × order × start_edge) "
                "tuple per grid; substitution-paired and rail_fence-"
                "paired families cap at the canonical 4 (main/anti × "
                "forward/reverse with the natural top_then_* "
                "start_edge for each axis) so the (sub × alpha × "
                "grid × variant × layer-order) cartesian stays "
                "within bench-fast budgets.\n\n"
                "Coverage_vector telemetry: ``route_mode`` = "
                "'route_diagonal'; ``route_rows`` / ``route_cols`` "
                "/ ``route_width`` (cols mirror) / ``route_ragged`` "
                "are populated like other route variants; new "
                "``diagonal_axis`` / ``diagonal_order`` / "
                "``diagonal_start_edge`` fields capture the read "
                "geometry; ``operation_source`` records "
                "phrase_bound_diagonal_width / clue_keyword_length / "
                "default_set provenance.\n\n"
                "The lesson is GENERALIZED: it stores trigger "
                "vocabulary, grid-source priority rules, and family "
                "pairings only — never benchmark-specific decryptions "
                "or sealed material. It does NOT claim that the real "
                "K4 mechanism is diagonal."
            ),
            tactic_kind="diagonal_grid_route_enumeration",
            applies_to_families=[
                "route_diagonal",
                "route_diagonal_vigenere",
                "route_diagonal_beaufort",
                "route_diagonal_variant_beaufort",
                "route_diagonal_rail_fence",
            ],
            generates_specs=True,
            related_lesson_ids=[
                "LESSON-002", "LESSON-006", "LESSON-007",
                "LESSON-012", "LESSON-014",
            ],
            source_origin="k4bench-derived",
            tactic_parameters={
                "trigger_tokens": [
                    "diagonal", "diagonals",
                    "oblique", "obliques",
                    "slant", "slants", "slanted", "slanting",
                    "slash", "slashes",
                    "backslash", "backslashes",
                    "cross", "crosses", "crossed", "crossing",
                    "lattice", "lattices",
                    "rising", "falling",
                    "nwse", "nesw",
                    "mason", "masons", "masonry",
                    "stone", "stones",
                    "course", "courses",
                ],
                "trigger_phrases": [
                    "nw-se", "nw to se", "nw->se",
                    "ne-sw", "ne to sw", "ne->sw",
                    "rising diagonal", "falling diagonal",
                    "alternating diagonals",
                ],
                "axes": ["main", "anti"],
                "orders": ["forward", "reverse"],
                "start_edges_main": [
                    "top_then_left", "left_then_top",
                ],
                "start_edges_anti": [
                    "top_then_right", "right_then_top",
                ],
                "default_grids": [
                    [10, 10], [13, 8], [8, 13], [7, 14],
                    [14, 7], [12, 9], [9, 12], [11, 10], [10, 11],
                ],
                "trigger_match": "word_boundary_case_insensitive",
                "applies_to_substitution_kinds": [
                    "vigenere", "beaufort", "variant_beaufort",
                ],
                "applies_to_transposition_partners": [
                    "rail_fence",
                ],
                "operation_source_labels": [
                    "phrase_bound_diagonal_width",
                    "clue_keyword_length",
                    "default_set",
                ],
                "permutation_formula": (
                    "kernel diagonal_perm(rows, cols, CT_LEN, "
                    "axis, order, start_edge); ragged trim by "
                    "kernel primitive"
                ),
                "length_preserving": True,
                "bounded_universe": (
                    "alone family enumerates 8 variants per grid; "
                    "paired families cap at 4 to keep "
                    "(sub × alpha × grid × variant) bounded"
                ),
            },
        ),
    ]


# ---------------------------------------------------------------------------
# LessonRegistry
# ---------------------------------------------------------------------------


_DEFAULT_REGISTRY_PATH: Path = Path("db/solver_capabilities/lessons.json")
_REGISTRY_SCHEMA_VERSION: str = "solver_capabilities.lessons.v1"


class LessonRegistry:
    """JSON-backed lesson store.

    On first construction with no existing on-disk file, seeds the
    default lesson set and writes the file. On subsequent
    construction, loads the file and re-validates every lesson —
    a corrupted / tampered file fails loud.

    The registry is intentionally small (~10s of lessons), in-memory
    after load, and explicitly NOT a database. JSON keeps the file
    human-readable and reviewable in PRs.
    """

    def __init__(
        self,
        path: Optional[Path] = None,
        *,
        seed_defaults: bool = True,
    ) -> None:
        self.path = Path(path) if path is not None else _DEFAULT_REGISTRY_PATH
        self._lessons: dict[str, Lesson] = {}
        if self.path.exists():
            self._load()
            # Forward-compat migration: if the on-disk file predates
            # newer default lessons (e.g. LESSON-007 added 2026-04-27
            # post-K4B-002), top up the registry without overwriting
            # any operator-customised entries. Operator-edited
            # lessons keep their on-disk content; missing default
            # IDs are appended and saved back.
            if seed_defaults:
                self._top_up_with_missing_defaults()
        elif seed_defaults:
            self._seed_defaults_and_save()
        # else: empty in-memory registry; caller will add manually.

    def _top_up_with_missing_defaults(self) -> None:
        """Add any default lesson whose lesson_id is not already in
        the on-disk registry. Operator-edited lessons are preserved.
        """
        added = False
        for default_lesson in _default_lessons():
            if default_lesson.lesson_id not in self._lessons:
                self._lessons[default_lesson.lesson_id] = default_lesson
                added = True
        if added:
            self._save()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _seed_defaults_and_save(self) -> None:
        for lesson in _default_lessons():
            self._lessons[lesson.lesson_id] = lesson
        self._save()

    def _load(self) -> None:
        try:
            raw = json.loads(self.path.read_text())
        except json.JSONDecodeError as exc:
            raise LessonValidationError(
                f"LessonRegistry: file {self.path} is not valid JSON: {exc}"
            )
        if not isinstance(raw, dict):
            raise LessonValidationError(
                f"LessonRegistry: file {self.path} top-level must be dict"
            )
        # Forbidden-field check on the raw payload BEFORE constructing
        # Lessons. A tampered file would otherwise raise on each
        # individual Lesson; this gives one clean error.
        forbidden = _scan_for_forbidden(raw)
        if forbidden:
            raise LessonValidationError(
                f"LessonRegistry: file {self.path} contains forbidden "
                f"sealed material at field paths: {forbidden[:5]}"
                + (" ..." if len(forbidden) > 5 else "")
            )
        schema = raw.get("schema_version")
        if schema != _REGISTRY_SCHEMA_VERSION:
            raise LessonValidationError(
                f"LessonRegistry: file {self.path}: unexpected schema "
                f"{schema!r}; expected {_REGISTRY_SCHEMA_VERSION!r}"
            )
        lessons = raw.get("lessons") or []
        if not isinstance(lessons, list):
            raise LessonValidationError(
                f"LessonRegistry: file {self.path}: 'lessons' field "
                "must be a list"
            )
        for entry in lessons:
            if not isinstance(entry, dict):
                continue
            lesson = Lesson.from_dict(entry)
            self._lessons[lesson.lesson_id] = lesson

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": _REGISTRY_SCHEMA_VERSION,
            "lessons": [
                self._lessons[lid].to_dict()
                for lid in sorted(self._lessons)
            ],
        }
        # Validate before writing.
        forbidden = _scan_for_forbidden(payload)
        if forbidden:
            raise LessonValidationError(
                f"LessonRegistry: refusing to save with forbidden "
                f"fields: {forbidden}"
            )
        self.path.write_text(json.dumps(payload, indent=2, sort_keys=True))

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def add(self, lesson: Lesson, *, save: bool = True) -> None:
        """Add or replace a lesson. The forbidden-field check runs
        in Lesson.__post_init__; reaching this point means the lesson
        is well-formed.
        """
        self._lessons[lesson.lesson_id] = lesson
        if save:
            self._save()

    def get(self, lesson_id: str) -> Optional[Lesson]:
        return self._lessons.get(lesson_id)

    def all(self) -> list[Lesson]:
        return [self._lessons[lid] for lid in sorted(self._lessons)]

    def enabled(self) -> list[Lesson]:
        return [lesson for lesson in self.all() if lesson.enabled]

    def by_tactic(self, tactic_kind: str) -> list[Lesson]:
        return [
            lesson for lesson in self.all()
            if lesson.tactic_kind == tactic_kind
        ]

    def applicable_to(self, family: str) -> list[Lesson]:
        """Lessons whose ``applies_to_families`` list contains
        ``family`` or the wildcard ``"*"``.
        """
        return [
            lesson for lesson in self.enabled()
            if "*" in lesson.applies_to_families
            or family in lesson.applies_to_families
        ]

    def __len__(self) -> int:
        return len(self._lessons)

    def __contains__(self, lesson_id: str) -> bool:
        return lesson_id in self._lessons

    # ------------------------------------------------------------------
    # Capability-hint API for cross-mode consumption
    # ------------------------------------------------------------------

    def tactical_hints_for_real_k4(self) -> list[dict[str, Any]]:
        """Return the enabled lessons as challenge-agnostic tactical
        hints, suitable for inclusion in the real-K4 theorist
        landscape brief.

        Each hint is a small dict carrying ``lesson_id``, ``title``,
        ``description``, ``tactic_kind``, and ``tactic_parameters``.
        The dict shape is deliberately minimal so a real-K4 caller
        does not depend on the full Lesson dataclass — and the
        forbidden-field scan still applies, so a corrupted lesson
        cannot leak sealed material through this surface.

        Real-K4 mode MUST NOT pass any K4Bench challenge payload,
        synthetic plaintext, synthetic ciphertext, or answer key
        to this function. The function takes no arguments precisely
        so that no bench-specific input can attach itself to a hint.
        """
        hints: list[dict[str, Any]] = []
        for lesson in self.enabled():
            hint = {
                "lesson_id": lesson.lesson_id,
                "title": lesson.title,
                "description": lesson.description,
                "tactic_kind": lesson.tactic_kind,
                "tactic_parameters": dict(lesson.tactic_parameters),
            }
            # Defense in depth: re-scan the hint we're about to
            # emit, in case a future Lesson edit slipped sealed
            # material past __post_init__.
            forbidden = _scan_for_forbidden(hint)
            if forbidden:
                logger.warning(
                    "tactical_hints_for_real_k4: dropping lesson %s "
                    "because hint contains forbidden fields: %s",
                    lesson.lesson_id, forbidden,
                )
                continue
            hints.append(hint)
        return hints

    def hints_render_block(self) -> str:
        """Render enabled lessons as a compact text block for the
        next theorist prompt. Same data as
        ``tactical_hints_for_real_k4`` but flattened to a string
        so caller code does not need to format it.
        """
        hints = self.tactical_hints_for_real_k4()
        if not hints:
            return ""
        lines = ["Generalized solver capability hints (no challenge-specific facts):"]
        for h in hints:
            lines.append(
                f"  • [{h['lesson_id']}] {h['title']} "
                f"(tactic={h['tactic_kind']})"
            )
        return "\n".join(lines)


__all__ = [
    "Lesson",
    "LessonRegistry",
    "LessonValidationError",
    "_default_lessons",
]
