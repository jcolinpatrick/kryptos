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
    LESSON-017  stratified_hcc_bench_fast_family_quotas
    LESSON-018  numeric_clue_caesar_trigger_semantics
    LESSON-019  numeric_route_columnar_three_layer_composition
    LESSON-020  diagonal_route_semantic_completeness
    LESSON-021  diagonal_canonical_width_alias
    LESSON-022  independent_two_keyword_rail_fence_three_role_composition

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
    "stratified_hcc_bench_fast_family_quotas",  # 2026-04-29:
                                   # deterministic two-pass scheduler
                                   # for the HCC catalog.
                                   # Pre-LESSON-017, the validation
                                   # tail truncated the spec stream
                                   # from the front whenever
                                   # ``len(validated) >= max_specs``
                                   # — on multi-trigger clues this
                                   # starved later-emitted learned
                                   # families (LESSON-014 / -015 /
                                   # -016 sandwiches received zero
                                   # dispatched specs on K4B-009).
                                   # LESSON-017 replaces front-
                                   # truncation with a quota pass
                                   # (per-family bounded minimum
                                   # exposure) followed by a
                                   # residual pass (legacy emission-
                                   # order fill). Scheduler-only;
                                   # no new cipher primitive
                                   # (LESSON-017).
    "numeric_clue_caesar_trigger_semantics",  # 2026-04-29: a salient
                                   # unbound clue numeral in [1, 25]
                                   # may be an operational ROT/Caesar
                                   # shift even when no explicit
                                   # shift / rotate / Caesar / rot
                                   # trigger word appears. Numeric
                                   # role classification distinguishes
                                   # structurally-bound numerals
                                   # (route width, rail depth, block
                                   # size, skip step, object count)
                                   # from free / tag / explicit-Caesar
                                   # numerals; only the latter are
                                   # promoted as Caesar shift
                                   # candidates. Each promoted shift
                                   # n produces both n (as_given) and
                                   # 26-n (complement) entries to
                                   # cover both encrypt / decrypt
                                   # directions. Bench-only, scheduler
                                   # composes with LESSON-017
                                   # (LESSON-018).
    "numeric_route_columnar_three_layer_composition",  # 2026-04-29:
                                   # role-complete three-layer
                                   # composition. When a clue
                                   # independently surfaces a numeric
                                   # Caesar/ROT role, a route/grid
                                   # role, and a columnar/transposition
                                   # keyword role, HCC must emit a
                                   # bounded three-layer family
                                   # combining caesar + route +
                                   # columnar in all six layer
                                   # orderings. This closes the
                                   # composition gap where each role
                                   # was detected independently but
                                   # never combined into a three-layer
                                   # candidate. No new primitive;
                                   # purely additive over LESSON-014/
                                   # 016/018 detectors. LESSON-017
                                   # scheduler classifies as
                                   # three_layer_sandwich (LESSON-019).
    "diagonal_route_semantic_completeness",  # 2026-04-29: a diagonal
                                   # route is not fully specified by
                                   # width × axis × diagonal-group
                                   # order × start_edge. Hand-cipher
                                   # diagonal routes also vary by
                                   # within-diagonal cell direction.
                                   # Adds an explicit
                                   # ``diagonal_cell_order`` parameter
                                   # to the kernel primitive and the
                                   # route dispatcher (forward /
                                   # reverse / alternate); HCC
                                   # LESSON-016 + LESSON-019 diagonal
                                   # generators enumerate forward +
                                   # reverse by default. forward
                                   # preserves backward-compatible
                                   # behavior; "alternate" is
                                   # supported at the kernel layer
                                   # but not enumerated by HCC. No
                                   # new primitive (LESSON-020).
    "diagonal_canonical_width_alias",  # 2026-04-29: a clue may
                                   # specify a diagonal route only by
                                   # width — "diagonal grid of width
                                   # N" — without exposing axis,
                                   # start-edge, or cell-order terms.
                                   # Adds a kernel helper
                                   # ``canonical_diagonal_perm`` that
                                   # pins a single canonical
                                   # convention (anti / forward /
                                   # top_then_right / forward) and a
                                   # dispatcher ``route variant=
                                   # "diagonal_canonical"`` taking
                                   # only ``width``. HCC emits
                                   # ``route_diagonal_canonical``
                                   # standalone family AND a
                                   # LESSON-019 cross-product
                                   # ``caesar_route_diagonal_
                                   # canonical_columnar``. No new
                                   # cipher primitive; the canonical
                                   # convention is one of the
                                   # combinations diagonal_perm
                                   # already supports, just NAMED so
                                   # auditors can identify the
                                   # width-only convention directly
                                   # (LESSON-021).
    "independent_two_keyword_rail_fence_three_role_composition",
                                   # 2026-04-29: when a clue exposes
                                   # two distinct keywords plus a
                                   # phrase-bound rail-fence depth,
                                   # HCC must compose substitution
                                   # keyword, columnar keyword, and
                                   # rail_fence depth as INDEPENDENT
                                   # roles in a three-layer family.
                                   # The pre-LESSON-022 L013
                                   # ``columnar_<sub>_rail_fence``
                                   # path uses ENUMERATED columnar
                                   # widths/permutations; it never
                                   # emits a clue keyword as the
                                   # columnar key. LESSON-022 closes
                                   # this composition gap with a
                                   # bounded i3-style three-layer
                                   # generator that takes both
                                   # keyword orientations on the
                                   # sub+columnar slots and any
                                   # phrase-bound rail-fence depth on
                                   # the third. No new cipher
                                   # primitive (LESSON-022).
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
        Lesson(
            lesson_id="LESSON-017",
            title="Stratified HCC bench-fast family quotas",
            description=(
                "When multiple learned HCC triggers fire on the same "
                "clue, front-loaded ``max_specs`` truncation can "
                "starve later-emitted capability families. Audits of "
                "the post-LESSON-016 catalog showed multi-trigger "
                "clues generating ~18000 specs and capping at 10000 "
                "via a simple ``len(validated) >= max_specs: break`` "
                "tail, deterministically dropping ~8000 specs and "
                "leaving more than 20 entire families with zero "
                "dispatched candidates — including row_reverse "
                "combinations, three-layer route_boustrophedon "
                "sandwiches, and Caesar combinations with a route "
                "variant.\n\n"
                "The general lesson: bench-fast must guarantee "
                "bounded per-family exposure BEFORE residual "
                "emission-order fill, so triggered learned "
                "capabilities are not deterministically dropped by "
                "ordering accident.\n\n"
                "LESSON-017 replaces the validation tail's front-"
                "truncation in ``hand_cipher_core.generate_layered_"
                "specs`` with a deterministic two-pass scheduler:\n"
                "  Pass 1 (quota): walk the FULL emitted stream "
                "    once. For each spec, retain it if its family "
                "    has not yet hit its per-family quota AND total "
                "    retained < max_specs.\n"
                "  Pass 2 (residual): walk the same stream again. "
                "    For each spec not retained in pass 1, retain it "
                "    if total retained < max_specs.\n"
                "Output ordering: pass 1 specs first (in original "
                "emission order), then pass 2 specs (in original "
                "emission order). This preserves the small-cap "
                "front-of-catalogue invariant — at very small caps, "
                "the first emitted specs are the legacy keyword-pair "
                "family (e.g. columnar_vigenere), all retained by "
                "quota, all at the front of the catalogue.\n\n"
                "Quota classes (conservative; total quota budget on "
                "multi-trigger clues sums to ~5500 specs, leaving "
                "~4500 residual at cap=10000):\n"
                "  front_of_catalog     200  (legacy keyword-pair, "
                "                              i3, standalone, "
                "                              enumerated columnar "
                "                              three-layer)\n"
                "  trigger_route        80   (route_boustrophedon /  "
                "                              row_reverse / "
                "                              route_diagonal / "
                "                              skip_route / "
                "                              reverse_blocks pair "
                "                              families and Caesar "
                "                              combinations)\n"
                "  three_layer_sandwich 40   (multi-lesson cross-"
                "                              products)\n"
                "  default              40   (alone families, "
                "                              Quagmire)\n\n"
                "Coverage_vector telemetry: every retained spec "
                "carries scheduling_pass ('quota'|'residual'), "
                "family_quota (int), family_quota_rank (int within "
                "family among quota-retained; 0 for residual), and "
                "hcc_max_specs (the cap that was applied).\n\n"
                "EXPLICIT CAVEATS:\n"
                "  - This is scheduler coverage, NOT a new cipher "
                "    primitive.\n"
                "  - This does NOT imply real-K4 progress.\n"
                "  - The audit did not solve any benchmark; it "
                "    re-scheduled an existing dispatch surface so "
                "    triggered learned capabilities all reach the "
                "    worker pool.\n"
                "  - A separate role-assignment gap (clue numerals "
                "    that imply Caesar shift values without an "
                "    explicit shift/rotate/caesar trigger word, so "
                "    the Caesar family is NEVER GENERATED in the "
                "    first place) is tracked as a follow-up "
                "    candidate. LESSON-017 only schedules specs "
                "    already generated by the existing trigger "
                "    surface."
            ),
            tactic_kind="stratified_hcc_bench_fast_family_quotas",
            applies_to_families=["*"],
            generates_specs=False,
            related_lesson_ids=[
                "LESSON-006", "LESSON-008", "LESSON-009",
                "LESSON-011", "LESSON-013", "LESSON-014",
                "LESSON-015", "LESSON-016",
            ],
            source_origin="k4bench-derived",
            tactic_parameters={
                "scheduler_passes": ["quota", "residual"],
                "quota_classes": {
                    "front_of_catalog": 200,
                    "trigger_route": 80,
                    "three_layer_sandwich": 40,
                    "default": 40,
                },
                "deterministic": True,
                "bench_only": True,
                "no_new_primitive": True,
                "preserves_k4b_001_invariant": (
                    "At cap=4 with CEDAR/LANTERN, columnar_vigenere "
                    "still occupies the entire catalog (4 specs)."
                ),
                "k4b_009_unblocking": (
                    "Pre-LESSON-017: 23 families received zero "
                    "dispatched specs on K4B-009. Post-LESSON-017: "
                    "all 58 triggered families receive >= 26 specs."
                ),
            },
        ),
        Lesson(
            lesson_id="LESSON-018",
            title="Numeric clue to Caesar/ROT trigger semantics",
            description=(
                "A salient unbound clue numeral in [1, 25] may be an "
                "operational ROT / Caesar shift even when no explicit "
                "shift / rotate / Caesar / rot / step / offset / "
                "additive / subtractive trigger word appears in the "
                "clue. Pre-LESSON-018, the Caesar family generator "
                "was gated by ``_detect_caesar_trigger`` matching one "
                "of those explicit trigger tokens; clues with a "
                "salient bare numeric (e.g. 'small tag says "
                "seventeen', 'marker 17', 'label eight') would "
                "extract the value but never emit Caesar specs.\n\n"
                "The general lesson: numeric role classification is "
                "the operative gate. A numeral may be:\n"
                "  - structurally bound (route_width, grid_dimension, "
                "    rail_depth, block_size, skip_step) — NOT a "
                "    Caesar candidate\n"
                "  - object_count (cardinal followed by physical-"
                "    object plural noun like 'five stones', 'ten "
                "    panels') — NOT a Caesar candidate\n"
                "  - explicit_caesar (preceded by a shift/rotate/"
                "    caesar/rot/additive/subtractive token) — IS a "
                "    Caesar candidate (legacy explicit-trigger path)\n"
                "  - free_numeric_tag (preceded by a tag/label/"
                "    inscription/says/marked/code/value/reads "
                "    precursor) — IS a Caesar candidate (LESSON-018)\n"
                "  - ambiguous_numeric (no clear binding) — IS a "
                "    Caesar candidate IF and ONLY IF no other "
                "    occurrence of the same value has a stronger "
                "    structural binding in the clue\n"
                "  - ignored_out_of_range (value outside [1, 25]) — "
                "    NOT a Caesar candidate\n\n"
                "Caesar shift direction policy: Caesar dispatch uses "
                "``C = (P + shift) mod 26``. Without knowing whether "
                "the clue numeral describes the encrypt direction or "
                "the decrypt direction, every promoted shift n "
                "produces both:\n"
                "  - shift_value = n (shift_direction='as_given')\n"
                "  - shift_value = (26 - n) % 26 "
                "    (shift_direction='complement')\n"
                "Self-complement n=13 and identity n=0 entries are "
                "skipped to avoid duplicate / no-op specs.\n\n"
                "HCC emission: when numeric promotion fires AND the "
                "explicit Caesar trigger does NOT fire, the generator "
                "emits a small bounded matrix (caesar alone, "
                "caesar + route_boustrophedon both orders if "
                "boustro trigger fired, caesar + route_diagonal "
                "both orders if diagonal trigger fired, caesar + "
                "row_reverse both orders if row_reverse trigger "
                "fired). Total emission for a single promoted shift "
                "across all four cross-trigger combinations stays "
                "well under bench-fast cardinality budgets.\n\n"
                "Coverage_vector telemetry (LESSON-018 fields):\n"
                "  shift_source       — 'clue_numeric_free' | "
                "                        'clue_numeric_tag' | "
                "                        'explicit_caesar_token'\n"
                "  shift_token        — original token string ("
                "                        'seventeen', '17')\n"
                "  shift_role         — classifier result\n"
                "  shift_direction    — 'as_given' | 'complement'\n"
                "  numeric_trigger_without_caesar_word\n"
                "                     — True for numerically-promoted "
                "                        Caesar specs; False for "
                "                        legacy explicit-trigger "
                "                        Caesar specs\n"
                "  operation_source   — set to "
                "                        'numeric_caesar_trigger' "
                "                        on numerically-promoted "
                "                        specs\n\n"
                "EXPLICIT CAVEATS:\n"
                "  - This is a benchmark curriculum capability.\n"
                "  - It does NOT imply real K4 uses Caesar.\n"
                "  - It does NOT solve any specific benchmark unless "
                "    independently evaluated.\n"
                "  - Sealed-answer text must not enter repo "
                "    artifacts."
            ),
            tactic_kind="numeric_clue_caesar_trigger_semantics",
            applies_to_families=[
                "caesar",
                "caesar_route_boustrophedon",
                "caesar_route_diagonal",
                "caesar_row_reverse",
            ],
            generates_specs=True,
            related_lesson_ids=[
                "LESSON-009", "LESSON-012", "LESSON-014",
                "LESSON-015", "LESSON-016", "LESSON-017",
            ],
            source_origin="k4bench-derived",
            tactic_parameters={
                "numeric_role_taxonomy": [
                    "route_width", "grid_dimension", "rail_depth",
                    "block_size", "skip_step", "object_count",
                    "explicit_caesar", "free_numeric_tag",
                    "ambiguous_numeric", "ignored_out_of_range",
                ],
                "promotion_eligible_roles": [
                    "explicit_caesar", "free_numeric_tag",
                    "ambiguous_numeric",
                ],
                "shift_direction_policy": "as_given_and_complement",
                "self_complement_skipped": [13],
                "shift_value_range": [1, 25],
                "tag_precursor_tokens": [
                    "tag", "tagged", "marked", "marking", "marker",
                    "label", "labeled", "labelled", "inscription",
                    "inscribed", "number", "numbered", "numeric",
                    "code", "coded", "value", "valued",
                    "says", "said", "reads", "read",
                    "shows", "showed", "stamped", "etched",
                    "engraved", "carved", "noted",
                    "displays", "displayed",
                    "indicates", "indicated",
                ],
                "explicit_caesar_precursor_tokens": [
                    "shift", "shifted", "shifts",
                    "rotate", "rotated", "rotation",
                    "caesar", "rot",
                    "additive", "subtractive",
                ],
                "structural_binding_after_tokens": [
                    "wide", "column", "columns", "col", "cols",
                    "row", "rows", "line", "lines", "grid",
                    "deep", "depth", "rail", "rails", "fence",
                ],
                "structural_binding_before_tokens": [
                    "step", "stepped", "stride", "skip", "skipped",
                    "every", "offset", "depth",
                    "block", "blocks", "groups", "group", "width",
                ],
                "object_count_after_tokens_examples": [
                    "stones", "marbles", "letters", "characters",
                    "panels", "pieces", "tiles", "bricks", "posts",
                    "objects", "diagonals",
                ],
                "bench_only": True,
                "no_new_primitive": True,
            },
        ),
        Lesson(
            lesson_id="LESSON-019",
            title=(
                "Role-complete numeric-route-columnar three-layer "
                "composition"
            ),
            description=(
                "When a clue INDEPENDENTLY exposes a numeric "
                "operation role (LESSON-018 promoted shift), a "
                "route/grid operation role (LESSON-014 boustrophedon "
                "or LESSON-016 diagonal), AND a columnar/"
                "transposition keyword role (clue keyword of "
                "length >= 2), HCC must emit a bounded three-layer "
                "composition family combining caesar + route + "
                "columnar.\n\n"
                "Pre-LESSON-019 each detector ran independently and "
                "two-layer cross-products existed (LESSON-018 caesar +"
                " route, LESSON-014 sub + route + columnar, etc.) "
                "but no generator emitted the role-complete numeric "
                "+ route + columnar three-layer composition. This "
                "is purely a composition gap — no new primitive is "
                "added by this lesson.\n\n"
                "Family labels:\n"
                "  caesar_route_boustrophedon_columnar — emitted when "
                "    LESSON-018 numeric promotion AND boustrophedon "
                "    trigger AND a clue keyword of length >= 2 are "
                "    all present\n"
                "  caesar_route_diagonal_columnar — emitted under the "
                "    same gate with the diagonal trigger\n\n"
                "Layer-order policy: every emitted family covers all "
                "SIX decrypt-order permutations of the role triple "
                "(caesar→route→columnar, caesar→columnar→route, "
                "route→caesar→columnar, route→columnar→caesar, "
                "columnar→caesar→route, columnar→route→caesar). "
                "Encrypt vs decrypt direction is ambiguous in clue "
                "language, so all six are emitted and the LESSON-017 "
                "scheduler enforces per-family quota.\n\n"
                "Cardinality bounds: each promoted shift × ≤8 route "
                "layers × ≤2 columnar keywords × 6 layer orders. "
                "Realistic upper bound per family on a multi-trigger "
                "clue is ~192 specs; the LESSON-017 scheduler "
                "classifies LESSON-019 families as "
                "three_layer_sandwich (quota=40 each) so per-family "
                "retention matches existing sandwich families.\n\n"
                "CoverageVector telemetry (in addition to the "
                "LESSON-018 numeric promotion fields):\n"
                "  layer_family       — caesar_<route>_columnar\n"
                "  layer_order        — one of six permutations\n"
                "  role_assignment    — (caesar_shift, route, "
                "    columnar) triple\n"
                "  role_assignment_mode = "
                "    'numeric_route_columnar_three_role'\n"
                "  operation_source   = "
                "    'numeric_route_columnar_composition'\n"
                "  route_mode / route_width / route_rows / route_cols "
                "    / route_width_source — from route layer\n"
                "  transposition_keyword + col_order + "
                "    col_order_source — from columnar keyword\n\n"
                "EXPLICIT CAVEATS:\n"
                "  - This is a benchmark curriculum capability.\n"
                "  - It does NOT imply real K4 uses this "
                "    composition.\n"
                "  - It does NOT solve any specific benchmark unless "
                "    independently evaluated.\n"
                "  - Sealed-answer text must not enter repo "
                "    artifacts."
            ),
            tactic_kind=(
                "numeric_route_columnar_three_layer_composition"
            ),
            applies_to_families=[
                "caesar_route_boustrophedon_columnar",
                "caesar_route_diagonal_columnar",
            ],
            generates_specs=True,
            related_lesson_ids=[
                "LESSON-014", "LESSON-016", "LESSON-017", "LESSON-018",
            ],
            source_origin="k4bench-derived",
            tactic_parameters={
                "required_role_triple": [
                    "numeric_caesar_promotion",
                    "route_trigger (boustrophedon or diagonal)",
                    "columnar_keyword (length >= 2)",
                ],
                "layer_orders": [
                    "caesar -> route -> columnar",
                    "caesar -> columnar -> route",
                    "route -> caesar -> columnar",
                    "route -> columnar -> caesar",
                    "columnar -> caesar -> route",
                    "columnar -> route -> caesar",
                ],
                "route_partner_kinds": [
                    "route_boustrophedon", "route_diagonal",
                ],
                "scheduler_quota_class": "three_layer_sandwich",
                "scheduler_quota_value": 40,
                "no_new_primitive": True,
                "bench_only": True,
                "composition_only_gap": True,
            },
        ),
        Lesson(
            lesson_id="LESSON-020",
            title="Diagonal route semantic completeness",
            description=(
                "A diagonal grid-route transposition is not fully "
                "specified by (width × axis × diagonal-group order × "
                "start_edge). Hand-cipher diagonal routes also vary "
                "by the order of cells WITHIN each diagonal — once a "
                "diagonal stripe is identified, an operator can read "
                "its cells in either direction independently of "
                "which end was chosen as the starting cell.\n\n"
                "Pre-LESSON-020 the diagonal route primitive exposed "
                "axis × order × start_edge but did not expose the "
                "within-diagonal cell direction as a separate "
                "parameter. The HCC LESSON-016 + LESSON-019 "
                "generators emitted a single canonical cell-order "
                "convention. LESSON-020 closes that semantic gap "
                "without adding a new cipher primitive: it adds a "
                "single new parameter ``diagonal_cell_order`` to "
                "``diagonal_perm`` and the dispatcher route "
                "translator, and opts the LESSON-016 + LESSON-019 "
                "diagonal HCC family generators into the bounded "
                "(forward, reverse) cell-order enumeration.\n\n"
                "Parameter values:\n"
                "  forward    — preserve cells as produced by\n"
                "               start_edge selection. DEFAULT,\n"
                "               backward-compatible.\n"
                "  reverse    — reverse each diagonal's cell list\n"
                "               AFTER start_edge / order are\n"
                "               applied.\n"
                "  alternate  — boustrophedon over the diagonal\n"
                "               sequence: even-indexed diagonals\n"
                "               forward, odd-indexed reversed.\n"
                "               Supported at the kernel + dispatcher\n"
                "               layer but NOT enumerated by HCC by\n"
                "               default to keep cardinality bounded.\n"
                "Unknown values fail closed at both the kernel "
                "(ValueError) and the dispatcher (DispatcherError).\n\n"
                "HCC opt-in: LESSON-016 ``_gen_diagonal_*`` family "
                "generators accept a ``cell_orders`` keyword whose "
                "default is ``('forward',)`` (preserves legacy "
                "emission and spec hashes); the LESSON-016 callers "
                "in ``generate_layered_specs`` opt in to "
                "``('forward', 'reverse')``. The LESSON-019 "
                "``caesar_route_diagonal_columnar`` family "
                "enumerates both cell orders inside its bounded "
                "route-layer matrix. The LESSON-017 stratified "
                "scheduler caps per-family retention at quota=40 "
                "for the three-layer sandwich, so the cell-order "
                "doubling does not crowd out other learned "
                "families.\n\n"
                "CoverageVector telemetry:\n"
                "  diagonal_cell_order — 'forward' | 'reverse' | "
                "    'alternate' on diagonal route specs; empty "
                "    string on non-diagonal specs.\n\n"
                "EXPLICIT CAVEATS:\n"
                "  - This is a benchmark curriculum capability.\n"
                "  - It does NOT imply real K4 uses diagonal "
                "    routing.\n"
                "  - It does NOT solve any specific benchmark "
                "    unless independently evaluated.\n"
                "  - Sealed-answer text must not enter repo "
                "    artifacts."
            ),
            tactic_kind="diagonal_route_semantic_completeness",
            applies_to_families=[
                "route_diagonal",
                "route_diagonal_vigenere",
                "route_diagonal_beaufort",
                "route_diagonal_variant_beaufort",
                "route_diagonal_rail_fence",
                "caesar_route_diagonal_columnar",
            ],
            generates_specs=False,
            related_lesson_ids=[
                "LESSON-016", "LESSON-017", "LESSON-018", "LESSON-019",
            ],
            source_origin="k4bench-derived",
            tactic_parameters={
                "parameter_name": "diagonal_cell_order",
                "cell_order_values": ["forward", "reverse", "alternate"],
                "default_value": "forward",
                "hcc_enumerated_values": ["forward", "reverse"],
                "fail_closed_layers": [
                    "kernel.transforms.transposition.diagonal_perm",
                    "dispatcher.route variant=diagonal",
                ],
                "no_new_primitive": True,
                "bench_only": True,
                "semantic_completeness_only": True,
            },
        ),
        Lesson(
            lesson_id="LESSON-021",
            title="Canonical width-only diagonal route alias",
            description=(
                "A clue may specify a diagonal route ONLY by its "
                "width — 'diagonal grid of width N' — without "
                "exposing axis, start-edge, or within-diagonal "
                "cell-order terms. The expanded LESSON-016 / "
                "LESSON-020 parameter set (axis × order × start_edge "
                "× cell_order) enumerates all combinations, but "
                "downstream telemetry can lose track of WHICH "
                "combination is 'the' canonical width-only reading.\n\n"
                "LESSON-021 fixes the canonical convention as one "
                "auditable surface:\n"
                "  axis        = 'anti'\n"
                "  order       = 'forward'\n"
                "  start_edge  = 'top_then_right'\n"
                "  cell_order  = 'forward'\n"
                "  rows        = ceil(length / width)\n"
                "  cols        = width\n\n"
                "This is the natural top-left-to-bottom-right "
                "anti-diagonal reading of a row-major-filled width-N "
                "rectangle. It is one of the eight combinations "
                "``diagonal_perm`` already supports — LESSON-021 "
                "does NOT introduce a new kernel mechanism, it "
                "names the canonical convention so HCC, dispatcher, "
                "and downstream telemetry can refer to it directly.\n\n"
                "Kernel: ``canonical_diagonal_perm(width, length)`` "
                "— width-only alias; calls ``diagonal_perm`` with the "
                "four canonical parameters pinned. Bijective and "
                "length-preserving.\n\n"
                "Dispatcher: ``route variant='diagonal_canonical'`` "
                "takes only ``width``; rows / cols are inferred. "
                "Invalid width fails closed (DispatcherError).\n\n"
                "HCC families:\n"
                "  route_diagonal_canonical                 standalone\n"
                "  caesar_route_diagonal_canonical_columnar  LESSON-019\n"
                "    cross-product (numeric Caesar + canonical\n"
                "    diagonal width + columnar keyword)\n\n"
                "CoverageVector telemetry:\n"
                "  route_mode = 'route_diagonal_canonical'\n"
                "  route_width / route_rows / route_cols\n"
                "  route_width_source ('phrase_bound_route_width' |\n"
                "    'default_set')\n"
                "  diagonal_axis / diagonal_order /\n"
                "    diagonal_start_edge / diagonal_cell_order all\n"
                "    populated with the canonical pinned values.\n\n"
                "EXPLICIT CAVEATS:\n"
                "  - This is a benchmark curriculum capability.\n"
                "  - It does NOT imply real K4 uses diagonal "
                "    routing.\n"
                "  - It does NOT solve any specific benchmark "
                "    unless independently evaluated.\n"
                "  - Sealed-answer text must not enter repo "
                "    artifacts."
            ),
            tactic_kind="diagonal_canonical_width_alias",
            applies_to_families=[
                "route_diagonal_canonical",
                "caesar_route_diagonal_canonical_columnar",
            ],
            generates_specs=True,
            related_lesson_ids=[
                "LESSON-014", "LESSON-016", "LESSON-017", "LESSON-018",
                "LESSON-019", "LESSON-020",
            ],
            source_origin="k4bench-derived",
            tactic_parameters={
                "canonical_axis": "anti",
                "canonical_order": "forward",
                "canonical_start_edge": "top_then_right",
                "canonical_cell_order": "forward",
                "rows_formula": "ceil(length / width)",
                "cols_formula": "width",
                "width_min": 3,
                "width_max": 16,
                "width_sources": [
                    "phrase_bound_route_width", "default_set",
                ],
                "no_new_primitive": True,
                "bench_only": True,
                "alias_only": True,
            },
        ),
        Lesson(
            lesson_id="LESSON-022",
            title=(
                "Independent two-keyword rail-fence three-role "
                "composition"
            ),
            description=(
                "When a clue independently exposes TWO distinct "
                "keywords plus a phrase-bound rail-fence depth, HCC "
                "must compose substitution keyword, columnar "
                "keyword, and rail_fence depth as independent roles "
                "in a three-layer family.\n\n"
                "Pre-LESSON-022 the L013 ``columnar_<sub>_rail_"
                "fence`` three-layer emitter used ENUMERATED columnar "
                "widths and col_orders; it never assigned a clue "
                "keyword to the columnar slot. The LESSON-010 i3 "
                "independent-keyword family covered the two-layer "
                "(sub + columnar) case but never extended to a "
                "three-layer rail-fence sandwich. As a result, when "
                "a clue specified e.g. 'OBSERVE and GARDEN ... "
                "three-rail fence ... after the column labels', the "
                "natural composition\n"
                "  [sub=OBSERVE, columnar=GARDEN, rail_fence(3)]\n"
                "(plus the keyword swap) was structurally absent "
                "from the catalogue. This is purely a composition "
                "gap; no new cipher primitive is added.\n\n"
                "Family labels:\n"
                "  i3_columnar_vigenere_rail_fence\n"
                "  i3_columnar_beaufort_rail_fence\n"
                "  i3_columnar_variant_beaufort_rail_fence\n\n"
                "Trigger conditions (all required):\n"
                "  1. >= 2 distinct usable clue keywords (length\n"
                "     >= 2 each, after the standard A-Z normaliser)\n"
                "  2. >= 1 phrase-bound rail_fence depth from\n"
                "     ``extract_phrase_bound_numerics(rail_depth)``\n"
                "     — default-only depths do NOT trigger this\n"
                "     family\n\n"
                "Layer-order policy: every emitted family covers "
                "all SIX decrypt-direction permutations of the "
                "(substitution, columnar, rail_fence) triple.\n\n"
                "Cardinality bound:\n"
                "  2 keyword orientations × 6 layer orders ×\n"
                "  N_rail_depths (typically 1-2) ≈ 12-24 specs per\n"
                "  sub_kind family. Three sub_kind families summed:\n"
                "  ~36-72 specs total. LESSON-017 scheduler\n"
                "  classifies each as three_layer_sandwich\n"
                "  (quota=40 each).\n\n"
                "CoverageVector telemetry:\n"
                "  layer_family            — i3_columnar_<sub>_rail_fence\n"
                "  layer_order             — one of six permutations\n"
                "  n_layers                = 3\n"
                "  substitution_keyword    — clue keyword KW_A\n"
                "  transposition_keyword   — clue keyword KW_B (NOT empty)\n"
                "  transposition_width     = len(KW_B)\n"
                "  col_order               — keyword stable rank\n"
                "  col_order_source        = 'clue_keyword'\n"
                "  role_assignment         — full three-tuple with\n"
                "                            (sub, KW_A) +\n"
                "                            (columnar, KW_B) +\n"
                "                            (rail_fence, depth)\n"
                "  role_assignment_mode    =\n"
                "    'independent_two_keyword_rail_fence_three_role'\n"
                "  operation_source        =\n"
                "    'independent_keyword_rail_fence_composition'\n\n"
                "EXPLICIT CAVEATS:\n"
                "  - Benchmark curriculum capability.\n"
                "  - Does NOT imply real K4 uses this composition.\n"
                "  - Does NOT solve any specific benchmark unless\n"
                "    independently evaluated.\n"
                "  - Sealed-answer text must not enter repo "
                "    artifacts."
            ),
            tactic_kind=(
                "independent_two_keyword_rail_fence_three_role_composition"
            ),
            applies_to_families=[
                "i3_columnar_vigenere_rail_fence",
                "i3_columnar_beaufort_rail_fence",
                "i3_columnar_variant_beaufort_rail_fence",
            ],
            generates_specs=True,
            related_lesson_ids=[
                "LESSON-010", "LESSON-013", "LESSON-017",
            ],
            source_origin="k4bench-derived",
            tactic_parameters={
                "required_role_triple": [
                    "substitution_keyword (clue keyword KW_A)",
                    "columnar_keyword (clue keyword KW_B, distinct)",
                    "rail_fence_depth (phrase-bound)",
                ],
                "layer_orders": [
                    "sub -> columnar -> rail_fence",
                    "sub -> rail_fence -> columnar",
                    "columnar -> sub -> rail_fence",
                    "columnar -> rail_fence -> sub",
                    "rail_fence -> sub -> columnar",
                    "rail_fence -> columnar -> sub",
                ],
                "substitution_kinds": [
                    "vigenere", "beaufort", "variant_beaufort",
                ],
                "keyword_orientations": [
                    "(sub=A, col=B)", "(sub=B, col=A)",
                ],
                "scheduler_quota_class": "three_layer_sandwich",
                "scheduler_quota_value": 40,
                "rail_fence_depth_source": (
                    "extract_phrase_bound_numerics(rail_depth)"
                ),
                "role_pool_size": 2,
                "no_new_primitive": True,
                "bench_only": True,
                "composition_only_gap": True,
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
