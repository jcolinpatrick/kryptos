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
