"""Job dispatcher — translates HypothesisSpec into bounded compute jobs.

Framework maturation Phase 4 (2026-04-21). The dispatcher is the bridge
between the LLM-authored HypothesisSpec DSL and the kernel's campaign
infrastructure. Its responsibilities:

    1. Admissibility pre-flight — reject specs that exceed budget, are
       already exhausted, or target cipher kinds that don't yet have a
       kernel translation path.
    2. Enumerate the Cartesian product of parameter ranges across the
       pipeline layers.
    3. Dispatch each config via ``multiprocessing.Pool`` (default
       ``cpu_count() - 2`` workers) against ``kryptos.kernel`` transforms.
    4. Kernel-verify every candidate using ``score_candidate`` from the
       canonical scoring path — not worker self-reports.
    5. Emit a structured ``JobResult`` with deterministic
       ``spec_hash``/``universe_hash``, artifact paths, and (when
       applicable) an ``eliminated_claim`` string for exhaustion-log
       logging.

What this module is NOT in Phase 4:
    - It does not fully support all CipherKind values from the DSL;
      kinds with no translation yet raise ``DispatcherError`` with a
      clear pointer. Phase 5+ extends this.
    - It does not yet integrate the Phase-6 null-baseline machinery;
      the ``null_baseline`` field on the spec is accepted for forward
      compat but does not alter the result p-values.
    - It does not integrate with the procedural-recipe enumerator;
      that is a Phase-8 deliverable.

See ``docs/maturation/phase_04_report.md`` for design rationale and three
worked examples.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import logging
import os
import time
from dataclasses import asdict, dataclass, field
from multiprocessing import Pool, cpu_count
from pathlib import Path
from typing import Any, Callable, Iterator, Optional

from .hypothesis_dsl import (
    CipherLayer,
    HypothesisSpec,
    ParamRange,
    validate_hypothesis_spec,
)

logger = logging.getLogger("kryptosbot.job_dispatcher")


# ─── Exceptions ──────────────────────────────────────────────────────────────

class DispatcherError(Exception):
    """Raised when a spec cannot be dispatched for any reason.

    The message is always machine-parseable: admissibility failures,
    translation gaps, and runtime errors all produce distinguishable
    strings. Callers should treat the exception as a hard fail — the
    brief's §6.3 policy is that specs without a valid translation path
    downgrade the owning theory to INCONCLUSIVE, not get silently
    re-attempted.
    """


# ─── Result dataclass ────────────────────────────────────────────────────────

@dataclass
class JobResult:
    """Outcome of dispatching one ``HypothesisSpec``.

    All fields are populated even on early-exit paths (admissibility
    rejection, no candidates). Serialized to an artifact JSON at
    ``artifact_path`` for downstream audit.
    """
    hypothesis_id: str
    spec_hash: str                              # sha256-16 of canonical spec JSON
    universe_hash: str                          # sha256-16 covering config_ids tested
    total_tested: int = 0
    total_stored: int = 0                       # above STORE_THRESHOLD
    best_candidate: Optional[dict[str, Any]] = None
    best_score: float = 0.0
    best_p_value_vs_null: Optional[float] = None  # populated in Phase 6
    information_gain_bits_realized: float = 0.0
    wall_time_sec: float = 0.0
    cpu_time_sec: float = 0.0
    artifact_path: str = ""
    checkpoint_path: str = ""
    assumption_bundle: list[str] = field(default_factory=list)
    eliminated_claim: Optional[str] = None      # populated when job runs to completion with no signal
    admissibility_verdict: str = ""             # "ok" | "rejected: <reason>"
    admissibility_reasons: list[str] = field(default_factory=list)
    # R2-3 (2026-04-21): when the spec carried override_exhaustion=True,
    # propagate the justification string into the result so the ledger
    # preserves WHY the override was claimed. Empty string when override
    # was not invoked.
    override_justification: str = ""
    # R2-3: list of exhaustion-log script_ids this run overrode. Empty
    # when override was not invoked OR when the spec had no overlap.
    override_exhaustion_overlap: list[str] = field(default_factory=list)
    # K4Bench attempt-replay (2026-04-27): the post-procedural-expansion
    # HypothesisSpec dict that was actually dispatched. Empty {} on
    # admissibility / translation rejection (nothing was dispatched).
    # Populated whenever ``execute()`` runs the spec through
    # ``_evaluate_one`` so downstream consumers (bench_attempts, the
    # offline evaluator) can replay layers without round-tripping
    # through the artifact_path file.
    dispatched_dsl_spec: dict[str, Any] = field(default_factory=dict)
    # K4Bench attempt-replay: the parameter binding that produced the
    # best candidate, as a list of [flat_key, value] pairs (e.g.
    # [["layer0.keyword", "CEDAR"], ["layer1.width", 7]]). Empty when
    # no candidate was produced or when the spec had no params (an
    # all-fixed pipeline). Combined with ``dispatched_dsl_spec.pipeline``
    # this is enough to reconstruct the resolved layer set the kernel
    # actually ran for the best result.
    best_config_bindings: list[list[Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, indent=2)


# ─── Admissibility pre-flight ────────────────────────────────────────────────

# Per-minute per-worker cost cap for the cardinality sanity check. Rough:
# a typical Vigenere+score on a 97-char CT runs at ~10000 configs/worker/min.
# We pad this up to be generous in the admissibility gate (we don't want
# false-negatives on modest specs). Overly-optimistic; dispatcher's wall
# clock is the real stop.
_CONFIGS_PER_CPU_MINUTE_CAP = 200_000


def _load_exhaustion_log(path: Optional[Path] = None) -> dict[str, dict[str, Any]]:
    """Load exhaustion_log.json (repo root). Returns empty dict on missing file.

    The caller may pass a custom path for testing; default looks upward
    from this module's location for the repo root.
    """
    if path is None:
        here = Path(__file__).resolve().parent
        repo_root = here.parent
        path = repo_root / "exhaustion_log.json"
    if not path.exists():
        return {}
    try:
        with open(path) as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {}
        return data
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Failed to load exhaustion log %s: %s", path, exc)
        return {}


def check_admissibility(
    spec: HypothesisSpec,
    exhaustion_log: Optional[dict[str, Any]] = None,
    *,
    bench_mode: bool = False,
) -> tuple[bool, list[str]]:
    """Validate that the spec is safe to dispatch.

    Returns ``(admissible, reasons)``. ``admissible`` is True only when
    ``reasons`` is empty. The dispatcher refuses to execute when
    ``admissible`` is False — the brief's §6.2 policy is "reject explicit,
    never silently clip" so the caller can surface the exact reason.

    K4Bench (2026-04-26): when ``bench_mode=True`` the real-K4
    ``exhaustion_log.json`` is ignored entirely — the controller is
    running a synthetic K4Bench challenge and the real-K4 elimination
    history does not constrain it. Spec-shape validation, translation-
    path check, and cardinality budget still fire normally; only the
    real-K4 overlap heuristic is treated as not-applicable. Equivalent
    to passing ``override_exhaustion=True`` on every bench-mode spec
    without the synthesised justification text.
    """
    reasons: list[str] = []

    validation_errors = spec.validate()
    if validation_errors:
        reasons.extend([f"spec invalid: {e}" for e in validation_errors])
        return (False, reasons)

    # Translation-path check: every layer kind must be something we can
    # translate. Unknown kinds are caught by spec.validate() already;
    # this catches the "kind is valid DSL but no dispatcher translation
    # yet" case (e.g. rail_fence in Phase 4).
    for i, layer in enumerate(spec.pipeline):
        if not _kind_has_translation(layer.kind):
            reasons.append(
                f"pipeline[{i}]: kind {layer.kind!r} has no dispatcher "
                f"translation in Phase 4; see kryptosbot.job_dispatcher "
                f"_SUPPORTED_KINDS (pending in later phases)"
            )

    # Cardinality budget check.
    card = spec.expected_cardinality()
    budget = spec.compute_budget_cpu_minutes * _CONFIGS_PER_CPU_MINUTE_CAP
    if card > budget:
        reasons.append(
            f"expected_cardinality {card} exceeds budget "
            f"{spec.compute_budget_cpu_minutes} min × "
            f"{_CONFIGS_PER_CPU_MINUTE_CAP} configs/min = {budget}"
        )

    # Exhaustion-log overlap check. R2-3 (2026-04-21) introduced an
    # override mechanism: if the spec carries override_exhaustion=True
    # with a non-empty justification, overlap is logged but NOT added to
    # reasons. Validation guarantees the justification is non-empty when
    # override=True, so we can trust it here.
    #
    # K4Bench (2026-04-26): bench_mode short-circuits the entire overlap
    # check — the real-K4 exhaustion log doesn't constrain a synthetic
    # challenge. Skip the file load too so a bench run cannot be
    # rejected by stale rows in the K4 log.
    if bench_mode:
        logger.info(
            "admissibility: bench_mode=True; real-K4 exhaustion log "
            "treated as not applicable for spec %s",
            spec.hypothesis_id,
        )
    else:
        log = exhaustion_log if exhaustion_log is not None else _load_exhaustion_log()
        overlap = _exhaustion_overlap(spec, log)
        if overlap:
            if getattr(spec, "override_exhaustion", False):
                logger.info(
                    "admissibility: exhaustion overlap (%d entries) present on "
                    "spec %s, overridden with justification: %s",
                    len(overlap),
                    spec.hypothesis_id,
                    (spec.override_justification or "")[:120],
                )
            else:
                reasons.append(
                    f"exhaustion overlap: {len(overlap)} prior entr{'y' if len(overlap) == 1 else 'ies'} "
                    f"already cover this spec's assumption bundle + family "
                    f"(first 3: {overlap[:3]}). If this spec genuinely "
                    "adds information beyond the overlap, re-submit with "
                    "override_exhaustion=True and an override_justification."
                )

    return (not reasons, reasons)


def _exhaustion_overlap(
    spec: HypothesisSpec,
    log: dict[str, Any],
) -> list[str]:
    """Return script_ids in exhaustion_log whose family overlaps the spec.

    Current heuristic: exact substring match between any layer.kind and
    the entry's 'family' field. Deliberately simple — a rigorous
    overlap check would need structured family + assumption bundle
    matching, which is Phase 8+ territory. False positives here are
    advisory; the caller still chooses whether to proceed.
    """
    if not log:
        return []
    kinds = {layer.kind.lower() for layer in spec.pipeline}
    matches: list[str] = []
    for script_id, entry in log.items():
        if not isinstance(entry, dict):
            continue
        family = str(entry.get("family", "")).lower()
        if any(kind in family for kind in kinds):
            if entry.get("status") in {"exhausted", "completed"}:
                matches.append(script_id)
    return matches


# ─── Cipher-kind translation ─────────────────────────────────────────────────

# Kinds the dispatcher can currently translate into kernel transforms.
# Extending this set requires (a) adding a _translate_<kind>() helper and
# (b) updating this frozenset. Add to both when a new kind is wired up.
_SUPPORTED_KINDS: frozenset[str] = frozenset({
    "identity",
    "vigenere",
    "beaufort",
    "variant_beaufort",
    "columnar",
    "atbash",
    # R3-0.5-1: procedural layers are expanded to their recipe template
    # pipeline in execute() BEFORE enumeration / translation. The
    # _translate_layer case below is a defensive guard — procedural
    # layers should never reach it.
    "procedural",
    # R3-0.5-2: Cardano-grille gather under the permutation-only
    # interpretation. Mask length must equal CT_LEN; translator delegates
    # to TransformType.GRILLE in compose.py, which calls
    # apply_grille_permutation.
    "grille",
    # R3-0.5-3: Polybius family. Dispatches to TransformType.BIFID in
    # compose.py (the length-preserving fractionation variant; straight
    # polybius is length-non-preserving and deferred to a later brief).
    # The translator accepts variant="bifid" only.
    "polybius",
    # B-DSL-expanded (2026-04-22): four additional cipher families that
    # were listed in R3 protocol §2.1 as deferred. (`key_tape`, the last
    # deferred kind, was promoted to supported on 2026-05-03 — see its
    # entry below.) All four route through existing kernel primitives:
    #   rail_fence  → transposition_full via rail_fence_perm
    #   myszkowski  → transposition_full via myszkowski_perm
    #   route       → transposition_full via serpentine_perm / spiral_perm
    #                 (variant selects the path)
    #   quagmire    → new TransformType.QUAGMIRE, enforces K1/K2 convention
    "rail_fence",
    "myszkowski",
    "route",
    "quagmire",
    # 2026-04-28 (LESSON-008): fixed-size block reversal. Pure
    # transposition primitive — divide CT into blocks of size N and
    # reverse each block. Self-inverse, length-preserving. Composes
    # with any substitution layer because it returns a
    # transposition_full perm. Two ``block_mode`` values:
    #   "reverse_partial" — every block including a partial trailing
    #                       block gets reversed (default; matches
    #                       the hand-cipher convention where the
    #                       last short group is still flipped).
    #   "truncate"        — only complete blocks are reversed; the
    #                       trailing tail is identity. Useful when
    #                       the clue pack signals a fixed grid that
    #                       does not divide the CT length.
    "reverse_blocks",
    # 2026-04-28 (LESSON-009): canonical Caesar / ROT-N. Param:
    # ``shift`` (int in [0, 25]). The translator emits a Vigenere
    # transform with a single-element key [shift], so the kernel
    # arithmetic is exactly C = (P + shift) mod 26. Using a first-
    # class kind (rather than collapsing into a 1-letter Vigenere)
    # keeps coverage_vector and attempt layers explicit so
    # telemetry distinguishes "caesar(shift=8)" from a Vigenere
    # spec that happened to pick a 1-character keyword.
    "caesar",
    # 2026-04-28 (LESSON-011): modular skip / step / stride route.
    # Params: ``step`` (int, 1 <= step < CT_LEN), ``offset``
    # (int, 0 <= offset < CT_LEN). The translator emits a
    # transposition_full perm with
    # ``perm[i] = (offset + i*step) mod CT_LEN``. Length-preserving,
    # deterministic, replayable from attempt artifacts. step and
    # CT_LEN must be coprime so the walk visits every position
    # exactly once; the translator rejects non-coprime steps with
    # a clear error rather than silently producing a partial
    # permutation.
    "skip_route",
    # 2026-04-28 (LESSON-014): width-only ragged boustrophedon
    # (serpentine) route. Params: ``width`` (int, 2 <= width <
    # CT_LEN), optional ``vertical`` (bool, default False). The
    # translator computes rows = ceil(CT_LEN / width) and reuses
    # ``serpentine_perm(rows, width, CT_LEN, vertical)`` which trims
    # positions beyond CT_LEN — that is what makes the layer
    # "ragged" (the final row/column may be short). Distinct from
    # the existing ``route`` kind, which requires an explicit
    # rows*cols >= CT_LEN grid; LESSON-014 generates the grid from
    # a single width parameter so width-only triggers can fire
    # cleanly. Length-preserving, deterministic.
    "route_boustrophedon",
    # 2026-04-28 (LESSON-015): folded-strip / alternate-row
    # reversal. Params: ``width`` (int, 2 <= width <= CT_LEN),
    # ``parity`` (str, "odd"|"even"|"both"), optional
    # ``start_row`` (int, 0|1, default 0). The translator splits
    # the text into rows of width ``width`` and reverses every row
    # whose 0-indexed row index matches the parity selector
    # (offset by ``start_row``). The trailing partial row is
    # reversed in place (still ragged-aware). Self-inverse:
    # applying the same parameter tuple twice returns the
    # identity — kernel ``transposition_full`` with direction=
    # 'undo' inverts the perm, but for an involutive perm the
    # inverse is the same perm so encrypt/decrypt direction is
    # unambiguous. Length-preserving, deterministic.
    "row_reverse",
    # 2026-05-03 (key_tape DSL build Task 9): finite substitution key tape
    # with optional null positions. The tape is a concrete integer sequence
    # (not a sweepable parameter), variant ∈ {vigenere, beaufort,
    # variant_beaufort}, null_rule ∈ {skip, consume}. The translator reads
    # directly from layer.params (a dict on the concrete layer) and delegates
    # to TransformType.KEY_TAPE in compose.py → apply_key_tape in the kernel.
    # validate_layer_for_kind is called first so all 9 DSL rules are enforced
    # on the production path (not test-only).
    "key_tape",
})


# Alphabets the dispatcher can currently translate into kernel transforms.
# R2-2 (2026-04-21) added KA and keyword_mixed; before that the dispatcher
# was AZ-only. Kept in sync with _resolve_alphabet_sequence(); extending
# this set requires (a) adding a branch there and (b) updating this
# frozenset.
_SUPPORTED_ALPHABETS: frozenset[str] = frozenset({
    "AZ",
    "KA",
    "keyword_mixed",
})


def _kind_has_translation(kind: str) -> bool:
    return kind in _SUPPORTED_KINDS


# ─── Procedural expansion (R3-0.5-1) ─────────────────────────────────────────

def _load_recipes_by_id(path: Optional[Path] = None) -> dict[str, Any]:
    """Return a ``{recipe_id: ProceduralRecipe}`` mapping from the catalogue.

    Thin wrapper over ``procedural_enumerator.load_recipes`` to provide
    O(1) lookup by ``recipe_id``. Not memoized — callers in the happy
    path build it once per ``execute()`` invocation. Tests can override
    ``path`` to supply a fixture catalogue.
    """
    from .procedural_enumerator import load_recipes
    return {r.recipe_id: r for r in load_recipes(path=path)}


def _expand_procedural_layers(
    spec: HypothesisSpec,
    recipes_by_id: Optional[dict[str, Any]] = None,
) -> HypothesisSpec:
    """Replace every ``kind='procedural'`` layer with its recipe template pipeline.

    A procedural layer carries a ``recipe_id`` pointing at
    ``docs/procedural_recipes.json``. The recipe's ``dsl_template``
    already describes a complete HypothesisSpec (see
    ``procedural_enumerator.recipe_to_spec``). Expansion replaces the
    placeholder layer with the template's own pipeline layers in-place,
    so downstream enumeration and translation see only primitive cipher
    kinds.

    Expansion runs BEFORE admissibility and BEFORE ``_enumerate_bindings``
    so the expanded spec's ``expected_cardinality`` reflects the real
    parameter universe — a recipe carrying a 5-keyword param sweep
    contributes 5 configs, not 1.

    Raises ``DispatcherError`` when:
      - ``recipe_id`` is missing or empty
      - ``recipe_id`` is not in the catalogue
      - the recipe is ``physical_only`` (no DSL realization)
      - ``recipe_to_spec`` returns None (malformed ``dsl_template``)

    Specs without any procedural layer are returned unchanged (identity
    short-circuit). Specs with at least one procedural layer return a
    new ``HypothesisSpec`` whose pipeline reflects the expansion; other
    fields are preserved verbatim so the spec_hash path downstream still
    sees the theorist's originally-declared scoring, null_baseline, etc.
    """
    if not any(layer.kind == "procedural" for layer in spec.pipeline):
        return spec

    from .procedural_enumerator import recipe_to_spec

    if recipes_by_id is None:
        recipes_by_id = _load_recipes_by_id()

    new_pipeline: list[CipherLayer] = []
    for i, layer in enumerate(spec.pipeline):
        if layer.kind != "procedural":
            new_pipeline.append(layer)
            continue

        recipe_id = layer.recipe_id
        if not recipe_id:
            raise DispatcherError(
                f"pipeline[{i}]: procedural layer requires recipe_id"
            )
        if recipe_id not in recipes_by_id:
            available = sorted(recipes_by_id)
            preview = ", ".join(available[:10])
            more = (
                "" if len(available) <= 10
                else f" (+{len(available) - 10} more)"
            )
            raise DispatcherError(
                f"pipeline[{i}]: recipe_id {recipe_id!r} not in "
                f"procedural_recipes.json catalogue; "
                f"available: [{preview}]{more}"
            )
        recipe = recipes_by_id[recipe_id]
        if getattr(recipe, "physical_only", False):
            raise DispatcherError(
                f"pipeline[{i}]: recipe {recipe_id} is physical_only; "
                "no DSL realization (physical-procedure-only recipes "
                "are filtered by the enumerator)"
            )
        template_spec = recipe_to_spec(recipe)
        if template_spec is None:
            raise DispatcherError(
                f"pipeline[{i}]: recipe {recipe_id} produced no valid "
                "HypothesisSpec (dsl_template missing or malformed); "
                "see kryptosbot.procedural_enumerator.recipe_to_spec"
            )
        # The template's pipeline layers replace this one. A multi-layer
        # template expands to multiple primitive layers; a single-layer
        # template contributes exactly one primitive layer.
        new_pipeline.extend(template_spec.pipeline)

    expanded = HypothesisSpec(
        hypothesis_id=spec.hypothesis_id,
        pipeline=new_pipeline,
        crib_alignment=spec.crib_alignment,
        scoring=spec.scoring,
        null_baseline=spec.null_baseline,
        information_gain_bits_estimate=spec.information_gain_bits_estimate,
        success_criteria=dict(spec.success_criteria),
        kill_criteria=dict(spec.kill_criteria),
        compute_budget_cpu_minutes=spec.compute_budget_cpu_minutes,
        checkpoint_every_sec=spec.checkpoint_every_sec,
        assumption_bundle=list(spec.assumption_bundle),
        notes=spec.notes,
        override_exhaustion=spec.override_exhaustion,
        override_justification=spec.override_justification,
    )
    return expanded


def _resolve_alphabet_sequence(
    alphabet: str,
    binding: dict[str, Any],
) -> Optional[str]:
    """Resolve the 26-char alphabet sequence for a layer.

    Returns None for alphabet="AZ" (the default; compose.py's VIGENERE
    path uses its AZ fast path). Returns a 26-char string for "KA" or
    "keyword_mixed". Raises DispatcherError if the binding is incomplete
    for "keyword_mixed".

    R2-2 (2026-04-21): added KA and keyword_mixed support. Phase 4 was
    AZ-only.
    """
    if alphabet == "AZ":
        return None
    if alphabet == "KA":
        from kryptos.kernel.constants import KRYPTOS_ALPHABET
        return KRYPTOS_ALPHABET
    if alphabet == "keyword_mixed":
        alph_kw = binding.get("alphabet_keyword")
        if alph_kw is None or not isinstance(alph_kw, str) or not alph_kw:
            raise DispatcherError(
                "alphabet='keyword_mixed' requires a ParamRange named "
                f"'alphabet_keyword' with a non-empty string value; got "
                f"binding={binding}"
            )
        if not alph_kw.isalpha():
            raise DispatcherError(
                f"alphabet_keyword {alph_kw!r} must contain only A-Z letters"
            )
        from kryptos.kernel.alphabet import keyword_mixed_alphabet
        return keyword_mixed_alphabet(alph_kw.upper())
    raise DispatcherError(
        f"alphabet {alphabet!r} not supported; expected one of "
        "'AZ' | 'KA' | 'keyword_mixed'"
    )


def _keyword_to_key_ints(
    keyword: str,
    alphabet: str,
    alphabet_sequence: Optional[str] = None,
) -> list[int]:
    """Convert a keyword string into a list of key indices.

    For alphabet='AZ' this is `[ord(c) - 65 for c in keyword]`. For
    alphabet='KA' or 'keyword_mixed' the indices are positions within the
    ALPHABET'S OWN ORDERING — e.g., 'K' in KRYPTOS-alphabet has index 0,
    not ord('K')-65 = 10. R2-2 added this path; Phase 4 was AZ-only.
    """
    keyword = keyword.strip().upper()
    if not keyword.isalpha():
        raise DispatcherError(
            f"keyword {keyword!r} must contain only A-Z letters"
        )
    if alphabet == "AZ":
        return [ord(c) - 65 for c in keyword]
    if alphabet not in ("KA", "keyword_mixed"):
        raise DispatcherError(
            f"alphabet {alphabet!r} not supported; expected one of "
            "'AZ' | 'KA' | 'keyword_mixed'"
        )
    if alphabet_sequence is None:
        raise DispatcherError(
            f"alphabet={alphabet!r} requires alphabet_sequence — "
            "caller must resolve via _resolve_alphabet_sequence first"
        )
    # Build lookup: ord(c) - 65 -> position in alphabet_sequence.
    idx_table = [0] * 26
    for i, ch in enumerate(alphabet_sequence):
        idx_table[ord(ch) - 65] = i
    return [idx_table[ord(c) - 65] for c in keyword]


def _translation_text_length(text_length: Optional[int]) -> int:
    """Return the active text length for permutation-producing translators."""
    if text_length is None:
        from kryptos.kernel.constants import CT_LEN
        return CT_LEN
    if not isinstance(text_length, int) or isinstance(text_length, bool) or text_length <= 0:
        raise DispatcherError(f"text_length must be a positive int; got {text_length!r}")
    return text_length


def _build_pipeline_config(
    spec: HypothesisSpec,
    bindings: tuple[tuple[str, Any], ...],
    *,
    text_length: Optional[int] = None,
) -> dict[str, Any]:
    """Translate one parameter binding across the pipeline into a
    serializable PipelineConfig dict.

    ``bindings`` is a tuple of (flat_key, value) pairs where flat_key is
    of form ``"layerN.paramname"``. The function collates bindings back
    to per-layer param dicts and emits a dict that the worker function
    can feed into the kernel's ``build_pipeline``.
    """
    # Lazy import so admissibility checks don't trigger kernel import at
    # module load time.
    from kryptos.kernel.transforms.compose import TransformType

    per_layer: dict[int, dict[str, Any]] = {}
    for flat_key, value in bindings:
        layer_idx_str, param_name = flat_key.split(".", 1)
        layer_idx = int(layer_idx_str[len("layer"):])
        per_layer.setdefault(layer_idx, {})[param_name] = value

    steps: list[dict[str, Any]] = []
    for i, layer in enumerate(spec.pipeline):
        binding = per_layer.get(i, {})
        step = _translate_layer(layer, binding, text_length=text_length)
        steps.append(step)

    return {
        "name": f"{spec.hypothesis_id}_spec_{spec.spec_hash}",
        "direction": "decrypt",
        "steps": steps,
    }


def _translate_layer(
    layer: CipherLayer,
    binding: dict[str, Any],
    *,
    text_length: Optional[int] = None,
) -> dict[str, Any]:
    """Translate one CipherLayer + its param binding into a
    serializable TransformConfig dict (dict form because multiprocessing
    needs pickleable step lists).

    Raises ``DispatcherError`` on unsupported kinds.
    """
    kind = layer.kind
    CT_LEN = _translation_text_length(text_length)
    if kind == "identity":
        return {"type": "identity", "params": {}}

    if kind in ("vigenere", "beaufort", "variant_beaufort"):
        keyword = binding.get("keyword")
        if keyword is None or not isinstance(keyword, str):
            raise DispatcherError(
                f"{kind} layer requires a 'keyword' parameter (str); "
                f"got binding={binding}"
            )
        # R2-2: resolve alphabet sequence first (None for AZ; 26-char str
        # for KA/keyword_mixed). The key must then be indexed in that
        # same alphabet.
        alph_seq = _resolve_alphabet_sequence(layer.alphabet, binding)
        key = _keyword_to_key_ints(keyword, layer.alphabet, alph_seq)
        tt_map = {
            "vigenere": "vigenere",
            "beaufort": "beaufort",
            "variant_beaufort": "var_beaufort",
        }
        params: dict[str, Any] = {
            "key": key,
            "direction": "decrypt",
        }
        if alph_seq is not None:
            params["alphabet_sequence"] = alph_seq
            params["alphabet_label"] = layer.alphabet
        return {
            "type": tt_map[kind],
            "params": params,
        }

    if kind == "columnar":
        width = binding.get("width")
        if width is None or not isinstance(width, int) or width < 2:
            raise DispatcherError(
                f"columnar layer requires int 'width' >= 2; got {width!r}"
            )
        # Phase 4 supports a single pre-enumerated permutation via 'col_order';
        # callers that want to sweep permutations enumerate those as values
        # in the ParamRange.
        col_order = binding.get("col_order")
        if col_order is None or not isinstance(col_order, (list, tuple)):
            raise DispatcherError(
                f"columnar layer requires 'col_order' (list[int]); got {col_order!r}"
            )
        if sorted(col_order) != list(range(width)):
            raise DispatcherError(
                f"columnar col_order {col_order} is not a permutation of [0, {width})"
            )
        # Build the full-text columnar permutation via the kernel helper.
        from kryptos.kernel.transforms.transposition import columnar_perm
        perm = columnar_perm(width, list(col_order), CT_LEN)
        return {
            "type": "transposition_full",
            "params": {
                "perm": list(perm),
                "direction": "undo",
            },
        }

    if kind == "caesar":
        # 2026-04-28 (LESSON-009): canonical Caesar / ROT-N. The
        # translator emits a Vigenere transform with a single-element
        # key [shift], so the kernel arithmetic is exactly the Caesar
        # decrypt formula P = (C - shift) mod 26. The first-class
        # kind keeps coverage_vector and attempt artifact layers
        # explicit so a downstream consumer can distinguish a
        # Caesar(shift=8) seed from a 1-letter Vigenere(I) seed even
        # though the kernel-level math is identical.
        shift = binding.get("shift")
        if not isinstance(shift, int) or not 0 <= shift <= 25:
            raise DispatcherError(
                f"caesar layer requires int 'shift' in [0, 25]; "
                f"got {shift!r}"
            )
        # 2026-04-28: canonical AZ alphabet only — Caesar is an
        # additive shift over the canonical 26-letter alphabet by
        # definition. A non-AZ alphabet would no longer be a Caesar
        # cipher (it would be a 1-letter Vigenere over a different
        # alphabet) and would mislead telemetry.
        if layer.alphabet != "AZ":
            raise DispatcherError(
                f"caesar layer requires alphabet='AZ'; got "
                f"{layer.alphabet!r}. A non-AZ alphabet collapses "
                "the operation to a 1-letter Vigenere over a "
                "different tableau and is not a Caesar cipher."
            )
        return {
            "type": "vigenere",
            "params": {
                "key": [shift],
                "direction": "decrypt",
            },
        }

    if kind == "atbash":
        # Atbash is self-inverse and parameter-free; treat as additive mask
        # with synthetic key. The kernel doesn't have a first-class atbash
        # transform, so wire via a small custom translation layer: compute
        # the Atbash as Beaufort with key = [25]*97 over AZ, which gives
        # C = (25 - P) mod 26.
        return {
            "type": "beaufort",
            "params": {
                "key": [25],
                "direction": "decrypt",
            },
        }

    if kind == "polybius":
        # R3-0.5-3: polybius-family translator. Dispatches to the
        # existing TransformType.BIFID in compose.py, which owns the
        # make_polybius_5x5 grid construction and bifid_encrypt/decrypt
        # (length-preserving fractionation). Straight polybius — the
        # length-doubling letter→coord encoding — has no TransformType
        # yet and is deferred. Translator rejects variant="polybius"
        # with a clear pointer.
        #
        # Note on K4 applicability: a 5x5 Polybius square forces a
        # 25-letter alphabet (I/J merged by default). K4 CT contains all
        # 26 letters (CLAUDE.md §Gotchas), so this translator is only
        # useful as a layer in multi-layer specs whose prior layers
        # already reduced the text to 25 letters. Single-layer dispatch
        # on raw K4 CT is admissible but will always score as noise
        # because the kernel decodes via I-only lookup when no J is
        # present; a J in input passes through unchanged, breaking the
        # 5x5 invariant. That noise floor is the expected behaviour, not
        # a bug.
        keyword = binding.get("square_keyword")
        if keyword is None:
            raise DispatcherError(
                "polybius layer requires 'square_keyword' parameter "
                "(empty string for canonical A-Z ordering; any keyword "
                "string builds a keyword-prefixed square)"
            )
        if not isinstance(keyword, str):
            raise DispatcherError(
                f"polybius square_keyword must be str; "
                f"got {type(keyword).__name__}"
            )
        variant = binding.get("variant", "bifid")
        if variant != "bifid":
            if variant == "polybius":
                raise DispatcherError(
                    "polybius layer variant='polybius' (straight, "
                    "length-doubling) is deferred to a later brief. "
                    "R3-0.5-3 supports variant='bifid' (length-preserving "
                    "fractionation) only."
                )
            raise DispatcherError(
                f"polybius variant {variant!r} unsupported; "
                "valid: 'bifid'"
            )
        merge = binding.get("merge", "IJ")
        if not isinstance(merge, str) or len(merge) != 2:
            raise DispatcherError(
                f"polybius merge {merge!r} must be a 2-char string; "
                "canonical values: 'IJ' (default), 'CK', 'VW'"
            )
        direction = binding.get("direction", "decrypt")
        if direction not in ("encrypt", "decrypt"):
            raise DispatcherError(
                f"polybius direction {direction!r} must be "
                "'encrypt' or 'decrypt'"
            )
        period = binding.get("period", 0)
        if not isinstance(period, int) or isinstance(period, bool) or period < 0:
            raise DispatcherError(
                f"polybius period {period!r} must be a non-negative int "
                "(0 = full-length classical bifid)"
            )
        return {
            "type": "bifid",
            "params": {
                "keyword": keyword,
                "merge": merge,
                "period": period,
                "direction": direction,
            },
        }

    if kind == "grille":
        # R3-0.5-2: Cardano-grille gather. Binding must carry a
        # "hole_mask" parameter whose value is a length-CT_LEN
        # permutation of range(CT_LEN). Mask validation runs here (not
        # in the kernel hot path) per the kernel's "validate once, apply
        # many" convention. Turning grilles, partial grilles, and mask
        # discovery from anomalies are explicitly out of R3-0.5-2 scope.
        mask_raw = binding.get("hole_mask")
        if mask_raw is None:
            raise DispatcherError(
                "grille layer requires 'hole_mask' parameter "
                "(a length-CT_LEN list of distinct 0-indexed positions)"
            )
        if not isinstance(mask_raw, (list, tuple)):
            raise DispatcherError(
                f"grille hole_mask must be list/tuple; "
                f"got {type(mask_raw).__name__}"
            )
        from kryptos.kernel.transforms.grille import validate_grille_mask
        errors = validate_grille_mask(mask_raw, CT_LEN)
        if errors:
            raise DispatcherError(
                f"grille hole_mask invalid: {'; '.join(errors)}"
            )
        return {
            "type": "grille",
            "params": {
                "mask_order": list(mask_raw),
            },
        }

    if kind == "rail_fence":
        # B-DSL-expanded (2026-04-22): rail-fence (zigzag) transposition.
        # Kernel primitive: rail_fence_perm(length, depth). Depth must be
        # in [2, length/2]; depths of 1 or ≥length are no-ops.
        depth = binding.get("depth")
        if depth is None or not isinstance(depth, int) or depth < 2:
            raise DispatcherError(
                f"rail_fence layer requires int 'depth' >= 2; got {depth!r}"
            )
        from kryptos.kernel.transforms.transposition import rail_fence_perm
        if depth >= CT_LEN:
            raise DispatcherError(
                f"rail_fence depth {depth} must be < CT_LEN={CT_LEN} "
                "(otherwise the permutation is identity)"
            )
        perm = rail_fence_perm(CT_LEN, depth)
        return {
            "type": "transposition_full",
            "params": {
                "perm": list(perm),
                "direction": "undo",
            },
        }

    if kind == "myszkowski":
        # B-DSL-expanded (2026-04-22): Myszkowski transposition — the
        # columnar variant where repeated keyword letters produce tied
        # columns that are read row-by-row. Kernel primitive:
        # myszkowski_perm(keyword, length).
        keyword = binding.get("keyword")
        if keyword is None or not isinstance(keyword, str) or len(keyword) < 2:
            raise DispatcherError(
                f"myszkowski layer requires str 'keyword' with len >= 2; "
                f"got {keyword!r}"
            )
        from kryptos.kernel.transforms.transposition import myszkowski_perm
        perm = myszkowski_perm(keyword.upper(), CT_LEN)
        return {
            "type": "transposition_full",
            "params": {
                "perm": list(perm),
                "direction": "undo",
            },
        }

    if kind == "route":
        # B-DSL-expanded (2026-04-22): route transposition wrapper.
        # Variant selects the read pattern over an implied rows×cols
        # grid filled row-by-row. Currently supports:
        #   variant="serpentine" — boustrophedon (alternating row/col
        #                           direction). Takes optional 'vertical' bool.
        #                           NOTE: Sanborn's AAA archive (Page 17,
        #                           UAN AAA-AAA_sanbojim_4129080) describes
        #                           Kryptos as "a serpentine copper screen
        #                           ... with Blaise De Vigenère's Tableaux"
        #                           — this variant is the natural anchor
        #                           for any serpentine-Vigenère hypothesis.
        #   variant="spiral"      — outside-in spiral. Takes optional
        #                           'clockwise' bool and 'start_corner'
        #                           ("top_left" default, "top_right",
        #                           "bottom_right", "bottom_left").
        #   variant="diagonal"    — LESSON-016: diagonal grid-route.
        #                           Takes axis ("main"|"anti"),
        #                           order ("forward"|"reverse"),
        #                           start_edge (axis-constrained).
        # All three kernel primitives (serpentine_perm, spiral_perm,
        # diagonal_perm) trim positions beyond `length` so rows*cols
        # may exceed CT_LEN (ragged grids).
        variant = binding.get("variant")
        if variant not in (
            "serpentine", "spiral", "diagonal", "diagonal_canonical",
        ):
            raise DispatcherError(
                f"route layer requires variant in "
                f"{{'serpentine', 'spiral', 'diagonal', "
                f"'diagonal_canonical'}}; got {variant!r}"
            )
        # LESSON-021: variant="diagonal_canonical" is a width-only
        # alias. Width is the only required cipher-semantic parameter;
        # rows/cols are inferred from width and CT_LEN. Translation
        # branches early so the rows/cols validation below applies
        # only to the row-major variants.
        if variant == "diagonal_canonical":
            width = binding.get("width")
            if not (isinstance(width, int) and width >= 1):
                raise DispatcherError(
                    f"route variant='diagonal_canonical' requires "
                    f"int 'width' >= 1; got {width!r}"
                )
            from kryptos.kernel.transforms.transposition import (
                canonical_diagonal_perm,
            )
            perm = canonical_diagonal_perm(width, CT_LEN)
            if len(perm) != CT_LEN:
                raise DispatcherError(
                    f"diagonal_canonical route translator produced "
                    f"perm of length {len(perm)} (expected {CT_LEN}); "
                    f"width={width}. This indicates a kernel "
                    f"primitive contract drift and is not safe to "
                    "dispatch."
                )
            return {
                "type": "transposition_full",
                "params": {
                    "perm": list(perm),
                    "direction": "undo",
                },
            }
        rows = binding.get("rows")
        cols = binding.get("cols")
        if not (isinstance(rows, int) and rows >= 1):
            raise DispatcherError(
                f"route layer requires int 'rows' >= 1; got {rows!r}"
            )
        if not (isinstance(cols, int) and cols >= 1):
            raise DispatcherError(
                f"route layer requires int 'cols' >= 1; got {cols!r}"
            )
        if rows * cols < CT_LEN:
            raise DispatcherError(
                f"route layer rows*cols={rows * cols} must be >= CT_LEN={CT_LEN} "
                "to cover every position"
            )
        if variant == "serpentine":
            from kryptos.kernel.transforms.transposition import serpentine_perm
            vertical = bool(binding.get("vertical", False))
            perm = serpentine_perm(rows, cols, CT_LEN, vertical=vertical)
        elif variant == "spiral":
            from kryptos.kernel.transforms.transposition import spiral_perm
            clockwise = bool(binding.get("clockwise", True))
            start_corner = binding.get("start_corner", "top_left")
            if start_corner not in (
                "top_left", "top_right", "bottom_right", "bottom_left",
            ):
                raise DispatcherError(
                    f"route variant='spiral' requires start_corner in "
                    f"{{'top_left', 'top_right', 'bottom_right', "
                    f"'bottom_left'}}; got {start_corner!r}"
                )
            perm = spiral_perm(
                rows,
                cols,
                CT_LEN,
                clockwise=clockwise,
                start_corner=start_corner,
            )
        else:  # variant == "diagonal" — LESSON-016 / LESSON-020
            # Validate axis / order / start_edge / cell_order with
            # explicit whitelists. Fail closed: unknown values raise
            # DispatcherError, NEVER silently default.
            axis = binding.get("diagonal_axis")
            order = binding.get("diagonal_order")
            start_edge = binding.get("diagonal_start_edge")
            # LESSON-020: optional within-diagonal cell ordering.
            # Defaults to "forward" so pre-LESSON-020 specs that omit
            # the field continue to dispatch with identical kernel
            # behavior.
            cell_order = binding.get("diagonal_cell_order", "forward")
            if axis not in ("main", "anti"):
                raise DispatcherError(
                    f"route variant='diagonal' requires "
                    f"diagonal_axis in {{'main', 'anti'}}; "
                    f"got {axis!r}"
                )
            if order not in ("forward", "reverse"):
                raise DispatcherError(
                    f"route variant='diagonal' requires "
                    f"diagonal_order in {{'forward', 'reverse'}}; "
                    f"got {order!r}"
                )
            valid_start = {
                "main": ("top_then_left", "left_then_top"),
                "anti": ("top_then_right", "right_then_top"),
            }
            if start_edge not in valid_start[axis]:
                raise DispatcherError(
                    f"route variant='diagonal' axis={axis!r} "
                    f"requires diagonal_start_edge in "
                    f"{valid_start[axis]}; got {start_edge!r}"
                )
            if cell_order not in ("forward", "reverse", "alternate"):
                raise DispatcherError(
                    f"route variant='diagonal' requires "
                    f"diagonal_cell_order in "
                    f"{{'forward', 'reverse', 'alternate'}}; "
                    f"got {cell_order!r}"
                )
            from kryptos.kernel.transforms.transposition import diagonal_perm
            perm = diagonal_perm(
                rows, cols, CT_LEN,
                axis=axis, order=order, start_edge=start_edge,
                cell_order=cell_order,
            )
            if len(perm) != CT_LEN:
                raise DispatcherError(
                    f"diagonal route translator produced perm of length "
                    f"{len(perm)} (expected {CT_LEN}); rows={rows}, "
                    f"cols={cols}, axis={axis}, order={order}, "
                    f"start_edge={start_edge}, cell_order={cell_order}. "
                    "This indicates a kernel primitive contract drift "
                    "and is not safe to dispatch."
                )
        return {
            "type": "transposition_full",
            "params": {
                "perm": list(perm),
                "direction": "undo",
            },
        }

    if kind == "reverse_blocks":
        # 2026-04-28 (LESSON-008): fixed-size in-block reversal. The
        # ciphertext is conceptually divided into consecutive blocks
        # of size ``block_size``; each block is then reversed in
        # place. The operation is its own inverse, so the same perm
        # serves encryption and decryption (we emit it with
        # direction="undo" to match the rest of the dispatcher's
        # transposition convention).
        #
        # Two block_mode values:
        #   "reverse_partial" — every block including the trailing
        #                       partial block is reversed (default).
        #   "truncate"        — only complete blocks are reversed;
        #                       the trailing tail is identity.
        block_size = binding.get("block_size")
        if not isinstance(block_size, int) or block_size < 2:
            raise DispatcherError(
                f"reverse_blocks layer requires int 'block_size' >= 2; "
                f"got {block_size!r}"
            )
        block_mode = binding.get("block_mode", "reverse_partial")
        if block_mode not in ("reverse_partial", "truncate"):
            raise DispatcherError(
                f"reverse_blocks layer requires block_mode in "
                f"{{'reverse_partial', 'truncate'}}; got {block_mode!r}"
            )
        if block_size > CT_LEN:
            raise DispatcherError(
                f"reverse_blocks block_size={block_size} exceeds "
                f"CT_LEN={CT_LEN}; the permutation would be identity"
            )
        perm = list(range(CT_LEN))
        if block_mode == "reverse_partial":
            # Reverse every block, including a trailing partial one.
            for start in range(0, CT_LEN, block_size):
                end = min(start + block_size, CT_LEN)
                # output[i] = input[perm[i]]; reversed block of width
                # w spans positions [start, end). After reversal the
                # input position at output index start+k is
                # start + (w-1-k).
                w = end - start
                for k in range(w):
                    perm[start + k] = start + (w - 1 - k)
        else:  # truncate
            full_blocks = CT_LEN // block_size
            for b in range(full_blocks):
                start = b * block_size
                for k in range(block_size):
                    perm[start + k] = start + (block_size - 1 - k)
            # Tail (positions full_blocks*block_size .. CT_LEN-1) is
            # left as identity by the initial range(CT_LEN) seed.
        return {
            "type": "transposition_full",
            "params": {
                "perm": perm,
                "direction": "undo",
            },
        }

    if kind == "skip_route":
        # 2026-04-28 (LESSON-011): modular skip / step / stride route.
        # Decryption convention:
        #     output[i] = input[(offset + i*step) mod CT_LEN]
        # i.e. walking through the input every ``step`` positions
        # starting at ``offset`` reads the plaintext in order. The
        # kernel's transposition_full with direction="undo" computes
        # ``inv = invert_perm(perm)`` and applies ``output[i] =
        # input[inv[i]]``, so we emit ``perm`` = the INVERSE of the
        # decryption map: ``perm[j] = ((j - offset) * step_inv) mod
        # CT_LEN`` where step_inv is the modular inverse of step
        # mod CT_LEN. This way the kernel inverts our ``perm`` back
        # to the desired ``inv[i] = (offset + i*step) mod CT_LEN``
        # and applies it.
        #
        # Length-preserving and deterministic. Coprimality of step
        # and CT_LEN is required so the walk visits every position
        # exactly once AND so the modular inverse exists. The
        # translator rejects non-coprime steps with an explicit
        # error.
        step = binding.get("step")
        offset = binding.get("offset")
        if not isinstance(step, int):
            raise DispatcherError(
                f"skip_route layer requires int 'step'; got {step!r}"
            )
        if not isinstance(offset, int):
            raise DispatcherError(
                f"skip_route layer requires int 'offset'; got {offset!r}"
            )
        if not 1 <= step < CT_LEN:
            raise DispatcherError(
                f"skip_route step={step} must be in "
                f"[1, {CT_LEN - 1}]"
            )
        if not 0 <= offset < CT_LEN:
            raise DispatcherError(
                f"skip_route offset={offset} must be in "
                f"[0, {CT_LEN - 1}]"
            )
        import math as _math
        g = _math.gcd(step, CT_LEN)
        if g != 1:
            raise DispatcherError(
                f"skip_route step={step} is not coprime with "
                f"CT_LEN={CT_LEN} (gcd={g}); the modular walk would "
                "skip positions and the modular inverse of step "
                "would not exist. Pick a step coprime to "
                f"{CT_LEN}."
            )
        # Modular inverse of step mod CT_LEN via extended Euclidean.
        step_inv = pow(step, -1, CT_LEN)
        perm = [
            ((j - offset) * step_inv) % CT_LEN for j in range(CT_LEN)
        ]
        return {
            "type": "transposition_full",
            "params": {
                "perm": perm,
                "direction": "undo",
            },
        }

    if kind == "route_boustrophedon":
        # 2026-04-28 (LESSON-014): width-only ragged boustrophedon
        # (serpentine) route. Distinct from the existing ``route``
        # kind: that kind requires explicit rows AND cols with
        # rows*cols >= CT_LEN; this kind takes ``width`` only and
        # implies rows = ceil(CT_LEN / width). The final row (or
        # column, if vertical) may be short — this is the "ragged"
        # contract. The kernel primitive ``serpentine_perm`` already
        # trims positions ``pos < length`` so out-of-bounds cells
        # in the trailing partial row never enter the permutation.
        #
        # Length-preserving: the emitted permutation has exactly
        # CT_LEN entries and is a bijection of [0, CT_LEN). Verified
        # by every (width, vertical) pair the LESSON-014 generator
        # emits (see test_lesson_route_boustrophedon_capability.py).
        #
        # Direction conventions:
        #   vertical=False — fill row-major, read alternating
        #                    row direction (left-to-right,
        #                    right-to-left, ...). This is the
        #                    "horizontal serpentine" reading.
        #   vertical=True  — fill row-major, read alternating
        #                    column direction (top-down, bottom-
        #                    up, ...). Matches clue language like
        #                    "arrows down, up, down, up".
        width = binding.get("width")
        if not isinstance(width, int):
            raise DispatcherError(
                f"route_boustrophedon layer requires int 'width'; "
                f"got {width!r}"
            )
        if not 2 <= width < CT_LEN:
            raise DispatcherError(
                f"route_boustrophedon width={width} must be in "
                f"[2, {CT_LEN - 1}]; width=1 is identity and width "
                f">= CT_LEN is degenerate (no row alternation)"
            )
        vertical = bool(binding.get("vertical", False))
        rows = (CT_LEN + width - 1) // width  # ceil(CT_LEN / width)
        from kryptos.kernel.transforms.transposition import serpentine_perm
        perm = serpentine_perm(rows, width, CT_LEN, vertical=vertical)
        # Length-preservation invariant. Any drift here means the
        # kernel primitive's trimming contract changed and we must
        # update LESSON-014 alongside.
        if len(perm) != CT_LEN:
            raise DispatcherError(
                f"route_boustrophedon translator produced perm of "
                f"length {len(perm)} (expected {CT_LEN}); width="
                f"{width}, rows={rows}, vertical={vertical}. "
                "This indicates a kernel primitive contract drift "
                "and is not safe to dispatch."
            )
        return {
            "type": "transposition_full",
            "params": {
                "perm": list(perm),
                "direction": "undo",
            },
        }

    if kind == "row_reverse":
        # 2026-04-28 (LESSON-015): folded-strip / alternate-row
        # reversal. The text is split into rows of width ``width``
        # (final row may be short — ragged). Rows whose 0-indexed
        # row-index is selected by ``parity`` are reversed in
        # place; other rows are kept verbatim. The whole thing is
        # length-preserving by construction.
        #
        # SELF-INVERSE invariant: row_reverse(row_reverse(x)) == x
        # under the same (width, parity, start_row) parameters.
        # The kernel applies direction='undo' which inverts the
        # supplied perm before applying. For an involutive perm
        # (inv == perm), undo is identical to do, so emitting
        # direction='undo' here is equivalent to direction='do'
        # — we keep 'undo' for symmetry with every other
        # transposition kind in this dispatcher.
        #
        # Width=CT_LEN with parity=odd is the "no-fold" identity
        # case (only row 0 exists; row 0 is even; parity=odd
        # selects no rows). This is intentionally reachable so
        # the LESSON-015 enumeration can express
        # "substitution-alone-equivalent" without adding a
        # separate substitution-alone family — keeping the
        # generalized capability surface small.
        width = binding.get("width")
        parity = binding.get("parity", "odd")
        start_row = binding.get("start_row", 0)
        if not isinstance(width, int):
            raise DispatcherError(
                f"row_reverse layer requires int 'width'; got {width!r}"
            )
        if not 2 <= width <= CT_LEN:
            raise DispatcherError(
                f"row_reverse width={width} must be in [2, {CT_LEN}]; "
                "width=1 reverses every single character (identity), "
                "width > CT_LEN has no row partition."
            )
        if parity not in ("odd", "even", "both"):
            raise DispatcherError(
                f"row_reverse parity {parity!r} must be in "
                "{'odd', 'even', 'both'}"
            )
        if not isinstance(start_row, int) or start_row not in (0, 1):
            raise DispatcherError(
                f"row_reverse start_row {start_row!r} must be 0 or 1"
            )
        # Build the in-place perm: rows that are reversed are
        # mirrored about their row's center; rows that are kept
        # map to themselves. The trailing partial row is reversed
        # in place when its row-index matches the parity selector.
        perm = list(range(CT_LEN))
        for row_idx, start in enumerate(range(0, CT_LEN, width)):
            end = min(start + width, CT_LEN)
            row_len = end - start
            # Apply start_row offset BEFORE the parity test so
            # start_row=1 effectively flips the parity selector.
            effective_idx = row_idx - start_row
            if parity == "both":
                reverse = True
            elif parity == "odd":
                reverse = (effective_idx % 2) == 1
            else:  # parity == "even"
                reverse = (effective_idx % 2) == 0
            if reverse:
                # Output position start+k receives the input character
                # at start + (row_len - 1 - k). This is the in-place
                # row reversal — same convention as reverse_blocks
                # (LESSON-008) at the row-block level.
                for k in range(row_len):
                    perm[start + k] = start + (row_len - 1 - k)
            # else: identity (already initialised by range(CT_LEN))
        # Length-preservation invariant.
        if len(perm) != CT_LEN:
            raise DispatcherError(
                f"row_reverse translator produced perm of length "
                f"{len(perm)} (expected {CT_LEN}); width={width}, "
                f"parity={parity}, start_row={start_row}. This "
                "indicates a partition bug and is not safe to "
                "dispatch."
            )
        # Self-inverse invariant. perm[perm[i]] == i for every i.
        # We only assert in debug-friendly form; a violation would
        # indicate the loop above corrupted the perm.
        for i in range(CT_LEN):
            if perm[perm[i]] != i:
                raise DispatcherError(
                    f"row_reverse translator violated self-inverse "
                    f"invariant at i={i} (width={width}, parity="
                    f"{parity}, start_row={start_row}). Refusing to "
                    "dispatch."
                )
        return {
            "type": "transposition_full",
            "params": {
                "perm": perm,
                "direction": "undo",
            },
        }

    if kind == "quagmire":
        # B-DSL-expanded (2026-04-22): straight Quagmire III / IV via the
        # kernel's quagmire_encrypt / quagmire_decrypt. This translator
        # enforces the K1/K2 calling convention the kernel documented
        # (see src/kryptos/kernel/transforms/quagmire.py §"K1/K2
        # CALLING CONVENTION"): pt_alphabet_keyword AND
        # ct_alphabet_keyword must both be set for a proper Quagmire III
        # run; indicator must be a single letter present in the CT
        # alphabet.
        #
        # Rejecting under-specified bindings is deliberate. The
        # f_w10_quagmire_iii_v1 campaign (project memo from 2026-04-21)
        # was misconfigured with only ct_alphabet_keyword set and
        # silently ran a different mechanism that could not reproduce
        # K2. A regression here protects future theories from the same
        # footgun.
        period_keyword = binding.get("period_keyword")
        if not (isinstance(period_keyword, str) and len(period_keyword) >= 1):
            raise DispatcherError(
                f"quagmire layer requires non-empty str 'period_keyword'; "
                f"got {period_keyword!r}"
            )
        ct_kw = binding.get("ct_alphabet_keyword")
        pt_kw = binding.get("pt_alphabet_keyword")
        variant = binding.get("variant", "quagmire_iii")
        if variant not in ("quagmire_iii", "quagmire_iv"):
            raise DispatcherError(
                f"quagmire layer variant {variant!r} unsupported; "
                "valid: 'quagmire_iii' (same keyword on PT and CT), "
                "'quagmire_iv' (different keywords on PT and CT)"
            )
        # Quagmire III requires both keywords identical and non-empty;
        # Quagmire IV requires both non-empty but distinct.
        if not (isinstance(ct_kw, str) and len(ct_kw) >= 1):
            raise DispatcherError(
                "quagmire layer requires non-empty str "
                "'ct_alphabet_keyword'. The K1/K2 convention requires "
                "BOTH alphabet keywords; calling the kernel with only "
                "ct_alphabet_keyword set implements a different "
                "mechanism that cannot reproduce K1/K2 (see kernel "
                "docstring)."
            )
        if not (isinstance(pt_kw, str) and len(pt_kw) >= 1):
            raise DispatcherError(
                "quagmire layer requires non-empty str "
                "'pt_alphabet_keyword'. The K1/K2 convention requires "
                "BOTH alphabet keywords (see kernel docstring for why)."
            )
        if variant == "quagmire_iii" and ct_kw != pt_kw:
            raise DispatcherError(
                f"quagmire_iii requires ct_alphabet_keyword == "
                f"pt_alphabet_keyword; got {ct_kw!r} vs {pt_kw!r}. "
                f"Use variant='quagmire_iv' for different keywords."
            )
        if variant == "quagmire_iv" and ct_kw == pt_kw:
            raise DispatcherError(
                f"quagmire_iv requires distinct ct/pt alphabet keywords; "
                f"got identical {ct_kw!r}. Use variant='quagmire_iii' "
                f"for same-keyword Quagmire (the K1/K2 convention)."
            )
        indicator = binding.get("indicator")
        if not (isinstance(indicator, str) and len(indicator) == 1):
            raise DispatcherError(
                f"quagmire layer requires single-character str 'indicator'; "
                f"got {indicator!r}. For K1/K2 Quagmire III with "
                f"keyword='KRYPTOS', indicator='K' is the zero-shift row."
            )
        direction = binding.get("direction", "decrypt")
        if direction not in ("encrypt", "decrypt"):
            raise DispatcherError(
                f"quagmire direction {direction!r} must be "
                "'encrypt' or 'decrypt'"
            )
        return {
            "type": "quagmire",
            "params": {
                "period_keyword": period_keyword,
                "indicator": indicator,
                "ct_alphabet_keyword": ct_kw,
                "pt_alphabet_keyword": pt_kw,
                "direction": direction,
            },
        }

    if kind == "key_tape":
        # 2026-05-03 (key_tape DSL build Task 9): finite substitution key
        # tape with optional null positions. Parameters are resolved from
        # ``binding`` (the concrete param dict produced by the Cartesian
        # enumeration step) — NOT from layer.params, which is a list of
        # ParamRange objects. validate_layer_for_kind is called first to
        # enforce all 9 DSL rules on the production path; without this call
        # the rules are test-only.
        #
        # 2026-05-07: alphabet is a CipherLayer-level attribute, not part
        # of the enumerated binding. Fold the layer-level alphabet into a
        # local copy of the binding before validation so the validator
        # sees the same value the kernel will receive (the kernel reads
        # ``alphabet`` from the params dict at compose.py:265). Without
        # this, every real-world key_tape spec from the theorist hits
        # ``alphabet None must be 'AZ' or 'KA'`` and the worker errors
        # out before any kernel call. See
        # project_key_tape_alphabet_passthrough_fix_2026_05_07.md.
        from kryptosbot.hypothesis_dsl import (
            validate_layer_for_kind,
        )
        params = dict(binding)  # local copy; do not mutate binding
        # getattr defends against test fakes that omit the attribute
        # entirely; CipherLayer always has alphabet defaulted to "AZ".
        params.setdefault("alphabet", getattr(layer, "alphabet", "AZ"))
        errors = validate_layer_for_kind("key_tape", params)
        if errors:
            raise ValueError("; ".join(errors))

        tape = tuple(params.get("tape", ()))
        variant = params.get("variant")
        direction = params.get("direction", "decrypt")
        null_positions = frozenset(params.get("null_positions", ()))
        null_rule = params.get("null_rule")
        alphabet_kind = params.get("alphabet", "AZ")

        # All other translators wrap step-specific fields in a nested
        # ``"params"`` dict (consumed by compose.py via TransformConfig.params
        # → _build_transform step). Matching that shape here is required so
        # _evaluate_one can construct TransformConfig with params=s["params"].
        return {
            "type": "key_tape",
            "params": {
                "tape": tape,
                "variant": variant,
                "direction": direction,
                "null_positions": null_positions,
                "null_rule": null_rule if null_rule is not None else "skip",
                "alphabet": alphabet_kind,
            },
        }

    if kind == "procedural":
        # R3-0.5-1: procedural layers must be expanded in execute() before
        # translation runs. Reaching _translate_layer with a procedural
        # layer means _expand_procedural_layers was skipped — a bug worth
        # shouting about rather than silently limping.
        raise DispatcherError(
            f"procedural layer with recipe_id={layer.recipe_id!r} reached "
            "_translate_layer without being expanded. Callers must use "
            "execute() (which runs _expand_procedural_layers) rather than "
            "invoking translation directly on a spec that contains "
            "procedural layers."
        )

    raise DispatcherError(
        f"CipherLayer.kind {kind!r} has no dispatcher translation; "
        f"allowed: {sorted(_SUPPORTED_KINDS)}"
    )


# ─── Universe enumeration ────────────────────────────────────────────────────

def _enumerate_bindings(
    spec: HypothesisSpec,
) -> Iterator[tuple[tuple[str, Any], ...]]:
    """Yield every cross-layer parameter binding tuple for the spec.

    Each yielded element is a tuple of (flat_key, value) pairs covering
    every parameter on every layer. Empty-params layers contribute
    nothing. Generator form so we never materialize the full universe
    in memory.
    """
    # For each layer, build the per-param Cartesian product. Each
    # element of per_layer_choices is the list of valid bindings for
    # that layer; an empty list means the layer had no params.
    per_layer_choices: list[list[tuple[tuple[str, Any], ...]]] = []
    for i, layer in enumerate(spec.pipeline):
        if not layer.params:
            per_layer_choices.append([])
            continue
        # For each param on this layer, enumerate its values and tag
        # with the flat key.
        param_axes: list[list[tuple[str, Any]]] = []
        for p in layer.params:
            flat_key = f"layer{i}.{p.name}"
            param_axes.append([(flat_key, v) for v in p.enumerate()])
        # Cartesian product WITHIN this layer.
        layer_bindings: list[tuple[tuple[str, Any], ...]] = [
            combo for combo in itertools.product(*param_axes)
        ]
        per_layer_choices.append(layer_bindings)

    # Flatten: cartesian product ACROSS layers.
    # But per_layer_choices is list of lists of tuples; we want all tuples
    # joined into one flat tuple per combination.
    non_empty = [lst for lst in per_layer_choices if lst]
    if not non_empty:
        # All layers are param-free → single "empty" binding.
        yield ()
        return
    for combo in itertools.product(*non_empty):
        flat: list[tuple[str, Any]] = []
        for subgroup in combo:
            flat.extend(subgroup)
        yield tuple(flat)


def _config_id(spec_hash: str, bindings: tuple[tuple[str, Any], ...]) -> str:
    """Deterministic, human-readable config ID."""
    if not bindings:
        return f"{spec_hash}_identity"
    parts = [f"{k}={v}" for k, v in bindings]
    return f"{spec_hash}_" + "|".join(parts)


def _universe_hash(
    spec_hash: str,
    config_ids: list[str],
    *,
    run_context_hash: str = "",
) -> str:
    """Deterministic hash over the full tested universe.

    Folds config IDs in insertion order (they come from deterministic
    enumeration) so two runs of the same spec produce the same
    universe_hash. Used by exhaustion-log matching.
    """
    payload = json.dumps(
        {
            "spec_hash": spec_hash,
            "config_ids": sorted(config_ids),
            "run_context_hash": run_context_hash,
        },
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def _challenge_context_hash(
    ciphertext: Optional[str],
    crib_dict: Optional[dict[int, str]],
) -> str:
    """Hash challenge-only inputs so non-K4 universes do not alias real K4."""
    if ciphertext is None and crib_dict is None:
        return ""
    payload = json.dumps(
        {
            "challenge_ciphertext_sha256": hashlib.sha256((ciphertext or "").encode()).hexdigest(),
            "challenge_length": len(ciphertext or ""),
            "challenge_cribs": sorted((crib_dict or {}).items()),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


# Additive cipher variants used to infer Bean status from a candidate
# plaintext. This mirrors the contract-boundary verifier: dispatcher
# artifacts are not trusted for control flow, but they should still carry
# the kernel-verifiable Bean signal when the candidate implies one.
_BEAN_VARIANT_DERIVERS: tuple[tuple[str, Callable[[int, int], int]], ...] = (
    ("vigenere",         lambda c, p: (c - p) % 26),
    ("beaufort",         lambda c, p: (c + p) % 26),
    ("variant_beaufort", lambda c, p: (p - c) % 26),
)


def _candidate_bean_status(ct: str, pt: str) -> tuple[bool, Optional[str]]:
    """Return Bean PASS status implied by ``ct``/``pt`` under additive variants.

    The aggregate scorer intentionally does not guess the cipher variant.
    For dispatcher audit artifacts, however, a candidate plaintext plus CT
    determines a keystream under each additive convention. Accept Bean PASS
    only when the kernel constraint verifier accepts one of those exact
    keystreams.
    """
    try:
        from kryptos.kernel.constraints.bean import verify_bean_simple
        from kryptos.kernel.text import text_to_nums

        ct_nums = text_to_nums(ct)
        pt_nums = text_to_nums(pt)
        for variant_name, derive in _BEAN_VARIANT_DERIVERS:
            keystream = [derive(c, p) for c, p in zip(ct_nums, pt_nums)]
            if verify_bean_simple(keystream):
                return (True, variant_name)
    except Exception:
        logger.debug("Bean status inference failed for dispatcher candidate", exc_info=True)
    return (False, None)


def _score_known_cribs(candidate_pt: str, crib_dict: dict[int, str]) -> int:
    """Score candidate text against an explicit crib dictionary.

    This is used only for dispatcher challenge mode, where the caller
    supplies a synthetic CT and crib registry. The default real-K4 path
    still uses the canonical kernel scorer.
    """
    score = 0
    for pos, expected in crib_dict.items():
        if 0 <= pos < len(candidate_pt) and candidate_pt[pos] == expected:
            score += 1
    return score


def _validate_challenge_inputs(
    ciphertext: Optional[str],
    crib_dict: Optional[dict[int, str]],
) -> tuple[Optional[str], Optional[dict[int, str]]]:
    """Validate optional dispatcher challenge-mode inputs.

    Challenge mode supplies an arbitrary uppercase A-Z ciphertext and an
    explicit crib registry. Permutation-producing translators are parameterized
    by this ciphertext length, so non-K4 known-answer fixtures can exercise the
    same dispatcher path as real K4 candidates.
    """
    if ciphertext is None and crib_dict is None:
        return (None, None)
    if not isinstance(ciphertext, str) or not ciphertext:
        raise DispatcherError("challenge ciphertext must be a non-empty A-Z string")
    if not ciphertext.isalpha() or not ciphertext.isupper():
        raise DispatcherError("challenge ciphertext must contain uppercase A-Z letters only")
    if not isinstance(crib_dict, dict) or not crib_dict:
        raise DispatcherError("challenge crib_dict must be a non-empty dict[int, str]")
    normalized: dict[int, str] = {}
    for raw_pos, raw_ch in crib_dict.items():
        if not isinstance(raw_pos, int) or isinstance(raw_pos, bool):
            raise DispatcherError(f"challenge crib position {raw_pos!r} is not an int")
        if not 0 <= raw_pos < len(ciphertext):
            raise DispatcherError(
                f"challenge crib position {raw_pos} outside ciphertext length {len(ciphertext)}"
            )
        if not isinstance(raw_ch, str) or len(raw_ch) != 1 or raw_ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            raise DispatcherError(
                f"challenge crib at position {raw_pos} must be one uppercase A-Z character"
            )
        normalized[raw_pos] = raw_ch
    return (ciphertext, normalized)


def _matched_null_family_from_kinds(kinds: list[str]) -> str:
    """Map dispatcher pipeline kinds to a calibrated matched-null family."""
    if len(kinds) == 1:
        k = kinds[0]
        if k == "columnar":
            return "columnar_single"
        if k in ("beaufort", "variant_beaufort", "vigenere"):
            return k
        return ""
    if len(kinds) == 2 and kinds[0] == "columnar" and kinds[1] == "columnar":
        return "columnar_double"
    return ""


def _annotate_best_candidate_p_values(
    *,
    best: Optional[dict[str, Any]],
    spec: HypothesisSpec,
    n_tests: int,
    universe_hash: str,
    challenge_mode: bool,
) -> Optional[float]:
    """Populate p-value annotations on the best candidate when meaningful."""
    if best is None or challenge_mode:
        return None
    try:
        from .null_baselines import family_wise_p_value, p_value_for_alert

        family = _matched_null_family_from_kinds([layer.kind for layer in spec.pipeline])
        p, status = p_value_for_alert(
            str(best.get("candidate_pt", "")),
            int(best.get("crib_score", 0) or 0),
            family=family,
        )
        best["p_value_status"] = status
        best["matched_null_family"] = family
        if p is None:
            return None
        correction = family_wise_p_value(
            p,
            n_tests=max(1, n_tests),
            universe_hash=universe_hash,
        )
        best["candidate_p_value_vs_null"] = p
        best["family_wise_p_value_vs_null"] = correction
        return correction["bonferroni_p_value"]
    except Exception as exc:
        logger.warning("Failed to annotate dispatcher p-values: %s", exc)
        if best is not None:
            best["p_value_status"] = "error"
        return None


# ─── Worker function (top-level for multiprocessing picklability) ────────────

def _evaluate_one(work_item: dict[str, Any]) -> dict[str, Any]:
    """Evaluate a single config: decrypt CT, kernel-score, return result.

    Must be defined at module top level to be pickleable by
    multiprocessing. All imports lazy so worker processes don't incur
    kernel import costs on tasks that fail early.
    """
    from kryptos.kernel.constants import CT
    from kryptos.kernel.scoring.aggregate import score_candidate
    from kryptos.kernel.transforms.compose import (
        PipelineConfig,
        TransformConfig,
        TransformType,
        build_pipeline,
    )

    config_id = work_item["config_id"]
    pipeline_dict = work_item["pipeline_dict"]
    challenge_ciphertext = work_item.get("challenge_ciphertext")
    challenge_crib_dict = work_item.get("challenge_crib_dict")

    try:
        ct = challenge_ciphertext if challenge_ciphertext is not None else CT
        steps = tuple(
            TransformConfig(
                transform_type=TransformType(s["type"]),
                params=dict(s.get("params", {})),
                description=s.get("description", ""),
            )
            for s in pipeline_dict["steps"]
        )
        pipeline = PipelineConfig(
            name=pipeline_dict["name"],
            steps=steps,
            direction=pipeline_dict.get("direction", "decrypt"),
        )
        fn = build_pipeline(pipeline)
        candidate_pt = fn(ct)
        if len(candidate_pt) != len(ct):
            return {
                "config_id": config_id,
                "error": f"pipeline output length {len(candidate_pt)} != CT length {len(ct)}",
            }
        if challenge_crib_dict is not None:
            crib_score = _score_known_cribs(candidate_pt, challenge_crib_dict)
            bean_passed = False
            bean_variant = None
            classification = (
                "challenge_known_answer"
                if crib_score == len(challenge_crib_dict)
                else "challenge_crib_mismatch"
            )
        else:
            breakdown = score_candidate(candidate_pt)
            crib_score = int(breakdown.crib_score)
            bean_passed, bean_variant = _candidate_bean_status(ct, candidate_pt)
            classification = getattr(breakdown, "crib_classification", "unknown")
        from kryptos.kernel.scoring.ngram import get_default_scorer
        ngram_score = float(get_default_scorer().score_per_char(candidate_pt))
        return {
            "config_id": config_id,
            "candidate_pt": candidate_pt,
            "crib_score": int(crib_score),
            "bean_passed": bool(bean_passed),
            "bean_variant": bean_variant,
            "ngram_score": ngram_score,
            "classification": classification,
        }
    except Exception as exc:  # pragma: no cover - defensive
        return {"config_id": config_id, "error": f"{type(exc).__name__}: {exc}"}


# ─── Main dispatch entrypoint ────────────────────────────────────────────────

def execute(
    spec: HypothesisSpec,
    *,
    workers: Optional[int] = None,
    artifact_root: Optional[Path] = None,
    parallel: Optional[bool] = None,
    exhaustion_log: Optional[dict[str, Any]] = None,
    store_threshold: Optional[int] = None,
    bench_mode: bool = False,
    challenge_ciphertext: Optional[str] = None,
    challenge_crib_dict: Optional[dict[int, str]] = None,
) -> JobResult:
    """Run a HypothesisSpec end-to-end and return a JobResult.

    Args:
        spec:               The spec to run. Will be admissibility-checked.
        workers:            Pool size. Defaults to ``cpu_count() - 2``
                            (minimum 1). Set to 1 for deterministic tests.
        artifact_root:      Directory for result artifact JSON. Defaults
                            to ``<repo_root>/results/dsl_jobs/``.
        parallel:           If None, auto-decide: serial for <10 configs
                            and in test contexts, parallel otherwise.
                            Set explicitly for deterministic tests.
        exhaustion_log:     Override for admissibility check (test hook).
        store_threshold:    Override for STORE_THRESHOLD (default: import
                            from kernel.constants).
        bench_mode:         When True (K4Bench synthetic challenge run),
                            real-K4 exhaustion-overlap admissibility is
                            skipped. All other admissibility checks
                            (validation, translation, cardinality budget)
                            still fire. See ``check_admissibility``.
        challenge_ciphertext / challenge_crib_dict:
                            Optional synthetic challenge inputs for
                            independent known-answer tests. When set,
                            workers decrypt this CT and score against
                            these cribs instead of the real-K4 constants.
                            Permutation translators use len(challenge_ct),
                            so non-K4 lengths exercise the live dispatcher
                            path without importing real K4 CT.
    """
    t_wall_start = time.monotonic()
    t_cpu_start = time.process_time()
    try:
        challenge_ciphertext, challenge_crib_dict = _validate_challenge_inputs(
            challenge_ciphertext, challenge_crib_dict,
        )
    except DispatcherError as exc:
        return JobResult(
            hypothesis_id=spec.hypothesis_id,
            spec_hash=spec.spec_hash,
            universe_hash="",
            admissibility_verdict="rejected",
            admissibility_reasons=[f"challenge inputs: {exc}"],
            wall_time_sec=time.monotonic() - t_wall_start,
            cpu_time_sec=time.process_time() - t_cpu_start,
            assumption_bundle=list(spec.assumption_bundle),
        )

    # R3-0.5-1: expand any procedural layers before admissibility so the
    # cardinality check sees the real parameter universe. A bad recipe
    # reference (missing id, physical-only, malformed template) surfaces
    # here as an admissibility rejection with the DispatcherError
    # message preserved in reasons.
    try:
        spec = _expand_procedural_layers(spec)
    except DispatcherError as exc:
        return JobResult(
            hypothesis_id=spec.hypothesis_id,
            spec_hash=spec.spec_hash,
            universe_hash="",
            admissibility_verdict="rejected",
            admissibility_reasons=[f"procedural expansion: {exc}"],
            wall_time_sec=time.monotonic() - t_wall_start,
            cpu_time_sec=time.process_time() - t_cpu_start,
            assumption_bundle=list(spec.assumption_bundle),
        )

    # Admissibility check. bench_mode skips the real-K4 exhaustion log
    # entirely; everything else (validation, translation, budget) still
    # fires, so a malformed bench spec is still rejected.
    admissible, reasons = check_admissibility(
        spec, exhaustion_log=exhaustion_log, bench_mode=bench_mode,
    )
    if not admissible:
        return JobResult(
            hypothesis_id=spec.hypothesis_id,
            spec_hash=spec.spec_hash,
            universe_hash="",
            admissibility_verdict="rejected",
            admissibility_reasons=reasons,
            wall_time_sec=time.monotonic() - t_wall_start,
            cpu_time_sec=time.process_time() - t_cpu_start,
            assumption_bundle=list(spec.assumption_bundle),
        )

    if store_threshold is None:
        from kryptos.kernel.constants import STORE_THRESHOLD
        store_threshold = STORE_THRESHOLD

    # Enumerate work items.
    work_items: list[dict[str, Any]] = []
    config_ids: list[str] = []
    challenge_length = len(challenge_ciphertext) if challenge_ciphertext is not None else None
    run_context_hash = _challenge_context_hash(challenge_ciphertext, challenge_crib_dict)
    # K4Bench attempt-replay: index from config_id -> bindings so we can
    # recover the parameter binding that produced the best candidate
    # without re-parsing the human-readable config_id string.
    bindings_by_config_id: dict[str, tuple[tuple[str, Any], ...]] = {}
    for bindings in _enumerate_bindings(spec):
        cfg_id = _config_id(spec.spec_hash, bindings)
        try:
            pipeline_dict = _build_pipeline_config(
                spec,
                bindings,
                text_length=challenge_length,
            )
        except DispatcherError as exc:
            # A translation error makes the whole spec un-executable.
            return JobResult(
                hypothesis_id=spec.hypothesis_id,
                spec_hash=spec.spec_hash,
                universe_hash="",
                admissibility_verdict="rejected",
                admissibility_reasons=[f"translation error: {exc}"],
                wall_time_sec=time.monotonic() - t_wall_start,
                cpu_time_sec=time.process_time() - t_cpu_start,
                assumption_bundle=list(spec.assumption_bundle),
                dispatched_dsl_spec=spec.to_dict(),
            )
        work_items.append({
            "config_id": cfg_id,
            "pipeline_dict": pipeline_dict,
            "challenge_ciphertext": challenge_ciphertext,
            "challenge_crib_dict": challenge_crib_dict,
        })
        config_ids.append(cfg_id)
        bindings_by_config_id[cfg_id] = bindings

    # Dispatch.
    if parallel is None:
        parallel = len(work_items) >= 10 and os.getenv("PYTEST_CURRENT_TEST") is None
    if workers is None:
        workers = max(1, cpu_count() - 2)

    if parallel and workers > 1 and len(work_items) > 1:
        with Pool(processes=workers) as pool:
            results = list(pool.imap_unordered(_evaluate_one, work_items))
    else:
        results = [_evaluate_one(item) for item in work_items]

    # Aggregate.
    stored: list[dict[str, Any]] = []
    best: Optional[dict[str, Any]] = None
    best_score = -1.0
    total_errors = 0
    for r in results:
        if "error" in r:
            total_errors += 1
            continue
        crib = r.get("crib_score", 0)
        if crib >= store_threshold:
            stored.append(r)
        # Rank by crib_score (primary) then by ngram_score (less-negative wins).
        combined = crib + max(-20.0, r.get("ngram_score", 0.0)) / 100.0
        if combined > best_score:
            best_score = combined
            best = r

    # Artifact write.
    if artifact_root is None:
        here = Path(__file__).resolve().parent
        repo_root = here.parent
        artifact_root = repo_root / "results" / "dsl_jobs"
    artifact_root.mkdir(parents=True, exist_ok=True)
    # Filename-safety: HCC-derived hypothesis_ids can be >200 chars
    # for 3-layer route_boustrophedon + columnar enumerated specs
    # (the layer_order + role_assignment + extras serialize into the
    # slug). Linux/ext4 caps a SINGLE pathname component at 255 bytes,
    # so a long id + spec_hash + the trailing artifact filename trips
    # OSError errno 36 ("File name too long"). The 2026-04-28 real-K4
    # HCC audit hit this failure mode on ~9700 of 28000 specs.
    #
    # Truncate long hypothesis_ids to a 180-char head plus the
    # spec_hash; the spec_hash provides the full disambiguation
    # (it's a 16-char sha256-16 over the canonical spec, so two
    # specs with the same truncated head but different params get
    # distinct directories via spec_hash). The truncation affects
    # filesystem layout only; the JobResult.hypothesis_id field
    # carries the full id so audit consumers don't lose
    # information.
    _ARTIFACT_DIR_HID_MAX = 180
    safe_hid = spec.hypothesis_id
    if len(safe_hid) > _ARTIFACT_DIR_HID_MAX:
        safe_hid = safe_hid[:_ARTIFACT_DIR_HID_MAX]
    artifact_dir = artifact_root / f"{safe_hid}_{spec.spec_hash}"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = artifact_dir / "result.json"

    wall_time = time.monotonic() - t_wall_start
    cpu_time = time.process_time() - t_cpu_start

    # R2-3: propagate override metadata into the result so the ledger
    # preserves WHY a prior-exhaustion spec was run anyway.
    #
    # K4Bench: bench_mode bypasses the real-K4 exhaustion log entirely,
    # so override_exhaustion_overlap stays empty regardless of what the
    # spec carries — the synthetic challenge has no overlap with the
    # K4 history by definition.
    override_overlap_list: list[str] = []
    if getattr(spec, "override_exhaustion", False) and not bench_mode:
        override_overlap_list = list(_exhaustion_overlap(
            spec,
            exhaustion_log if exhaustion_log is not None else _load_exhaustion_log(),
        ))

    # K4Bench attempt-replay: lift the bindings tuple for whichever
    # config produced ``best`` into a JSON-serializable list of pairs.
    # When best is None (zero successful evaluations) the list stays
    # empty; downstream consumers must check before assuming a binding.
    best_bindings_list: list[list[Any]] = []
    if best is not None and best.get("config_id") in bindings_by_config_id:
        best_bindings_tuple = bindings_by_config_id[best["config_id"]]
        best_bindings_list = [[k, v] for k, v in best_bindings_tuple]

    universe_hash = _universe_hash(
        spec.spec_hash,
        config_ids,
        run_context_hash=run_context_hash,
    )
    best_family_p = _annotate_best_candidate_p_values(
        best=best,
        spec=spec,
        n_tests=len(config_ids),
        universe_hash=universe_hash,
        challenge_mode=challenge_crib_dict is not None,
    )

    result = JobResult(
        hypothesis_id=spec.hypothesis_id,
        spec_hash=spec.spec_hash,
        universe_hash=universe_hash,
        total_tested=len(results) - total_errors,
        total_stored=len(stored),
        best_candidate=best,
        best_score=float(best["crib_score"]) if best and "crib_score" in best else 0.0,
        best_p_value_vs_null=best_family_p,
        information_gain_bits_realized=0.0,  # Phase 6 populates
        wall_time_sec=wall_time,
        cpu_time_sec=cpu_time,
        artifact_path=str(artifact_path),
        assumption_bundle=list(spec.assumption_bundle),
        admissibility_verdict="ok",
        override_justification=(
            spec.override_justification
            if getattr(spec, "override_exhaustion", False) else ""
        ),
        override_exhaustion_overlap=override_overlap_list,
        dispatched_dsl_spec=spec.to_dict(),
        best_config_bindings=best_bindings_list,
    )

    # An elimination claim is earned only when the job ran to completion
    # with NO candidate ≥ STORE_THRESHOLD and the spec had a non-trivial
    # universe. Otherwise leave eliminated_claim=None so callers don't
    # mistake a budget-short run for an elimination.
    if (
        len(results) > 0
        and total_errors == 0
        and len(stored) == 0
        and not spec.pipeline == []  # skip the degenerate identity-only spec
    ):
        result.eliminated_claim = (
            f"Spec {spec.hypothesis_id} ({spec.spec_hash}) tested "
            f"{len(results)} configurations; none exceeded STORE_THRESHOLD="
            f"{store_threshold}. Assumption bundle: "
            f"{spec.assumption_bundle or 'none'}"
        )

    # Write artifact manifest + full results.
    with open(artifact_path, "w") as f:
        json.dump(
            {
                "manifest": result.to_dict(),
                "spec": spec.to_dict(),
                "all_results": results,
            },
            f,
            indent=2,
            default=str,
        )

    return result


# ─── Convenience: one-shot validate + execute ────────────────────────────────

def job_result_to_worker_contract(
    result: JobResult,
    *,
    hypothesis_id: Optional[str] = None,
) -> "Any":  # quoted to avoid import at module load
    """Convert a ``JobResult`` into a ``WorkerContract`` for ledger ingestion.

    Phase 4 minimal integration helper. A future session can wire this
    into the controller's dispatch flow; Phase 4 keeps the existing SDK
    worker path unchanged (brief §6.6 acceptance criterion) and only
    exposes the conversion primitive.

    The produced contract is passed through ``_verify_against_kernel``
    so the Phase 3 kernel-overrule guarantees still hold — the worker
    contract cannot inflate its kernel-verified crib_score via this
    path either.

    Args:
        result:         The JobResult to convert.
        hypothesis_id:  Override for the contract's hypothesis_id. Falls
                        back to result.hypothesis_id.

    Returns:
        A WorkerContract with status=SUCCESS if anything was stored,
        DISPROVED if the job ran to completion with no signal,
        INCONCLUSIVE if admissibility rejected the spec.
    """
    from .contracts import _verify_against_kernel
    from .models import WorkerContract, WorkerStatus

    # Determine terminal status. R3-2: rejected admissibility now maps
    # to WorkerStatus.REJECTED_ADMISSIBILITY (was INCONCLUSIVE pre-R3-2).
    if result.admissibility_verdict == "rejected":
        status = WorkerStatus.REJECTED_ADMISSIBILITY
    elif result.eliminated_claim:
        status = WorkerStatus.DISPROVED
    elif result.total_stored > 0:
        status = WorkerStatus.SUCCESS
    else:
        status = WorkerStatus.INCONCLUSIVE

    best_pt = ""
    if result.best_candidate and "candidate_pt" in result.best_candidate:
        best_pt = str(result.best_candidate["candidate_pt"])

    raw_artifacts: dict[str, Any] = {
        "job_result": result.to_dict(),
        # The DSL spec itself is preserved elsewhere (artifact_path); here
        # we only record enough for ledger lookup.
        "artifact_path": result.artifact_path,
        "spec_hash": result.spec_hash,
        "universe_hash": result.universe_hash,
        # K4Bench attempt-replay (2026-04-27): inline the dispatched
        # spec + best-config bindings so bench_attempts.emit_attempt_artifact
        # can surface replayable layers without re-reading artifact_path
        # (which the ledger does not retain across processes). Both fields
        # are empty on rejection paths; bench_attempts checks before use.
        "dispatched_dsl_spec": dict(result.dispatched_dsl_spec),
        "best_config_bindings": [list(p) for p in result.best_config_bindings],
    }

    disproof_evidence = []
    if result.eliminated_claim:
        disproof_evidence.append(result.eliminated_claim)
    if result.admissibility_verdict == "rejected":
        disproof_evidence.extend(
            f"ADMISSIBILITY: {r}" for r in result.admissibility_reasons
        )

    contract = WorkerContract(
        hypothesis_id=hypothesis_id or result.hypothesis_id,
        worker_role="dsl_dispatcher",
        status=status,
        score=float(result.best_score),
        crib_score=int(result.best_candidate.get("crib_score", 0))
            if result.best_candidate else 0,
        bean_passed=bool(result.best_candidate.get("bean_passed", False))
            if result.best_candidate else False,
        best_plaintext=best_pt,
        disproof_evidence=disproof_evidence,
        next_action=(
            "retired: DSL dispatch complete"
            if status == WorkerStatus.DISPROVED
            else ""
        ),
        family_generalization="",  # caller annotates from the theory record
        raw_artifacts=raw_artifacts,
        duration_seconds=result.wall_time_sec,
        narrative_summary=(
            f"DSL spec {result.spec_hash} tested {result.total_tested} "
            f"configs; {result.total_stored} stored; best crib_score="
            f"{int(result.best_candidate.get('crib_score', 0)) if result.best_candidate else 0}"
        ),
    )

    # Kernel overrules even here. If best_pt is CT97-shaped, the verifier
    # re-scores it; if not, fields get zeroed with a verification_error.
    _verify_against_kernel(contract)
    return contract


def execute_from_json(raw: str | dict[str, Any], **kwargs: Any) -> JobResult:
    """Parse raw JSON/dict, validate, and execute in one call.

    If validation fails, returns a ``JobResult`` with
    ``admissibility_verdict == "rejected"`` and the parse errors in
    ``admissibility_reasons`` — consistent shape so callers don't need
    to distinguish parse failures from admissibility failures.

    ``bench_mode`` and any other ``execute`` kwargs are forwarded
    verbatim.
    """
    parsed = validate_hypothesis_spec(raw)
    if not parsed.is_valid:
        return JobResult(
            hypothesis_id="<unparsed>",
            spec_hash="",
            universe_hash="",
            admissibility_verdict="rejected",
            admissibility_reasons=parsed.errors,
        )
    assert parsed.value is not None
    return execute(parsed.value, **kwargs)


__all__ = [
    "DispatcherError",
    "JobResult",
    "check_admissibility",
    "execute",
    "execute_from_json",
    "job_result_to_worker_contract",
    "_SUPPORTED_KINDS",
    "_SUPPORTED_ALPHABETS",
    "_kind_has_translation",
    # R3-0.5-1
    "_expand_procedural_layers",
    "_load_recipes_by_id",
]
