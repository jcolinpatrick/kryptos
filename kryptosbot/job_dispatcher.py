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
) -> tuple[bool, list[str]]:
    """Validate that the spec is safe to dispatch.

    Returns ``(admissible, reasons)``. ``admissible`` is True only when
    ``reasons`` is empty. The dispatcher refuses to execute when
    ``admissible`` is False — the brief's §6.2 policy is "reject explicit,
    never silently clip" so the caller can surface the exact reason.
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


def _build_pipeline_config(
    spec: HypothesisSpec,
    bindings: tuple[tuple[str, Any], ...],
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
        step = _translate_layer(layer, binding)
        steps.append(step)

    return {
        "name": f"{spec.hypothesis_id}_spec_{spec.spec_hash}",
        "direction": "decrypt",
        "steps": steps,
    }


def _translate_layer(layer: CipherLayer, binding: dict[str, Any]) -> dict[str, Any]:
    """Translate one CipherLayer + its param binding into a
    serializable TransformConfig dict (dict form because multiprocessing
    needs pickleable step lists).

    Raises ``DispatcherError`` on unsupported kinds.
    """
    kind = layer.kind
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
        from kryptos.kernel.constants import CT_LEN
        from kryptos.kernel.transforms.transposition import columnar_perm
        perm = columnar_perm(width, list(col_order), CT_LEN)
        return {
            "type": "transposition_full",
            "params": {
                "perm": list(perm),
                "direction": "undo",
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
        from kryptos.kernel.constants import CT_LEN
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


def _universe_hash(spec_hash: str, config_ids: list[str]) -> str:
    """Deterministic hash over the full tested universe.

    Folds config IDs in insertion order (they come from deterministic
    enumeration) so two runs of the same spec produce the same
    universe_hash. Used by exhaustion-log matching.
    """
    payload = json.dumps(
        {"spec_hash": spec_hash, "config_ids": sorted(config_ids)},
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


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

    try:
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
        candidate_pt = fn(CT)
        if len(candidate_pt) != len(CT):
            return {
                "config_id": config_id,
                "error": f"pipeline output length {len(candidate_pt)} != CT length {len(CT)}",
            }
        breakdown = score_candidate(candidate_pt)
        return {
            "config_id": config_id,
            "candidate_pt": candidate_pt,
            "crib_score": int(breakdown.crib_score),
            "bean_passed": bool(breakdown.bean_passed),
            "ngram_score": float(getattr(breakdown, "ngram_score", 0.0) or 0.0),
            "classification": getattr(
                breakdown, "crib_classification", "unknown"
            ),
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
    """
    t_wall_start = time.monotonic()
    t_cpu_start = time.process_time()

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

    # Admissibility check.
    admissible, reasons = check_admissibility(spec, exhaustion_log=exhaustion_log)
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
    for bindings in _enumerate_bindings(spec):
        cfg_id = _config_id(spec.spec_hash, bindings)
        try:
            pipeline_dict = _build_pipeline_config(spec, bindings)
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
            )
        work_items.append({"config_id": cfg_id, "pipeline_dict": pipeline_dict})
        config_ids.append(cfg_id)

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
    artifact_dir = artifact_root / f"{spec.hypothesis_id}_{spec.spec_hash}"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = artifact_dir / "result.json"

    wall_time = time.monotonic() - t_wall_start
    cpu_time = time.process_time() - t_cpu_start

    # R2-3: propagate override metadata into the result so the ledger
    # preserves WHY a prior-exhaustion spec was run anyway.
    override_overlap_list: list[str] = []
    if getattr(spec, "override_exhaustion", False):
        override_overlap_list = list(_exhaustion_overlap(
            spec,
            exhaustion_log if exhaustion_log is not None else _load_exhaustion_log(),
        ))

    result = JobResult(
        hypothesis_id=spec.hypothesis_id,
        spec_hash=spec.spec_hash,
        universe_hash=_universe_hash(spec.spec_hash, config_ids),
        total_tested=len(results) - total_errors,
        total_stored=len(stored),
        best_candidate=best,
        best_score=float(best["crib_score"]) if best and "crib_score" in best else 0.0,
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

    # Determine terminal status.
    if result.admissibility_verdict == "rejected":
        status = WorkerStatus.INCONCLUSIVE
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
    "_kind_has_translation",
    # R3-0.5-1
    "_expand_procedural_layers",
    "_load_recipes_by_id",
]
