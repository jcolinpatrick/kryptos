"""Procedural recipe enumerator.

Framework maturation Phase 8 (2026-04-21). Brief §10: MEMORY.md and the
theorist prompt in controller.py push toward procedural hypotheses
(Sanborn-as-sculptor). docs/procedural_anomaly_recipes.md catalogues
candidate recipes. This module parses a structured companion JSON
(docs/procedural_recipes.json) and converts admissible recipes into
HypothesisSpecs that the Phase-4 dispatcher can execute.

Pipeline:

    procedural_recipes.json
            │
            ▼
    load_recipes() ──► ProceduralRecipe (validated)
            │
            ▼
    enumerate_all_procedural(assumption_bundle, max_cost_minutes)
            │      ├── filter out physical-only (no DSL translation)
            │      ├── filter out recipes with closed anomaly anchors
            │      ├── filter out recipes whose known_eliminations cover
            │      │   the current assumption bundle
            │      └── cap total cardinality at
            │          max_cost_minutes × per-minute cap
            ▼
    list[HypothesisSpec] ──► job_dispatcher.execute()

Use case: ``--mode procedural_sweep`` on the controller skips the
theorist entirely and dispatches every admissible procedural recipe as
a batch. That's the brief's §10.3 "use-the-CPU-aggressively mode that
doesn't require LLM creativity".

See docs/maturation/phase_08_report.md for enumerator coverage and the
first-sweep results.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

from .hypothesis_dsl import (
    CipherLayer,
    HypothesisSpec,
    NullBaselineSpec,
    ParamRange,
)

logger = logging.getLogger("kryptosbot.procedural_enumerator")


# ─── Paths ───────────────────────────────────────────────────────────────────

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_RECIPES_PATH = _REPO_ROOT / "docs" / "procedural_recipes.json"


# ─── Dataclass ───────────────────────────────────────────────────────────────

@dataclass
class ProceduralRecipe:
    """One structured recipe parsed from docs/procedural_recipes.json.

    Field semantics:

        recipe_id:          Stable identifier (e.g. "P-F1-1", "P-E0e-1a").
                            Stored as the CipherLayer.recipe_id of the
                            leading layer when a DSL template exists.
        title:              Short human-readable summary.
        anomaly_id:         Which anomaly this recipe exploits (e.g. "F1",
                            "E0e", "baseline"). Used for anomaly-anchor
                            filtering.
        procedure:          Prose description; never parsed.
        tested_status:      "tested_noise" | "tested_exhaustive" |
                            "tested_partial" | "tested_control" |
                            "untested" | "untested_physical"
        priority:           "baseline" | "low" | "medium" | "high"
        physical_only:      True if the recipe requires physical
                            sculpture access (no DSL translation).
        known_eliminations: List of prior-run identifiers that cover
                            this recipe under specific assumption
                            bundles. Filtered at enumeration time.
        dsl_template:       Raw dict → HypothesisSpec template; None
                            when physical_only=True.
    """
    recipe_id: str
    title: str
    anomaly_id: str
    procedure: str
    tested_status: str
    priority: str
    physical_only: bool = False
    known_eliminations: list[str] = field(default_factory=list)
    dsl_template: Optional[dict[str, Any]] = None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ProceduralRecipe":
        return cls(
            recipe_id=str(d.get("recipe_id", "")),
            title=str(d.get("title", "")),
            anomaly_id=str(d.get("anomaly_id", "")),
            procedure=str(d.get("procedure", "")),
            tested_status=str(d.get("tested_status", "untested")),
            priority=str(d.get("priority", "low")),
            physical_only=bool(d.get("physical_only", False)),
            known_eliminations=list(d.get("known_eliminations", []) or []),
            dsl_template=d.get("dsl_template"),
        )


# ─── Source loader ──────────────────────────────────────────────────────────

def load_recipes(
    path: Optional[Path] = None,
) -> list[ProceduralRecipe]:
    """Load structured recipes from docs/procedural_recipes.json.

    Raises FileNotFoundError if the file is missing; JSONDecodeError on
    malformed JSON. Every entry must have a non-empty ``recipe_id`` —
    duplicates are rejected at load time so the enumerator never emits
    two specs for the same recipe.
    """
    src = path or _DEFAULT_RECIPES_PATH
    if not src.exists():
        raise FileNotFoundError(
            f"Procedural recipes source not found: {src}. "
            f"Phase 8 expects docs/procedural_recipes.json to exist."
        )

    with open(src) as f:
        payload = json.load(f)

    raw = payload.get("recipes", [])
    if not isinstance(raw, list):
        raise ValueError(f"'recipes' must be a list in {src}")

    out: list[ProceduralRecipe] = []
    seen_ids: set[str] = set()
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ValueError(
                f"Recipe at index {i} must be an object, got "
                f"{type(entry).__name__}"
            )
        recipe = ProceduralRecipe.from_dict(entry)
        if not recipe.recipe_id:
            raise ValueError(f"Recipe at index {i} missing recipe_id")
        if recipe.recipe_id in seen_ids:
            raise ValueError(
                f"Duplicate recipe_id {recipe.recipe_id!r} in {src}"
            )
        seen_ids.add(recipe.recipe_id)
        out.append(recipe)
    return out


# ─── DSL-template → HypothesisSpec ──────────────────────────────────────────

def recipe_to_spec(recipe: ProceduralRecipe) -> Optional[HypothesisSpec]:
    """Convert a recipe's dsl_template into a HypothesisSpec.

    Returns None when:
        - The recipe is physical_only (no template exists).
        - The template is malformed (logged, None returned).

    The generated ``hypothesis_id`` is ``f"PROC-{recipe.recipe_id}"`` —
    prefixed so ledger queries can select procedural-origin specs.
    """
    if recipe.physical_only or recipe.dsl_template is None:
        return None

    tpl = recipe.dsl_template
    try:
        pipeline = []
        for layer_dict in tpl.get("pipeline", []):
            params = []
            for p in layer_dict.get("params", []) or []:
                pr = ParamRange(
                    name=str(p.get("name", "")),
                    values=list(p.get("values", []) or []),
                    start=p.get("start"),
                    stop=p.get("stop"),
                    source_corpus=p.get("source_corpus"),
                    cardinality_cap=int(p.get("cardinality_cap", 10_000)),
                )
                params.append(pr)
            pipeline.append(CipherLayer(
                kind=str(layer_dict.get("kind", "")),
                alphabet=str(layer_dict.get("alphabet", "AZ")),
                params=params,
                recipe_id=layer_dict.get("recipe_id"),
            ))

        null_baseline_raw = tpl.get("null_baseline")
        null_baseline = (
            NullBaselineSpec(
                method=str(null_baseline_raw.get("method", "random_text")),
                n_samples=int(null_baseline_raw.get("n_samples", 10_000)),
                cache_key=null_baseline_raw.get("cache_key"),
            )
            if null_baseline_raw else None
        )

        spec = HypothesisSpec(
            hypothesis_id=f"PROC-{recipe.recipe_id}",
            pipeline=pipeline,
            crib_alignment=str(tpl.get("crib_alignment", "direct_positional")),
            scoring=str(tpl.get("scoring", "composite")),
            null_baseline=null_baseline,
            information_gain_bits_estimate=float(
                tpl.get("information_gain_bits_estimate", 0.0)
            ),
            success_criteria=dict(tpl.get("success_criteria", {}) or {}),
            kill_criteria=dict(tpl.get("kill_criteria", {}) or {}),
            compute_budget_cpu_minutes=int(
                tpl.get("compute_budget_cpu_minutes", 1)
            ),
            checkpoint_every_sec=int(tpl.get("checkpoint_every_sec", 60)),
            assumption_bundle=list(tpl.get("assumption_bundle", []) or []),
            notes=f"Procedural recipe {recipe.recipe_id}: {recipe.title}",
        )
    except Exception as exc:
        logger.warning(
            "Failed to translate recipe %s to HypothesisSpec: %s",
            recipe.recipe_id, exc,
        )
        return None

    errs = spec.validate()
    if errs:
        logger.warning(
            "Recipe %s produced an invalid HypothesisSpec: %s",
            recipe.recipe_id, errs,
        )
        return None
    return spec


# ─── Admissibility filter ───────────────────────────────────────────────────

def _recipe_admissible(
    recipe: ProceduralRecipe,
    assumption_bundle: list[str],
    open_anomaly_ids: Optional[Iterable[str]],
) -> tuple[bool, list[str]]:
    """Return (admissible, reasons_if_not)."""
    reasons: list[str] = []

    if recipe.physical_only:
        reasons.append("physical_only")

    # Anomaly-anchor filter.
    if open_anomaly_ids is not None:
        open_set = set(open_anomaly_ids)
        # "baseline" is always admissible regardless of anomaly state.
        if recipe.anomaly_id not in open_set and recipe.anomaly_id != "baseline":
            reasons.append(
                f"anomaly {recipe.anomaly_id!r} not in open anomaly list"
            )

    # Known-eliminations filter: if any of the recipe's eliminations is a
    # superset of the current assumption_bundle, the recipe is covered.
    bundle_set = set(assumption_bundle or [])
    for elim in recipe.known_eliminations:
        # Simple substring overlap: this is a heuristic, not a rigorous
        # bundle-equality check. Matches the Phase-4 dispatcher's
        # _exhaustion_overlap posture.
        if bundle_set and any(
            term.lower() in elim.lower() for term in bundle_set
        ):
            reasons.append(
                f"covered by known_elimination {elim!r} for bundle overlap"
            )
            break

    return (not reasons, reasons)


@dataclass
class EnumerationResult:
    """Result of ``enumerate_all_procedural``."""
    specs: list[HypothesisSpec]
    total_recipes: int
    admitted: int
    physical_only_count: int
    filtered_reasons: dict[str, list[str]] = field(default_factory=dict)
    """For each rejected recipe_id, the list of reasons."""
    total_expected_cardinality: int = 0


# ─── Public API ─────────────────────────────────────────────────────────────

_CONFIGS_PER_CPU_MINUTE_CAP = 200_000  # mirrors job_dispatcher constant


def enumerate_all_procedural(
    assumption_bundle: Optional[list[str]] = None,
    max_cost_minutes: int = 60,
    open_anomaly_ids: Optional[Iterable[str]] = None,
    recipes_path: Optional[Path] = None,
) -> EnumerationResult:
    """Return admissible procedural DSL specs.

    Args:
        assumption_bundle:  Current assumption tags. Recipes whose
                            known_eliminations cover this bundle are
                            filtered out.
        max_cost_minutes:   Hard ceiling on total enumeration
                            cardinality (× per-minute cap). Recipes
                            added until the ceiling is reached; later
                            recipes are deferred.
        open_anomaly_ids:   If provided, restrict recipes to those
                            targeting an open anomaly. Pass ``None`` to
                            skip this filter.
        recipes_path:       Override for test harnesses. Defaults to
                            ``docs/procedural_recipes.json``.
    """
    recipes = load_recipes(recipes_path)
    bundle = list(assumption_bundle or [])

    budget_total = max_cost_minutes * _CONFIGS_PER_CPU_MINUTE_CAP

    specs: list[HypothesisSpec] = []
    total_card = 0
    physical_count = 0
    filtered: dict[str, list[str]] = {}

    # Priority order: "baseline" < "low" < "medium" < "high"; lower
    # priority recipes run first as a warm-up, higher last when budget
    # may be tight. (Reversed vs intuitive because admissibility is
    # where the cap matters, and recipes that ARE expected to find
    # signal should not be shut out by exhausted budget.)
    priority_order = {"high": 0, "medium": 1, "low": 2, "baseline": 3}
    for recipe in sorted(recipes, key=lambda r: priority_order.get(r.priority, 9)):
        admissible, reasons = _recipe_admissible(
            recipe, bundle, open_anomaly_ids,
        )
        if recipe.physical_only:
            physical_count += 1
        if not admissible:
            filtered[recipe.recipe_id] = reasons
            continue

        spec = recipe_to_spec(recipe)
        if spec is None:
            filtered[recipe.recipe_id] = ["spec translation failed"]
            continue

        card = spec.expected_cardinality()
        if total_card + card > budget_total:
            filtered[recipe.recipe_id] = [
                f"total budget exhausted: would add {card} configs to "
                f"running total {total_card}; cap {budget_total}"
            ]
            continue

        specs.append(spec)
        total_card += card

    return EnumerationResult(
        specs=specs,
        total_recipes=len(recipes),
        admitted=len(specs),
        physical_only_count=physical_count,
        filtered_reasons=filtered,
        total_expected_cardinality=total_card,
    )


# ─── Sweep entry point ──────────────────────────────────────────────────────

def run_procedural_sweep(
    assumption_bundle: Optional[list[str]] = None,
    max_cost_minutes: int = 60,
    open_anomaly_ids: Optional[Iterable[str]] = None,
    artifact_root: Optional[Path] = None,
    recipes_path: Optional[Path] = None,
) -> list[dict[str, Any]]:
    """Enumerate + dispatch all admissible procedural specs.

    Returns a list of JobResult.to_dict() dicts, one per executed spec.
    The dispatcher writes per-spec artifacts to
    ``results/dsl_jobs/<hypothesis_id>_<spec_hash>/`` as usual.

    This is what ``--mode procedural_sweep`` on the controller invokes.
    """
    from .job_dispatcher import execute

    enum = enumerate_all_procedural(
        assumption_bundle=assumption_bundle,
        max_cost_minutes=max_cost_minutes,
        open_anomaly_ids=open_anomaly_ids,
        recipes_path=recipes_path,
    )

    logger.info(
        "Procedural sweep: %d recipes total, %d admitted "
        "(physical_only=%d, filtered=%d), "
        "total_expected_cardinality=%d",
        enum.total_recipes, enum.admitted,
        enum.physical_only_count, len(enum.filtered_reasons),
        enum.total_expected_cardinality,
    )

    results: list[dict[str, Any]] = []
    for spec in enum.specs:
        job_result = execute(spec, parallel=False, artifact_root=artifact_root)
        results.append(job_result.to_dict())
    return results


__all__ = [
    "ProceduralRecipe",
    "EnumerationResult",
    "load_recipes",
    "recipe_to_spec",
    "enumerate_all_procedural",
    "run_procedural_sweep",
]


# ─── CLI entry point (brief §10.3 --mode procedural_sweep) ──────────────────
#
# Invoked as:
#     PYTHONPATH=src python3 -m kryptosbot.procedural_enumerator --dry-run
#     PYTHONPATH=src python3 -m kryptosbot.procedural_enumerator --sweep
#
# The controller's own cycle loop does not call this directly — the
# procedural sweep is an operator-invoked standalone runner. Brief
# §10.3 framed this as a "cycle mode"; in practice a CLI-invoked
# module-level runner is equivalent in scope and avoids touching the
# async controller path.

def _cli(argv: Optional[list[str]] = None) -> int:
    import argparse
    import json as _json
    import sys

    ap = argparse.ArgumentParser(
        description="Procedural recipe enumerator / sweep runner."
    )
    ap.add_argument(
        "--dry-run", action="store_true",
        help="Enumerate admissible recipes and print the list; do NOT execute."
    )
    ap.add_argument(
        "--sweep", action="store_true",
        help="Dispatch every admissible procedural recipe through the "
             "DSL dispatcher."
    )
    ap.add_argument(
        "--max-cost-minutes", type=int, default=60,
        help="Total enumeration budget ceiling (default: 60)."
    )
    ap.add_argument(
        "--assumption", action="append", default=[],
        help="Assumption bundle tag. May be passed multiple times."
    )
    ap.add_argument(
        "--recipes-path", type=str, default=None,
        help="Override path to docs/procedural_recipes.json."
    )
    ap.add_argument(
        "--report-path", type=str, default=None,
        help="Write the sweep results to this JSON file (with --sweep)."
    )
    args = ap.parse_args(argv)

    recipes_path = Path(args.recipes_path) if args.recipes_path else None

    if args.dry_run or not args.sweep:
        enum = enumerate_all_procedural(
            assumption_bundle=args.assumption,
            max_cost_minutes=args.max_cost_minutes,
            recipes_path=recipes_path,
        )
        print(f"Procedural enumeration (dry-run)")
        print(f"  total recipes:   {enum.total_recipes}")
        print(f"  admitted:        {enum.admitted}")
        print(f"  physical_only:   {enum.physical_only_count}")
        print(f"  filtered:        {len(enum.filtered_reasons)}")
        print(f"  total cardinality: {enum.total_expected_cardinality}")
        print()
        print("Admitted specs:")
        for s in enum.specs:
            print(f"  {s.hypothesis_id:32s}  card={s.expected_cardinality():4d}"
                  f"  pipeline=[{','.join(l.kind for l in s.pipeline)}]")
        if enum.filtered_reasons:
            print("\nFiltered:")
            for rid, reasons in sorted(enum.filtered_reasons.items()):
                print(f"  {rid:24s}: {reasons[0]}")
        return 0

    # --sweep: execute
    results = run_procedural_sweep(
        assumption_bundle=args.assumption,
        max_cost_minutes=args.max_cost_minutes,
        recipes_path=recipes_path,
    )
    print(f"Procedural sweep complete: {len(results)} spec(s) executed")
    best_by_spec: list[dict[str, Any]] = []
    for r in results:
        hb = r.get("best_candidate") or {}
        line = (f"  {r['hypothesis_id']:32s}  "
                f"tested={r['total_tested']:4d} "
                f"best_score={r['best_score']:5.1f}  "
                f"bean={hb.get('bean_passed', False)}  "
                f"wall={r['wall_time_sec']:.2f}s")
        if r.get("eliminated_claim"):
            line += "  [eliminated]"
        print(line)
        best_by_spec.append(r)

    if args.report_path:
        out_path = Path(args.report_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(_json.dumps({
            "assumption_bundle": args.assumption,
            "max_cost_minutes": args.max_cost_minutes,
            "results": best_by_spec,
        }, indent=2, default=str))
        print(f"\nReport: {out_path}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_cli())
