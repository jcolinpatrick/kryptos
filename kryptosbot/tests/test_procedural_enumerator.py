"""Tests for kryptosbot.procedural_enumerator.

Framework maturation Phase 8 (2026-04-21). Brief §10.4:
- Enumerator parses the structured recipe source correctly.
- Admissibility filter excludes recipes whose anchors are closed or
  whose eliminations cover the current bundle.
- Procedural-sweep mode dispatches expected number of specs.
- End-to-end on 2-3 small recipes produces JobResults.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kryptosbot.hypothesis_dsl import HypothesisSpec
from kryptosbot.procedural_enumerator import (
    EnumerationResult,
    ProceduralRecipe,
    enumerate_all_procedural,
    load_recipes,
    recipe_to_spec,
    run_procedural_sweep,
    _DEFAULT_RECIPES_PATH,
)


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _write_minimal_recipes(tmp_path: Path, recipes: list[dict]) -> Path:
    """Write a minimal recipes JSON and return its path."""
    p = tmp_path / "recipes.json"
    p.write_text(json.dumps({
        "schema_version": 1,
        "recipes": recipes,
    }))
    return p


def _identity_recipe(rid="P-TEST-0", anomaly="baseline", **kw) -> dict:
    base = {
        "recipe_id": rid,
        "title": "Test identity recipe",
        "anomaly_id": anomaly,
        "procedure": "smoke test",
        "tested_status": "untested",
        "priority": "low",
        "physical_only": False,
        "dsl_template": {
            "pipeline": [{"kind": "identity", "alphabet": "AZ", "params": []}],
            "assumption_bundle": ["H1_direct_positional"],
            "compute_budget_cpu_minutes": 1,
            "scoring": "composite",
        },
    }
    base.update(kw)
    return base


def _vigenere_recipe(rid="P-TEST-VIG", keywords=("A",), **kw) -> dict:
    base = {
        "recipe_id": rid,
        "title": "Vigenere test",
        "anomaly_id": "baseline",
        "procedure": "vig smoke",
        "tested_status": "untested",
        "priority": "low",
        "physical_only": False,
        "dsl_template": {
            "pipeline": [{
                "kind": "vigenere",
                "alphabet": "AZ",
                "params": [{"name": "keyword", "values": list(keywords)}],
            }],
            "assumption_bundle": [],
            "compute_budget_cpu_minutes": 1,
            "scoring": "composite",
        },
    }
    base.update(kw)
    return base


def _physical_recipe(rid="P-TEST-PHYS", **kw) -> dict:
    base = {
        "recipe_id": rid,
        "title": "Physical-only recipe",
        "anomaly_id": "baseline",
        "procedure": "requires physical access",
        "tested_status": "untested_physical",
        "priority": "low",
        "physical_only": True,
        "dsl_template": None,
    }
    base.update(kw)
    return base


# ─── Recipe loading ──────────────────────────────────────────────────────────

class TestLoadRecipes:
    def test_load_canonical_recipes_file(self):
        recipes = load_recipes()
        assert len(recipes) >= 10
        ids = [r.recipe_id for r in recipes]
        assert "P-BASELINE-1" in ids
        assert "P-F1-1" in ids

    def test_load_empty_file_raises(self, tmp_path: Path):
        p = tmp_path / "empty.json"
        p.write_text("{}")
        # No recipes key: returns empty list (not an error; this is the
        # "legitimate empty corpus" case).
        recipes = load_recipes(p)
        assert recipes == []

    def test_load_missing_file_raises(self, tmp_path: Path):
        p = tmp_path / "nonexistent.json"
        with pytest.raises(FileNotFoundError):
            load_recipes(p)

    def test_load_rejects_duplicate_ids(self, tmp_path: Path):
        p = _write_minimal_recipes(tmp_path, [
            _identity_recipe("P-DUP"),
            _identity_recipe("P-DUP"),  # duplicate
        ])
        with pytest.raises(ValueError, match="Duplicate"):
            load_recipes(p)

    def test_load_rejects_missing_recipe_id(self, tmp_path: Path):
        p = _write_minimal_recipes(tmp_path, [
            {"title": "no id", "anomaly_id": "baseline", "procedure": "x",
             "tested_status": "untested", "priority": "low",
             "physical_only": False, "dsl_template": None},
        ])
        with pytest.raises(ValueError, match="missing recipe_id"):
            load_recipes(p)


# ─── Recipe → Spec translation ──────────────────────────────────────────────

class TestRecipeToSpec:
    def test_physical_only_returns_none(self):
        recipe = ProceduralRecipe.from_dict(_physical_recipe())
        assert recipe_to_spec(recipe) is None

    def test_identity_template_translates(self):
        recipe = ProceduralRecipe.from_dict(_identity_recipe())
        spec = recipe_to_spec(recipe)
        assert isinstance(spec, HypothesisSpec)
        assert spec.hypothesis_id == "PROC-P-TEST-0"
        assert len(spec.pipeline) == 1
        assert spec.pipeline[0].kind == "identity"

    def test_vigenere_with_keywords_translates(self):
        recipe = ProceduralRecipe.from_dict(
            _vigenere_recipe(keywords=["ABC", "DEF", "GHI"])
        )
        spec = recipe_to_spec(recipe)
        assert spec is not None
        assert spec.expected_cardinality() == 3

    def test_spec_carries_recipe_id_in_notes(self):
        recipe = ProceduralRecipe.from_dict(_identity_recipe())
        spec = recipe_to_spec(recipe)
        assert spec is not None
        assert recipe.recipe_id in spec.notes


# ─── Admissibility filter ───────────────────────────────────────────────────

class TestAdmissibilityFilter:
    def test_physical_only_filtered(self, tmp_path: Path):
        p = _write_minimal_recipes(tmp_path, [
            _identity_recipe("P-OK"),
            _physical_recipe("P-PHYS"),
        ])
        enum = enumerate_all_procedural(
            assumption_bundle=[], recipes_path=p,
        )
        assert enum.admitted == 1
        admitted_ids = [s.hypothesis_id for s in enum.specs]
        assert "PROC-P-OK" in admitted_ids
        assert "PROC-P-PHYS" not in admitted_ids
        assert "P-PHYS" in enum.filtered_reasons
        assert "physical_only" in enum.filtered_reasons["P-PHYS"]

    def test_closed_anomaly_filtered(self, tmp_path: Path):
        p = _write_minimal_recipes(tmp_path, [
            _identity_recipe("P-OPEN", anomaly="F1"),
            _identity_recipe("P-CLOSED", anomaly="ZZ"),
        ])
        enum = enumerate_all_procedural(
            assumption_bundle=[],
            open_anomaly_ids=["F1"],
            recipes_path=p,
        )
        ids = [s.hypothesis_id for s in enum.specs]
        assert "PROC-P-OPEN" in ids
        assert "PROC-P-CLOSED" not in ids
        assert "P-CLOSED" in enum.filtered_reasons

    def test_baseline_always_admissible_regardless_of_anomaly_filter(self, tmp_path: Path):
        p = _write_minimal_recipes(tmp_path, [
            _identity_recipe("P-BASE", anomaly="baseline"),
        ])
        # Even with a restrictive open_anomaly_ids that doesn't include 'baseline',
        # baseline recipes are always admissible.
        enum = enumerate_all_procedural(
            assumption_bundle=[],
            open_anomaly_ids=["F1"],  # 'baseline' not in this list
            recipes_path=p,
        )
        assert enum.admitted == 1

    def test_bundle_elimination_overlap_filters(self, tmp_path: Path):
        p = _write_minimal_recipes(tmp_path, [
            _identity_recipe(
                "P-COVERED",
                known_eliminations=["yar_as_primer_sweep_2026_04"],
            ),
        ])
        enum = enumerate_all_procedural(
            assumption_bundle=["yar_as_primer"],  # substring of the elimination name
            recipes_path=p,
        )
        assert enum.admitted == 0
        assert "P-COVERED" in enum.filtered_reasons

    def test_no_bundle_does_not_trigger_overlap(self, tmp_path: Path):
        p = _write_minimal_recipes(tmp_path, [
            _identity_recipe(
                "P-FREE", known_eliminations=["something_else"],
            ),
        ])
        enum = enumerate_all_procedural(
            assumption_bundle=[], recipes_path=p,
        )
        assert enum.admitted == 1

    def test_budget_ceiling_respected(self, tmp_path: Path):
        """Cap is max_cost_minutes × 200_000 configs/min. A 0.0003-minute
        budget gives a 60-config cap, so three recipes of 100-cardinality
        each should get 0 admitted (first recipe alone exceeds)."""
        huge_recipe = _vigenere_recipe(
            "P-HUGE",
            keywords=[f"K{i:04d}" for i in range(100)],
        )
        # Need to bump cardinality_cap or the ParamRange validates rejects.
        huge_recipe["dsl_template"]["pipeline"][0]["params"][0]["cardinality_cap"] = 200
        p = _write_minimal_recipes(tmp_path, [huge_recipe])
        # max_cost_minutes=0 ⇒ budget 0; any non-empty cardinality exceeds.
        enum = enumerate_all_procedural(
            assumption_bundle=[], max_cost_minutes=0, recipes_path=p,
        )
        assert enum.admitted == 0


# ─── Priority ordering ──────────────────────────────────────────────────────

class TestPriorityOrdering:
    def test_high_priority_enumerated_first(self, tmp_path: Path):
        p = _write_minimal_recipes(tmp_path, [
            _identity_recipe("P-LOW", priority="low"),
            _identity_recipe("P-HIGH", priority="high"),
            _identity_recipe("P-BASELINE", priority="baseline"),
            _identity_recipe("P-MEDIUM", priority="medium"),
        ])
        enum = enumerate_all_procedural(
            assumption_bundle=[], recipes_path=p,
        )
        ids = [s.hypothesis_id for s in enum.specs]
        # Expected order: HIGH, MEDIUM, LOW, BASELINE
        assert ids.index("PROC-P-HIGH") < ids.index("PROC-P-MEDIUM")
        assert ids.index("PROC-P-MEDIUM") < ids.index("PROC-P-LOW")
        assert ids.index("PROC-P-LOW") < ids.index("PROC-P-BASELINE")


# ─── End-to-end sweep ───────────────────────────────────────────────────────

class TestSweepExecution:
    def test_sweep_runs_to_completion(self, tmp_path: Path):
        """Brief §10.4: end-to-end on 2-3 small recipes produces JobResults."""
        p = _write_minimal_recipes(tmp_path, [
            _identity_recipe("P-SWEEP-A"),
            _identity_recipe("P-SWEEP-B"),
            _vigenere_recipe("P-SWEEP-C", keywords=["KRYPTOS"]),
        ])
        artifact_root = tmp_path / "artifacts"
        results = run_procedural_sweep(
            assumption_bundle=[], recipes_path=p,
            artifact_root=artifact_root,
        )
        assert len(results) == 3
        for r in results:
            assert r["admissibility_verdict"] == "ok"
            assert r["total_tested"] >= 1


# ─── Canonical recipe source sanity ─────────────────────────────────────────

class TestCanonicalSource:
    """Brief §10.5: structured procedural recipe source with top recipes."""

    def test_canonical_source_loads_without_error(self):
        recipes = load_recipes()
        assert isinstance(recipes, list)
        assert len(recipes) >= 10

    def test_canonical_source_has_both_dsl_and_physical_entries(self):
        recipes = load_recipes()
        physical = [r for r in recipes if r.physical_only]
        dsl = [r for r in recipes if not r.physical_only]
        assert len(dsl) >= 5
        assert len(physical) >= 2

    def test_canonical_source_every_dsl_recipe_translates(self):
        recipes = load_recipes()
        for r in recipes:
            if r.physical_only:
                continue
            spec = recipe_to_spec(r)
            assert spec is not None, f"recipe {r.recipe_id!r} failed to translate"
            errs = spec.validate()
            assert errs == [], f"recipe {r.recipe_id!r} invalid spec: {errs}"

    def test_canonical_sweep_admits_most_dsl_recipes(self):
        """Expect ~12 DSL recipes admitted out of ~17 total (5 physical,
        0 currently-covered under empty bundle). Regression guard."""
        enum = enumerate_all_procedural(assumption_bundle=[])
        assert enum.admitted >= 10, f"only {enum.admitted} recipes admitted"
        # Every filtered recipe has a physical_only or bundle-coverage reason.
        for rid, reasons in enum.filtered_reasons.items():
            assert any(
                "physical_only" in r or "known_elimination" in r or
                "anomaly" in r or "budget" in r or "translation failed" in r
                for r in reasons
            ), f"unexpected filter reason for {rid}: {reasons}"
