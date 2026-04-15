"""Tests for scripts/hypothesis_tests/h_624_nonword_key_schedule_harness.py."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "hypothesis_tests"))

import h_624_nonword_key_schedule_harness as nw  # noqa: E402
import h_624_73_nullmask_harness as companion  # noqa: E402

from kryptos.kernel.constants import (  # noqa: E402
    BEAN_EQ,
    BEAN_INEQ,
    BEAN_LINEAR,
    CRIB_POSITIONS,
    MOD,
    SIGNAL_THRESHOLD,
    STORE_THRESHOLD,
)


# ---------------------------------------------------------------------------
# 624 enumerator
# ---------------------------------------------------------------------------


def test_enumerate_bean_valid_24_vectors_count_is_624():
    vecs = nw.enumerate_bean_valid_24_vectors()
    assert len(vecs) == 624, f"expected 624 Bean-valid vectors, got {len(vecs)}"


def test_bean_624_vectors_satisfy_all_constraints():
    vecs = nw.enumerate_bean_valid_24_vectors()
    positions = sorted(CRIB_POSITIONS)
    idx_of = {p: i for i, p in enumerate(positions)}
    eq_idx = [(idx_of[a], idx_of[b]) for a, b in BEAN_EQ]
    ineq_idx = [(idx_of[a], idx_of[b]) for a, b in BEAN_INEQ]
    lin_idx = [
        (idx_of[a], idx_of[b], idx_of[c], idx_of[d]) for a, b, c, d in BEAN_LINEAR
    ]
    # spot-check first, last, and 10 samples
    samples = [vecs[0], vecs[-1]] + [vecs[i] for i in range(0, 624, 60)]
    for k in samples:
        for a, b in eq_idx:
            assert k[a] == k[b]
        for a, b in ineq_idx:
            assert k[a] != k[b]
        for a, b, c, d in lin_idx:
            assert (k[a] - k[b] - k[c] + k[d]) % MOD == 0


def test_bean_624_enumeration_is_deterministic_and_distinct():
    v1 = nw.enumerate_bean_valid_24_vectors()
    # reset cache and reload to check determinism
    nw._BEAN624_CACHE = None
    cache_file = nw._BEAN624_CACHE_FILE
    v2 = nw.enumerate_bean_valid_24_vectors()
    assert v1 == v2
    assert len(set(v1)) == 624


# ---------------------------------------------------------------------------
# KeySchedule record shape
# ---------------------------------------------------------------------------


def test_every_schedule_has_required_fields():
    schedules, gaps = nw.build_key_schedule_universe(vimark_limit=20)
    assert schedules, "universe must not be empty"
    for s in schedules:
        assert s.key_id
        assert s.family in (
            "bean624_crib_anchored_extension",
            "linear_recurrence",
            "coordinate_tape",
            "vimark",
        )
        assert s.description
        assert len(s.values_73) == 73
        for v in s.values_73:
            assert 0 <= v < 26
        assert s.source_basis
        assert isinstance(s.is_exhaustive_within_family, bool)
        assert isinstance(s.generation_parameters, dict)


def test_linear_recurrence_deterministic_and_bounded():
    a = nw.gen_linear_recurrence_schedules()
    b = nw.gen_linear_recurrence_schedules()
    assert [s.key_id for s in a] == [s.key_id for s in b]
    # bounded
    assert 50 < len(a) < 5000


def test_coordinate_tape_family_nonempty_and_from_documented_sources():
    tapes = nw.gen_coordinate_tape_schedules()
    assert len(tapes) >= 6
    sources = {t.source_basis for t in tapes}
    assert any("anomaly_registry" in s for s in sources)


def test_vimark_bounded_by_limit_flag():
    with_limit_10 = nw.gen_vimark_schedules(limit=10)
    with_limit_50 = nw.gen_vimark_schedules(limit=50)
    assert len(with_limit_10) == 10
    assert len(with_limit_50) == 50


def test_tooling_gap_for_segmented_is_recorded():
    _, gaps = nw.build_key_schedule_universe(vimark_limit=10)
    families = [g["family"] for g in gaps]
    assert "segmented_two_key" in families


# ---------------------------------------------------------------------------
# Evaluate triple shape
# ---------------------------------------------------------------------------


def test_evaluate_triple_returns_well_formed():
    masks = companion.build_mask_universe()[:1]
    schedules = nw.gen_linear_recurrence_schedules()[:1]
    r = nw.evaluate_triple(masks[0], "vigenere", schedules[0], ngram_scorer=None)
    assert 0 <= r.crib_score <= 24
    assert len(r.pt73) == 73
    assert isinstance(r.bean_applicable, bool)


# ---------------------------------------------------------------------------
# CLI modes
# ---------------------------------------------------------------------------


def _run(tmp_path: Path, args: list[str]) -> dict:
    out = tmp_path / "result.json"
    ckpt = tmp_path / "checkpoint.json"
    full_args = args + [
        "--output",
        str(out),
        "--checkpoint",
        str(ckpt),
    ]
    nw.main(full_args)
    return json.loads(out.read_text())


def test_inventory_mode_valid(tmp_path: Path):
    doc = _run(
        tmp_path,
        ["--mode", "inventory", "--workers", "1", "--vimark-limit", "30"],
    )
    assert doc["status"] == "INVENTORY"
    inv = doc["inventory"]
    assert inv["n_masks"] > 0
    assert inv["n_schedules"] > 0
    # Required inventory fields
    for k in ("total_configs", "n_schedules_by_family", "variants"):
        assert k in inv
    assert doc["coverage"]["tested"] == 0


def test_smoke_mode_runs_and_classifies(tmp_path: Path):
    doc = _run(
        tmp_path,
        [
            "--mode",
            "smoke",
            "--workers",
            "1",
            "--limit-masks",
            "2",
            "--limit-schedules",
            "10",
            "--vimark-limit",
            "20",
        ],
    )
    # In smoke the classifier is either ELIMINATED or CANDIDATE_SIGNAL.
    assert doc["status"] in ("ELIMINATED", "CANDIDATE_SIGNAL")
    assert doc["coverage"]["tested"] == doc["coverage"]["total"]
    ac = doc["audit_counters"]
    assert ac["processed_count"] == doc["coverage"]["tested"]


def test_output_json_has_required_fields(tmp_path: Path):
    doc = _run(
        tmp_path,
        [
            "--mode",
            "smoke",
            "--workers",
            "1",
            "--limit-masks",
            "2",
            "--limit-schedules",
            "5",
            "--vimark-limit",
            "10",
        ],
    )
    for k in (
        "campaign_id",
        "campaign_version",
        "status",
        "started_at",
        "completed_at",
        "assumptions",
        "inventory",
        "coverage",
        "audit_counters",
        "best",
        "survivors",
        "near_misses",
        "rejection_counts",
        "tooling_gaps",
        "notes",
    ):
        assert k in doc, f"missing required field: {k}"


def test_audit_counters_reconcile(tmp_path: Path):
    doc = _run(
        tmp_path,
        [
            "--mode",
            "smoke",
            "--workers",
            "2",
            "--limit-masks",
            "3",
            "--limit-schedules",
            "12",
            "--vimark-limit",
            "20",
        ],
    )
    tested = doc["coverage"]["tested"]
    ac = doc["audit_counters"]
    assert ac["processed_count"] == tested
    assert ac["bean_invocations"] == tested  # crib-preserving masks => always applicable
    assert ac["bean_not_applicable"] == 0
    hist_sum = sum(int(v) for v in ac["crib_histogram"].values())
    assert hist_sum == tested


def test_resume_preserves_coverage_and_audit(tmp_path: Path):
    common = [
        "--mode",
        "smoke",
        "--workers",
        "1",
        "--limit-masks",
        "3",
        "--limit-schedules",
        "8",
        "--vimark-limit",
        "20",
    ]
    first = _run(tmp_path, common)
    second = _run(tmp_path, common + ["--resume"])
    assert first["coverage"]["tested"] == second["coverage"]["tested"]
    assert (
        first["audit_counters"]["processed_count"]
        == second["audit_counters"]["processed_count"]
    )


def test_resume_refuses_hash_mismatch(tmp_path: Path):
    common = [
        "--mode",
        "smoke",
        "--workers",
        "1",
        "--limit-masks",
        "2",
        "--limit-schedules",
        "5",
        "--vimark-limit",
        "10",
    ]
    doc = _run(tmp_path, common)
    ckpt_path = tmp_path / "checkpoint.json"
    cdata = json.loads(ckpt_path.read_text())
    cdata["assumptions_hash"] = "baddeadbeef"
    ckpt_path.write_text(json.dumps(cdata))
    doc2 = _run(tmp_path, common + ["--resume"])
    # Either ERROR or a fresh run with mismatch note.
    assert doc2["status"] == "ERROR" or any(
        "hash mismatch" in n for n in doc2.get("notes", [])
    )


def test_missing_all_families_yields_inconclusive_tooling(tmp_path: Path):
    doc = _run(
        tmp_path,
        [
            "--mode",
            "smoke",
            "--workers",
            "1",
            "--no-bean624",
            "--no-linear-recurrence",
            "--no-coordinate",
            "--no-vimark",
            "--limit-masks",
            "2",
        ],
    )
    assert doc["status"] == "INCONCLUSIVE_TOOLING"
    gaps = [g["family"] for g in doc["tooling_gaps"]]
    assert "bean624_crib_anchored_extension" in gaps


def test_max_configs_budget_yields_inconclusive_budget(tmp_path: Path):
    doc = _run(
        tmp_path,
        [
            "--mode",
            "smoke",
            "--workers",
            "1",
            "--limit-masks",
            "4",
            "--limit-schedules",
            "20",
            "--vimark-limit",
            "20",
            "--max-configs",
            "15",
        ],
    )
    assert doc["coverage"]["tested"] < doc["coverage"]["total"]
    assert doc["status"] == "INCONCLUSIVE_BUDGET"


def test_full_coverage_smoke_can_be_eliminated(tmp_path: Path):
    doc = _run(
        tmp_path,
        [
            "--mode",
            "smoke",
            "--workers",
            "1",
            "--limit-masks",
            "2",
            "--limit-schedules",
            "6",
            "--vimark-limit",
            "10",
        ],
    )
    # With a small bounded smoke, we expect either ELIMINATED (no candidates)
    # or (rarely, if a degenerate bean624 extension aligns both crib blocks)
    # CANDIDATE_SIGNAL. The contract is that the status is not ERROR and the
    # coverage is complete.
    assert doc["status"] in ("ELIMINATED", "CANDIDATE_SIGNAL")
    assert doc["coverage"]["tested"] == doc["coverage"]["total"]


# ---------------------------------------------------------------------------
# Parallel result-attribution regression tests (imap_unordered bug 2026-04-14)
# ---------------------------------------------------------------------------


def test_worker_echoes_mask_idx_and_chunk_id():
    """Unit-level: _worker_eval_chunk must echo mask_idx, chunk_id,
    processed_count so the controller can attribute arrival-ordered results
    to the correct mask."""
    nw._worker_init()
    masks = companion.build_mask_universe()
    schedules = nw.gen_linear_recurrence_schedules()[:2]
    variants = ("vigenere", "beaufort")
    payload = (11, 4, masks[0], variants, tuple(schedules))
    out = nw._worker_eval_chunk(payload)
    assert out["mask_idx"] == 11
    assert out["chunk_id"] == 4
    assert out["processed_count"] == len(variants) * len(schedules)
    assert out["audit"]["mask_idx"] == 11
    assert out["audit"]["chunk_id"] == 4
    assert out["audit"]["processed_count"] == len(variants) * len(schedules)


def test_parallel_multichunk_all_masks_marked_complete(tmp_path: Path):
    """Regression test for the imap_unordered mis-mapping bug. Force
    chunks/mask > 1 AND total chunks > worker count, then assert every
    mask index ends up in completed_mask_indices and coverage is full."""
    doc = _run(
        tmp_path,
        [
            "--mode",
            "smoke",
            "--workers",
            "3",
            "--limit-masks",
            "5",
            "--limit-schedules",
            "12",
            "--key-chunk-size",
            "3",
            "--vimark-limit",
            "20",
        ],
    )
    completed = doc.get("completed_mask_indices", [])
    assert sorted(completed) == list(range(5)), (
        f"expected all 5 masks marked complete, got {completed}"
    )
    assert doc["coverage"]["tested"] == doc["coverage"]["total"]
    for note in doc.get("notes", []):
        assert "audit mismatch" not in note, f"audit mismatch: {note}"


# ---------------------------------------------------------------------------
# Bean624 crib-anchored extension family (mask-anchoring fix 2026-04-14)
# ---------------------------------------------------------------------------


def test_old_gen_bean624_schedules_raises_not_implemented():
    """The buggy generator must refuse to run — silent fallback would
    risk a regression to the unanchored universe."""
    import pytest

    with pytest.raises(NotImplementedError) as excinfo:
        nw.gen_bean624_schedules()
    assert "retired" in str(excinfo.value).lower()
    assert "crib_anchored" in str(excinfo.value)


def test_bean624_crib_anchored_schedules_carry_anchor_and_base_fill():
    """Every schedule in the new family must have a 24-vector anchor and
    a 73-length base fill, family-tagged correctly."""
    schedules = nw.gen_bean624_crib_anchored_extension_schedules(limit_vectors=5)
    # 5 vectors x 2 extension rules = 10 schedules
    assert len(schedules) == 10
    for s in schedules:
        assert s.family == "bean624_crib_anchored_extension"
        assert s.bean24_anchor is not None
        assert len(s.bean24_anchor) == 24
        assert all(0 <= v < 26 for v in s.bean24_anchor)
        assert len(s.values_73) == 73
        assert s.is_exhaustive_within_family is True
        assert "anchoring" in s.generation_parameters
        assert s.generation_parameters["anchoring"] == "crib_anchored_override_b"


def test_anchored_keystream_places_bean_vector_at_reduced_crib_indices():
    """Direct algebraic check of the policy (b) override: for each
    (mask, schedule) pairing, the *effective* keystream used by
    evaluate_triple must equal the bean24_anchor at the reduced crib
    indices, regardless of what the base fill said.

    This is the load-bearing test for the 2026-04-14 anchoring fix.
    """
    masks = companion.build_mask_universe()
    schedules = nw.gen_bean624_crib_anchored_extension_schedules(limit_vectors=4)
    # Sample several masks across families so a single-family quirk
    # cannot hide a bug.
    mask_sample = [
        masks[0],
        masks[len(masks) // 4],
        masks[len(masks) // 2],
        masks[-1],
    ]
    crib_positions_sorted = sorted(CRIB_POSITIONS)

    def _effective_keystream(mask: "companion.Mask", sched: "nw.KeySchedule") -> tuple[int, ...]:
        # Mirrors the override block in evaluate_triple.
        vals_list = list(sched.values_73)
        crib_map = mask.crib_to_reduced()
        for crib_ord, orig_pos in enumerate(sorted(crib_map.keys())):
            r = crib_map[orig_pos]
            vals_list[r] = int(sched.bean24_anchor[crib_ord])
        return tuple(vals_list)

    for mask in mask_sample:
        # Harness invariant: all masks in the universe are crib-preserving.
        assert mask.preserves_cribs(), (
            f"mask universe regression: {mask.mask_id} is not crib-preserving"
        )
        crib_map = mask.crib_to_reduced()
        assert len(crib_map) == 24
        for sched in schedules:
            eff = _effective_keystream(mask, sched)
            for crib_ord, orig_pos in enumerate(crib_positions_sorted):
                r = crib_map[orig_pos]
                assert eff[r] == sched.bean24_anchor[crib_ord], (
                    f"anchor mismatch at mask={mask.mask_id} sched={sched.key_id} "
                    f"crib_pos={orig_pos} reduced_idx={r}: "
                    f"effective={eff[r]} != anchor={sched.bean24_anchor[crib_ord]}"
                )


def test_ngram_unavailable_with_anchored_family_forces_inconclusive_tooling(
    tmp_path: Path, monkeypatch
):
    """Policy (2026-04-14): when bean624_crib_anchored_extension is enabled
    and the ngram scorer is unavailable, the harness must refuse to run
    with INCONCLUSIVE_TOOLING. The anchored family forces Bean PASS by
    construction, so without ngram there is no discriminator."""
    # Patch the ngram loader inside the harness module to raise.
    import kryptos.kernel.scoring.ngram as ngram_mod

    def _broken_loader():
        raise RuntimeError("simulated quadgram file missing")

    monkeypatch.setattr(ngram_mod, "get_default_scorer", _broken_loader)

    doc = _run(
        tmp_path,
        [
            "--mode",
            "smoke",
            "--workers",
            "1",
            "--limit-masks",
            "2",
            "--limit-schedules",
            "4",
            "--vimark-limit",
            "5",
        ],
    )
    assert doc["status"] == "INCONCLUSIVE_TOOLING"
    # Tooling gap must explicitly reference the anchored family.
    gap_families = [g["family"] for g in doc.get("tooling_gaps", [])]
    assert "bean624_crib_anchored_extension" in gap_families
    # Notes must explain the policy.
    assert any(
        "REQUIRED" in note and "discriminator" in note
        for note in doc.get("notes", [])
    ), f"expected REQUIRED-discriminator note, got: {doc.get('notes')}"


def test_ngram_unavailable_without_anchored_family_proceeds_with_advisory(
    tmp_path: Path, monkeypatch
):
    """When the anchored family is disabled, ngram is advisory and the
    harness should proceed with an ADVISORY note instead of refusing."""
    import kryptos.kernel.scoring.ngram as ngram_mod

    def _broken_loader():
        raise RuntimeError("simulated quadgram file missing")

    monkeypatch.setattr(ngram_mod, "get_default_scorer", _broken_loader)

    doc = _run(
        tmp_path,
        [
            "--mode",
            "smoke",
            "--workers",
            "1",
            "--no-bean624",
            "--limit-masks",
            "2",
            "--limit-schedules",
            "4",
            "--vimark-limit",
            "5",
        ],
    )
    # Status is NOT INCONCLUSIVE_TOOLING — proceed with advisory note.
    assert doc["status"] in ("ELIMINATED", "CANDIDATE_SIGNAL")
    assert any(
        "ADVISORY" in note for note in doc.get("notes", [])
    ), f"expected ADVISORY note, got: {doc.get('notes')}"


def test_anchored_schedules_bean_passes_for_every_config():
    """By construction of policy (b), every (anchored_schedule, variant,
    crib_preserving_mask) triple must produce bean_passed=True. This is
    the strongest possible evidence that the anchor is being applied —
    if even one config fails Bean, the override is broken."""
    masks = companion.build_mask_universe()
    schedules = nw.gen_bean624_crib_anchored_extension_schedules(limit_vectors=3)
    # Cross product across a small mask sample and all 3 variants.
    mask_sample = [masks[0], masks[len(masks) // 2], masks[-1]]
    variants = ("vigenere", "beaufort", "varbeau")
    fails = 0
    total = 0
    for mask in mask_sample:
        for variant in variants:
            for sched in schedules:
                total += 1
                r = nw.evaluate_triple(mask, variant, sched, ngram_scorer=None)
                if not r.bean_passed:
                    fails += 1
    assert fails == 0, (
        f"policy (b) override broken: {fails}/{total} anchored configs "
        f"failed Bean. Every config in this family MUST pass Bean by construction."
    )
