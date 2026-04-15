"""Tests for scripts/hypothesis_tests/h_624_73_nullmask_harness.py."""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Make the script importable.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "hypothesis_tests"))

import h_624_73_nullmask_harness as harness  # noqa: E402

from kryptos.kernel.constants import (  # noqa: E402
    BREAKTHROUGH_THRESHOLD,
    CRIB_POSITIONS,
    CT_LEN,
    NOISE_FLOOR,
    SIGNAL_THRESHOLD,
    STORE_THRESHOLD,
)


# ---------------------------------------------------------------------------
# Mask construction invariants
# ---------------------------------------------------------------------------


def test_head_tail_masks_shapes():
    hd = harness.gen_head_block_masks()
    tl = harness.gen_tail_block_masks()
    assert len(hd) == 1 and len(tl) == 1
    for m in hd + tl:
        assert len(m.deleted_positions) == 24
        assert len(m.kept_positions) == 73
        assert set(m.deleted_positions).isdisjoint(CRIB_POSITIONS)
        assert set(m.kept_positions) | set(m.deleted_positions) == set(range(CT_LEN))


def test_periodic_step_masks_all_preserve_cribs_and_have_correct_size():
    masks = harness.gen_periodic_step_masks()
    for m in masks:
        assert len(m.deleted_positions) == 24
        assert len(m.kept_positions) == 73
        assert set(m.deleted_positions).isdisjoint(CRIB_POSITIONS)
        assert m.preserves_cribs()


def test_residue_class_masks_preserve_cribs():
    # Residue-class masks may legitimately be empty because cribs occupy
    # two contiguous blocks and tend to intersect most residue classes.
    # If any are produced, they must be valid.
    masks = harness.gen_residue_class_masks()
    for m in masks:
        assert len(m.deleted_positions) == 24
        assert set(m.deleted_positions).isdisjoint(CRIB_POSITIONS)


def test_width_row_column_masks_preserve_cribs_and_24_cells():
    for m in harness.gen_width_row_masks() + harness.gen_width_column_masks():
        assert len(m.deleted_positions) == 24
        assert set(m.deleted_positions).isdisjoint(CRIB_POSITIONS)


def test_build_mask_universe_is_deterministic():
    a = harness.build_mask_universe()
    b = harness.build_mask_universe()
    assert [m.mask_id for m in a] == [m.mask_id for m in b]
    # No duplicates by deleted_positions.
    dedupe = {m.deleted_positions for m in a}
    assert len(dedupe) == len(a)


def test_random_masks_seeded():
    a = harness.gen_random_sampled_masks(5, seed=42)
    b = harness.gen_random_sampled_masks(5, seed=42)
    assert [m.mask_id for m in a] == [m.mask_id for m in b]
    c = harness.gen_random_sampled_masks(5, seed=43)
    assert [m.mask_id for m in a] != [m.mask_id for m in c]


def test_mask_crib_to_reduced_maps_all_cribs_in_crib_preserving_mask():
    m = harness.gen_head_block_masks()[0]
    mapping = m.crib_to_reduced()
    assert set(mapping.keys()) == set(CRIB_POSITIONS)
    # All reduced indices are in [0, 73)
    for r in mapping.values():
        assert 0 <= r < 73


# ---------------------------------------------------------------------------
# Universe and assumption hashes
# ---------------------------------------------------------------------------


def test_assumptions_hash_stable_across_calls():
    a1 = harness.hash_dict(harness.build_assumptions())
    a2 = harness.hash_dict(harness.build_assumptions())
    assert a1 == a2


def test_universe_hash_stable_across_dry_runs(tmp_path: Path):
    masks = harness.build_mask_universe()[:10]
    keys = harness.build_key_universe(limit_thematic=5)
    variants = tuple(harness.CIPHER_VARIANTS)
    h1 = harness.compute_universe_hash(masks, keys, variants)
    h2 = harness.compute_universe_hash(masks, keys, variants)
    assert h1 == h2
    # Changing content changes the hash.
    h3 = harness.compute_universe_hash(masks[:9], keys, variants)
    assert h1 != h3


# ---------------------------------------------------------------------------
# Evaluation core
# ---------------------------------------------------------------------------


def test_evaluate_triple_crib_preserving_mask_returns_well_formed():
    m = harness.gen_head_block_masks()[0]
    k = harness.Key(
        key_id="test:ABCDE", family="test", keyword="ABCDE", period=5, source="test"
    )
    r = harness.evaluate_triple(m, "vigenere", k, ngram_scorer=None)
    assert r.bean_applicable is True
    assert r.assumption_violated is False
    assert len(r.pt73) == 73
    assert 0 <= r.crib_score <= 24


def test_evaluate_triple_non_crib_preserving_is_assumption_violated():
    # Construct a deliberately invalid mask that deletes a crib position.
    forced_del = tuple(sorted([21] + list(harness.NON_CRIB_POSITIONS[:23])))
    assert 21 in forced_del
    bad = harness.Mask(
        mask_id="bad",
        family="test_bad",
        description="deliberately deletes crib pos 21",
        deleted_positions=forced_del,
        kept_positions=tuple(p for p in range(CT_LEN) if p not in set(forced_del)),
        is_exhaustive_within_family=False,
        generation_parameters={},
    )
    k = harness.Key(
        key_id="test:AAAA", family="test", keyword="AAAA", period=4, source="test"
    )
    r = harness.evaluate_triple(bad, "beaufort", k, ngram_scorer=None)
    assert r.assumption_violated is True
    assert r.crib_score == 0
    assert r.rejection_reason.startswith("assumption_violated")


# ---------------------------------------------------------------------------
# Inventory / dry-run / smoke
# ---------------------------------------------------------------------------


def test_inventory_mode_writes_output_without_evaluating(tmp_path: Path):
    out = tmp_path / "result.json"
    ckpt = tmp_path / "checkpoint.json"
    rc = harness.main(
        [
            "--mode",
            "inventory",
            "--output",
            str(out),
            "--checkpoint",
            str(ckpt),
            "--workers",
            "1",
        ]
    )
    assert rc == 0
    doc = json.loads(out.read_text())
    assert doc["status"] == "INVENTORY"
    assert doc["inventory"]["n_masks"] >= 10
    assert doc["inventory"]["total_configs"] > 0
    assert doc["assumptions"]["assumes_direct_positional_crib_mapping"] is True
    assert doc["coverage"]["tested"] == 0
    # No evaluation happened.
    assert doc["survivors"] == []


def test_dry_run_is_inventory(tmp_path: Path):
    out = tmp_path / "result.json"
    ckpt = tmp_path / "checkpoint.json"
    rc = harness.main(
        [
            "--dry-run",
            "--output",
            str(out),
            "--checkpoint",
            str(ckpt),
            "--workers",
            "1",
        ]
    )
    assert rc == 0
    doc = json.loads(out.read_text())
    assert doc["status"] == "INVENTORY"


def test_smoke_mode_runs_bounded_universe(tmp_path: Path):
    out = tmp_path / "result.json"
    ckpt = tmp_path / "checkpoint.json"
    rc = harness.main(
        [
            "--mode",
            "smoke",
            "--output",
            str(out),
            "--checkpoint",
            str(ckpt),
            "--workers",
            "1",
            "--limit-masks",
            "3",
            "--limit-keys",
            "5",
        ]
    )
    assert rc == 0
    doc = json.loads(out.read_text())
    # tested == n_masks * n_keys * n_variants (3*5*3 = 45)
    assert doc["coverage"]["tested"] == 3 * 5 * 3
    assert doc["coverage"]["total"] == 3 * 5 * 3
    assert doc["status"] in ("ELIMINATED", "CANDIDATE_SIGNAL")
    # no signal from a 15-config smoke with random keywords
    assert doc["status"] == "ELIMINATED"


# ---------------------------------------------------------------------------
# Output schema completeness
# ---------------------------------------------------------------------------


REQUIRED_OUTPUT_KEYS = {
    "campaign_id",
    "campaign_version",
    "status",
    "started_at",
    "completed_at",
    "assumptions",
    "inventory",
    "coverage",
    "best",
    "survivors",
    "rejection_counts",
    "notes",
}


def test_output_json_has_all_required_fields(tmp_path: Path):
    out = tmp_path / "result.json"
    ckpt = tmp_path / "checkpoint.json"
    harness.main(
        [
            "--mode",
            "smoke",
            "--output",
            str(out),
            "--checkpoint",
            str(ckpt),
            "--workers",
            "1",
            "--limit-masks",
            "2",
            "--limit-keys",
            "3",
        ]
    )
    doc = json.loads(out.read_text())
    missing = REQUIRED_OUTPUT_KEYS - set(doc.keys())
    assert not missing, f"missing required keys: {missing}"


# ---------------------------------------------------------------------------
# Checkpoint / resume
# ---------------------------------------------------------------------------


def test_resume_with_matching_hashes_does_not_duplicate_work(tmp_path: Path):
    out = tmp_path / "result.json"
    ckpt = tmp_path / "checkpoint.json"
    # First run: complete fully.
    harness.main(
        [
            "--mode",
            "smoke",
            "--output",
            str(out),
            "--checkpoint",
            str(ckpt),
            "--workers",
            "1",
            "--limit-masks",
            "3",
            "--limit-keys",
            "3",
        ]
    )
    first = json.loads(out.read_text())
    first_tested = first["coverage"]["tested"]
    # Second run with --resume should find everything completed and do zero extra work.
    harness.main(
        [
            "--mode",
            "smoke",
            "--output",
            str(out),
            "--checkpoint",
            str(ckpt),
            "--workers",
            "1",
            "--limit-masks",
            "3",
            "--limit-keys",
            "3",
            "--resume",
        ]
    )
    second = json.loads(out.read_text())
    assert second["coverage"]["tested"] == first_tested


def test_resume_refuses_hash_mismatch(tmp_path: Path):
    out = tmp_path / "result.json"
    ckpt = tmp_path / "checkpoint.json"
    harness.main(
        [
            "--mode",
            "smoke",
            "--output",
            str(out),
            "--checkpoint",
            str(ckpt),
            "--workers",
            "1",
            "--limit-masks",
            "2",
            "--limit-keys",
            "3",
        ]
    )
    # Mutate the checkpoint's assumptions_hash.
    doc = json.loads(ckpt.read_text())
    doc["assumptions_hash"] = "deadbeef"
    ckpt.write_text(json.dumps(doc))
    # Running with --resume should refuse (status=ERROR, notes mention mismatch).
    harness.main(
        [
            "--mode",
            "smoke",
            "--output",
            str(out),
            "--checkpoint",
            str(ckpt),
            "--workers",
            "1",
            "--limit-masks",
            "2",
            "--limit-keys",
            "3",
            "--resume",
        ]
    )
    second = json.loads(out.read_text())
    # Either an ERROR status with a mismatch note, or a fresh run that ignored
    # the bad checkpoint (we pick ERROR path for strict safety).
    assert second["status"] == "ERROR" or any(
        "hash mismatch" in n for n in second.get("notes", [])
    )


# ---------------------------------------------------------------------------
# Budget vs elimination epistemic distinction
# ---------------------------------------------------------------------------


def test_max_configs_limit_returns_inconclusive_budget(tmp_path: Path):
    out = tmp_path / "result.json"
    ckpt = tmp_path / "checkpoint.json"
    # Force a tight budget that cannot cover the universe.
    harness.main(
        [
            "--mode",
            "smoke",
            "--output",
            str(out),
            "--checkpoint",
            str(ckpt),
            "--workers",
            "1",
            "--limit-masks",
            "5",
            "--limit-keys",
            "10",
            "--max-configs",
            "12",
        ]
    )
    doc = json.loads(out.read_text())
    # Total would be 5*10*3 = 150; budget 12 forces partial coverage.
    assert doc["coverage"]["tested"] < doc["coverage"]["total"]
    assert doc["status"] == "INCONCLUSIVE_BUDGET"


# ---------------------------------------------------------------------------
# Forensic audit counters (Part A hardening)
# ---------------------------------------------------------------------------


def _run_smoke_and_load(tmp_path: Path, workers: int = 1, **extra) -> dict:
    out = tmp_path / "result.json"
    ckpt = tmp_path / "checkpoint.json"
    argv = [
        "--mode",
        "smoke",
        "--output",
        str(out),
        "--checkpoint",
        str(ckpt),
        "--workers",
        str(workers),
    ]
    for k, v in extra.items():
        argv += [f"--{k.replace('_', '-')}", str(v)]
    harness.main(argv)
    return json.loads(out.read_text())


def test_audit_counters_exist_and_nonempty(tmp_path: Path):
    doc = _run_smoke_and_load(tmp_path, workers=1, limit_masks=3, limit_keys=5)
    ac = doc.get("audit_counters", {})
    assert ac, "audit_counters must not be empty after a smoke run"
    assert ac["processed_count"] > 0
    assert ac["bean_invocations"] > 0
    assert "crib_histogram" in ac and ac["crib_histogram"]


def test_audit_counters_reconcile_to_tested(tmp_path: Path):
    doc = _run_smoke_and_load(tmp_path, workers=2, limit_masks=4, limit_keys=6)
    tested = doc["coverage"]["tested"]
    ac = doc["audit_counters"]
    assert ac["processed_count"] == tested
    assert ac["bean_invocations"] == tested  # crib-preserving masks => always applicable
    assert ac["bean_not_applicable"] == 0
    # crib histogram entries sum to tested (keys may be int or str after JSON round-trip)
    hist_sum = sum(int(v) for v in ac["crib_histogram"].values())
    assert hist_sum == tested
    # bean_pass + bean_fail + bean_not_applicable == tested
    bean_sum = ac["bean_pass"] + ac["bean_fail"] + ac["bean_not_applicable"]
    assert bean_sum == tested
    # ngram_invocations equals tested when scorer loads successfully
    assert ac["ngram_invocations"] in (0, tested)


def test_per_worker_audit_sums_match_global(tmp_path: Path):
    doc = _run_smoke_and_load(tmp_path, workers=4, limit_masks=5, limit_keys=6)
    ac = doc["audit_counters"]
    pw = doc["per_worker_audit"]
    assert pw, "per_worker_audit must not be empty"
    assert sum(int(e["processed_count"]) for e in pw) == int(ac["processed_count"])
    assert sum(int(e["bean_invocations"]) for e in pw) == int(ac["bean_invocations"])
    assert sum(int(e["bean_pass"]) for e in pw) == int(ac["bean_pass"])
    assert sum(int(e["bean_fail"]) for e in pw) == int(ac["bean_fail"])
    # Stable sort order: processed_count descending.
    processed = [int(e["processed_count"]) for e in pw]
    assert processed == sorted(processed, reverse=True)


def test_audit_no_note_mismatch(tmp_path: Path):
    doc = _run_smoke_and_load(tmp_path, workers=3, limit_masks=4, limit_keys=5)
    for note in doc.get("notes", []):
        assert "audit mismatch" not in note, f"audit reconciliation warning: {note}"


def test_near_misses_deterministic_sort_and_capped(tmp_path: Path):
    # Build an artificial near-miss list to confirm the sort key.
    a = {"crib_score": 5, "ngram_per_char": -3.0, "mask_id": "m1", "variant": "vigenere", "key_id": "k1"}
    b = {"crib_score": 8, "ngram_per_char": -2.5, "mask_id": "m2", "variant": "beaufort", "key_id": "k2"}
    c = {"crib_score": 8, "ngram_per_char": -2.5, "mask_id": "m1", "variant": "beaufort", "key_id": "k2"}
    bucket: list[dict] = []
    for e in (a, b, c):
        harness._insert_near_miss(bucket, e, cap=10)
    # Expected order: higher crib_score first; on tie, mask_id asc.
    assert bucket[0]["mask_id"] == "m1" and bucket[0]["crib_score"] == 8
    assert bucket[1]["mask_id"] == "m2" and bucket[1]["crib_score"] == 8
    assert bucket[2]["crib_score"] == 5
    # Cap enforcement.
    more = [
        {
            "crib_score": i % 10,
            "ngram_per_char": 0.0,
            "mask_id": f"mm{i}",
            "variant": "v",
            "key_id": f"k{i}",
        }
        for i in range(50)
    ]
    for e in more:
        harness._insert_near_miss(bucket, e, cap=10)
    assert len(bucket) == 10


def test_distinct_pt73_sampling_present(tmp_path: Path):
    doc = _run_smoke_and_load(tmp_path, workers=1, limit_masks=3, limit_keys=5)
    ac = doc["audit_counters"]
    assert ac["pt73_distinct_total"] >= 1
    # Fingerprints are 12-char hex strings.
    fps = ac["pt73_fingerprints"]
    assert all(isinstance(f, str) and len(f) == 12 for f in fps)


def test_resume_preserves_audit_totals(tmp_path: Path):
    """After a full run, --resume should be a no-op that preserves audit totals."""
    out = tmp_path / "result.json"
    ckpt = tmp_path / "checkpoint.json"
    common = [
        "--mode",
        "smoke",
        "--output",
        str(out),
        "--checkpoint",
        str(ckpt),
        "--workers",
        "1",
        "--limit-masks",
        "3",
        "--limit-keys",
        "4",
    ]
    harness.main(common)
    first = json.loads(out.read_text())
    harness.main(common + ["--resume"])
    second = json.loads(out.read_text())
    assert first["audit_counters"]["processed_count"] == second["audit_counters"]["processed_count"]


def test_full_coverage_no_survivors_returns_eliminated(tmp_path: Path):
    out = tmp_path / "result.json"
    ckpt = tmp_path / "checkpoint.json"
    harness.main(
        [
            "--mode",
            "smoke",
            "--output",
            str(out),
            "--checkpoint",
            str(ckpt),
            "--workers",
            "1",
            "--limit-masks",
            "2",
            "--limit-keys",
            "2",
        ]
    )
    doc = json.loads(out.read_text())
    assert doc["coverage"]["tested"] == doc["coverage"]["total"]
    # 2*2*3 = 12 random-keyword evaluations won't hit signal
    assert doc["status"] == "ELIMINATED"


# ---------------------------------------------------------------------------
# Parallel result-attribution regression tests
# ---------------------------------------------------------------------------
#
# These tests cover the imap_unordered mis-mapping bug identified on
# 2026-04-14 by third-party review. The bug: the old controller loop did
# `for i, out in enumerate(pool.imap_unordered(...)): mi = mi_lookup[i]`,
# which associates results with their *arrival rank*, not their input index.
# The fix: payloads now carry (mask_idx, chunk_id, ...) and workers echo
# `mask_idx`, `chunk_id`, and `processed_count` so the controller can
# attribute results correctly regardless of arrival order.


def test_worker_echoes_mask_idx_and_chunk_id():
    """Unit-level: _worker_eval_chunk must echo mask_idx, chunk_id,
    processed_count for the controller to attribute results correctly."""
    # Build a minimal synthetic payload using the harness's own helpers.
    harness._worker_init()
    masks = harness.build_mask_universe()
    keys = harness.build_key_universe(limit_thematic=2)
    variants = ("vigenere", "beaufort")
    payload = (7, 3, masks[0], variants, tuple(keys[:2]))
    out = harness._worker_eval_chunk(payload)
    assert out["mask_idx"] == 7, "worker must echo mask_idx unchanged"
    assert out["chunk_id"] == 3, "worker must echo chunk_id unchanged"
    expected_processed = len(variants) * len(keys)
    assert out["processed_count"] == expected_processed
    # Audit block must also carry the identity fields so per-worker
    # attribution downstream works.
    assert out["audit"]["mask_idx"] == 7
    assert out["audit"]["chunk_id"] == 3
    assert out["audit"]["processed_count"] == expected_processed


def test_parallel_multichunk_all_masks_marked_complete(tmp_path: Path):
    """Regression test for the imap_unordered mis-mapping bug.

    Force chunk_count per mask > 1 AND total chunks > worker count. If the
    controller is using arrival rank to attribute mask completion, the wrong
    masks get marked complete and coverage accounting drifts. This test
    asserts that after a full run:
      - every expected mask index appears in completed_mask_indices,
      - coverage.tested equals coverage.total,
      - no audit-mismatch note is appended.
    """
    out = tmp_path / "result.json"
    ckpt = tmp_path / "checkpoint.json"
    # 6 masks x 8 keys with key-chunk-size=2 yields 4 chunks/mask = 24 chunks
    # across 3 workers. Out-of-order arrival is essentially guaranteed.
    harness.main(
        [
            "--mode",
            "smoke",
            "--output",
            str(out),
            "--checkpoint",
            str(ckpt),
            "--workers",
            "3",
            "--limit-masks",
            "6",
            "--limit-keys",
            "8",
            "--key-chunk-size",
            "2",
        ]
    )
    doc = json.loads(out.read_text())
    # All masks must be marked complete.
    completed = doc.get("completed_mask_indices", [])
    assert sorted(completed) == list(range(6)), (
        f"expected all 6 masks marked complete, got {completed}"
    )
    # Coverage must equal total (full run, no INCONCLUSIVE_BUDGET).
    assert doc["coverage"]["tested"] == doc["coverage"]["total"]
    # No reconciliation warnings.
    for note in doc.get("notes", []):
        assert "audit mismatch" not in note, f"audit mismatch: {note}"
    # Per-mask charge check: coverage.tested should equal 6 masks * n_keys
    # * n_variants where n_keys and n_variants come from inventory.
    inv = doc["inventory"]
    expected_total = inv["n_masks"] * inv["n_keys"] * inv["n_variants"]
    assert doc["coverage"]["total"] == expected_total
    assert doc["coverage"]["tested"] == expected_total


def test_parallel_resume_after_partial_completion(tmp_path: Path):
    """Run the harness twice with --max-configs to force a resume. The
    second run must pick up where the first left off. Under the old bug,
    completed_mask_indices could include masks whose chunks weren't yet
    processed, corrupting resume state.
    """
    out1 = tmp_path / "r1.json"
    out2 = tmp_path / "r2.json"
    ckpt = tmp_path / "ckpt.json"
    # First run: limit to a small budget to force partial completion.
    harness.main(
        [
            "--mode",
            "smoke",
            "--output",
            str(out1),
            "--checkpoint",
            str(ckpt),
            "--workers",
            "2",
            "--limit-masks",
            "4",
            "--limit-keys",
            "6",
            "--key-chunk-size",
            "2",
            "--max-configs",
            "24",
        ]
    )
    doc1 = json.loads(out1.read_text())
    # Partial run: at least one mask may have finished, but not all four.
    completed_after_run1 = set(doc1.get("completed_mask_indices", []))
    # Second run: no max-configs, should resume and complete.
    harness.main(
        [
            "--mode",
            "smoke",
            "--output",
            str(out2),
            "--checkpoint",
            str(ckpt),
            "--workers",
            "2",
            "--limit-masks",
            "4",
            "--limit-keys",
            "6",
            "--key-chunk-size",
            "2",
            "--resume",
        ]
    )
    doc2 = json.loads(out2.read_text())
    completed_after_run2 = set(doc2.get("completed_mask_indices", []))
    # Resume must preserve all previously-completed masks.
    assert completed_after_run1 <= completed_after_run2
    # Second run must finish everything.
    assert completed_after_run2 == set(range(4))
    assert doc2["coverage"]["tested"] == doc2["coverage"]["total"]
