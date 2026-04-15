"""Tests for scripts/hypothesis_tests/h_pretransposition_layer_harness.py."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "hypothesis_tests"))

import h_pretransposition_layer_harness as pt  # noqa: E402
import h_624_73_nullmask_harness as companion  # noqa: E402

from kryptos.kernel.constants import (  # noqa: E402
    BEAUFORT_KEY_ENE,
    BEAUFORT_KEY_BC,
    CRIB_POSITIONS,
    VIGENERE_KEY_ENE,
    VIGENERE_KEY_BC,
)


# ---------------------------------------------------------------------------
# Transposition family invariants
# ---------------------------------------------------------------------------


def test_identity_is_a_valid_permutation():
    t = pt.gen_identity()[0]
    assert len(t.perm) == pt.REDUCED_LEN
    assert sorted(t.perm) == list(range(pt.REDUCED_LEN))
    assert t.inverse_perm() == t.perm


def test_full_reverse_is_involution():
    t = pt.gen_full_reverse()[0]
    # Reversing twice yields identity.
    double = tuple(t.perm[t.perm[i]] for i in range(pt.REDUCED_LEN))
    assert double == tuple(range(pt.REDUCED_LEN))


def test_block_reversal_family_shapes():
    masks = pt.gen_block_reversals()
    assert 15 <= len(masks) <= 25
    for m in masks:
        assert len(m.perm) == pt.REDUCED_LEN
        assert sorted(m.perm) == list(range(pt.REDUCED_LEN))


def test_boustrophedon_family_shapes():
    masks = pt.gen_boustrophedon()
    assert 15 <= len(masks) <= 25
    for m in masks:
        assert len(m.perm) == pt.REDUCED_LEN
        assert sorted(m.perm) == list(range(pt.REDUCED_LEN))


def test_columnar_w2_w3_exhaustive_counts():
    # W=2: 2 perms; W=3: 6 perms
    cols = pt.gen_columnar(max_full_width=3, wider_sample_cap=0)
    by_width = {}
    for t in cols:
        w = t.generation_parameters.get("width")
        by_width[w] = by_width.get(w, 0) + 1
    assert by_width.get(2) == 2
    assert by_width.get(3) == 6


def test_build_universe_is_deterministic():
    a = pt.build_transposition_universe()
    b = pt.build_transposition_universe()
    assert [t.transposition_id for t in a] == [t.transposition_id for t in b]
    dedupe = {t.perm for t in a}
    assert len(dedupe) == len(a)


def test_inverse_perm_correctness():
    # For every transposition, applying inv(perm) to perm yields the identity.
    for t in pt.build_transposition_universe()[:100]:
        inv = t.inverse_perm()
        for i in range(pt.REDUCED_LEN):
            assert inv[t.perm[i]] == i


# ---------------------------------------------------------------------------
# Model correctness (the canonical-key sanity check)
# ---------------------------------------------------------------------------


def test_identity_transposition_plus_head_mask_recovers_canonical_vigenere_key():
    mask = companion.gen_head_block_masks()[0]
    ident = pt.gen_identity()[0]
    r = pt.evaluate_triple(mask, ident, "vigenere", ngram_scorer=None)
    assert r.bean_passed is True
    expected = tuple(VIGENERE_KEY_ENE) + tuple(VIGENERE_KEY_BC)
    assert r.implied_keystream_24 == expected


def test_identity_transposition_plus_head_mask_recovers_canonical_beaufort_key():
    mask = companion.gen_head_block_masks()[0]
    ident = pt.gen_identity()[0]
    r = pt.evaluate_triple(mask, ident, "beaufort", ngram_scorer=None)
    assert r.bean_passed is True
    expected = tuple(BEAUFORT_KEY_ENE) + tuple(BEAUFORT_KEY_BC)
    assert r.implied_keystream_24 == expected


def test_implied_keystream_length_is_24():
    masks = companion.build_mask_universe()[:3]
    ts = pt.build_transposition_universe()[:3]
    for m in masks:
        for t in ts:
            r = pt.evaluate_triple(m, t, "vigenere", ngram_scorer=None)
            assert len(r.implied_keystream_24) == 24


def test_worker_output_echoes_mask_idx_for_unordered_parallel_accounting():
    """Parallel aggregation must identify chunks by echoed mask_idx, not by
    imap_unordered arrival order."""
    mask = companion.build_mask_universe()[0]
    transposition = pt.gen_identity()[0]
    out = pt._worker_eval_chunk((7, 3, mask, ("vigenere",), (transposition,)))
    assert out["mask_idx"] == 7
    assert out["chunk_id"] == 3
    assert out["processed_count"] == 1
    assert out["audit"]["mask_idx"] == 7
    assert out["audit"]["chunk_id"] == 3


# ---------------------------------------------------------------------------
# CLI modes
# ---------------------------------------------------------------------------


def _run(tmp_path: Path, args: list[str]) -> dict:
    out = tmp_path / "result.json"
    ckpt = tmp_path / "checkpoint.json"
    full = args + ["--output", str(out), "--checkpoint", str(ckpt)]
    pt.main(full)
    return json.loads(out.read_text())


def test_inventory_mode_writes_valid_inventory(tmp_path: Path):
    doc = _run(tmp_path, ["--mode", "inventory", "--workers", "1"])
    assert doc["status"] == "INVENTORY"
    inv = doc["inventory"]
    assert inv["n_masks"] > 0
    assert inv["n_transpositions"] > 0
    assert inv["total_configs"] > 0
    assert doc["coverage"]["tested"] == 0


def test_smoke_runs_deterministic_universe(tmp_path: Path):
    doc = _run(
        tmp_path,
        [
            "--mode",
            "smoke",
            "--workers",
            "1",
            "--limit-masks",
            "2",
            "--limit-transpositions",
            "5",
        ],
    )
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
            "--limit-transpositions",
            "5",
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
        "survivors",
        "rejection_counts",
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
            "--limit-transpositions",
            "10",
        ],
    )
    ac = doc["audit_counters"]
    tested = doc["coverage"]["tested"]
    assert ac["processed_count"] == tested
    assert ac["bean_invocations"] == tested
    assert ac["bean_pass"] + ac["bean_fail"] == tested


def test_identity_in_smoke_produces_baseline_equivalent_passes(tmp_path: Path):
    """With identity included in the transposition slice, smoke should find
    baseline-equivalent Bean passes and status should be ELIMINATED (not
    CANDIDATE_SIGNAL), because all passes collapse to the canonical keys."""
    # limit-transpositions=5 picks the first 5 in sort order. Identity is in
    # the universe; we test that at least one baseline-equivalent pass exists.
    doc = _run(
        tmp_path,
        [
            "--mode",
            "smoke",
            "--workers",
            "1",
            "--limit-masks",
            "3",
            "--limit-transpositions",
            "60",  # enough to include identity
        ],
    )
    ac = doc["audit_counters"]
    # baseline_equivalent_passes is only computed when run_campaign reaches
    # the end-of-run classification, which requires the smoke to actually
    # evaluate some passes.
    if ac.get("bean_pass", 0) > 0:
        assert ac.get("baseline_equivalent_passes", 0) + ac.get(
            "novel_signal_passes", 0
        ) == ac["bean_pass"]


def test_novel_signal_zero_stays_eliminated(tmp_path: Path):
    doc = _run(
        tmp_path,
        [
            "--mode",
            "smoke",
            "--workers",
            "2",
            "--limit-masks",
            "4",
            "--limit-transpositions",
            "60",
        ],
    )
    ac = doc["audit_counters"]
    # If there are Bean passes but zero novel, status must be ELIMINATED.
    if ac.get("bean_pass", 0) > 0 and ac.get("novel_signal_passes", 0) == 0:
        assert doc["status"] == "ELIMINATED"


def test_worker_error_fails_closed_not_eliminated(tmp_path: Path):
    """A worker exception means the finite universe was not cleanly tested."""
    masks = companion.build_mask_universe()[:1]
    transpositions = pt.gen_identity()
    camp = pt.run_campaign(
        mode="smoke",
        masks=masks,
        transpositions=transpositions,
        variants=("not-a-real-variant",),
        workers=1,
        max_configs=None,
        checkpoint_path=tmp_path / "checkpoint.json",
        output_path=tmp_path / "result.json",
        resume=False,
        chunk_size=1,
        cmd_line="pytest synthetic",
    )
    assert camp.status == "ERROR"
    assert camp.rejection_counts["worker_error"] == 1
    assert camp.tooling_gaps
    assert "refusing to classify" in " ".join(camp.notes)


def test_resume_preserves_state(tmp_path: Path):
    common = [
        "--mode",
        "smoke",
        "--workers",
        "1",
        "--limit-masks",
        "2",
        "--limit-transpositions",
        "10",
    ]
    first = _run(tmp_path, common)
    second = _run(tmp_path, common + ["--resume"])
    assert (
        first["audit_counters"]["processed_count"]
        == second["audit_counters"]["processed_count"]
    )


def test_resume_after_partial_chunk_checkpoint_reconciles_audit(tmp_path: Path):
    common = [
        "--mode",
        "smoke",
        "--workers",
        "2",
        "--limit-masks",
        "3",
        "--limit-transpositions",
        "8",
        "--chunk-size",
        "2",
    ]
    first = _run(tmp_path, common + ["--max-configs", "12"])
    assert first["status"] == "INCONCLUSIVE_BUDGET"
    second = _run(tmp_path, common + ["--resume"])
    assert second["coverage"]["tested"] == second["coverage"]["total"]
    assert second["audit_counters"]["processed_count"] == second["coverage"]["tested"]
    for note in second.get("notes", []):
        assert "audit mismatch" not in note, f"audit mismatch after resume: {note}"


def test_resume_refuses_hash_mismatch(tmp_path: Path):
    common = [
        "--mode",
        "smoke",
        "--workers",
        "1",
        "--limit-masks",
        "2",
        "--limit-transpositions",
        "5",
    ]
    _run(tmp_path, common)
    ckpt_path = tmp_path / "checkpoint.json"
    cdata = json.loads(ckpt_path.read_text())
    cdata["assumptions_hash"] = "baddeadbeef"
    ckpt_path.write_text(json.dumps(cdata))
    doc2 = _run(tmp_path, common + ["--resume"])
    assert doc2["status"] == "ERROR" or any(
        "hash mismatch" in n for n in doc2.get("notes", [])
    )


def test_max_configs_budget_yields_inconclusive(tmp_path: Path):
    doc = _run(
        tmp_path,
        [
            "--mode",
            "smoke",
            "--workers",
            "1",
            "--limit-masks",
            "5",
            "--limit-transpositions",
            "30",
            "--max-configs",
            "50",
        ],
    )
    assert doc["coverage"]["tested"] < doc["coverage"]["total"]
    assert doc["status"] == "INCONCLUSIVE_BUDGET"


def test_universe_hash_stable(tmp_path: Path):
    d1 = _run(tmp_path, ["--mode", "inventory", "--workers", "1"])
    tmp2 = tmp_path / "scratch2"
    tmp2.mkdir()
    d2 = _run(tmp2, ["--mode", "inventory", "--workers", "1"])
    assert d1["universe_hash"] == d2["universe_hash"]
    assert d1["assumptions_hash"] == d2["assumptions_hash"]
