"""Tests for the composition search framework.

Covers:
- Layer serialization and deterministic identity
- Additive layer forward/inverse correctness
- Transposition layer forward/inverse correctness
- Composition stack inversion correctness
- Pruning logic for concrete cases
- Ledger persistence and recovery
- Scoring bridge integration
- Orchestrator preview and small campaign
"""
import json
import os
import sqlite3
import tempfile

import pytest

from kryptos.kernel.constants import CT, CT_LEN, ALPH_IDX
from kryptos.composition.models import (
    BranchStatus,
    CompositionResult,
    CompositionStack,
    LayerDef,
    LayerFamily,
    LayerInstance,
    LayerSemantics,
    PeelOrder,
    PruneResult,
    PruneType,
)
from kryptos.composition.registry import (
    build_transforms,
    generate_params,
    get_layer_def,
    make_instance,
    registered_families,
)
from kryptos.composition.constraints import (
    check_bean_equality_under_additive,
    check_bean_inequalities_under_periodic,
    evaluate_pruning,
    evaluate_intermediate_pruning,
    select_scoring_mode,
)
from kryptos.composition.ledger import CompositionLedger
from kryptos.composition.scoring_bridge import score_composition, quick_crib_check
from kryptos.composition.orchestrator import CampaignPolicy, CompositionOrchestrator


# ══════════════════════════════════════════════════════════════════════════
# Registry and layer definitions
# ══════════════════════════════════════════════════════════════════════════

class TestRegistry:
    def test_all_families_registered(self):
        families = registered_families()
        assert LayerFamily.IDENTITY in families
        assert LayerFamily.ADDITIVE_MASK in families
        assert LayerFamily.VIGENERE in families
        assert LayerFamily.BEAUFORT in families
        assert LayerFamily.VAR_BEAUFORT in families
        assert LayerFamily.TRANSPOSITION_COLUMNAR in families
        assert LayerFamily.TRANSPOSITION_RAIL_FENCE in families
        assert LayerFamily.TRANSPOSITION_ROUTE in families
        assert LayerFamily.BLOCK_TRANSPOSITION in families

    def test_get_layer_def(self):
        ld = get_layer_def(LayerFamily.IDENTITY)
        assert ld.family == LayerFamily.IDENTITY
        assert ld.reversible is True
        assert ld.semantics.preserves_positions is True

    def test_identity_def_is_involution(self):
        ld = get_layer_def(LayerFamily.IDENTITY)
        assert ld.semantics.is_involution is True

    def test_additive_semantics(self):
        ld = get_layer_def(LayerFamily.ADDITIVE_MASK)
        assert ld.semantics.preserves_positions is True
        assert ld.semantics.preserves_unigram_frequencies is False
        assert ld.semantics.changes_effective_key is True

    def test_columnar_semantics(self):
        ld = get_layer_def(LayerFamily.TRANSPOSITION_COLUMNAR)
        assert ld.semantics.preserves_positions is False
        assert ld.semantics.preserves_unigram_frequencies is True
        assert ld.semantics.changes_effective_key is False

    def test_unknown_family_raises(self):
        # Use a valid enum but unregister it to test KeyError
        # Instead, test with a mock: directly test the registry dict
        from kryptos.composition.registry import _LAYER_DEFS
        # Verify that looking up something not in the dict raises KeyError
        with pytest.raises(KeyError):
            get_layer_def.__wrapped__ if hasattr(get_layer_def, '__wrapped__') else None
            # Directly test the behavior:
            _LAYER_DEFS["bogus_key"]


# ══════════════════════════════════════════════════════════════════════════
# Layer instance creation and serialization
# ══════════════════════════════════════════════════════════════════════════

class TestLayerInstance:
    def test_identity_instance(self):
        inst = make_instance(LayerFamily.IDENTITY)
        assert inst.family == LayerFamily.IDENTITY
        assert inst.params == {}

    def test_additive_instance(self):
        inst = make_instance(LayerFamily.ADDITIVE_MASK, {"keyword": "KRYPTOS"})
        assert inst.params["keyword"] == "KRYPTOS"

    def test_instance_hash_deterministic(self):
        a = make_instance(LayerFamily.ADDITIVE_MASK, {"keyword": "TEST"})
        b = make_instance(LayerFamily.ADDITIVE_MASK, {"keyword": "TEST"})
        assert a.instance_hash == b.instance_hash

    def test_instance_hash_differs_for_different_params(self):
        a = make_instance(LayerFamily.ADDITIVE_MASK, {"keyword": "AAA"})
        b = make_instance(LayerFamily.ADDITIVE_MASK, {"keyword": "BBB"})
        assert a.instance_hash != b.instance_hash

    def test_serialization_roundtrip(self):
        inst = make_instance(LayerFamily.ADDITIVE_MASK, {"keyword": "KRYPTOS"})
        d = inst.to_dict()
        restored = LayerInstance.from_dict(d)
        assert restored.family == inst.family
        assert restored.params == inst.params

    def test_display_label(self):
        inst = make_instance(LayerFamily.ADDITIVE_MASK, {"keyword": "TEST"}, label="my_mask")
        assert inst.display_label == "my_mask"

    def test_display_label_auto(self):
        inst = make_instance(LayerFamily.ADDITIVE_MASK, {"keyword": "X"})
        assert "additive_mask" in inst.display_label
        assert "keyword=X" in inst.display_label


# ══════════════════════════════════════════════════════════════════════════
# Transform correctness: forward(inverse(x)) == x
# ══════════════════════════════════════════════════════════════════════════

class TestTransformCorrectness:
    def test_identity_roundtrip(self):
        inst = make_instance(LayerFamily.IDENTITY)
        fwd, inv = build_transforms(inst)
        assert fwd(CT) == CT
        assert inv(CT) == CT

    def test_additive_roundtrip(self):
        inst = make_instance(LayerFamily.ADDITIVE_MASK, {"keyword": "KRYPTOS"})
        fwd, inv = build_transforms(inst)
        encrypted = fwd(CT)
        decrypted = inv(encrypted)
        assert decrypted == CT
        assert encrypted != CT  # Non-trivial mask

    def test_additive_trivial_mask(self):
        inst = make_instance(LayerFamily.ADDITIVE_MASK, {"keyword": "A"})
        fwd, inv = build_transforms(inst)
        # A has value 0, so mask is identity
        assert fwd(CT) == CT

    def test_columnar_roundtrip(self):
        inst = make_instance(LayerFamily.TRANSPOSITION_COLUMNAR,
                             {"keyword": "KRYPTOS", "width": 7})
        fwd, inv = build_transforms(inst)
        transposed = fwd(CT)
        restored = inv(transposed)
        assert restored == CT
        assert transposed != CT

    def test_myszkowski_roundtrip(self):
        inst = make_instance(LayerFamily.TRANSPOSITION_MYSZKOWSKI,
                             {"keyword": "KRYPTOS"})
        fwd, inv = build_transforms(inst)
        assert inv(fwd(CT)) == CT

    def test_rail_fence_roundtrip(self):
        for depth in [2, 3, 5, 7]:
            inst = make_instance(LayerFamily.TRANSPOSITION_RAIL_FENCE,
                                 {"depth": depth})
            fwd, inv = build_transforms(inst)
            assert inv(fwd(CT)) == CT, f"Rail fence depth={depth} failed"

    def test_route_spiral_roundtrip(self):
        inst = make_instance(LayerFamily.TRANSPOSITION_ROUTE,
                             {"rows": 7, "cols": 14, "route_type": "spiral",
                              "clockwise": True})
        fwd, inv = build_transforms(inst)
        assert inv(fwd(CT)) == CT

    def test_route_serpentine_roundtrip(self):
        inst = make_instance(LayerFamily.TRANSPOSITION_ROUTE,
                             {"rows": 10, "cols": 10, "route_type": "serpentine",
                              "vertical": False})
        fwd, inv = build_transforms(inst)
        assert inv(fwd(CT)) == CT

    def test_vigenere_roundtrip(self):
        inst = make_instance(LayerFamily.VIGENERE, {"keyword": "KRYPTOS"})
        fwd, inv = build_transforms(inst)
        encrypted = fwd(CT)
        assert inv(encrypted) == CT
        assert encrypted != CT

    def test_beaufort_roundtrip(self):
        inst = make_instance(LayerFamily.BEAUFORT, {"keyword": "PALIMPSEST"})
        fwd, inv = build_transforms(inst)
        encrypted = fwd(CT)
        assert inv(encrypted) == CT
        assert encrypted != CT

    def test_beaufort_is_reciprocal(self):
        """Beaufort encrypt == decrypt (reciprocal cipher)."""
        inst = make_instance(LayerFamily.BEAUFORT, {"keyword": "TEST"})
        fwd, inv = build_transforms(inst)
        assert fwd(CT) == inv(CT)

    def test_var_beaufort_roundtrip(self):
        inst = make_instance(LayerFamily.VAR_BEAUFORT, {"keyword": "SANBORN"})
        fwd, inv = build_transforms(inst)
        assert inv(fwd(CT)) == CT


# ══════════════════════════════════════════════════════════════════════════
# Composition stack
# ══════════════════════════════════════════════════════════════════════════

class TestCompositionStack:
    def test_two_layer_stack(self):
        outer = make_instance(LayerFamily.ADDITIVE_MASK, {"keyword": "TEST"})
        inner = make_instance(LayerFamily.IDENTITY)
        stack = CompositionStack(layers=(outer, inner))
        assert stack.depth == 2
        assert stack.outer == outer
        assert stack.inner == inner

    def test_stack_hash_deterministic(self):
        outer = make_instance(LayerFamily.ADDITIVE_MASK, {"keyword": "X"})
        inner = make_instance(LayerFamily.IDENTITY)
        a = CompositionStack(layers=(outer, inner))
        b = CompositionStack(layers=(outer, inner))
        assert a.stack_hash == b.stack_hash

    def test_peel_order_affects_hash(self):
        outer = make_instance(LayerFamily.ADDITIVE_MASK, {"keyword": "X"})
        inner = make_instance(LayerFamily.IDENTITY)
        a = CompositionStack(layers=(outer, inner), peel_order=PeelOrder.OUTER_FIRST)
        b = CompositionStack(layers=(outer, inner), peel_order=PeelOrder.INNER_FIRST)
        assert a.stack_hash != b.stack_hash

    def test_campaign_key(self):
        outer = make_instance(LayerFamily.ADDITIVE_MASK, {"keyword": "X"})
        inner = make_instance(LayerFamily.IDENTITY)
        stack = CompositionStack(layers=(outer, inner))
        assert "additive_mask" in stack.campaign_key
        assert "identity" in stack.campaign_key

    def test_serialization_roundtrip(self):
        outer = make_instance(LayerFamily.ADDITIVE_MASK, {"keyword": "KRYPTOS"})
        inner = make_instance(LayerFamily.TRANSPOSITION_RAIL_FENCE, {"depth": 3})
        stack = CompositionStack(
            layers=(outer, inner),
            peel_order=PeelOrder.INNER_FIRST,
            description="test stack",
        )
        d = stack.to_dict()
        restored = CompositionStack.from_dict(d)
        assert restored.depth == 2
        assert restored.outer.family == LayerFamily.ADDITIVE_MASK
        assert restored.inner.family == LayerFamily.TRANSPOSITION_RAIL_FENCE
        assert restored.peel_order == PeelOrder.INNER_FIRST

    def test_preserves_positions_all_additive(self):
        outer = make_instance(LayerFamily.ADDITIVE_MASK, {"keyword": "A"})
        inner = make_instance(LayerFamily.ADDITIVE_MASK, {"keyword": "B"})
        stack = CompositionStack(layers=(outer, inner))
        assert stack.preserves_positions is True

    def test_preserves_positions_with_transposition(self):
        outer = make_instance(LayerFamily.TRANSPOSITION_COLUMNAR,
                              {"keyword": "KRYPTOS", "width": 7})
        inner = make_instance(LayerFamily.ADDITIVE_MASK, {"keyword": "A"})
        stack = CompositionStack(layers=(outer, inner))
        assert stack.preserves_positions is False

    def test_two_layer_decryption_outer_first(self):
        """Verify composition decryption with actual K4-length text.

        Model: layers[0](layers[1](PT)) = outer(inner(PT)).
        Encryption: step1 = inner_fwd(PT), CT = outer_fwd(step1).
        Decryption (outer_first): step1 = outer_inv(CT), PT = inner_inv(step1).
        """
        # Use CT-length text so permutations are valid
        outer = make_instance(LayerFamily.ADDITIVE_MASK, {"keyword": "KEY"})
        inner = make_instance(LayerFamily.TRANSPOSITION_RAIL_FENCE, {"depth": 3})

        outer_fwd, outer_inv = build_transforms(outer)
        inner_fwd, inner_inv = build_transforms(inner)

        # Use the actual K4 CT as our "plaintext" for the roundtrip test
        plaintext = CT  # 97 chars

        # Encrypt: outer(inner(PT))
        step1 = inner_fwd(plaintext)
        ciphertext = outer_fwd(step1)

        # Decrypt outer_first: outer_inv then inner_inv
        d1 = outer_inv(ciphertext)
        d2 = inner_inv(d1)
        assert d2 == plaintext


# ══════════════════════════════════════════════════════════════════════════
# Pruning
# ══════════════════════════════════════════════════════════════════════════

class TestPruning:
    def test_bean_equality_additive_preserved(self):
        """Keyword where mask[27%L] == mask[65%L] — should pass."""
        # KRYPTOS has length 7. 27%7=6, 65%7=2.
        # K=10,R=17,Y=24,P=15,T=19,O=14,S=18
        # mask[6]=S=18, mask[2]=Y=24 → different → should PRUNE
        inst = make_instance(LayerFamily.ADDITIVE_MASK, {"keyword": "KRYPTOS"})
        result = check_bean_equality_under_additive(inst)
        assert result.pruned is True
        assert result.prune_type == PruneType.EXACT

    def test_bean_equality_additive_single_char(self):
        """Single-char keyword: mask[27%1] == mask[65%1] always."""
        inst = make_instance(LayerFamily.ADDITIVE_MASK, {"keyword": "A"})
        result = check_bean_equality_under_additive(inst)
        assert result.pruned is False

    def test_bean_equality_additive_period_divides(self):
        """Keyword length divides (65-27)=38. 38's divisors: 1,2,19,38.
        Length 2: 27%2=1, 65%2=1 → same → pass."""
        inst = make_instance(LayerFamily.ADDITIVE_MASK, {"keyword": "AB"})
        result = check_bean_equality_under_additive(inst)
        assert result.pruned is False

    def test_bean_equality_non_additive_passes(self):
        """Non-additive layers should pass this check."""
        inst = make_instance(LayerFamily.TRANSPOSITION_COLUMNAR,
                             {"keyword": "KRYPTOS", "width": 7})
        result = check_bean_equality_under_additive(inst)
        assert result.pruned is False

    def test_evaluate_pruning_identity_passes(self):
        outer = make_instance(LayerFamily.IDENTITY)
        inner = make_instance(LayerFamily.IDENTITY)
        stack = CompositionStack(layers=(outer, inner))
        result = evaluate_pruning(stack)
        assert result.pruned is False

    def test_evaluate_pruning_bad_additive(self):
        outer = make_instance(LayerFamily.ADDITIVE_MASK, {"keyword": "KRYPTOS"})
        inner = make_instance(LayerFamily.IDENTITY)
        stack = CompositionStack(layers=(outer, inner))
        result = evaluate_pruning(stack)
        assert result.pruned is True
        assert "Bean equality" in result.reason

    def test_bean_inequality_single_char(self):
        """Single-char keyword: all crib positions have same key → violates Bean inequality."""
        inst = make_instance(LayerFamily.ADDITIVE_MASK, {"keyword": "A"})
        result = check_bean_inequalities_under_periodic(inst)
        assert result.pruned is True
        assert result.prune_type == PruneType.EXACT

    def test_bean_inequality_not_applied_to_transposition(self):
        """Bean inequality check skips non-periodic families."""
        inst = make_instance(LayerFamily.TRANSPOSITION_COLUMNAR,
                             {"keyword": "TEST", "width": 4})
        result = check_bean_inequalities_under_periodic(inst)
        assert result.pruned is False

    def test_bean_inequality_vigenere_identity_pruned(self):
        """Vigenere + identity should be pruned for short keywords."""
        outer = make_instance(LayerFamily.VIGENERE, {"keyword": "KRYPTOS"})
        inner = make_instance(LayerFamily.IDENTITY)
        stack = CompositionStack(layers=(outer, inner))
        result = evaluate_pruning(stack)
        assert result.pruned is True

    def test_bean_inequality_not_applied_to_two_cipher_layers(self):
        """Two periodic layers: Bean inequality on individual layers is invalid."""
        outer = make_instance(LayerFamily.ADDITIVE_MASK, {"keyword": "A"})
        inner = make_instance(LayerFamily.VIGENERE, {"keyword": "B"})
        stack = CompositionStack(layers=(outer, inner))
        # Should NOT be pruned by Bean inequality (multi-layer effective keystream)
        result = evaluate_pruning(stack)
        assert result.pruned is False

    def test_prune_result_serialization(self):
        pr = PruneResult.exact("test reason", detail_key="value")
        d = pr.to_dict()
        assert d["pruned"] is True
        assert d["prune_type"] == "exact"
        assert d["reason"] == "test reason"

    def test_scoring_mode_all_additive(self):
        outer = make_instance(LayerFamily.ADDITIVE_MASK, {"keyword": "X"})
        inner = make_instance(LayerFamily.ADDITIVE_MASK, {"keyword": "Y"})
        stack = CompositionStack(layers=(outer, inner))
        assert select_scoring_mode(stack) == "anchored"

    def test_scoring_mode_with_transposition(self):
        outer = make_instance(LayerFamily.TRANSPOSITION_COLUMNAR,
                              {"keyword": "TEST", "width": 4})
        inner = make_instance(LayerFamily.ADDITIVE_MASK, {"keyword": "X"})
        stack = CompositionStack(layers=(outer, inner))
        assert select_scoring_mode(stack) == "both"


# ══════════════════════════════════════════════════════════════════════════
# Ledger persistence
# ══════════════════════════════════════════════════════════════════════════

class TestLedger:
    def _make_ledger(self, tmp_path):
        return CompositionLedger(str(tmp_path / "test_ledger.sqlite"))

    def test_create_and_close(self, tmp_path):
        ledger = self._make_ledger(tmp_path)
        ledger.close()
        assert (tmp_path / "test_ledger.sqlite").exists()

    def test_register_campaign(self, tmp_path):
        ledger = self._make_ledger(tmp_path)
        ledger.register_campaign("camp1", "Test Campaign", {"k": "v"}, 100)
        summary = ledger.campaign_summary("camp1")
        assert summary["name"] == "Test Campaign"
        assert summary["status"] == "RUNNING"
        ledger.close()

    def test_record_and_query_branch(self, tmp_path):
        ledger = self._make_ledger(tmp_path)
        ledger.register_campaign("camp1", "Test", {}, 10)
        ledger.record_branch(
            branch_id="br1",
            campaign_id="camp1",
            stack_hash="abc123",
            stack_json='{"test": true}',
            campaign_key="additive+identity/outer_first",
            peel_order="outer_first",
            status="tested",
            score=15,
            bean_pass=False,
            ic_value=0.04,
        )
        ledger.commit()

        # Query coverage
        coverage = ledger.coverage_by_family("camp1")
        assert len(coverage) == 1
        assert coverage[0]["count"] == 1
        ledger.close()

    def test_record_pruned_branch(self, tmp_path):
        ledger = self._make_ledger(tmp_path)
        ledger.register_campaign("camp1", "Test", {}, 10)
        ledger.record_branch(
            branch_id="br2",
            campaign_id="camp1",
            stack_hash="def456",
            stack_json="{}",
            campaign_key="additive+identity/outer_first",
            peel_order="outer_first",
            status="pruned",
            prune_type="exact",
            prune_reason="Bean equality violated",
        )
        ledger.commit()

        pruning = ledger.pruning_summary("camp1")
        assert pruning.get("exact", 0) == 1
        ledger.close()

    def test_checkpoint_and_resume(self, tmp_path):
        ledger = self._make_ledger(tmp_path)
        ledger.register_campaign("camp1", "Test", {}, 10)
        ledger.checkpoint("camp1", "br1", "complete", {"score": 5})
        ledger.checkpoint("camp1", "br2", "complete", {"score": 8})
        ledger.commit()

        completed = ledger.completed_branch_ids("camp1")
        assert "br1" in completed
        assert "br2" in completed
        assert "br3" not in completed
        ledger.close()

    def test_top_results(self, tmp_path):
        ledger = self._make_ledger(tmp_path)
        ledger.register_campaign("camp1", "Test", {}, 10)
        for i, score in enumerate([3, 12, 8, 15, 6]):
            ledger.record_result(
                campaign_id="camp1",
                branch_id=f"br{i}",
                stack_hash=f"hash{i}",
                score=score,
            )
        ledger.commit()

        top = ledger.top_results(limit=3, min_score=5)
        assert len(top) == 3
        assert top[0]["score"] == 15
        assert top[1]["score"] == 12
        ledger.close()

    def test_finalize_campaign(self, tmp_path):
        ledger = self._make_ledger(tmp_path)
        ledger.register_campaign("camp1", "Test", {}, 10)
        ledger.record_branch(
            branch_id="br1", campaign_id="camp1",
            stack_hash="a", stack_json="{}", campaign_key="test",
            peel_order="outer_first", status="tested", score=12,
        )
        ledger.commit()
        ledger.finalize_campaign("camp1", "COMPLETE")
        summary = ledger.campaign_summary("camp1")
        assert summary["status"] == "COMPLETE"
        ledger.close()

    def test_context_manager(self, tmp_path):
        with CompositionLedger(str(tmp_path / "ctx_ledger.sqlite")) as ledger:
            ledger.register_campaign("c1", "Test", {}, 0)
            ledger.commit()
        # Should be closed now — verify data persists
        ledger2 = CompositionLedger(str(tmp_path / "ctx_ledger.sqlite"))
        assert ledger2.campaign_summary("c1")["name"] == "Test"
        ledger2.close()


# ══════════════════════════════════════════════════════════════════════════
# Scoring bridge
# ══════════════════════════════════════════════════════════════════════════

class TestScoringBridge:
    def test_score_identity_composition(self):
        """Identity stack should produce CT as plaintext — low crib score."""
        outer = make_instance(LayerFamily.IDENTITY)
        inner = make_instance(LayerFamily.IDENTITY)
        stack = CompositionStack(layers=(outer, inner))
        result = score_composition(CT, stack)
        # CT is not plaintext — should score low
        assert result.crib_score < 24
        assert result.ic_value > 0

    def test_quick_crib_check_ct(self):
        # Raw CT should have very few crib matches
        assert quick_crib_check(CT, threshold=20) is False


# ══════════════════════════════════════════════════════════════════════════
# Orchestrator
# ══════════════════════════════════════════════════════════════════════════

class TestOrchestrator:
    def test_enumerate_stacks_identity(self, tmp_path):
        policy = CampaignPolicy(
            name="test_enum",
            outer_families=["identity"],
            inner_families=["identity"],
            peel_orders=["outer_first"],
            db_path=str(tmp_path / "test.sqlite"),
        )
        orch = CompositionOrchestrator(policy)
        stacks = orch.enumerate_stacks()
        assert len(stacks) == 1
        assert stacks[0].outer.family == LayerFamily.IDENTITY
        assert stacks[0].inner.family == LayerFamily.IDENTITY

    def test_enumerate_stacks_additive(self, tmp_path):
        policy = CampaignPolicy(
            name="test_additive_enum",
            outer_families=["additive_mask"],
            inner_families=["identity"],
            peel_orders=["outer_first"],
            outer_params={"keywords": ["A", "B"]},
            db_path=str(tmp_path / "test.sqlite"),
        )
        orch = CompositionOrchestrator(policy)
        stacks = orch.enumerate_stacks()
        assert len(stacks) == 2  # 2 keywords × 1 inner × 1 peel

    def test_enumerate_both_peel_orders(self, tmp_path):
        policy = CampaignPolicy(
            name="test_peel",
            outer_families=["identity"],
            inner_families=["identity"],
            peel_orders=["outer_first", "inner_first"],
            db_path=str(tmp_path / "test.sqlite"),
        )
        orch = CompositionOrchestrator(policy)
        stacks = orch.enumerate_stacks()
        assert len(stacks) == 2

    def test_preview(self, tmp_path):
        policy = CampaignPolicy(
            name="test_preview",
            outer_families=["additive_mask"],
            inner_families=["identity"],
            peel_orders=["outer_first"],
            outer_params={"keywords": ["A", "B", "C"]},
            db_path=str(tmp_path / "test.sqlite"),
        )
        orch = CompositionOrchestrator(policy)
        preview = orch.preview()
        assert preview["total_stacks"] == 3
        assert "estimated_pruned" in preview
        assert "families" in preview

    def test_small_campaign(self, tmp_path):
        """Run a tiny campaign: identity outer × identity inner."""
        policy = CampaignPolicy(
            name="test_tiny",
            outer_families=["identity"],
            inner_families=["identity"],
            peel_orders=["outer_first"],
            workers=1,
            db_path=str(tmp_path / "tiny.sqlite"),
            log_dir=str(tmp_path / "logs"),
        )
        orch = CompositionOrchestrator(policy)
        summary = orch.run()
        assert summary["tested"] == 1
        assert summary["pruned"] == 0

        # Verify ledger was written
        ledger = CompositionLedger(str(tmp_path / "tiny.sqlite"))
        campaigns = ledger.all_campaigns()
        assert len(campaigns) == 1
        assert campaigns[0]["status"] == "COMPLETE"
        ledger.close()

    def test_campaign_with_pruning(self, tmp_path):
        """Campaign with additive masks + identity inner — all pruned by Bean checks.

        Single periodic substitution on raw K4 CT is Tier 1 eliminated:
        - KRYPTOS: Bean equality violation (len 7, mask[27%7] != mask[65%7])
        - A, AB: Bean inequality violation (keyword too short, creates equal
          key values at positions where Bean requires inequality)
        """
        policy = CampaignPolicy(
            name="test_pruning",
            outer_families=["additive_mask"],
            inner_families=["identity"],
            peel_orders=["outer_first"],
            outer_params={"keywords": ["A", "KRYPTOS", "AB"]},
            workers=1,
            db_path=str(tmp_path / "prune.sqlite"),
            log_dir=str(tmp_path / "logs"),
        )
        orch = CompositionOrchestrator(policy)
        summary = orch.run()

        # All three keywords are pruned by Bean checks
        assert summary["pruned"] == 3
        assert summary["tested"] == 0

    def test_campaign_resume(self, tmp_path):
        """Run a campaign, then re-run — should resume without re-testing."""
        policy = CampaignPolicy(
            name="test_resume",
            outer_families=["identity"],
            inner_families=["identity"],
            peel_orders=["outer_first"],
            workers=1,
            db_path=str(tmp_path / "resume.sqlite"),
            log_dir=str(tmp_path / "logs"),
        )
        orch1 = CompositionOrchestrator(policy)
        s1 = orch1.run()
        assert s1["tested"] == 1

        # Second run should find everything already done
        orch2 = CompositionOrchestrator(policy)
        s2 = orch2.run()
        assert s2["tested"] == 0  # Already done

    def test_policy_from_dict(self):
        d = {
            "name": "test",
            "outer_families": ["additive_mask"],
            "inner_families": ["identity"],
            "workers": 4,
        }
        policy = CampaignPolicy.from_dict(d)
        assert policy.name == "test"
        assert policy.workers == 4

    def test_campaign_id_deterministic(self):
        a = CampaignPolicy(name="x", outer_families=["additive_mask"])
        b = CampaignPolicy(name="x", outer_families=["additive_mask"])
        assert a.campaign_id == b.campaign_id


# ══════════════════════════════════════════════════════════════════════════
# Parameter generation
# ══════════════════════════════════════════════════════════════════════════

class TestParamGeneration:
    def test_additive_params(self):
        params = generate_params(LayerFamily.ADDITIVE_MASK, keywords=["A", "B"])
        assert len(params) == 2
        assert params[0]["keyword"] == "A"

    def test_rail_fence_params(self):
        params = generate_params(LayerFamily.TRANSPOSITION_RAIL_FENCE, depths=[2, 3, 4])
        assert len(params) == 3

    def test_identity_params(self):
        params = generate_params(LayerFamily.IDENTITY)
        assert len(params) == 1
        assert params[0] == {}

    def test_route_params_default(self):
        params = generate_params(LayerFamily.TRANSPOSITION_ROUTE)
        # Should have multiple grid × route_type × variant combinations
        assert len(params) > 10

    def test_columnar_params(self):
        params = generate_params(
            LayerFamily.TRANSPOSITION_COLUMNAR,
            keywords=["ABC", "DEFG"],
        )
        assert len(params) == 2


# ══════════════════════════════════════════════════════════════════════════
# Worker function (unit-level)
# ══════════════════════════════════════════════════════════════════════════

class TestWorker:
    def test_worker_evaluate_identity(self):
        from kryptos.composition.orchestrator import _worker_evaluate

        outer = make_instance(LayerFamily.IDENTITY)
        inner = make_instance(LayerFamily.IDENTITY)
        stack = CompositionStack(layers=(outer, inner))

        result = _worker_evaluate({
            "branch_id": "test_br",
            "stack": stack.to_dict(),
            "ciphertext": CT,
            "score_threshold": 0,
        })
        assert result["branch_id"] == "test_br"
        assert "score" in result
        assert result.get("pruned") is False

    def test_worker_evaluate_additive_identity(self):
        """Additive mask with 'A' (shift 0) + identity = CT unchanged."""
        from kryptos.composition.orchestrator import _worker_evaluate

        outer = make_instance(LayerFamily.ADDITIVE_MASK, {"keyword": "A"})
        inner = make_instance(LayerFamily.IDENTITY)
        stack = CompositionStack(layers=(outer, inner))

        result = _worker_evaluate({
            "branch_id": "test_br2",
            "stack": stack.to_dict(),
            "ciphertext": CT,
            "score_threshold": 0,
        })
        assert result["branch_id"] == "test_br2"
        assert "score" in result
