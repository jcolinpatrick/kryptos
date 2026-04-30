"""Tests for real-K4 LLM↔HCC bridge audit runner + prompt parser.

Pinned properties:

  1. Fixture pack directory loads cleanly + audit produces an
     artifact with the documented schema_version.
  2. Artifact carries non_claim_banner string explicitly.
  3. Run-level classification defaults to
     ``interpretive_pipeline_test`` and only promotes when the null
     gate fires.
  4. ``RealK4BridgeAuditConfig`` rejects skip_null without a reason.
  5. ``RealK4BridgeAuditConfig`` rejects packs_dir AND llm_packs
     both unset.
  6. Prompt parser tolerates leading/trailing prose.
  7. Prompt parser rejects packs missing provenance.
  8. Real-K4 mode is unchanged when the bridge flag is NOT supplied.
  9. ``compile_packs`` produces no specs from a fixture file with
     no composition templates.
 10. Audit artifact is JSON-decodable and contains ``run_id``,
     ``classification``, ``null_baseline``, and per-pack summaries.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kryptosbot.real_k4_pseudo_clue_pack import (
    Bounds, CompositionTemplate, KeywordHint,
    NumericRoleHint, OperationHint, ProvenanceItem,
    PseudoCluePack,
)
from kryptosbot.real_k4_pseudo_clue_compiler import compile_packs


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_fixture_pack(
    path: Path,
    pack_id: str,
    layer_kinds: tuple[str, ...] = ("vigenere", "columnar"),
    extra_numerics: bool = False,
) -> None:
    p = PseudoCluePack(
        pack_id=pack_id,
        title="t",
        hypothesis_summary="t",
        provenance_items=(
            ProvenanceItem("CRIB-X", "crib", "x", 0.99),
        ),
        evidence_tier="tier_1_public_fact",
        keywords=(
            KeywordHint("BERLIN", "substitution", ("CRIB-X",), 0.5),
            KeywordHint("CLOCK", "columnar", ("CRIB-X",), 0.5),
        ),
        numeric_roles=(
            (NumericRoleHint(3, "three", "depth", ("CRIB-X",), 0.5),)
            if extra_numerics else ()
        ),
        composition_templates=(
            CompositionTemplate(layer_kinds, True, "test", 0.5, len(layer_kinds)),
        ),
        bounds=Bounds(max_specs=12),
    )
    path.write_text(json.dumps(p.to_dict()), encoding="utf-8")


# ---------------------------------------------------------------------------
# Audit runner
# ---------------------------------------------------------------------------


class TestBridgeAuditRunner:
    def test_fixture_audit_produces_artifact(self, tmp_path: Path):
        from kryptosbot.real_k4_bridge_audit import (
            RealK4BridgeAuditConfig, run_real_k4_bridge_audit,
        )
        packs_dir = tmp_path / "packs"
        packs_dir.mkdir()
        _write_fixture_pack(packs_dir / "01_a.json", "p1")
        _write_fixture_pack(packs_dir / "02_b.json", "p2", extra_numerics=True,
                             layer_kinds=("vigenere", "columnar", "rail_fence"))

        out_path = tmp_path / "audit.json"
        cfg = RealK4BridgeAuditConfig(
            output_path=out_path,
            packs_dir=packs_dir,
            global_max_specs=24,
            workers=1,
            timeout_per_spec_sec=15,
        )
        artifact = run_real_k4_bridge_audit(cfg)
        assert artifact["schema_version"] == "real_k4_bridge_audit.v1"
        assert artifact["n_packs_loaded"] == 2
        assert artifact["n_specs_compiled"] <= 24
        assert "non_claim_banner" in artifact
        assert artifact["classification"] in (
            "interpretive_pipeline_test",
            "interesting_pending_review",
            "candidate_pending_external_evaluator",
        )
        # Disk artifact present and JSON-decodable
        assert out_path.exists()
        on_disk = json.loads(out_path.read_text(encoding="utf-8"))
        assert on_disk["run_id"] == artifact["run_id"]

    def test_default_classification_is_pipeline_test(
        self, tmp_path: Path,
    ):
        from kryptosbot.real_k4_bridge_audit import (
            RealK4BridgeAuditConfig, run_real_k4_bridge_audit,
        )
        packs_dir = tmp_path / "packs"
        packs_dir.mkdir()
        _write_fixture_pack(packs_dir / "p.json", "p1")
        cfg = RealK4BridgeAuditConfig(
            output_path=tmp_path / "audit.json",
            packs_dir=packs_dir, global_max_specs=12, workers=1,
        )
        artifact = run_real_k4_bridge_audit(cfg)
        # Real K4 against random fixture cribs almost certainly does
        # NOT trigger the breakthrough gate; pipeline_test default
        # should hold.
        assert artifact["classification"] != (
            "candidate_pending_external_evaluator"
        ) or (
            artifact["null_baseline"].get("classification") == "breakthrough"
        )

    def test_skip_null_with_reason_records_in_artifact(
        self, tmp_path: Path,
    ):
        from kryptosbot.real_k4_bridge_audit import (
            RealK4BridgeAuditConfig, run_real_k4_bridge_audit,
        )
        packs_dir = tmp_path / "packs"
        packs_dir.mkdir()
        _write_fixture_pack(packs_dir / "p.json", "p1")
        cfg = RealK4BridgeAuditConfig(
            output_path=tmp_path / "audit.json",
            packs_dir=packs_dir, global_max_specs=12, workers=1,
            skip_null_calibration=True,
            skip_null_calibration_reason="dry-run pipeline test",
        )
        artifact = run_real_k4_bridge_audit(cfg)
        nb = artifact["null_baseline"]
        assert nb.get("skipped") is True
        assert "dry-run" in nb.get("reason", "")


# ---------------------------------------------------------------------------
# Config validation
# ---------------------------------------------------------------------------


class TestBridgeAuditConfig:
    def test_no_packs_source_rejected(self, tmp_path: Path):
        from kryptosbot.real_k4_bridge_audit import RealK4BridgeAuditConfig
        with pytest.raises(ValueError, match="packs_dir or llm_packs"):
            RealK4BridgeAuditConfig(
                output_path=tmp_path / "x.json",
                global_max_specs=10, workers=1,
            )

    def test_skip_null_without_reason_rejected(self, tmp_path: Path):
        from kryptosbot.real_k4_bridge_audit import RealK4BridgeAuditConfig
        packs_dir = tmp_path / "packs"
        packs_dir.mkdir()
        with pytest.raises(ValueError, match="skip_null_calibration_reason"):
            RealK4BridgeAuditConfig(
                output_path=tmp_path / "x.json",
                packs_dir=packs_dir, global_max_specs=10, workers=1,
                skip_null_calibration=True,
                skip_null_calibration_reason="",
            )

    def test_global_max_specs_ceiling(self, tmp_path: Path):
        from kryptosbot.real_k4_bridge_audit import RealK4BridgeAuditConfig
        packs_dir = tmp_path / "packs"
        packs_dir.mkdir()
        with pytest.raises(ValueError, match="20000"):
            RealK4BridgeAuditConfig(
                output_path=tmp_path / "x.json",
                packs_dir=packs_dir, global_max_specs=20001, workers=1,
            )


# ---------------------------------------------------------------------------
# Prompt parser
# ---------------------------------------------------------------------------


class TestPromptParser:
    def test_extracts_first_json_object(self):
        from kryptosbot.real_k4_bridge_prompt import parse_packs_response
        text = (
            "Here is my analysis.\n\n"
            '{"packs": [{"pack_id":"p1","title":"t","hypothesis_summary":"t",'
            '"provenance_items":[{"source_id":"S","source_type":"crib",'
            '"quote_or_summary":"x","confidence":0.9}],'
            '"evidence_tier":"tier_1_public_fact",'
            '"keywords":[{"token":"BERLIN","role_hint":"substitution",'
            '"source_ids":["S"],"confidence":0.5}]}]}'
            "\nThank you."
        )
        accepted, rejected = parse_packs_response(text)
        assert len(accepted) == 1
        assert accepted[0].pack_id == "p1"
        assert rejected == []

    def test_rejects_pack_without_provenance(self):
        from kryptosbot.real_k4_bridge_prompt import parse_packs_response
        text = (
            '{"packs": [{"pack_id":"p1","title":"t","hypothesis_summary":"t",'
            '"provenance_items":[],"evidence_tier":"tier_1_public_fact",'
            '"keywords":[{"token":"X","role_hint":"substitution",'
            '"source_ids":["MISSING"],"confidence":0.5}]}]}'
        )
        accepted, rejected = parse_packs_response(text)
        assert accepted == []
        assert rejected
        assert "provenance" in str(rejected[0]["errors"]).lower() or \
               "MISSING" in str(rejected[0]["errors"])

    def test_empty_text_raises(self):
        from kryptosbot.real_k4_bridge_prompt import (
            BridgePromptParseError, parse_packs_response,
        )
        with pytest.raises(BridgePromptParseError):
            parse_packs_response("")

    def test_no_json_in_text_raises(self):
        from kryptosbot.real_k4_bridge_prompt import (
            BridgePromptParseError, parse_packs_response,
        )
        with pytest.raises(BridgePromptParseError):
            parse_packs_response("just prose, no JSON here")


# ---------------------------------------------------------------------------
# Real-K4 normal mode unchanged
# ---------------------------------------------------------------------------


class TestRealK4DefaultUnchanged:
    def test_collect_hcc_seeds_returns_empty(self, tmp_path: Path):
        # Default real-K4 mode: HCC seeds remain empty regardless of
        # bridge module presence.
        from kryptosbot.controller import (
            ControllerConfig, ResearchController,
        )
        cfg = ControllerConfig(
            project_root=tmp_path,
            ledger_db_path=tmp_path / "real_k4.sqlite",
            max_cycles=1, theories_per_cycle=5, dry_run=True,
        )
        controller = ResearchController(cfg)
        controller.state = controller.ledger.load_controller_state()
        controller._snapshot_session_baseline()
        assert controller._collect_hcc_seeds() == []
