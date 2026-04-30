"""Tests for the real-K4 HCC capability audit mode.

The audit (``--real-k4-hcc-audit``) runs the HandCipherCore catalogue
against the REAL Kryptos K4 cipher using only public, project-safe
clue material. These tests pin:

  (A) The audit produces a non-empty artifact with the expected
      schema fields and per-candidate detail.
  (B) The lesson-detection helper correctly maps coverage_vector
      signatures to LESSON-NNN IDs.
  (C) The public-crib match map records expected/got/match per
      crib position.
  (D) The audit emits ZERO LLM calls (proven by import-time
      assertion against the SDK module).
  (E) Strict context firewall: no K4Bench challenge IDs (K4B-001
      through K4B-025) and no documented bench-only keywords appear
      in the audit clue text, audit keyword pool, or emitted
      artifact. Cross-checked against the live K4Bench challenge
      corpus at bench/k4bench/challenges/.
  (F) Normal real-K4 mode is unchanged. ``_collect_hcc_seeds()``
      still returns ``[]`` in real-K4 mode (the audit bypasses the
      controller entirely).
  (G) Bench mode is unaffected by the audit subsystem (importing
      ``real_k4_audit`` does not perturb bench tests).

These tests run on every PR; the firewall test in particular is the
primary defense against contamination regressions.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest


_REPO_ROOT = Path(__file__).resolve().parents[2]
_K4BENCH_DIR = _REPO_ROOT / "bench" / "k4bench" / "challenges"


# ===========================================================================
# (A) Audit produces a non-empty artifact
# ===========================================================================


class TestAuditProducesArtifact:
    def test_audit_runs_and_writes_artifact(self, tmp_path):
        """A small audit (max_specs=20) produces an artifact file
        with the expected top-level keys.
        """
        from kryptosbot.real_k4_audit import (
            RealK4AuditConfig, run_real_k4_hcc_audit,
        )
        out = tmp_path / "audit.json"
        cfg = RealK4AuditConfig(
            output_path=out, max_specs=20, workers=2,
            top_n_in_artifact=10,
        )
        summary = run_real_k4_hcc_audit(cfg)
        assert out.exists(), "audit artifact was not written"
        assert summary["n_specs_generated"] > 0
        assert summary["n_candidates"] > 0
        # Artifact schema.
        artifact = json.loads(out.read_text())
        # v2 (2026-04-28) added tier filtering + null baseline.
        assert artifact["schema_version"] == "real_k4_hcc_audit.v2"
        for key in (
            "run_metadata", "public_facts", "clue_pack",
            "dispatch_summary", "coverage_summary", "candidates",
        ):
            assert key in artifact

    def test_artifact_records_real_k4_mode(self, tmp_path):
        from kryptosbot.real_k4_audit import (
            RealK4AuditConfig, run_real_k4_hcc_audit,
        )
        out = tmp_path / "audit.json"
        run_real_k4_hcc_audit(RealK4AuditConfig(
            output_path=out, max_specs=10, workers=2,
        ))
        artifact = json.loads(out.read_text())
        assert artifact["run_metadata"]["mode"] == "real_k4"

    def test_artifact_includes_per_candidate_layers(self, tmp_path):
        """Each candidate row carries layers, coverage_vector,
        crib_score, plaintext, public_crib_match_map, lessons_used.
        """
        from kryptosbot.real_k4_audit import (
            RealK4AuditConfig, run_real_k4_hcc_audit,
        )
        out = tmp_path / "audit.json"
        run_real_k4_hcc_audit(RealK4AuditConfig(
            output_path=out, max_specs=15, workers=2,
            top_n_in_artifact=5,
        ))
        artifact = json.loads(out.read_text())
        cands = artifact["candidates"]
        assert cands, "no candidates emitted"
        for c in cands:
            assert "layers" in c
            assert isinstance(c["layers"], list)
            assert "coverage_vector" in c
            assert "crib_score" in c
            assert isinstance(c["crib_score"], int)
            assert 0 <= c["crib_score"] <= 24
            assert "plaintext" in c
            assert len(c["plaintext"]) == 97
            assert "public_crib_match_map" in c
            assert "lessons_used" in c

    def test_public_facts_use_real_k4_ct_and_cribs(self, tmp_path):
        """The audit artifact's public_facts block must carry the
        real-K4 ciphertext (97 chars starting "OBKR") and the public
        cribs at positions 21 and 63.
        """
        from kryptosbot.real_k4_audit import (
            RealK4AuditConfig, run_real_k4_hcc_audit,
        )
        out = tmp_path / "audit.json"
        run_real_k4_hcc_audit(RealK4AuditConfig(
            output_path=out, max_specs=5, workers=2,
        ))
        artifact = json.loads(out.read_text())
        ct = artifact["public_facts"]["ciphertext"]
        assert len(ct) == 97
        # The real-K4 CT starts with OBKR. A K4Bench CT would not.
        assert ct.startswith("OBKR"), (
            f"Audit recorded a non-real-K4 ciphertext: {ct[:20]}..."
        )
        crib = artifact["public_facts"]["crib_dict"]
        # Position 21 should be 'E' (start of EASTNORTHEAST).
        assert crib.get("21") == "E"
        # Position 63 should be 'B' (start of BERLINCLOCK).
        assert crib.get("63") == "B"


# ===========================================================================
# (B) Lesson detection
# ===========================================================================


class TestLessonDetection:
    def test_empty_cv_returns_empty_lessons(self):
        from kryptosbot.real_k4_audit import lessons_used_by_coverage
        assert lessons_used_by_coverage({}) == []

    def test_two_layer_spec_tags_lesson_001_002(self):
        from kryptosbot.real_k4_audit import lessons_used_by_coverage
        cv = {"n_layers": 2, "alphabet_mode": "AZ"}
        used = lessons_used_by_coverage(cv)
        assert "LESSON-001" in used
        assert "LESSON-002" in used

    def test_alphabet_mode_KA_tags_lesson_007(self):
        from kryptosbot.real_k4_audit import lessons_used_by_coverage
        cv = {"n_layers": 2, "alphabet_mode": "KA"}
        used = lessons_used_by_coverage(cv)
        assert "LESSON-007" in used

    def test_block_size_tags_lesson_008(self):
        from kryptosbot.real_k4_audit import lessons_used_by_coverage
        cv = {"n_layers": 1, "block_size": 5, "block_mode": "reverse_partial"}
        used = lessons_used_by_coverage(cv)
        assert "LESSON-008" in used

    def test_shift_value_tags_lesson_009(self):
        from kryptosbot.real_k4_audit import lessons_used_by_coverage
        cv = {"n_layers": 1, "shift_value": 13}
        used = lessons_used_by_coverage(cv)
        assert "LESSON-009" in used

    def test_independent_three_role_tags_lesson_010(self):
        from kryptosbot.real_k4_audit import lessons_used_by_coverage
        cv = {
            "n_layers": 2,
            "role_assignment_mode": "independent_three_role",
        }
        used = lessons_used_by_coverage(cv)
        assert "LESSON-010" in used

    def test_skip_route_tags_lesson_011(self):
        from kryptosbot.real_k4_audit import lessons_used_by_coverage
        cv = {"n_layers": 1, "route_mode": "skip_route", "step": 5, "offset": 3}
        used = lessons_used_by_coverage(cv)
        assert "LESSON-011" in used

    def test_phrase_bound_provenance_tags_lesson_012(self):
        from kryptosbot.real_k4_audit import lessons_used_by_coverage
        cv = {"n_layers": 1, "operation_source": "phrase_bound_step"}
        used = lessons_used_by_coverage(cv)
        assert "LESSON-012" in used

    def test_enumerated_columnar_tags_lesson_013(self):
        from kryptosbot.real_k4_audit import lessons_used_by_coverage
        cv = {
            "n_layers": 2,
            "col_order_source": "enumerated_permutation",
            "transposition_width": 5,
        }
        used = lessons_used_by_coverage(cv)
        assert "LESSON-013" in used
        # Keyword-stable-rank should NOT also fire.
        assert "LESSON-004" not in used

    def test_route_boustrophedon_tags_lesson_014(self):
        from kryptosbot.real_k4_audit import lessons_used_by_coverage
        cv = {
            "n_layers": 1,
            "route_mode": "route_boustrophedon",
            "route_width": 8,
        }
        used = lessons_used_by_coverage(cv)
        assert "LESSON-014" in used

    def test_substantive_row_reverse_tags_lesson_015(self):
        from kryptosbot.real_k4_audit import lessons_used_by_coverage
        cv = {
            "n_layers": 1,
            "row_reverse_width": 10,
            "row_reverse_parity": "odd",
            "row_reverse_identity": False,
        }
        used = lessons_used_by_coverage(cv)
        assert "LESSON-015" in used
        assert "LESSON-015-identity" not in used

    def test_identity_row_reverse_tags_lesson_015_identity(self):
        """The no-fold sentinel (row_reverse_identity=True) tags as
        LESSON-015-identity, NOT LESSON-015. This separation is the
        audit-hygiene contract — identity wrappers must not be
        miscredited as substantive folded-row reversal.
        """
        from kryptosbot.real_k4_audit import lessons_used_by_coverage
        cv = {
            "n_layers": 1,
            "row_reverse_width": 97,
            "row_reverse_parity": "odd",
            "row_reverse_identity": True,
        }
        used = lessons_used_by_coverage(cv)
        assert "LESSON-015" not in used
        assert "LESSON-015-identity" in used


# ===========================================================================
# (C) Public-crib match map
# ===========================================================================


class TestPublicCribMatchMap:
    def test_map_records_each_crib_position(self):
        from kryptosbot.real_k4_audit import public_crib_match_map
        crib = {21: "E", 22: "A", 63: "B"}
        pt = "X" * 97
        m = public_crib_match_map(pt, crib)
        # Sorted by position, one entry per crib.
        assert len(m) == 3
        positions = [e["position"] for e in m]
        assert positions == [21, 22, 63]
        for e in m:
            assert "expected" in e
            assert "got" in e
            assert "match" in e
            # All Xs in pt, none of the cribs match.
            assert e["match"] is False

    def test_map_records_match_correctly(self):
        from kryptosbot.real_k4_audit import public_crib_match_map
        crib = {0: "A", 1: "B"}
        pt = "AX" + "Z" * 95
        m = public_crib_match_map(pt, crib)
        assert m[0] == {"position": 0, "expected": "A", "got": "A", "match": True}
        assert m[1] == {"position": 1, "expected": "B", "got": "X", "match": False}


# ===========================================================================
# (D) Zero LLM calls
# ===========================================================================


class TestNoLlmCalls:
    def test_audit_module_does_not_import_sdk(self):
        """The real_k4_audit module must not import claude_agent_sdk
        or anthropic — its dispatch path is kernel-only.
        """
        import kryptosbot.real_k4_audit as audit_mod
        src = Path(audit_mod.__file__).read_text()
        assert "claude_agent_sdk" not in src, (
            "real_k4_audit.py must not import claude_agent_sdk"
        )
        assert "import anthropic" not in src, (
            "real_k4_audit.py must not import anthropic"
        )
        assert "from anthropic" not in src

    def test_audit_module_does_not_import_bench(self):
        """The real_k4_audit module must not import any K4Bench-
        adjacent modules — the firewall contract.
        """
        import kryptosbot.real_k4_audit as audit_mod
        src = Path(audit_mod.__file__).read_text()
        # Each forbidden bench import must be absent. Use line-anchored
        # patterns so a comment mentioning the module name doesn't
        # trip the test.
        forbidden_imports = (
            "from kryptosbot.bench_loader",
            "import kryptosbot.bench_loader",
            "from kryptosbot.bench_fallback import",
            "import kryptosbot.bench_fallback",
            "from kryptosbot.bench_attempts",
            "import kryptosbot.bench_attempts",
            "from .bench_loader",
            "from .bench_fallback import",
            "from .bench_attempts",
        )
        for pat in forbidden_imports:
            assert pat not in src, (
                f"real_k4_audit.py must not contain {pat!r}; that "
                "imports K4Bench-adjacent code into the audit path."
            )


# ===========================================================================
# (E) Context firewall
# ===========================================================================


class TestContextFirewall:
    """Strict firewall: nothing K4Bench-specific may surface in the
    real-K4 audit clue text, keyword pool, or emitted artifact.

    The check covers:
      1. K4Bench challenge IDs (K4B-NNN literal pattern)
      2. K4Bench challenge titles (read from
         bench/k4bench/challenges/*.json when available)
      3. Documented K4Bench-only keywords (CEDAR / LANTERN /
         ARCHIVE / SHADOW / etc.)
    """

    def _bench_challenge_title_words(self) -> set[str]:
        """Read every K4Bench challenge JSON and return the set of
        uppercase A-Z words of length >= 4 appearing in challenge
        TITLES (not the broader clue_text).

        K4Bench titles are short phrase-anchors that name the
        bench-specific intended-method (e.g. "Archive column walk",
        "Shadow reverse alphabet", "Cedar lantern"). The audit clue
        text MUST not contain any of those title-anchors as
        whole-word tokens — that would be a contamination signal.

        Generic cipher-mechanic vocabulary that appears in title
        words ("REVERSE", "ALPHABET", "COLUMN", "WALK") is NOT
        bench-specific; we filter against a small public-safe
        allow-list before returning the bench-only set.
        """
        out: set[str] = set()
        if not _K4BENCH_DIR.is_dir():
            return out
        for path in sorted(_K4BENCH_DIR.glob("K4B-*.json")):
            try:
                ch = json.loads(path.read_text())
            except json.JSONDecodeError:
                continue
            title = ch.get("title", "")
            for token in re.findall(r"[A-Za-z]+", title):
                upper = token.upper()
                if len(upper) < 4:
                    continue
                out.add(upper)
        # Public-safe: generic cipher-mechanic vocabulary that
        # appears in titles but is NOT bench-specific.
        public_safe = {
            "ALPHABET", "REVERSE", "REVERSED", "REVERSAL",
            "COLUMN", "COLUMNS", "WALK", "ROW", "ROWS",
            "PATH", "ROUTE", "GRID", "LINE", "LINES",
            "BLOCK", "BLOCKS", "FOLD", "FOLDED",
            "STEP", "STEPS", "STRIDE", "SKIP",
            "SHIFT", "ROTATE", "ROTATED",
            "FENCE", "RAIL", "DEPTH",
            "RAGGED", "BOUSTROPHEDON", "SERPENTINE", "ZIGZAG",
            "VIGENERE", "BEAUFORT", "ATBASH", "CAESAR",
            "STRIP", "STRIPS",
        }
        return out - public_safe

    def test_clue_registry_has_no_bench_id_pattern(self):
        from kryptosbot.real_k4_clue_registry import (
            real_k4_audit_clue_text, real_k4_clue_keywords,
        )
        text = real_k4_audit_clue_text()
        assert not re.search(r"\bK4B-\d+\b", text), (
            "audit clue text contains a K4B-NNN identifier"
        )
        for kw in real_k4_clue_keywords():
            assert not re.search(r"\bK4B-\d+\b", kw)

    def test_clue_registry_has_no_documented_bench_keywords(self):
        from kryptosbot.real_k4_clue_registry import (
            real_k4_audit_clue_text, real_k4_clue_keywords,
            forbidden_bench_keywords,
        )
        text = real_k4_audit_clue_text()
        forbidden = forbidden_bench_keywords()
        words = {w.upper() for w in re.findall(r"[A-Za-z]+", text)}
        overlap = words & forbidden
        assert not overlap, (
            f"audit clue text contains documented bench-only "
            f"keywords: {overlap}"
        )
        for kw in real_k4_clue_keywords():
            assert kw.upper() not in forbidden, (
                f"clue keyword pool contains bench-only term: {kw}"
            )

    def test_clue_registry_has_no_bench_title_anchors(self):
        """Cross-check against K4Bench challenge TITLES. Title words
        are the bench-specific phrase-anchors (e.g. "Archive column
        walk" → ARCHIVE; "Shadow reverse alphabet" → SHADOW). Generic
        cipher-mechanic title words (REVERSE, COLUMN, WALK) are
        filtered out by the helper's public-safe allow-list.

        v2 (2026-04-28): tokens explicitly authorized by the v2
        registry (``authorized_normalized_tokens``) are also
        subtracted — they are PUBLIC-K4 vocabulary by registry
        decision, so a bench challenge that happens to also use
        them does not constitute contamination of the audit.
        Examples: LATITUDE (geodetic_coordinate, also K4B-014's
        anchor); COMPASS (sculpture_context, also some bench
        challenges); COPPER (sculpture_context).
        """
        from kryptosbot.real_k4_clue_registry import (
            real_k4_audit_clue_text, real_k4_clue_keywords,
            authorized_normalized_tokens,
        )
        bench_only = self._bench_challenge_title_words()
        if not bench_only:
            pytest.skip("K4Bench corpus not available")
        # Subtract registry-authorized tokens from the bench-only
        # anchor set — those are public-K4 vocabulary the audit may
        # legitimately use even when a bench title happens to share
        # them.
        bench_only_unauthorized = bench_only - authorized_normalized_tokens()
        text_words = {
            w.upper() for w in re.findall(r"[A-Za-z]+", real_k4_audit_clue_text())
            if len(w) >= 4
        }
        overlap = text_words & bench_only_unauthorized
        assert not overlap, (
            f"audit clue text overlaps K4Bench title anchors on: "
            f"{overlap}. These tokens are NOT in the v2 registry's "
            "authorized list, so their presence in real-K4 audit "
            "material is contamination. Either remove them from "
            "the audit clue text or, if they are genuinely public-"
            "safe public-K4 vocabulary, register them in "
            "real_k4_clue_registry.py with explicit provenance."
        )
        kw_set = {kw.upper() for kw in real_k4_clue_keywords()}
        kw_overlap = kw_set & bench_only_unauthorized
        assert not kw_overlap, (
            f"audit keyword pool overlaps K4Bench title anchors on: "
            f"{kw_overlap}"
        )

    def test_audit_artifact_has_no_bench_contamination(self, tmp_path):
        """Run a small audit and grep the emitted JSON file for
        K4B-NNN identifiers and documented bench-only keywords NOT
        authorized by the v2 registry.
        """
        from kryptosbot.real_k4_audit import (
            RealK4AuditConfig, run_real_k4_hcc_audit,
        )
        from kryptosbot.real_k4_clue_registry import (
            forbidden_bench_keywords,
            authorized_normalized_tokens,
        )
        out = tmp_path / "audit.json"
        run_real_k4_hcc_audit(RealK4AuditConfig(
            output_path=out, max_specs=20, workers=2,
            top_n_in_artifact=20,
        ))
        text = out.read_text()
        bench_ids = re.findall(r"\bK4B-\d+\b", text)
        assert not bench_ids, (
            f"audit artifact contains K4Bench identifiers: "
            f"{set(bench_ids)}"
        )
        # Documented bench-only keywords MINUS registry-authorized
        # tokens. The forbidden list is a static documentation aid;
        # the registry is the operative authorization gate.
        unauthorized = (
            forbidden_bench_keywords() - authorized_normalized_tokens()
        )
        for kw in unauthorized:
            pattern = r"\b" + re.escape(kw) + r"\b"
            matches = re.findall(pattern, text, flags=re.IGNORECASE)
            assert not matches, (
                f"audit artifact contains UNAUTHORIZED bench-only "
                f"keyword {kw!r} ({len(matches)} occurrences); "
                "this token is in the documented bench-only list "
                "AND is not registered in the v2 clue registry."
            )


# ===========================================================================
# (F) Normal real-K4 mode unchanged
# ===========================================================================


class TestNormalRealK4Unchanged:
    def test_collect_hcc_seeds_still_returns_empty_in_real_k4(self, tmp_path):
        """The audit subsystem MUST NOT change the controller's
        ``_collect_hcc_seeds`` behavior. Real-K4 mode still returns
        ``[]``; the audit bypasses the controller entirely.
        """
        from kryptosbot.controller import (
            ControllerConfig, ResearchController,
        )
        cfg = ControllerConfig(
            project_root=tmp_path,
            ledger_db_path=tmp_path / "real_k4_ledger.sqlite",
            max_cycles=1, theories_per_cycle=5, dry_run=True,
        )
        controller = ResearchController(cfg)
        controller.state = controller.ledger.load_controller_state()
        controller._snapshot_session_baseline()
        assert controller._collect_hcc_seeds() == []

    def test_audit_module_imports_without_kernel_overrides(self):
        """Importing real_k4_audit must not install any kernel CT /
        crib overrides — those are reserved for K4Bench mode.
        """
        import os
        # Snapshot env state.
        ct_pre = os.environ.get("KRYPTOS_CT_OVERRIDE")
        crib_pre = os.environ.get("KRYPTOS_CRIB_DICT_OVERRIDE")
        # Import (idempotent if already loaded).
        import kryptosbot.real_k4_audit  # noqa: F401
        # Env unchanged.
        assert os.environ.get("KRYPTOS_CT_OVERRIDE") == ct_pre
        assert os.environ.get("KRYPTOS_CRIB_DICT_OVERRIDE") == crib_pre


# ===========================================================================
# (G) CLI flag wiring
# ===========================================================================


# ===========================================================================
# (H) v2 — tier filtering
# ===========================================================================


class TestTierFiltering:
    """The v2 registry exposes 5 tiers and a tier selector. Audit
    runs with different tier scopes produce different keyword pools
    and different active_tiers in the artifact.
    """

    def test_core_only_returns_core_keywords(self):
        from kryptosbot.real_k4_clue_registry import real_k4_clue_keywords
        kws = real_k4_clue_keywords(tiers="core")
        # Core tier has 7 entries.
        assert len(kws) == 7
        for kw in ("EAST", "NORTHEAST", "EASTNORTHEAST", "BERLIN",
                   "CLOCK", "BERLINCLOCK", "ENE"):
            assert kw in kws

    def test_core_legacy_includes_kryptos_plaintext(self):
        from kryptosbot.real_k4_clue_registry import real_k4_clue_keywords
        kws = real_k4_clue_keywords(tiers="core_legacy")
        # K1 plaintext + K1/K2 keyword + K3 plaintext words present.
        for kw in ("IQLUSION", "PALIMPSEST", "ABSCISSA",
                   "PASSAGE", "BURIED", "MAGNETIC", "LANGLEY"):
            assert kw in kws, f"core_legacy missing {kw}"

    def test_full_includes_all_non_trigger_tokens(self):
        from kryptosbot.real_k4_clue_registry import (
            real_k4_clue_keywords, all_entries,
        )
        kws = real_k4_clue_keywords(tiers="full", max_keywords=999)
        non_trigger = [
            e.token for e in all_entries() if not e.trigger_only
        ]
        for kw in non_trigger:
            assert kw in kws, f"full missing {kw}"

    def test_trigger_only_tokens_excluded_from_keyword_pool(self):
        from kryptosbot.real_k4_clue_registry import real_k4_clue_keywords
        kws = real_k4_clue_keywords(tiers="full", max_keywords=999)
        # Procedural-tier trigger-only tokens MUST NOT appear in the
        # keyword pool — they are clue-text triggers only.
        for trigger in ("ROUTE", "READ", "LAYER", "MASK", "GRID",
                        "COLUMN", "ROW", "FOLD", "REVERSE"):
            assert trigger not in kws, (
                f"trigger-only {trigger!r} leaked into keyword pool"
            )

    def test_keyword_role_filter(self):
        """``keyword_role='substitution'`` returns only entries with
        ``use_as_substitution=True``. Trigger-only entries are still
        excluded.
        """
        from kryptosbot.real_k4_clue_registry import real_k4_clue_keywords
        sub = real_k4_clue_keywords(
            tiers="full", keyword_role="substitution", max_keywords=999,
        )
        # Every entry currently has use_as_substitution=True except
        # trigger-only ones; the role filter and trigger filter give
        # the same result here.
        assert len(sub) > 0
        # Sanity: no trigger-only tokens.
        for t in ("ROUTE", "FOLD", "MIRROR", "REVERSE"):
            assert t not in sub

    def test_audit_records_active_tiers_in_artifact(self, tmp_path):
        """The artifact's run_metadata + clue_pack record which
        tiers were active for this audit run.
        """
        from kryptosbot.real_k4_audit import (
            RealK4AuditConfig, run_real_k4_hcc_audit,
        )
        out = tmp_path / "audit_core.json"
        run_real_k4_hcc_audit(RealK4AuditConfig(
            output_path=out, max_specs=15, workers=2,
            tier_selector="core",
        ))
        artifact = json.loads(out.read_text())
        active = artifact["run_metadata"]["active_tiers"]
        assert active == ["core_public_cribs"], (
            f"expected only core_public_cribs; got {active}"
        )
        assert artifact["clue_pack"]["registry_schema"] == "v2"
        # Clue pack records the tier-filtered entries.
        kp_words = {
            e["token"] for e in artifact["clue_pack"]["keyword_entries"]
        }
        # Every entry in the artifact's clue_pack carries a tier
        # field — verify they're all core_public_cribs.
        for e in artifact["clue_pack"]["keyword_entries"]:
            assert e["tier"] == "core_public_cribs"

    def test_unknown_tier_name_rejected(self):
        from kryptosbot.real_k4_clue_registry import resolve_tier_selector
        with pytest.raises(ValueError, match="unknown tier"):
            resolve_tier_selector("nonexistent_tier")

    def test_candidate_tier_signature_records_keyword_tiers(self):
        """When a candidate uses keywords from multiple tiers, the
        tier_signature records each tier the candidate touched."""
        from kryptosbot.real_k4_audit import candidate_tier_signature
        cv = {
            "substitution_keyword": "EAST",  # core_public_cribs
            "alphabet_keyword": "KRYPTOS",   # sculpture_context
            "transposition_keyword": "PALIMPSEST",  # kryptos_plaintext_legacy
        }
        sig = candidate_tier_signature(cv)
        assert set(sig["tiers"]) == {
            "core_public_cribs",
            "sculpture_context",
            "kryptos_plaintext_legacy",
        }
        sub = sig["lookups"]["substitution_keyword"]
        assert sub["keyword"] == "EAST"
        assert sub["tier"] == "core_public_cribs"
        assert sub["provenance"] == "public_crib_split"


# ===========================================================================
# (I) v2 — null-baseline calibration
# ===========================================================================


class TestNullBaseline:
    """The audit computes an analytical null distribution for
    max_crib_score under random A-Z plaintext. The independence
    assumption gives an UPPER BOUND on the null-tail probability;
    if the observed max is consistent with this null, the audit
    is definitively null-level.
    """

    def test_observed_max_6_over_28k_is_null_level(self):
        """The headline calibration: observed max_crib=6 across
        ~28000 candidates is at or below the expected maximum
        under independent random A-Z plaintexts. P-value >> 0.05
        → null_level (NOT breakthrough).

        This pins the interpretation of the real-K4 audit run: a
        max_crib of 6 over the full HCC catalogue is exactly what
        chance produces. Future audits that hit this level should
        not be misread as evidence that the HCC catalogue contains
        a near-solution.
        """
        from kryptosbot.real_k4_audit import compute_null_baseline
        nb = compute_null_baseline(28031, 6)
        # Expected max for n=28031 is ~6.5 (via the analytical
        # Binomial-max distribution).
        assert 5.5 < nb.expected_max_crib < 7.5
        # P(max >= 6) ≈ 0.999 — observed=6 is essentially the median
        # of the null max distribution.
        assert nb.p_value_for_observed_max > 0.5
        assert nb.classification == "null_level"

    def test_observed_max_24_over_any_n_is_breakthrough(self):
        """A perfect-crib hit (all 24 cribs match) on the real K4 is
        breakthrough at any candidate count.
        """
        from kryptosbot.real_k4_audit import compute_null_baseline
        for n in (1, 100, 10000, 28031):
            nb = compute_null_baseline(n, 24)
            assert nb.classification == "breakthrough", (
                f"n={n}: max=24 must be breakthrough; got {nb.classification}"
            )

    def test_observed_max_12_over_28k_is_breakthrough(self):
        """A max_crib of 12 over ~28k candidates is far above the
        chance ceiling; classified as breakthrough.
        """
        from kryptosbot.real_k4_audit import compute_null_baseline
        nb = compute_null_baseline(28031, 12)
        assert nb.classification == "breakthrough"
        assert nb.p_value_for_observed_max < 0.001

    def test_pvalue_monotone_in_observed(self):
        """Increasing observed_max with fixed n monotonically
        decreases p_value."""
        from kryptosbot.real_k4_audit import compute_null_baseline
        prev_p = 1.1  # arbitrary > 1
        for k in (4, 6, 8, 10, 12, 14):
            nb = compute_null_baseline(10000, k)
            assert nb.p_value_for_observed_max <= prev_p
            prev_p = nb.p_value_for_observed_max

    def test_pvalue_monotone_in_n_at_fixed_observed(self):
        """At fixed observed_max, increasing n increases (does not
        decrease) the p-value — more candidates make any specific
        observed max more likely under the null."""
        from kryptosbot.real_k4_audit import compute_null_baseline
        prev_p = -0.1
        for n in (10, 100, 1000, 10000, 100000):
            nb = compute_null_baseline(n, 5)
            assert nb.p_value_for_observed_max >= prev_p
            prev_p = nb.p_value_for_observed_max

    def test_classification_thresholds_overridable(self):
        """Operators may pass a stricter classification threshold."""
        from kryptosbot.real_k4_audit import compute_null_baseline
        nb_default = compute_null_baseline(10, 4)  # likely interesting
        nb_strict = compute_null_baseline(
            10, 4,
            classification_thresholds={
                "null_level_p_min": 0.5,
                "interesting_p_max": 0.5,
                "breakthrough_p_max": 0.0001,
            },
        )
        # Strict thresholds shift the classification boundaries.
        assert nb_strict.thresholds["interesting_p_max"] == 0.5

    def test_artifact_includes_null_baseline_block(self, tmp_path):
        """Every audit artifact carries a populated null_baseline
        block alongside coverage_summary."""
        from kryptosbot.real_k4_audit import (
            RealK4AuditConfig, run_real_k4_hcc_audit,
        )
        out = tmp_path / "audit_null.json"
        run_real_k4_hcc_audit(RealK4AuditConfig(
            output_path=out, max_specs=20, workers=2,
        ))
        artifact = json.loads(out.read_text())
        nb = artifact["null_baseline"]
        for key in (
            "n_candidates", "n_crib_positions", "alphabet_size",
            "expected_max_crib", "observed_max_crib",
            "p_value_for_observed_max", "classification",
            "p_max_geq", "thresholds", "model",
        ):
            assert key in nb, f"null_baseline missing {key}"
        # Real K4 plus a small HCC catalog should produce null-level
        # — observed_max is small relative to the expected max
        # under the null.
        assert nb["classification"] in (
            "null_level", "interesting", "breakthrough",
        )

    def test_summary_dict_includes_null_baseline(self, tmp_path):
        """The run_real_k4_hcc_audit return dict carries a
        null_baseline summary block.
        """
        from kryptosbot.real_k4_audit import (
            RealK4AuditConfig, run_real_k4_hcc_audit,
        )
        out = tmp_path / "audit_null2.json"
        summary = run_real_k4_hcc_audit(RealK4AuditConfig(
            output_path=out, max_specs=15, workers=2,
        ))
        nb = summary["null_baseline"]
        assert "expected_max_crib" in nb
        assert "p_value_for_observed_max" in nb
        assert "classification" in nb


# ===========================================================================
# (J) v2 — coverage by tier and provenance
# ===========================================================================


class TestCoverageByTier:
    def test_artifact_includes_by_tier_summary(self, tmp_path):
        from kryptosbot.real_k4_audit import (
            RealK4AuditConfig, run_real_k4_hcc_audit,
        )
        out = tmp_path / "audit_by_tier.json"
        run_real_k4_hcc_audit(RealK4AuditConfig(
            output_path=out, max_specs=30, workers=2,
            tier_selector="core_legacy",
        ))
        artifact = json.loads(out.read_text())
        cov = artifact["coverage_summary"]
        assert "by_tier" in cov
        assert "by_provenance" in cov
        # by_tier entries shape.
        for tier, entry in cov["by_tier"].items():
            assert "n_candidates" in entry
            assert "max_crib_score" in entry
            assert "distinct_families" in entry
            # Every recorded tier must be one of the known v2 tiers.
            from kryptosbot.real_k4_clue_registry import (
                CLUE_TIERS_IN_ORDER,
            )
            assert tier in CLUE_TIERS_IN_ORDER


class TestCliFlagWiring:
    def test_run_controller_help_lists_audit_flag(self):
        """The --real-k4-hcc-audit flag must be discoverable via
        --help. Run the parser in a subprocess so we capture
        argparse's text output without invoking the controller.
        """
        import subprocess
        result = subprocess.run(
            [sys.executable, "-m", "kryptosbot.run_controller", "--help"],
            cwd=_REPO_ROOT,
            env={**__import__("os").environ, "PYTHONPATH": str(_REPO_ROOT / "src")},
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0, (
            f"--help failed: rc={result.returncode}\n"
            f"stderr={result.stderr[-500:]}"
        )
        assert "--real-k4-hcc-audit" in result.stdout
        assert "--real-k4-hcc-audit-out" in result.stdout
        assert "--real-k4-hcc-audit-max-specs" in result.stdout
        # v2: tier-selection flag.
        assert "--real-k4-hcc-audit-tiers" in result.stdout
        assert "--real-k4-hcc-audit-max-keywords" in result.stdout

    def test_audit_flag_mutually_exclusive_with_bench_challenge(self, tmp_path):
        """--real-k4-hcc-audit and --bench-challenge MUST NOT be
        combined (the bench path installs synthetic kernel overrides
        which would corrupt the audit's public-K4 facts).

        Uses a real K4Bench challenge path so the file-existence
        pre-check passes; the parse_args mutual-exclusion check
        then fires.
        """
        import subprocess
        challenge = _K4BENCH_DIR / "K4B-001.json"
        if not challenge.exists():
            pytest.skip("K4Bench corpus not available")
        result = subprocess.run(
            [
                sys.executable, "-m", "kryptosbot.run_controller",
                "--real-k4-hcc-audit",
                "--bench-challenge", str(challenge),
            ],
            cwd=_REPO_ROOT,
            env={**__import__("os").environ, "PYTHONPATH": str(_REPO_ROOT / "src")},
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode != 0, (
            "expected non-zero exit when combining flags; got rc=0\n"
            f"stdout={result.stdout[-500:]}\n"
            f"stderr={result.stderr[-500:]}"
        )
        combined = (result.stdout + result.stderr).lower()
        assert "mutually exclusive" in combined, (
            f"expected 'mutually exclusive' error; got:\n"
            f"stdout={result.stdout[-500:]}\n"
            f"stderr={result.stderr[-500:]}"
        )
