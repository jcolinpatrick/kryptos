"""Audit-hygiene tests for LESSON-015 row_reverse + the standalone
single-layer substitution family.

These tests cover the post-LESSON-015 audit-hygiene patch
(2026-04-28). Two related concerns:

  (A) Identity wrappers must be tagged. The no-fold sentinel
      ``row_reverse(width=CT_LEN, parity=odd, start_row=0)`` is
      the identity permutation. Without an explicit tag in the
      coverage_vector, downstream success-attribution tooling
      cannot distinguish "folded-row reversal was the missing
      capability" from "an identity wrapper rode a substitution
      layer to surface a substitution-alone-equivalent spec".
      Every emitted row_reverse spec MUST carry
      ``row_reverse_identity = _row_reverse_is_identity(...)`` so
      this distinction is auditable from the attempt artifact
      alone.

  (B) Standalone single-layer substitution must be reachable
      directly. The pre-2026-04-28 catalog never emitted
      single-layer Vigenere / Beaufort / Variant Beaufort
      candidates — every substitution layer was paired with a
      transposition partner. K4B-008's intended decryption is
      a single-layer Vigenere(SHADOW, mirrored_KA), and reaching
      it through an identity row_reverse wrapper is fragile and
      misleading in attribution. The standalone substitution
      family is now an always-on default that emits one spec per
      (sub_kind × clue_keyword × alphabet_mode).

The tests below pin both behaviours and prove real-K4 normal
mode is unchanged (HCC remains bench-only via _collect_hcc_seeds).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from kryptosbot.hand_cipher_core import (
    AlphabetMode,
    CoverageVector,
    _gen_row_reverse_alone_family,
    _gen_row_reverse_substitution_family,
    _gen_standalone_substitution_family,
    _row_reverse_is_identity,
    generate_layered_specs,
)


_REPO_ROOT = Path(__file__).resolve().parents[2]
_K4B008_PATH = _REPO_ROOT / "bench" / "k4bench" / "challenges" / "K4B-008.json"


# ===========================================================================
# (A) Identity tagging on row_reverse
# ===========================================================================


class TestRowReverseIdentityHelper:
    """Pin the truth-table for ``_row_reverse_is_identity``. The
    helper duplicates the dispatcher's parity logic exactly; if
    the dispatcher's logic changes, this helper must change too,
    and these tests catch silent drift.
    """

    def test_no_fold_sentinel_is_identity(self):
        """The canonical no-fold sentinel: width=CT_LEN, parity=odd,
        start_row=0. Only row 0 exists; row 0 is even; parity=odd
        selects no rows → identity.
        """
        assert _row_reverse_is_identity(97, "odd", 0) is True

    def test_full_reversal_is_not_identity(self):
        """width=CT_LEN, parity=even, start_row=0 reverses the entire
        text. Not identity.
        """
        assert _row_reverse_is_identity(97, "even", 0) is False

    def test_normal_alternate_row_reversal_is_not_identity(self):
        """The substantive case: width=10, any parity. Multi-row
        partition with selected rows of length > 1.
        """
        assert _row_reverse_is_identity(10, "odd", 0) is False
        assert _row_reverse_is_identity(10, "even", 0) is False

    def test_parity_both_is_never_identity_for_normal_widths(self):
        """parity=both reverses every row; identity would require
        every row to have length ≤ 1, which doesn't happen for any
        practical width.
        """
        assert _row_reverse_is_identity(10, "both", 0) is False
        assert _row_reverse_is_identity(97, "both", 0) is False

    def test_start_row_offset_flips_parity_at_width_ct_length(self):
        """At width=CT_LEN there is only row 0. With start_row=1 the
        effective row index becomes -1, which under Python modulo
        flips the parity selector.
        """
        # width=97, parity=odd, start_row=1: -1%2==1 → reverse row 0
        # (length 97) → not identity.
        assert _row_reverse_is_identity(97, "odd", 1) is False
        # width=97, parity=even, start_row=1: -1%2==0 → False but
        # parity=even checks ==0; (-1)%2==1 in Python so ==0 is
        # False → row 0 not reversed → identity.
        assert _row_reverse_is_identity(97, "even", 1) is True


class TestRowReverseAloneFamilyIdentityTag:
    """Every row_reverse alone-family spec carries a populated
    ``row_reverse_identity`` field whose value matches the helper.
    """

    def test_alone_family_identity_field_populated(self):
        out = _gen_row_reverse_alone_family(
            bench_slug="t",
            widths=[
                (97, "default_set"),       # no-fold sentinel
                (10, "phrase_bound_row_reverse_width"),
                (5, "clue_keyword_length"),
            ],
        )
        assert out, "alone family produced no specs"
        for s in out:
            cv = s.coverage
            # The identity field must be a bool (never None for
            # specs that DO include a row_reverse layer).
            assert cv.row_reverse_identity is not None
            assert isinstance(cv.row_reverse_identity, bool)
            # The value must agree with the helper.
            expected = _row_reverse_is_identity(
                cv.row_reverse_width,
                cv.row_reverse_parity,
                cv.row_reverse_start_row,
            )
            assert cv.row_reverse_identity is expected

    def test_no_fold_sentinel_tagged_as_identity(self):
        """The (width=97, parity=odd) variant in the alone family
        MUST have row_reverse_identity=True.
        """
        out = _gen_row_reverse_alone_family(
            bench_slug="t",
            widths=[(97, "default_set")],
        )
        sentinel = [
            s for s in out
            if s.coverage.row_reverse_width == 97
            and s.coverage.row_reverse_parity == "odd"
        ]
        assert sentinel, "no-fold sentinel not in alone family"
        for s in sentinel:
            assert s.coverage.row_reverse_identity is True, (
                "no-fold sentinel must be tagged identity=True; "
                "without this flag a no-fold-sentinel win cannot be "
                "distinguished from substantive folded-row reversal "
                "in attribution."
            )

    def test_substantive_row_reverse_tagged_non_identity(self):
        """The width=10, parity=odd variant DOES reverse rows
        (substantive case). Must be tagged identity=False.
        """
        out = _gen_row_reverse_alone_family(
            bench_slug="t",
            widths=[(10, "phrase_bound_row_reverse_width")],
        )
        substantive = [
            s for s in out
            if s.coverage.row_reverse_width == 10
        ]
        assert substantive
        for s in substantive:
            assert s.coverage.row_reverse_identity is False


class TestRowReverseSubstitutionFamilyIdentityTag:
    """Identity tag is propagated through the substitution-paired
    family generator too — not just the alone family.
    """

    def test_paired_family_carries_identity_tag(self):
        out = _gen_row_reverse_substitution_family(
            bench_slug="t",
            sub_kind="vigenere",
            keyword_a="ALPHA", keyword_b="BRAVO",
            widths=[
                (97, "default_set"),
                (10, "phrase_bound_row_reverse_width"),
            ],
        )
        assert out
        for s in out:
            cv = s.coverage
            assert cv.row_reverse_identity is not None
            expected = _row_reverse_is_identity(
                cv.row_reverse_width,
                cv.row_reverse_parity,
                cv.row_reverse_start_row,
            )
            assert cv.row_reverse_identity is expected

    def test_paired_family_separates_identity_from_substantive(self):
        """The same family contains both identity wrappers
        (width=97, parity=odd) and substantive folded-row reversals
        (width=10). Both must be tagged correctly so attribution
        can split them.
        """
        out = _gen_row_reverse_substitution_family(
            bench_slug="t",
            sub_kind="vigenere",
            keyword_a="ALPHA", keyword_b="BRAVO",
            widths=[
                (97, "default_set"),
                (10, "phrase_bound_row_reverse_width"),
            ],
        )
        identity_specs = [
            s for s in out if s.coverage.row_reverse_identity is True
        ]
        substantive_specs = [
            s for s in out if s.coverage.row_reverse_identity is False
        ]
        assert identity_specs, (
            "no-fold-sentinel identity specs missing from paired family"
        )
        assert substantive_specs, (
            "substantive folded-row specs missing from paired family"
        )
        # Identity specs must all have width=97 (the only no-fold
        # case). Substantive specs must all have width != 97 OR
        # parity != odd (i.e. they actually reverse something).
        for s in identity_specs:
            assert s.coverage.row_reverse_width == 97
            assert s.coverage.row_reverse_parity == "odd"
        for s in substantive_specs:
            assert not (
                s.coverage.row_reverse_width == 97
                and s.coverage.row_reverse_parity == "odd"
            )


class TestRowReverseIdentityRoundTrip:
    """The identity tag round-trips through the CoverageVector
    dict serialization."""

    def test_identity_field_in_to_dict(self):
        cv = CoverageVector(
            layer_family="row_reverse",
            layer_order=("row_reverse",),
            role_assignment=(),
            alphabet="AZ", n_layers=1,
            row_reverse_width=97,
            row_reverse_parity="odd",
            row_reverse_source="default_set",
            row_reverse_ragged=False,
            row_reverse_start_row=0,
            row_reverse_identity=True,
        )
        d = cv.to_dict()
        assert d["row_reverse_identity"] is True
        cv2 = CoverageVector.from_dict(d)
        assert cv2.row_reverse_identity is True

    def test_identity_false_round_trip(self):
        cv = CoverageVector(
            layer_family="row_reverse",
            layer_order=("row_reverse",),
            role_assignment=(),
            alphabet="AZ", n_layers=1,
            row_reverse_width=10,
            row_reverse_parity="odd",
            row_reverse_source="phrase_bound_row_reverse_width",
            row_reverse_ragged=True,
            row_reverse_start_row=0,
            row_reverse_identity=False,
        )
        d = cv.to_dict()
        assert d["row_reverse_identity"] is False
        cv2 = CoverageVector.from_dict(d)
        assert cv2.row_reverse_identity is False

    def test_identity_none_for_legacy_specs(self):
        """A spec without a row_reverse layer leaves the field at
        None. Round-trip preserves None.
        """
        cv = CoverageVector(
            layer_family="columnar_vigenere",
            layer_order=("vigenere", "columnar"),
            role_assignment=(("vigenere", "ALPHA"), ("columnar", "BRAVO")),
            alphabet="AZ", n_layers=2,
        )
        d = cv.to_dict()
        assert d["row_reverse_identity"] is None
        cv2 = CoverageVector.from_dict(d)
        assert cv2.row_reverse_identity is None


# ===========================================================================
# (B) Standalone single-layer substitution family
# ===========================================================================


class TestStandaloneSubstitutionFamily:
    """The standalone family emits one spec per (sub_kind ×
    clue_keyword × alphabet_mode) and is always on (no trigger
    required). This closes the K4B-008-style coverage gap where
    single-layer substitution was previously only reachable
    through an identity row_reverse wrapper.
    """

    def test_emits_specs_from_clue_pack(self):
        out = _gen_standalone_substitution_family(
            bench_slug="t",
            sub_kind="vigenere",
            clue_keywords=["ALPHA", "BRAVO", "CHARLIE"],
            alphabet_modes=[
                AlphabetMode("AZ", "AZ", None, "default"),
                AlphabetMode("KA", "KA", None, "kryptos_alphabet"),
            ],
        )
        # 3 keywords × 2 alphabets = 6 specs.
        assert len(out) == 6
        for s in out:
            assert s.coverage.layer_family == "standalone_vigenere"
            assert s.coverage.layer_order == ("vigenere",)
            assert s.coverage.n_layers == 1
            # Single-layer; no row_reverse / route fields populated.
            assert s.coverage.row_reverse_identity is None
            assert s.coverage.route_mode == ""

    def test_emits_for_all_three_sub_kinds(self):
        for sub_kind in ("vigenere", "beaufort", "variant_beaufort"):
            out = _gen_standalone_substitution_family(
                bench_slug="t",
                sub_kind=sub_kind,
                clue_keywords=["ALPHA"],
                alphabet_modes=[
                    AlphabetMode("AZ", "AZ", None, "default"),
                ],
            )
            assert out
            for s in out:
                assert s.coverage.layer_family == (
                    f"standalone_{sub_kind}"
                )
                assert s.coverage.layer_order == (sub_kind,)

    def test_dedups_identical_keyword_alphabet_pairs(self):
        """Passing the same (keyword, alphabet_mode) twice produces
        one spec, not two. Hash-based dedup on
        (keyword, mode_label, source).
        """
        mode = AlphabetMode("AZ", "AZ", None, "default")
        out = _gen_standalone_substitution_family(
            bench_slug="t",
            sub_kind="vigenere",
            clue_keywords=["ALPHA", "alpha", "ALPHA"],  # case + dup
            alphabet_modes=[mode, mode],  # dup mode
        )
        # All three keyword inputs upper-case to ALPHA; both modes
        # have the same key. So dedup → 1 spec.
        assert len(out) == 1

    def test_emits_in_default_catalogue_without_trigger(self):
        """The standalone family fires on every clue pack (no
        trigger required). A clue with NO row_reverse / route
        triggers must still produce standalone substitution specs.

        Uses production-scale ``max_specs`` because standalone is
        placed AFTER the legacy keyword-pair families (so the
        K4B-001 cap-preservation invariant holds for very small
        caps). At production scale (~10000 specs) standalone is
        reliably reachable.
        """
        specs = generate_layered_specs(
            ["ALPHA", "BRAVO"], bench_slug="t",
            clue_text="ordinary cipher problem",
            max_specs=10000,
        )
        standalone = [
            s for s in specs
            if s.coverage.layer_family.startswith("standalone_")
        ]
        assert standalone, (
            "standalone substitution family must fire without a "
            "trigger; this is a coverage-floor contract at "
            "production scale."
        )
        # At least one of each sub_kind.
        families = {s.coverage.layer_family for s in standalone}
        assert "standalone_vigenere" in families
        assert "standalone_beaufort" in families
        assert "standalone_variant_beaufort" in families

    def test_alphabet_modes_propagate(self):
        """Standalone specs surface ALL triggered alphabet modes —
        AZ, KA, keyword_mixed, mirrored_az, mirrored_ka — when
        the clue text fires the mirror trigger.
        """
        clue = (
            "A dark strip gives SHADOW and a KRYPTOS alphabet "
            "with the far end folded back over the near end."
        )
        specs = generate_layered_specs(
            ["SHADOW", "KRYPTOS", "DARK"], bench_slug="t",
            clue_text=clue, max_specs=20000,
        )
        standalone = [
            s for s in specs
            if s.coverage.layer_family == "standalone_vigenere"
        ]
        modes = {s.coverage.alphabet_mode for s in standalone}
        # Mirror trigger fires on this clue → mirrored_ka must be
        # in the standalone mode set.
        assert "AZ" in modes
        assert "KA" in modes
        assert "keyword_mixed" in modes
        assert "mirrored_az" in modes
        assert "mirrored_ka" in modes


class TestK4B008StandaloneCoverage:
    """K4B-008 canary: the HCC catalog must contain a standalone
    Vigenere(SHADOW) + mirrored_KA candidate WITHOUT requiring
    an identity row_reverse wrapper.
    """

    def test_k4b008_standalone_vigenere_shadow_mirror_ka(self):
        if not _K4B008_PATH.exists():
            pytest.skip(f"K4B-008 fixture not on disk at {_K4B008_PATH}")
        from kryptosbot.bench_loader import load_k4bench_challenge
        from kryptosbot.bench_fallback import hand_cipher_core_fallback
        ch = load_k4bench_challenge(_K4B008_PATH)
        ch.install_kernel_overrides()
        seeds = hand_cipher_core_fallback(
            ch.canonical_facts(), n_target=20,
        )
        match = [
            s for s in seeds
            if s.minimal_test_spec.get("coverage_vector", {}).get(
                "layer_family"
            ) == "standalone_vigenere"
            and s.minimal_test_spec.get("coverage_vector", {}).get(
                "substitution_keyword"
            ) == "SHADOW"
            and s.minimal_test_spec.get("coverage_vector", {}).get(
                "alphabet_mode"
            ) == "mirrored_ka"
        ]
        assert match, (
            "K4B-008 catalog must contain a STANDALONE "
            "Vigenere(SHADOW) + mirrored_KA candidate (single-layer, "
            "no row_reverse wrapper). The pre-audit catalog reached "
            "this answer only via an identity row_reverse(width=97, "
            "parity=odd) wrapper — that workaround misattributes the "
            "win to folded-row reversal."
        )

    def test_k4b008_standalone_layers_are_single_layer(self):
        if not _K4B008_PATH.exists():
            pytest.skip(f"K4B-008 fixture not on disk at {_K4B008_PATH}")
        from kryptosbot.bench_loader import load_k4bench_challenge
        from kryptosbot.bench_fallback import hand_cipher_core_fallback
        ch = load_k4bench_challenge(_K4B008_PATH)
        ch.install_kernel_overrides()
        seeds = hand_cipher_core_fallback(
            ch.canonical_facts(), n_target=20,
        )
        standalone = [
            s for s in seeds
            if s.minimal_test_spec.get("coverage_vector", {}).get(
                "layer_family", ""
            ).startswith("standalone_")
        ]
        assert standalone, (
            "K4B-008 catalog has no standalone substitution seeds"
        )
        for s in standalone[:50]:
            cv = s.minimal_test_spec["coverage_vector"]
            assert cv.get("n_layers") == 1
            assert len(cv.get("layer_order") or []) == 1
            # No row_reverse fields on a standalone substitution
            # spec — they're substantively different families.
            assert cv.get("row_reverse_identity") is None
            assert cv.get("row_reverse_width") is None


# ===========================================================================
# (C) Real-K4 normal mode unchanged
# ===========================================================================


class TestRealK4NormalModeUnchanged:
    """Audit-hygiene patch must not alter real-K4 mode behaviour.
    HCC remains bench-only via _collect_hcc_seeds; the standalone
    substitution family adds catalog coverage but stays gated by
    the same bench-mode mechanism that gates LESSON-014 / LESSON-
    015 emission.
    """

    def test_real_k4_collect_hcc_seeds_returns_empty(self, tmp_path):
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
        seeds = controller._collect_hcc_seeds()
        assert seeds == [], (
            "real-K4 mode must NOT auto-emit HCC seeds — including "
            "the new standalone substitution family. HCC is bench-"
            "only by design; the standalone family does not bypass "
            "that gate."
        )

    def test_standalone_family_in_default_catalogue_for_bench(self):
        """A bench-style call with a normal clue MUST produce
        standalone substitution specs in the default catalogue.
        Together with the previous test this proves the gating is
        bench-mode-only: real-K4 returns empty, bench-mode returns
        full catalogue including standalone_*.
        """
        specs = generate_layered_specs(
            ["ALPHA"], bench_slug="t",
            clue_text="ordinary cipher problem",
            max_specs=10000,
        )
        standalone = [
            s for s in specs
            if s.coverage.layer_family.startswith("standalone_")
        ]
        assert standalone


# ===========================================================================
# (D) Coverage_vector dict round-trip with identity tag
# ===========================================================================


class TestCoverageVectorDictRoundTripWithIdentity:
    """End-to-end: an HCC spec's coverage_vector serializes to a
    dict that preserves the row_reverse_identity field through
    JSON serialization in the attempt artifact.
    """

    def test_hcc_spec_dict_round_trip(self):
        out = _gen_row_reverse_alone_family(
            bench_slug="t",
            widths=[(97, "default_set"),
                    (10, "phrase_bound_row_reverse_width")],
        )
        for s in out:
            d = s.coverage.to_dict()
            assert "row_reverse_identity" in d
            cv2 = CoverageVector.from_dict(d)
            assert cv2.row_reverse_identity == (
                s.coverage.row_reverse_identity
            )
