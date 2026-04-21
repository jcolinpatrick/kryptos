"""Tests for kryptosbot.self_test.

Framework maturation Phase 7 (2026-04-21). Brief §9.5:
- Self-test harness runs end-to-end in dry-run mode.
- Kernel-verified scoring on K1 PT returns expected score.
- Contextmanager correctly restores original CT after the test.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kryptosbot.self_test import (
    Panel,
    PanelResult,
    _K1, _K2, _K3, _PANELS,
    _score_panel_candidate,
    _quagmire_iii_candidates,
    ct_override,
    main,
    run_panel_dryrun,
    verify_known_answer_contained,
)


# ─── Contextmanager restores CT ─────────────────────────────────────────────

class TestCtOverride:
    def test_ct_override_swaps_and_restores(self):
        from kryptos.kernel import constants as kc
        original_ct = kc.CT
        original_ct_len = kc.CT_LEN
        assert len(original_ct) == 97

        with ct_override(_K1):
            assert kc.CT == _K1.ciphertext
            assert kc.CT_LEN == len(_K1.ciphertext)
            assert kc.CT_LEN == 63

        # After exit, must be restored exactly.
        assert kc.CT == original_ct
        assert kc.CT_LEN == original_ct_len

    def test_ct_override_restores_on_exception(self):
        from kryptos.kernel import constants as kc
        original_ct = kc.CT

        with pytest.raises(RuntimeError, match="synthetic"):
            with ct_override(_K2):
                assert kc.CT == _K2.ciphertext
                raise RuntimeError("synthetic")
        # Restored even after exception.
        assert kc.CT == original_ct


# ─── Kernel sanity on known keys ────────────────────────────────────────────

class TestKernelSanity:
    """Brief §9.5: kernel-verified scoring on K1 PT returns expected.

    We strengthen this: for K1 and K2, verify the kernel's quagmire_decrypt
    with the published key produces the published plaintext (prefix match).
    """

    def test_k1_kernel_decrypt_matches_known_plaintext(self):
        v = verify_known_answer_contained(_K1)
        assert v["direct_kernel_decrypt_works"] is True, (
            f"kernel regression for K1: {v}"
        )
        # Full prefix must match (the kernel either solves it or it doesn't).
        assert v["recovered_prefix"].startswith("BETWEEN")

    def test_k2_kernel_decrypt_matches_known_plaintext(self):
        v = verify_known_answer_contained(_K2)
        assert v["direct_kernel_decrypt_works"] is True, (
            f"kernel regression for K2: {v}"
        )
        assert v["recovered_prefix"].startswith("ITWASTOT")

    def test_k3_reports_not_single_call(self):
        """K3 double columnar transposition can't be decrypted in a single
        kernel call; the sanity check correctly reports that."""
        v = verify_known_answer_contained(_K3)
        assert v["direct_kernel_decrypt_works"] is None
        assert "double-columnar" in v["note"].lower() or \
               "not expressible" in v["note"].lower()


# ─── Per-panel scoring ──────────────────────────────────────────────────────

class TestPanelScoring:
    def test_full_match_gives_max(self):
        """Exact known plaintext → full pseudo-crib match."""
        assert _score_panel_candidate(_K1, _K1.known_plaintext) == \
            _K1.cribs_prefix_chars + _K1.cribs_suffix_chars

    def test_all_zeros_scores_zero(self):
        assert _score_panel_candidate(_K1, "X" * 100) == 0

    def test_partial_match_scores_partial(self):
        # Prefix only:
        c = _K1.known_plaintext[:10] + "X" * 100
        score = _score_panel_candidate(_K1, c)
        # Expect 10 (prefix) + whatever suffix match (probably 0):
        assert score >= 10


# ─── Dry-run panel execution ────────────────────────────────────────────────

class TestDryRunExecution:
    """Brief §9.6: self-test runnable in dry-run mode."""

    def test_dryrun_k1_discovers_within_budget(self):
        r = run_panel_dryrun(_K1, max_cycles=500)
        assert r.discovered is True, (
            f"K1 dry-run failed to discover: peak_score={r.peak_score}, "
            f"tested={r.total_candidates_tested}"
        )
        assert r.discovered_via == "quagmire_iii"
        assert r.peak_score == r.pseudo_crib_total
        assert r.cycles_to_discovery is not None
        assert r.cycles_to_discovery <= r.total_candidates_tested

    def test_dryrun_k2_discovers_within_budget(self):
        r = run_panel_dryrun(_K2, max_cycles=500)
        assert r.discovered is True, (
            f"K2 dry-run failed to discover: peak_score={r.peak_score}, "
            f"tested={r.total_candidates_tested}"
        )
        assert r.discovered_via == "quagmire_iii"

    def test_dryrun_k3_reports_accurate_result(self):
        """K3 is out of scope for Phase 7's single-layer enumerator. The
        harness must report accurately — NOT falsely claim discovery."""
        r = run_panel_dryrun(_K3, max_cycles=500)
        # Either discovered=False (expected) or if somehow discovered,
        # the method and score must be consistent.
        if r.discovered:
            # Framework actually found K3 via some luck path — record that.
            # Not expected in Phase 7 but not a failure either.
            assert r.peak_score == r.pseudo_crib_total
        else:
            assert r.peak_score < r.pseudo_crib_total

    def test_dryrun_emits_zero_false_positives(self):
        """Brief §9.2: false-positive breakthroughs must be zero.
        (None of our dry-run candidates self-report crib_score=24 because
        the harness doesn't feed results through the K4 alert path.)"""
        for panel in _PANELS.values():
            r = run_panel_dryrun(panel, max_cycles=100)
            assert r.false_positive_breakthroughs == 0


# ─── Keyword corpus coverage ────────────────────────────────────────────────

class TestKeywordCorpus:
    """Brief §9.4: K1/K2 keys must appear in the reasonable corpus."""

    def test_palimpsest_in_corpus(self):
        from kryptosbot.self_test import _keyword_corpus
        assert "PALIMPSEST" in _keyword_corpus(_K1)

    def test_abscissa_in_corpus(self):
        from kryptosbot.self_test import _keyword_corpus
        assert "ABSCISSA" in _keyword_corpus(_K2)


# ─── CLI integration ────────────────────────────────────────────────────────

class TestCli:
    def test_main_all_panels_dryrun(self, tmp_path: Path, capsys):
        report_path = tmp_path / "selftest.json"
        rc = main([
            "--panel", "all", "--mode", "dry-run",
            "--cycles", "100",
            "--report-path", str(report_path),
        ])
        assert rc == 0
        assert report_path.exists()
        payload = json.loads(report_path.read_text())
        assert payload["mode"] == "dry-run"
        panels = {r["panel"] for r in payload["results"]}
        assert panels == {"k1", "k2", "k3"}
        # K1 and K2 must solve.
        for r in payload["results"]:
            if r["panel"] in ("k1", "k2"):
                assert r["discovered"] is True, (
                    f"{r['panel']} should solve in dry-run; got {r}"
                )

    def test_main_real_mode_skips_cleanly(self, tmp_path: Path, capsys):
        """Real-API mode isn't implemented; CLI must print SKIPPED
        and exit 0 without crashing."""
        rc = main([
            "--panel", "k1", "--mode", "real", "--cycles", "5",
        ])
        assert rc == 0
        out = capsys.readouterr().out
        assert "SKIPPED" in out


# ─── Panel inventory integrity ──────────────────────────────────────────────

class TestPanelIntegrity:
    def test_panel_ciphertexts_are_uppercase_alpha(self):
        for p in _PANELS.values():
            assert p.ciphertext.isupper()
            assert p.ciphertext.isalpha(), (
                f"{p.name} ciphertext has non-alpha: "
                f"{set(p.ciphertext) - set('ABCDEFGHIJKLMNOPQRSTUVWXYZ')}"
            )

    def test_k1_k2_lengths_match_canonical(self):
        assert len(_K1.ciphertext) == 63
        # K2 in Elonka's canonical with ?-nulls stripped is 369.
        assert len(_K2.ciphertext) == 369

    def test_known_plaintexts_are_non_empty(self):
        for p in _PANELS.values():
            assert len(p.known_plaintext) >= 40
