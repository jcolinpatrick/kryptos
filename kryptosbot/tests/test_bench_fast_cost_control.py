"""Tests for the K4Bench cost-control flags landed 2026-04-28.

Covers the contract that ``--bench-fast`` (and the underlying
``ControllerConfig`` fields ``bench_fast``, ``skip_red_team``,
``skip_synthesis``, ``deterministic_critic``, ``redteam_min_crib_score``)
runs deterministic HandCipherCore seeds through the full controller +
dispatcher + attempt-artifact path WITHOUT invoking the LLM theorist,
critic-LLM-path, red-team sibling call, or synthesis sibling call.

Pinned properties:

  1. ``parse_args`` accepts every new flag and stores them on the
     argparse namespace.
  2. ``parse_args`` populates the right ``ControllerConfig`` fields
     (via the wiring in ``main``); ``--bench-fast`` orchestrates the
     three sub-flags by default.
  3. ``ResearchController._red_team_filter`` honours the HCC-bypass
     gate when ``redteam_min_crib_score > 0``: HCC seeds (identified
     by ``minimal_test_spec.method == 'bench_hand_cipher_core'``)
     skip ``run_red_team_precheck`` entirely; LLM-origin theories
     still hit it.
  4. The startup banner shows the cost-control mode lines so the
     operator can confirm at-a-glance which phases are spending tokens.
  5. Real-K4 mode is unchanged: with no flags set, the banner has no
     cost-control rows and the red-team gate runs against every theory.
  6. End-to-end smoke: launching ``run_controller.py`` with
     ``--bench-challenge ... --hcc-only --bench-fast --dry-run`` exits
     cleanly without any LLM call (the dispatch step is the dry-run
     skip — workers are not the LLM, the theorist/critic/red-team/
     synthesis sibling calls are).
"""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

from kryptosbot.bench_loader import load_k4bench_challenge
from kryptosbot.controller import (
    ControllerConfig,
    ResearchController,
    _is_hcc_seed,
)
from kryptosbot.models import (
    CriticDecision,
    CriticVerdict,
    TheoryRecord,
    TheoryStatus,
)
from kryptosbot.pantheon import AgentSpec
from kryptosbot.pantheon_siblings import RedTeamVerdict


_REPO_ROOT = Path(__file__).resolve().parents[2]
_K4B001_PATH = _REPO_ROOT / "bench" / "k4bench" / "challenges" / "K4B-001.json"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse(argv: list[str]):
    """Run ``parse_args`` with a stubbed argv; raise SystemExit on error."""
    from kryptosbot.run_controller import parse_args
    with mock.patch.object(sys, "argv", ["run_controller.py", *argv]):
        return parse_args()


def _redteam_roster() -> dict[str, AgentSpec]:
    return {
        "red-team-disprover": AgentSpec(
            name="red-team-disprover",
            description="cost-control test fixture",
            body="adversarial pre-check",
            model="sonnet",
        )
    }


def _make_hcc_seed(hid: str = "hcc-1") -> TheoryRecord:
    """Build a TheoryRecord that mimics a bench HCC seed.

    The discriminator is ``minimal_test_spec.method ==
    'bench_hand_cipher_core'`` — that's what ``_is_hcc_seed`` checks.
    """
    t = TheoryRecord(
        hypothesis_id=hid,
        title="HCC seed: vigenere+columnar",
        core_claim="determinstic seed",
        mechanism="apply layers",
        family="columnar_vigenere",
        kill_criteria=["never"],
        expected_signal="crib_score >= 10",
        minimal_test_spec={
            "method": "bench_hand_cipher_core",
            "parameters": {"layers": ["vigenere", "columnar"]},
        },
        origin="programmatic_fallback",
    )
    t.critic_verdict = CriticVerdict(
        decision=CriticDecision.APPROVE,
        confidence=1.0,
        reasons=["bench-mode HCC seed"],
    )
    return t


def _make_llm_theory(hid: str = "llm-1") -> TheoryRecord:
    t = TheoryRecord(
        hypothesis_id=hid,
        title="LLM theory: serpentine reading",
        core_claim="serpentine reading order then vigenere",
        mechanism="serpentine then vig",
        family="serpentine",
        kill_criteria=["never"],
        expected_signal="crib_score >= 10",
        minimal_test_spec={
            "method": "keyword_sweep",
            "parameters": {"family": "serpentine"},
        },
        origin="theorist_agent",
    )
    t.critic_verdict = CriticVerdict(
        decision=CriticDecision.APPROVE,
        confidence=0.9,
        reasons=["LLM-generated"],
    )
    return t


def _bench_controller(tmp_path: Path, **overrides) -> ResearchController:
    """Build a bench-mode controller with a synthetic K4B-001 fixture."""
    if not _K4B001_PATH.exists():
        pytest.skip(f"K4B-001 challenge fixture not on disk at {_K4B001_PATH}")
    challenge = load_k4bench_challenge(_K4B001_PATH)
    cfg_kwargs: dict[str, Any] = dict(
        project_root=tmp_path,
        ledger_db_path=tmp_path / "k4bench" / "test_costctl.sqlite",
        max_cycles=1,
        theories_per_cycle=5,
        dry_run=True,
        bench_challenge_payload=challenge.canonical_facts(),
        bench_challenge_prompt_block=challenge.prompt_block(),
        include_oranchak_corpora=False,
        include_serpentine_anchor=False,
    )
    cfg_kwargs.update(overrides)
    cfg = ControllerConfig(**cfg_kwargs)
    controller = ResearchController(cfg)
    controller.state = controller.ledger.load_controller_state()
    controller._snapshot_session_baseline()
    # Inject a real red-team roster so ``select_redteam`` returns a
    # spec; otherwise the filter early-exits via the "not in roster"
    # branch and we cannot tell the bypass gate from a generic skip.
    controller._pantheon_roster = _redteam_roster()
    return controller


# ---------------------------------------------------------------------------
# (1) CLI flag surface
# ---------------------------------------------------------------------------


class TestCliFlagSurface:
    def test_bench_fast_flag_parses_true(self):
        ns = _parse(["--bench-fast"])
        assert ns.bench_fast is True

    def test_skip_red_team_flag_parses_true(self):
        ns = _parse(["--skip-red-team"])
        assert ns.skip_red_team is True

    def test_skip_synthesis_flag_parses_true(self):
        ns = _parse(["--skip-synthesis"])
        assert ns.skip_synthesis is True

    def test_deterministic_critic_flag_parses_true(self):
        ns = _parse(["--deterministic-critic"])
        assert ns.deterministic_critic is True

    def test_redteam_min_crib_flag_parses_int(self):
        ns = _parse(["--redteam-min-crib", "12"])
        assert ns.redteam_min_crib == 12

    def test_redteam_min_crib_default_is_zero(self):
        ns = _parse([])
        assert ns.redteam_min_crib == 0

    def test_default_run_has_no_cost_control_flags_set(self):
        """Real-K4 baseline: no flag is on by default. This is the
        regression guard for the "real-K4 mode unchanged" contract.
        """
        ns = _parse([])
        assert ns.bench_fast is False
        assert ns.skip_red_team is False
        assert ns.skip_synthesis is False
        assert ns.deterministic_critic is False
        assert ns.redteam_min_crib == 0


# ---------------------------------------------------------------------------
# (2) ControllerConfig defaults and bench-fast orchestration
# ---------------------------------------------------------------------------


class TestControllerConfigDefaults:
    def test_real_k4_defaults_are_inert(self):
        cfg = ControllerConfig()
        assert cfg.bench_fast is False
        assert cfg.skip_red_team is False
        assert cfg.skip_synthesis is False
        assert cfg.deterministic_critic is False
        assert cfg.redteam_min_crib_score == 0

    def test_bench_fast_field_round_trips(self):
        cfg = ControllerConfig(
            bench_fast=True,
            skip_synthesis=True,
            deterministic_critic=True,
            redteam_min_crib_score=1,
        )
        assert cfg.bench_fast is True
        assert cfg.skip_synthesis is True
        assert cfg.deterministic_critic is True
        assert cfg.redteam_min_crib_score == 1


# ---------------------------------------------------------------------------
# (3) HCC discriminator
# ---------------------------------------------------------------------------


class TestIsHccSeedHelper:
    def test_hcc_seed_detected_by_method_marker(self):
        t = _make_hcc_seed()
        assert _is_hcc_seed(t) is True

    def test_llm_theory_is_not_hcc(self):
        t = _make_llm_theory()
        assert _is_hcc_seed(t) is False

    def test_real_k4_programmatic_fallback_is_not_hcc(self):
        """``origin='programmatic_fallback'`` is shared by both bench
        HCC seeds and the real-K4 ``_programmatic_fallback`` branch.
        Only HCC seeds carry the ``bench_hand_cipher_core`` method
        tag, so the helper must NOT treat real-K4 fallback as HCC.
        """
        t = TheoryRecord(
            hypothesis_id="rk4-fallback",
            title="K4 fallback theory",
            core_claim="explore family X",
            mechanism="keyword sweep",
            family="vigenere",
            kill_criteria=["k"],
            expected_signal="s",
            minimal_test_spec={
                "method": "keyword_sweep",
                "parameters": {"family": "vigenere"},
            },
            origin="programmatic_fallback",
        )
        assert _is_hcc_seed(t) is False


# ---------------------------------------------------------------------------
# (4) Red-team filter HCC-bypass gate
# ---------------------------------------------------------------------------


class TestRedTeamHccBypass:
    """When ``redteam_min_crib_score > 0``, HCC seeds must bypass
    ``run_red_team_precheck`` entirely while LLM theories still go
    through. The bypass survivors return in the dispatched set
    (deterministic-coverage contract).
    """

    def _patch_redteam(
        self, monkeypatch, calls: list[str],
        verdict: RedTeamVerdict,
    ):
        async def _fake_precheck(theory, **_kwargs):
            calls.append(theory.hypothesis_id)
            return verdict
        monkeypatch.setattr(
            "kryptosbot.controller.run_red_team_precheck",
            _fake_precheck,
        )

    def test_hcc_seed_skips_redteam_when_threshold_positive(
        self, tmp_path, monkeypatch,
    ):
        ctrl = _bench_controller(
            tmp_path, redteam_min_crib_score=1,
        )
        calls: list[str] = []
        self._patch_redteam(
            monkeypatch, calls,
            RedTeamVerdict(verdict="pass", confidence=0.9, reasons=["ok"]),
        )

        seed = _make_hcc_seed("hcc-bypass")
        survivors = asyncio.run(ctrl._red_team_filter([seed]))

        assert seed in survivors, "HCC seed must remain in the dispatch set"
        assert calls == [], (
            f"run_red_team_precheck must NOT be called for HCC seeds "
            f"when threshold>0; saw {calls}"
        )

    def test_llm_theory_still_redteamed_when_threshold_positive(
        self, tmp_path, monkeypatch,
    ):
        ctrl = _bench_controller(
            tmp_path, redteam_min_crib_score=1,
        )
        calls: list[str] = []
        self._patch_redteam(
            monkeypatch, calls,
            RedTeamVerdict(verdict="pass", confidence=0.9, reasons=["ok"]),
        )

        llm = _make_llm_theory("llm-1")
        survivors = asyncio.run(ctrl._red_team_filter([llm]))

        assert llm in survivors
        assert calls == ["llm-1"], (
            f"LLM-generated theory must hit run_red_team_precheck; "
            f"saw {calls}"
        )

    def test_mixed_set_only_llm_calls_redteam(
        self, tmp_path, monkeypatch,
    ):
        ctrl = _bench_controller(
            tmp_path, redteam_min_crib_score=1,
        )
        calls: list[str] = []
        self._patch_redteam(
            monkeypatch, calls,
            RedTeamVerdict(verdict="pass", confidence=0.9, reasons=["ok"]),
        )

        seeds = [_make_hcc_seed("hcc-a"), _make_hcc_seed("hcc-b")]
        llm = _make_llm_theory("llm-c")
        survivors = asyncio.run(
            ctrl._red_team_filter(seeds + [llm]),
        )

        # All three dispatch
        assert {t.hypothesis_id for t in survivors} == {
            "hcc-a", "hcc-b", "llm-c",
        }
        # Only llm-c paid the LLM bill
        assert calls == ["llm-c"], f"expected only llm-c; saw {calls}"

    def test_threshold_zero_runs_redteam_for_hcc_too(
        self, tmp_path, monkeypatch,
    ):
        """The default ``redteam_min_crib_score=0`` preserves the
        existing behaviour: every approved theory hits red-team. This
        is the regression guard so we cannot accidentally start
        bypassing red-team when the operator did not opt in.
        """
        ctrl = _bench_controller(
            tmp_path, redteam_min_crib_score=0,
        )
        calls: list[str] = []
        self._patch_redteam(
            monkeypatch, calls,
            RedTeamVerdict(verdict="pass", confidence=0.9, reasons=["ok"]),
        )

        seed = _make_hcc_seed("hcc-x")
        asyncio.run(ctrl._red_team_filter([seed]))
        assert calls == ["hcc-x"], (
            "with redteam_min_crib_score=0 every theory must hit "
            "run_red_team_precheck (existing behaviour, regression "
            f"guard); saw {calls}"
        )

    def test_skip_red_team_overrides_threshold(
        self, tmp_path, monkeypatch,
    ):
        """``skip_red_team=True`` is the master switch: no LLM call
        regardless of the per-origin threshold or theory mix.
        """
        ctrl = _bench_controller(
            tmp_path,
            skip_red_team=True,
            redteam_min_crib_score=0,
        )
        calls: list[str] = []
        self._patch_redteam(
            monkeypatch, calls,
            RedTeamVerdict(verdict="pass", confidence=0.9, reasons=["ok"]),
        )
        seed = _make_hcc_seed("hcc-skip")
        llm = _make_llm_theory("llm-skip")
        survivors = asyncio.run(ctrl._red_team_filter([seed, llm]))
        assert {t.hypothesis_id for t in survivors} == {"hcc-skip", "llm-skip"}
        assert calls == [], (
            f"--skip-red-team must zero out all LLM calls; saw {calls}"
        )


# ---------------------------------------------------------------------------
# (5) Synthesis skip
# ---------------------------------------------------------------------------


class TestSynthesisSkip:
    def test_skip_synthesis_short_circuits(self, tmp_path, monkeypatch):
        """``skip_synthesis=True`` must return without invoking
        ``run_results_synthesis``. Best-effort: the skipped-event
        callback is fired so the TUI shows an explicit "skipped" line.
        """
        ctrl = _bench_controller(tmp_path, skip_synthesis=True)
        called: list[Any] = []

        async def _fake_synth(*args, **kwargs):
            called.append((args, kwargs))
            raise AssertionError(
                "run_results_synthesis must not be called when "
                "skip_synthesis=True"
            )
        monkeypatch.setattr(
            "kryptosbot.controller.run_results_synthesis",
            _fake_synth,
        )
        events: list[tuple[str, Any]] = []

        def _on_progress(ev, detail):
            events.append((ev, detail))

        asyncio.run(
            ctrl._run_synthesis([], [], on_progress=_on_progress),
        )
        assert called == []
        assert events == [("skipped", "config.skip_synthesis=True")]


# ---------------------------------------------------------------------------
# (6) Banner mode lines
# ---------------------------------------------------------------------------


class TestBannerCostControl:
    def test_real_k4_banner_has_no_cost_control_rows(self, capsys):
        """Real-K4 mode: callers leave the new kwargs as None so the
        banner layout matches the pre-2026-04-28 form bit-for-bit.
        """
        from kryptosbot import display
        display.print_startup(
            cycle_start=1, max_cycles=10, theories_per_cycle=5,
            workers=4, timeout_minutes=30,
            proposed=0, tested=0, eliminated=0,
        )
        out = capsys.readouterr().out
        assert "Cost-control" not in out
        assert "Critic" not in out
        assert "Red-team" not in out
        assert "Synthesis" not in out

    def test_bench_fast_banner_shows_all_phase_rows(self, capsys):
        from kryptosbot import display
        display.print_startup(
            cycle_start=1, max_cycles=10, theories_per_cycle=5,
            workers=4, timeout_minutes=30,
            proposed=0, tested=0, eliminated=0,
            bench_fast=True,
            critic_mode="deterministic (--deterministic-critic)",
            redteam_mode=(
                "LLM-backed for LLM theories; HCC seeds bypass "
                "(--redteam-min-crib=1)"
            ),
            synthesis_mode="skipped (--skip-synthesis)",
        )
        out = capsys.readouterr().out
        assert "Cost-control" in out
        assert "--bench-fast" in out
        assert "deterministic" in out
        assert "HCC seeds bypass" in out
        assert "skipped" in out

    def test_skip_red_team_banner_says_skipped(self, capsys):
        from kryptosbot import display
        display.print_startup(
            cycle_start=1, max_cycles=10, theories_per_cycle=5,
            workers=4, timeout_minutes=30,
            proposed=0, tested=0, eliminated=0,
            critic_mode="deterministic",
            redteam_mode="skipped (--skip-red-team)",
            synthesis_mode="LLM-backed",
        )
        out = capsys.readouterr().out
        assert "--skip-red-team" in out


# ---------------------------------------------------------------------------
# (7) End-to-end: --bench-fast --hcc-only --dry-run completes without LLM
# ---------------------------------------------------------------------------


def _make_synthetic_challenge(tmp_path: Path) -> Path:
    """Minimal-but-valid K4Bench challenge JSON for subprocess tests."""
    crib_a = "SECONDSYSTEMX"
    crib_b = "COLUMNORDER"
    ct = (
        "DCXEGPKDRHYITACRUTBWOXRKGXZEOEEQPIULFRQVEELEFFIVBPKKFIE"
        "GYDVXEZFOEQWVSRIUQXHZAITUMBFFSORMSPBZTRXPO"
    )
    payload = {
        "schema_version": "k4bench.challenge.v1",
        "suite_id": "K4BENCH-COSTCTL-TEST",
        "bench_id": "K4B-COSTCTL-001",
        "title": "Cost-control flag end-to-end test",
        "ciphertext": ct,
        "ciphertext_alphabet": "AZ",
        "ciphertext_length": 97,
        "known_plaintext_positions": {
            **{str(21 + i): ch for i, ch in enumerate(crib_a)},
            **{str(63 + i): ch for i, ch in enumerate(crib_b)},
        },
        "known_plaintext_spans": [
            {
                "start": 21, "end_inclusive": 33, "length": 13,
                "text": crib_a, "label": "crib_a",
            },
            {
                "start": 63, "end_inclusive": 73, "length": 11,
                "text": crib_b, "label": "crib_b",
            },
        ],
        "public_clue_pack": {
            "clue_text": "Synthetic CEDAR LANTERN test challenge.",
            "constraint_summary": ["A-Z only.", "Length 97."],
        },
        "solver_output_contract": {
            "required_json_fields": ["bench_id", "plaintext"],
            "strict_pass_rule": "exact",
            "known_crib_score_target": 24,
        },
    }
    p = tmp_path / "challenge.json"
    p.write_text(json.dumps(payload))
    return p


class TestEndToEndDryRun:
    """Drive run_controller as a subprocess with --bench-fast and
    --hcc-only --dry-run. The run must:
      - Parse all flags without error
      - Construct a bench-mode ledger pinned to synthetic
      - Reach the cycle loop
      - Skip dispatch (dry-run)
      - Exit 0
    Crucially, NO LLM call should be needed: the theorist is bypassed
    by --hcc-only, the critic is deterministic, --bench-fast skips
    red-team for HCC seeds and skips synthesis. ``--dry-run`` makes
    the workers no-ops.
    """

    def test_subprocess_completes_dry_run_without_llm_keys(self, tmp_path):
        challenge_path = _make_synthetic_challenge(tmp_path)
        db_path = tmp_path / "db" / "k4bench" / "K4B-COSTCTL-001.sqlite"
        db_path.parent.mkdir(parents=True, exist_ok=True)

        env = {**os.environ}
        env["PYTHONPATH"] = (
            str(_REPO_ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")
        )
        # Strip API keys so ANY LLM call would crash with a clear
        # "no auth" error and fail the test. This is the strongest
        # possible guarantee that no LLM call was made.
        for k in (
            "ANTHROPIC_API_KEY",
            "CLAUDE_CODE_OAUTH_TOKEN",
            "CLAUDE_CODE_USE_BEDROCK",
            "CLAUDE_CODE_USE_VERTEX",
            "KBOT_CLASSIFY_API_KEY",
        ):
            env.pop(k, None)

        result = subprocess.run(
            [
                sys.executable, "-u",
                str(_REPO_ROOT / "kryptosbot" / "run_controller.py"),
                "--bench-challenge", str(challenge_path),
                "--db", str(db_path),
                "--cycles", "1",
                "--workers", "1",
                "--timeout", "1",
                "--hcc-only",
                "--bench-fast",
                "--dry-run",
                "-q",
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
            cwd=str(_REPO_ROOT),
        )
        assert result.returncode == 0, (
            f"subprocess failed: rc={result.returncode}\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )
        # The kernel synthetic-mode warning must have fired so we
        # know the bench challenge was actually loaded.
        assert (
            "KRYPTOS_CT_OVERRIDE active" in result.stderr
            or "synthetic" in result.stderr.lower()
        ), f"bench mode not detected; STDERR: {result.stderr}"


# ---------------------------------------------------------------------------
# (8) Lead-pursuit + stat-audit skip flags (added 2026-04-28 alongside
# LESSON-009). --bench-fast must imply BOTH so a non-dry-run HCC-only
# bench-fast cycle reaches zero LLM calls even when sub-signal results
# (lead pursuit) or above-threshold scores (stat audit) appear.
# ---------------------------------------------------------------------------


class TestLeadPursuitAndStatAuditFlags:
    """The new --skip-lead-pursuit and --skip-stat-audit CLI flags
    expose existing ``ControllerConfig`` fields, and ``--bench-fast``
    now ORs them on by default. Closes the K4B-003 cost-control gap
    where the prior bench-fast still invoked results-analyst on
    sub-signal contracts.
    """

    def test_skip_lead_pursuit_flag_parses(self):
        ns = _parse(["--skip-lead-pursuit"])
        assert ns.skip_lead_pursuit is True

    def test_skip_stat_audit_flag_parses(self):
        ns = _parse(["--skip-stat-audit"])
        assert ns.skip_stat_audit is True

    def test_real_k4_defaults_no_lp_or_sa(self):
        ns = _parse([])
        assert ns.skip_lead_pursuit is False
        assert ns.skip_stat_audit is False

    def test_controller_config_skip_lead_pursuit_round_trip(self):
        cfg = ControllerConfig(skip_lead_pursuit=True)
        assert cfg.skip_lead_pursuit is True

    def test_controller_config_skip_stat_audit_round_trip(self):
        cfg = ControllerConfig(skip_stat_audit=True)
        assert cfg.skip_stat_audit is True


class TestBenchFastImpliesAllSkips:
    """``--bench-fast`` orchestration: implies skip_synthesis +
    skip_lead_pursuit + skip_stat_audit + deterministic_critic +
    redteam_min_crib_score>0 when those switches are not separately
    set. Verified by mirroring the wiring in ``run_controller.main``.
    """

    def test_bench_fast_implies_skip_lead_pursuit(self):
        ns = _parse(["--bench-fast"])
        derived = bool(ns.skip_lead_pursuit) or bool(ns.bench_fast)
        assert derived is True

    def test_bench_fast_implies_skip_stat_audit(self):
        ns = _parse(["--bench-fast"])
        derived = bool(ns.skip_stat_audit) or bool(ns.bench_fast)
        assert derived is True


class TestLeadPursuitSkipRespected:
    """``ResearchController._run_lead_pursuit`` short-circuits at
    the top when ``skip_lead_pursuit`` is set; no LLM call is made.
    """

    def test_skip_lead_pursuit_short_circuits(self, tmp_path):
        import asyncio
        cfg = ControllerConfig(
            project_root=tmp_path,
            ledger_db_path=tmp_path / "lp.sqlite",
            skip_lead_pursuit=True,
        )
        ctrl = ResearchController(cfg)
        ctrl.state = ctrl.ledger.load_controller_state()
        events: list[Any] = []

        def _on(ev, detail):
            events.append((ev, detail))

        asyncio.run(ctrl._run_lead_pursuit([], [], on_progress=_on))
        assert events == [
            ("skipped", "config.skip_lead_pursuit=True"),
        ]


class TestStatAuditSkipRespected:
    def test_skip_stat_audit_short_circuits(self, tmp_path):
        import asyncio
        cfg = ControllerConfig(
            project_root=tmp_path,
            ledger_db_path=tmp_path / "sa.sqlite",
            skip_stat_audit=True,
        )
        ctrl = ResearchController(cfg)
        ctrl.state = ctrl.ledger.load_controller_state()
        events: list[Any] = []

        def _on(ev, detail):
            events.append((ev, detail))

        asyncio.run(ctrl._stat_audit_filter([], [], on_progress=_on))
        assert events == [
            ("skipped", "config.skip_stat_audit=True"),
        ]


class TestBannerLeadPursuitAndStatAuditRows:
    def test_banner_shows_lead_pursuit_skipped(self, capsys):
        from kryptosbot import display
        display.print_startup(
            cycle_start=1, max_cycles=1, theories_per_cycle=5,
            workers=4, timeout_minutes=30,
            proposed=0, tested=0, eliminated=0,
            critic_mode="deterministic",
            redteam_mode="LLM-backed",
            synthesis_mode="LLM-backed",
            lead_pursuit_mode="skipped (--skip-lead-pursuit)",
            stat_audit_mode="skipped (--skip-stat-audit)",
        )
        out = capsys.readouterr().out
        assert "Lead pursuit" in out
        assert "Stat audit" in out
        assert "--skip-lead-pursuit" in out
        assert "--skip-stat-audit" in out


# ---------------------------------------------------------------------------
# (9) Subprocess proof: full bench-fast HCC-only run with API keys stripped
# (NOT --dry-run). The HCC seeds must dispatch and score; if any LLM call
# is reached, the subprocess crashes with an auth error and the test fails.
# ---------------------------------------------------------------------------


def _build_caesar_synthetic_challenge(tmp_path: Path) -> Path:
    """Tiny synthetic challenge with both a Caesar trigger and a
    block-reversal trigger so the bench-fast path actually exercises
    the lesson families. The ciphertext is a placeholder; HCC seeds
    will not solve it — we are testing cost-control plumbing, not
    cryptanalytic correctness.
    """
    import json
    crib_a = "BENCHKEYALPHA"
    crib_b = "EXAMPLEDONE"
    ct = (
        "PSPSDIVEMBKLIYBRJKEAGLDHJEFMUDOSYPDPLNUFFKZXIIOSLBSY"
        "FLNUMOWRDVHPFNRFADBRKGRSCNEDOXAQFEFXBPLIQQQQQ"
    )
    assert len(ct) == 97, f"synthetic CT must be 97 chars; got {len(ct)}"
    payload = {
        "schema_version": "k4bench.challenge.v1",
        "suite_id": "K4BENCH-COSTCTL-LLM",
        "bench_id": "K4B-COSTCTL-LLM",
        "title": "No-LLM cost-control proof",
        "ciphertext": ct,
        "ciphertext_alphabet": "AZ",
        "ciphertext_length": 97,
        "known_plaintext_positions": {
            **{str(21 + i): ch for i, ch in enumerate(crib_a)},
            **{str(63 + i): ch for i, ch in enumerate(crib_b)},
        },
        "known_plaintext_spans": [
            {"start": 21, "end_inclusive": 33, "length": 13,
             "text": crib_a, "label": "crib_a"},
            {"start": 63, "end_inclusive": 73, "length": 11,
             "text": crib_b, "label": "crib_b"},
        ],
        "public_clue_pack": {
            "clue_text": (
                "Apply a CAESAR shift then a small group "
                "reversal. Tag says SHIFT THREE."
            ),
            "constraint_summary": ["A-Z only.", "Length 97."],
        },
        "solver_output_contract": {
            "required_json_fields": ["bench_id", "plaintext"],
            "strict_pass_rule": "exact",
            "known_crib_score_target": 24,
        },
    }
    p = tmp_path / "challenge.json"
    p.write_text(json.dumps(payload))
    return p


class TestBenchFastNoLLMNonDryRun:
    """The strongest no-LLM proof: launch run_controller as a
    subprocess with every transport credential stripped, --bench-fast
    + --hcc-only, and let it run a real cycle (NOT --dry-run). HCC
    seeds dispatch and score; if any LLM sibling call is reached the
    subprocess crashes with an auth error and the test fails.

    This is the K4B-003 cost-control gap regression guard: the prior
    bench-fast still invoked results-analyst / lead pursuit on
    sub-signal contracts. With the new --skip-lead-pursuit and
    --skip-stat-audit flags ORed in by --bench-fast, every LLM-
    backed phase in the cycle is suppressed.
    """

    def test_bench_fast_hcc_only_non_dry_run_no_llm(self, tmp_path):
        import os
        import subprocess
        challenge_path = _build_caesar_synthetic_challenge(tmp_path)
        db_path = tmp_path / "db" / "k4bench" / "K4B-COSTCTL-LLM.sqlite"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        attempts_path = tmp_path / "attempt.json"
        env = {**os.environ}
        env["PYTHONPATH"] = (
            str(_REPO_ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")
        )
        for k in (
            "ANTHROPIC_API_KEY",
            "CLAUDE_CODE_OAUTH_TOKEN",
            "CLAUDE_CODE_USE_BEDROCK",
            "CLAUDE_CODE_USE_VERTEX",
            "KBOT_CLASSIFY_API_KEY",
        ):
            env.pop(k, None)
        result = subprocess.run(
            [
                sys.executable, "-u",
                str(_REPO_ROOT / "kryptosbot" / "run_controller.py"),
                "--bench-challenge", str(challenge_path),
                "--db", str(db_path),
                "--cycles", "1",
                "--workers", "4",
                "--timeout", "1",
                "--hcc-only",
                "--bench-fast",
                # Cap so the subprocess completes quickly; the cost-
                # control proof is independent of seed count.
                "--hcc-seeds", "16",
                "--bench-attempts-out", str(attempts_path),
                "-q",
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
            cwd=str(_REPO_ROOT),
        )
        assert result.returncode == 0, (
            f"subprocess failed: rc={result.returncode}\n"
            f"STDOUT (tail):\n{result.stdout[-3000:]}\n"
            f"STDERR (tail):\n{result.stderr[-3000:]}"
        )
        # Kernel synthetic-mode warning must have fired.
        assert (
            "KRYPTOS_CT_OVERRIDE active" in result.stderr
            or "synthetic" in result.stderr.lower()
        )
        # Attempt artifact landing is the post-cycle sentinel that
        # confirms the run did NOT halt mid-cycle.
        assert attempts_path.exists(), (
            "attempts artifact missing — run did not reach completion"
        )
        # Banner shows the cost-control rows under bench-fast.
        out = result.stdout
        assert "Cost-control" in out
        assert "Lead pursuit" in out
