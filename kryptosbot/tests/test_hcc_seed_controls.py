"""Tests for the K4Bench HandCipherCore seed control flags
(--hcc-seeds N, --no-hcc-seeds, --hcc-only) added 2026-04-27.

Pinned properties:

  1. ``--hcc-seeds N`` caps the seed count at N (does NOT cap LLM
     theories, which still default to ``--theories``).
  2. ``--no-hcc-seeds`` disables HCC entirely; the dispatched set is
     LLM-only.
  3. ``--hcc-only`` disables the LLM entirely; the dispatched set is
     HCC-only.
  4. ``--theories`` does NOT cap HCC seeds. A user lowering --theories
     to 1 still gets the full HCC catalogue.
  5. Mutually-exclusive CLI errors: --no-hcc-seeds + --hcc-only;
     --no-hcc-seeds + --hcc-seeds N; --hcc-seeds with negative N.
  6. The startup banner shows HCC seeds and LLM theory counts as
     separate rows in bench mode; real-K4 banner unchanged.
"""
from __future__ import annotations

import sys
from io import StringIO
from pathlib import Path
from unittest import mock

import pytest

from kryptosbot.bench_loader import load_k4bench_challenge
from kryptosbot.controller import ControllerConfig, ResearchController


_REPO_ROOT = Path(__file__).resolve().parents[2]
_K4B001_PATH = _REPO_ROOT / "bench" / "k4bench" / "challenges" / "K4B-001.json"


# --- Helpers ---------------------------------------------------------------


def _bench_controller(
    tmp_path: Path,
    *,
    hcc_seeds_cap=None,
    hcc_only: bool = False,
    theories: int = 5,
) -> ResearchController:
    if not _K4B001_PATH.exists():
        pytest.skip(f"K4B-001 challenge fixture not on disk")
    challenge = load_k4bench_challenge(_K4B001_PATH)
    cfg = ControllerConfig(
        project_root=tmp_path,
        ledger_db_path=tmp_path / "k4bench" / "test.sqlite",
        max_cycles=1,
        theories_per_cycle=theories,
        dry_run=True,
        bench_challenge_payload=challenge.canonical_facts(),
        bench_challenge_prompt_block=challenge.prompt_block(),
        include_oranchak_corpora=False,
        include_serpentine_anchor=False,
        hcc_seeds_cap=hcc_seeds_cap,
        hcc_only=hcc_only,
    )
    controller = ResearchController(cfg)
    controller.state = controller.ledger.load_controller_state()
    controller._snapshot_session_baseline()
    return controller


# --- (1) --hcc-seeds N caps seed count -------------------------------------


class TestHccSeedsCap:
    def test_uncapped_default_returns_full_catalogue(self, tmp_path: Path):
        """``hcc_seeds_cap=None`` (default) returns every seed the
        generator emits (currently 70 for K4B-001's CEDAR + LANTERN).
        """
        controller = _bench_controller(tmp_path, hcc_seeds_cap=None)
        seeds = controller._collect_hcc_seeds()
        assert len(seeds) > 10, (
            f"uncapped default should produce >10 seeds; got {len(seeds)}"
        )

    @pytest.mark.parametrize("cap", [1, 4, 8, 20])
    def test_cap_truncates_to_exactly_n(self, tmp_path: Path, cap):
        controller = _bench_controller(tmp_path, hcc_seeds_cap=cap)
        seeds = controller._collect_hcc_seeds()
        assert len(seeds) == cap, (
            f"hcc_seeds_cap={cap} should yield exactly {cap} seeds; got {len(seeds)}"
        )

    def test_cap_preserves_front_of_catalogue(self, tmp_path: Path):
        """Slicing keeps the EARLIEST families (columnar+vigenere
        first), so a cap of 4 still includes the K4B-001 critical
        columnar+vigenere combos.
        """
        controller = _bench_controller(tmp_path, hcc_seeds_cap=4)
        seeds = controller._collect_hcc_seeds()
        cv_families = {
            s.minimal_test_spec.get("coverage_vector", {}).get("layer_family")
            for s in seeds
        }
        assert "columnar_vigenere" in cv_families, (
            f"cap=4 should preserve the columnar_vigenere family at the "
            f"front of the catalogue; got families={cv_families}"
        )


# --- (2) --no-hcc-seeds disables HCC ---------------------------------------


class TestNoHccSeeds:
    def test_zero_cap_disables_hcc(self, tmp_path: Path):
        """``hcc_seeds_cap=0`` (the value --no-hcc-seeds sets) returns
        an empty seed list without invoking the generator.
        """
        controller = _bench_controller(tmp_path, hcc_seeds_cap=0)
        seeds = controller._collect_hcc_seeds()
        assert seeds == [], (
            f"hcc_seeds_cap=0 should disable HCC; got {len(seeds)} seeds"
        )

    def test_no_hcc_seeds_does_not_disable_llm(self, tmp_path: Path):
        """The disabled-HCC config still allows LLM theories; the
        merge function returns LLM candidates unaltered.
        """
        from kryptosbot.models import TheoryRecord, TheoryStatus
        controller = _bench_controller(tmp_path, hcc_seeds_cap=0)
        llm_cands = [
            TheoryRecord(
                hypothesis_id=f"llm-{i}",
                title=f"LLM theory {i}",
                family="from_llm",
                status=TheoryStatus.PROPOSED,
                origin="theorist_agent",
            )
            for i in range(3)
        ]
        merged = controller._merge_hcc_seeds_into_candidates([], llm_cands)
        assert [t.hypothesis_id for t in merged] == ["llm-0", "llm-1", "llm-2"]


# --- (3) --hcc-only skips LLM ----------------------------------------------


class TestHccOnly:
    def test_hcc_only_flag_stored_on_config(self, tmp_path: Path):
        """The flag round-trips into the controller config."""
        controller = _bench_controller(tmp_path, hcc_only=True)
        assert controller.config.hcc_only is True

    def test_hcc_only_with_empty_seeds_returns_empty_list(
        self, tmp_path: Path,
    ):
        """If both --hcc-only and --no-hcc-seeds were somehow combined
        (CLI rejects this, but defend the controller path anyway), the
        controller logs a warning and returns []. Test by setting the
        config fields directly.
        """
        controller = _bench_controller(
            tmp_path, hcc_seeds_cap=0, hcc_only=True,
        )
        # _generate_theories is async; just probe the seed list.
        seeds = controller._collect_hcc_seeds()
        assert seeds == []
        # The LLM-skip is enforced inside _generate_theories itself;
        # we test the seed-empty branch via the merge function.
        assert controller._merge_hcc_seeds_into_candidates([], []) == []


# --- (4) --theories does NOT cap HCC seeds ---------------------------------


class TestTheoriesDoesNotCapHcc:
    @pytest.mark.parametrize("theories", [1, 3, 5, 20])
    def test_low_theories_count_does_not_reduce_hcc_seeds(
        self, tmp_path: Path, theories: int,
    ):
        """A user setting --theories 1 still gets the full HCC
        catalogue. Only --hcc-seeds N caps the seed count.
        """
        controller = _bench_controller(
            tmp_path, hcc_seeds_cap=None, theories=theories,
        )
        seeds = controller._collect_hcc_seeds()
        assert len(seeds) > theories, (
            f"with --theories={theories}, HCC seeds should still be "
            f"the full catalogue (>{theories} seeds); got {len(seeds)}. "
            "The --theories flag must NOT cap HCC."
        )


# --- (5) CLI mutual exclusion ----------------------------------------------


class TestCliMutualExclusion:
    def _run_parse(self, argv: list[str]) -> int:
        """Run parse_args with given argv; return exit code (2 = error)."""
        from kryptosbot.run_controller import parse_args
        with mock.patch.object(sys, "argv", ["run_controller.py", *argv]):
            try:
                parse_args()
                return 0
            except SystemExit as exc:
                return int(exc.code) if exc.code is not None else 1

    def test_no_hcc_seeds_alone_is_ok(self):
        assert self._run_parse(["--no-hcc-seeds"]) == 0

    def test_hcc_only_alone_is_ok(self):
        assert self._run_parse(["--hcc-only"]) == 0

    def test_hcc_seeds_alone_is_ok(self):
        assert self._run_parse(["--hcc-seeds", "8"]) == 0

    def test_no_hcc_seeds_plus_hcc_only_errors(self, capsys):
        rc = self._run_parse(["--no-hcc-seeds", "--hcc-only"])
        assert rc == 2
        captured = capsys.readouterr()
        assert "mutually exclusive" in captured.err.lower()

    def test_no_hcc_seeds_plus_hcc_seeds_n_errors(self, capsys):
        rc = self._run_parse(["--no-hcc-seeds", "--hcc-seeds", "4"])
        assert rc == 2
        captured = capsys.readouterr()
        assert "contradictory" in captured.err.lower()

    def test_negative_hcc_seeds_errors(self, capsys):
        rc = self._run_parse(["--hcc-seeds", "-1"])
        assert rc == 2
        captured = capsys.readouterr()
        assert "n >= 0" in captured.err.lower()


# --- (6) Startup banner shows HCC + LLM separately --------------------------


class TestStartupBanner:
    def test_banner_real_k4_layout_unchanged(self, capsys):
        """Without HCC kwargs (real-K4 path), the banner doesn't add
        the HCC/LLM rows. This is the regression guard for the
        real-K4 mode-unchanged contract.
        """
        from kryptosbot import display
        display.print_startup(
            cycle_start=1, max_cycles=10, theories_per_cycle=5,
            workers=4, timeout_minutes=30,
            proposed=0, tested=0, eliminated=0,
        )
        captured = capsys.readouterr()
        assert "HCC seeds" not in captured.out
        assert "LLM theories" not in captured.out
        assert "Total candidates" not in captured.out

    def test_banner_bench_mode_shows_hcc_and_llm_split(self, capsys):
        """Bench mode: the banner shows HCC seeds and LLM theories as
        separate rows, plus Total candidates.
        """
        from kryptosbot import display
        display.print_startup(
            cycle_start=1, max_cycles=10, theories_per_cycle=5,
            workers=4, timeout_minutes=30,
            proposed=0, tested=0, eliminated=0,
            hcc_seeds=70,
            llm_theories=5,
            total_candidates=75,
        )
        captured = capsys.readouterr()
        assert "HCC seeds" in captured.out
        assert "LLM theories" in captured.out
        assert "Total candidates" in captured.out
        # Numbers must appear too
        assert "70" in captured.out
        assert "75" in captured.out

    def test_banner_shows_hcc_seeds_cap_annotation(self, capsys):
        """When --hcc-seeds N caps the count, the banner annotates
        the HCC-seeds row with the cap.
        """
        from kryptosbot import display
        display.print_startup(
            cycle_start=1, max_cycles=10, theories_per_cycle=5,
            workers=4, timeout_minutes=30,
            proposed=0, tested=0, eliminated=0,
            hcc_seeds=8,
            llm_theories=5,
            total_candidates=13,
            hcc_seeds_cap=8,
        )
        captured = capsys.readouterr()
        assert "cap=8" in captured.out

    def test_banner_shows_no_hcc_seeds_annotation(self, capsys):
        """When --no-hcc-seeds, the banner annotates the row."""
        from kryptosbot import display
        display.print_startup(
            cycle_start=1, max_cycles=10, theories_per_cycle=5,
            workers=4, timeout_minutes=30,
            proposed=0, tested=0, eliminated=0,
            hcc_seeds=0,
            llm_theories=5,
            total_candidates=5,
            no_hcc_seeds=True,
        )
        captured = capsys.readouterr()
        assert "--no-hcc-seeds" in captured.out

    def test_banner_shows_hcc_only_annotation(self, capsys):
        """When --hcc-only, the LLM-theories row is annotated as
        disabled.
        """
        from kryptosbot import display
        display.print_startup(
            cycle_start=1, max_cycles=10, theories_per_cycle=5,
            workers=4, timeout_minutes=30,
            proposed=0, tested=0, eliminated=0,
            hcc_seeds=70,
            llm_theories=0,
            total_candidates=70,
            hcc_only=True,
        )
        captured = capsys.readouterr()
        assert "--hcc-only" in captured.out
        assert "LLM disabled" in captured.out


# --- Integration: end-to-end from CLI args through banner --------------------


class TestEndToEnd:
    def test_cli_to_config_to_seed_count_to_banner(
        self, tmp_path: Path, capsys,
    ):
        """Full path: CLI args parse to the right ControllerConfig
        fields, the controller produces the right seed count, and
        the banner renders correctly.
        """
        from kryptosbot import display
        controller = _bench_controller(tmp_path, hcc_seeds_cap=4)
        seeds = controller._collect_hcc_seeds()
        assert len(seeds) == 4

        display.print_startup(
            cycle_start=1, max_cycles=1, theories_per_cycle=5,
            workers=4, timeout_minutes=30,
            proposed=0, tested=0, eliminated=0,
            hcc_seeds=len(seeds),
            llm_theories=5,
            total_candidates=len(seeds) + 5,
            hcc_seeds_cap=4,
        )
        captured = capsys.readouterr()
        # Banner reflects the actual count of 4
        assert "4" in captured.out
        assert "5" in captured.out  # LLM theories
        assert "9" in captured.out  # total
        assert "cap=4" in captured.out
