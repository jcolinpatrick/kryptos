"""Controller-level tests for HandCipherCore deterministic-coverage
integration (2026-04-27 patch).

Property under test: in bench mode, ``ResearchController._collect_hcc_seeds``
runs BEFORE the LLM theorist and produces a deterministic seed list
that includes the K4B-001 critical candidate Vigenere(LANTERN) +
Columnar(CEDAR width=5, col_order from CEDAR). The seed list is
merged into the dispatched candidate set via
``_merge_hcc_seeds_into_candidates``; the LLM may add candidates
above the seeds but cannot replace or omit them.

Real-K4 mode is unchanged — these tests confirm the seeds list is
empty in real-K4 mode and the merge is a no-op.

The tests do NOT spin up the SDK: they call the deterministic
helpers directly and assert structural properties of the result.
That is by design — the contract is that the seeds appear before
any LLM output is parsed, so no LLM call is needed to verify it.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from kryptosbot.bench_loader import load_k4bench_challenge
from kryptosbot.controller import ControllerConfig, ResearchController


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


_REPO_ROOT = Path(__file__).resolve().parents[2]
_K4B001_PATH = _REPO_ROOT / "bench" / "k4bench" / "challenges" / "K4B-001.json"


def _bench_payload_and_prompt():
    """Load the live K4B-001 challenge and produce the canonical
    payload + prompt block the controller uses in bench mode.
    """
    challenge = load_k4bench_challenge(_K4B001_PATH)
    return challenge.canonical_facts(), challenge.prompt_block()


@pytest.fixture
def bench_controller(tmp_path: Path) -> ResearchController:
    """A bench-mode controller whose ledger lives in tmp_path so the
    test does not write to the real db/ directory.
    """
    if not _K4B001_PATH.exists():
        pytest.skip(f"K4B-001 challenge fixture not on disk at {_K4B001_PATH}")
    payload, prompt_block = _bench_payload_and_prompt()
    cfg = ControllerConfig(
        project_root=tmp_path,
        ledger_db_path=tmp_path / "k4bench" / "test_ledger.sqlite",
        max_cycles=1,
        theories_per_cycle=5,
        dry_run=True,
        bench_challenge_payload=payload,
        bench_challenge_prompt_block=prompt_block,
        include_oranchak_corpora=False,
        include_serpentine_anchor=False,
    )
    controller = ResearchController(cfg)
    controller.state = controller.ledger.load_controller_state()
    controller._snapshot_session_baseline()
    return controller


@pytest.fixture
def real_k4_controller(tmp_path: Path) -> ResearchController:
    """A real-K4 controller in tmp_path. Used to verify the bench
    integration does not change real-K4 behaviour.
    """
    cfg = ControllerConfig(
        project_root=tmp_path,
        ledger_db_path=tmp_path / "real_k4_ledger.sqlite",
        max_cycles=1,
        theories_per_cycle=5,
        dry_run=True,
    )
    controller = ResearchController(cfg)
    controller.state = controller.ledger.load_controller_state()
    controller._snapshot_session_baseline()
    return controller


# ---------------------------------------------------------------------------
# (a) Bench-mode HCC seeds run before the LLM and include the critical
#     Vig(LANTERN) + Col(CEDAR) candidate.
# ---------------------------------------------------------------------------


class TestHccSeedsBeforeLLM:
    def test_collect_hcc_seeds_returns_nonempty_for_k4b001(
        self, bench_controller,
    ):
        """The seed collector returns a non-empty list for the K4B-001
        challenge clue pack (CEDAR + LANTERN).
        """
        seeds = bench_controller._collect_hcc_seeds()
        assert len(seeds) > 0, (
            "HCC seeds were empty for K4B-001; the deterministic "
            "coverage matrix is not running."
        )

    def test_seeds_include_vig_lantern_col_cedar(self, bench_controller):
        """The K4B-001 critical candidate — Vigenere(LANTERN) then
        Columnar(CEDAR width=5, col_order from CEDAR) — must appear
        in the seed list. This is the previously-missing inverse
        role assignment that the original fallback omitted.
        """
        seeds = bench_controller._collect_hcc_seeds()
        # Find any seed whose pipeline matches Vig(LANTERN) + Col(CEDAR)
        matches = []
        for seed in seeds:
            pipeline = seed.dsl_spec.get("pipeline") or []
            if len(pipeline) != 2:
                continue
            if pipeline[0].get("kind") != "vigenere":
                continue
            if pipeline[1].get("kind") != "columnar":
                continue
            vig_kw = next(
                (p["values"][0] for p in pipeline[0].get("params", [])
                 if p.get("name") == "keyword"),
                None,
            )
            col_params = {
                p.get("name"): p["values"][0]
                for p in pipeline[1].get("params", [])
            }
            if vig_kw == "LANTERN" and col_params.get("width") == len("CEDAR"):
                matches.append(seed)
        assert len(matches) >= 1, (
            "Vigenere(LANTERN) + Columnar(CEDAR width=5) NOT in the "
            "HCC seed list. This is the K4B-001 missing-inverse-role "
            "case the patch must guarantee."
        )
        # Confirm the column order is keyword-derived, not identity.
        seed = matches[0]
        col_layer = seed.dsl_spec["pipeline"][1]
        col_params = {
            p["name"]: p["values"][0] for p in col_layer["params"]
        }
        from kryptosbot.hand_cipher_core import _keyword_to_col_order
        expected_order = _keyword_to_col_order("CEDAR")
        assert col_params["col_order"] == expected_order, (
            f"col_order should be derived from CEDAR; "
            f"expected {expected_order}, got {col_params['col_order']}"
        )

    def test_seeds_include_all_four_columnar_vigenere_combos(
        self, bench_controller,
    ):
        """All four (role × order) combos for the columnar+vigenere
        family on (CEDAR, LANTERN) appear as seeds.

        2026-04-27: with alphabet-mode enumeration, each (role × order)
        coordinate is replicated per alphabet mode. The coordinate
        count is what stays at 4; the spec count grows.

        2026-04-28 (LESSON-013): the family also emits enumerated
        col_order specs whose role_assignment uses synthetic
        identifiers (``W{w}_co{idx}``). The 4-coord invariant is on
        the KEYWORD-DERIVED specs only — filter via
        ``col_order_source != "enumerated_permutation"``.
        """
        seeds = bench_controller._collect_hcc_seeds()
        cv_seeds = [
            s for s in seeds
            if s.minimal_test_spec.get("coverage_vector", {}).get("layer_family")
            == "columnar_vigenere"
            and s.minimal_test_spec.get("coverage_vector", {}).get(
                "col_order_source", ""
            ) != "enumerated_permutation"
        ]
        coords = {
            (
                tuple(s.minimal_test_spec["coverage_vector"]["layer_order"]),
                tuple(sorted(s.minimal_test_spec["coverage_vector"]["role_assignment"].items())),
            )
            for s in cv_seeds
        }
        assert len(coords) == 4, (
            f"expected 4 distinct (layer_order, role_assignment) coords "
            f"for columnar_vigenere keyword path on K4B-001; got "
            f"{len(coords)} ({len(cv_seeds)} total specs across alphabet "
            "modes)"
        )

    def test_seed_list_is_deterministic_across_calls(self, bench_controller):
        """Two consecutive calls return the same seed list (same
        hypothesis_ids in the same order). Required so the dispatched
        set is reproducible and the ledger can dedupe correctly.
        """
        a = bench_controller._collect_hcc_seeds()
        b = bench_controller._collect_hcc_seeds()
        assert [s.hypothesis_id for s in a] == [s.hypothesis_id for s in b]


# ---------------------------------------------------------------------------
# (b) Merge logic: LLM cannot replace or omit seeds.
# ---------------------------------------------------------------------------


class TestMergeContract:
    def test_seeds_appear_first_in_merged_list(self, bench_controller):
        """The merge function returns seeds first, LLM candidates
        after.
        """
        seeds = bench_controller._collect_hcc_seeds()
        # Build a couple of fake LLM-side candidates with novel ids
        from kryptosbot.models import TheoryRecord, TheoryStatus
        llm_cands = [
            TheoryRecord(
                hypothesis_id="llm-novel-001",
                title="LLM-only theory",
                family="from_llm",
                status=TheoryStatus.PROPOSED,
                origin="theorist_agent",
            ),
            TheoryRecord(
                hypothesis_id="llm-novel-002",
                title="LLM-only theory 2",
                family="from_llm",
                status=TheoryStatus.PROPOSED,
                origin="theorist_agent",
            ),
        ]
        merged = bench_controller._merge_hcc_seeds_into_candidates(
            seeds, llm_cands,
        )
        # Seeds occupy the front of the list (in their original order)
        for i, seed in enumerate(seeds):
            if bench_controller.ledger.exists(seed.hypothesis_id):
                # Skip — ledger-already-present seeds are dropped from
                # the merge by design.
                continue
            assert merged[i].hypothesis_id == seed.hypothesis_id, (
                f"seed at position {i} reordered or dropped from merged "
                f"list; expected {seed.hypothesis_id}, got "
                f"{merged[i].hypothesis_id}"
            )
        # LLM novel candidates appear after the seeds
        merged_ids = {t.hypothesis_id for t in merged}
        assert "llm-novel-001" in merged_ids
        assert "llm-novel-002" in merged_ids

    def test_llm_candidate_with_seed_id_collision_is_dropped(
        self, bench_controller,
    ):
        """If the LLM produces a candidate whose hypothesis_id matches
        an HCC seed, the LLM duplicate is dropped (the seed wins).
        """
        seeds = bench_controller._collect_hcc_seeds()
        assert len(seeds) > 0
        # Construct a fake LLM candidate sharing the first seed's id
        from kryptosbot.models import TheoryRecord, TheoryStatus
        llm_dup = TheoryRecord(
            hypothesis_id=seeds[0].hypothesis_id,
            title="LLM tries to override the seed",
            family="from_llm",
            status=TheoryStatus.PROPOSED,
            origin="theorist_agent",
        )
        merged = bench_controller._merge_hcc_seeds_into_candidates(
            seeds, [llm_dup],
        )
        # The merged entry for that id should be the SEED, not the LLM dup
        match = next(
            t for t in merged if t.hypothesis_id == seeds[0].hypothesis_id
        )
        assert match.origin == "programmatic_fallback", (
            f"LLM candidate replaced the seed; expected "
            f"origin='programmatic_fallback', got {match.origin!r}"
        )

    def test_merge_preserves_seed_count_against_empty_llm(
        self, bench_controller,
    ):
        """When the LLM produces nothing, every seed still surfaces
        (modulo ledger dedup, which is empty in this fresh-ledger
        fixture).
        """
        seeds = bench_controller._collect_hcc_seeds()
        merged = bench_controller._merge_hcc_seeds_into_candidates(seeds, [])
        # Fresh ledger — none of the seeds are pre-existing
        assert len(merged) == len(seeds)


# ---------------------------------------------------------------------------
# (c) Real-K4 mode unchanged.
# ---------------------------------------------------------------------------


class TestRealK4Unchanged:
    def test_real_k4_controller_returns_empty_seeds(self, real_k4_controller):
        """In real-K4 mode the seed collector returns []. The controller's
        existing _generate_theories behaviour is then unchanged.
        """
        seeds = real_k4_controller._collect_hcc_seeds()
        assert seeds == [], (
            "Real-K4 controller should produce no HCC seeds; "
            f"got {len(seeds)}. Patch leaked into real-K4 mode."
        )

    def test_real_k4_merge_is_passthrough(self, real_k4_controller):
        """Empty seeds + LLM list = LLM list, in order, unchanged."""
        from kryptosbot.models import TheoryRecord, TheoryStatus
        llm_cands = [
            TheoryRecord(
                hypothesis_id=f"llm-{i}",
                title=f"theory {i}",
                family="real_k4",
                status=TheoryStatus.PROPOSED,
            )
            for i in range(3)
        ]
        merged = real_k4_controller._merge_hcc_seeds_into_candidates([], llm_cands)
        assert [t.hypothesis_id for t in merged] == ["llm-0", "llm-1", "llm-2"]


# ---------------------------------------------------------------------------
# (d) bench_attempts artifact includes ALL HCC seeds (not just top-5)
# ---------------------------------------------------------------------------


class TestArtifactIncludesAllHccSeeds:
    """Tests for the 2026-04-27 bench_attempts patch:

    - Every HCC seed with a 97-char plaintext appears in the artifact
      regardless of crib_score.
    - coverage_vector is populated on every HCC attempt entry.
    - The K4B-001 Vig(LANTERN)+Col(CEDAR) seed appears in the artifact
      even when its crib_score is below the (formerly capped) top-5.
    """

    def _build_dispatched_ledger(
        self, controller: ResearchController, n_seeds: int = 8,
    ):
        """Dispatch-simulate: persist N HCC theories into the ledger
        with synthetic best_plaintexts so they pass the bench_attempts
        97-char filter. Each is given a deliberately low crib_score
        (1) so any "top-5" cap would drop most of them.
        """
        from kryptosbot.models import (
            ExperimentRecord, TheoryStatus, WorkerContract, WorkerStatus,
        )
        seeds = controller._collect_hcc_seeds()
        assert len(seeds) >= n_seeds, (
            f"need at least {n_seeds} seeds; got {len(seeds)}"
        )
        # Take the FIRST n_seeds (deterministic order) and plant them
        # in the ledger with synthetic best_plaintexts.
        synthetic_pt = "Q" * 97
        used = []
        for i, seed in enumerate(seeds[:n_seeds]):
            seed.status = TheoryStatus.COMPLETED
            seed.best_plaintext = synthetic_pt
            seed.best_score = 1.0  # deliberately very low
            controller.ledger.upsert_theory(seed)
            # Record an experiment so the layer-source resolver finds
            # the dispatched DSL spec. Use a per-seed experiment_id
            # that is GUARANTEED unique (the seed slugs all share the
            # ``hcc-<bench-id>-`` prefix, so a [:8] slice would collide
            # across seeds — use the index instead).
            exp = ExperimentRecord(
                experiment_id=f"exp-fixture-{i:04d}",
                hypothesis_id=seed.hypothesis_id,
                worker_role="dsl_dispatcher",
                config={"dsl_spec": dict(seed.dsl_spec)},
                result=WorkerContract(
                    hypothesis_id=seed.hypothesis_id,
                    worker_role="dsl_dispatcher",
                    status=WorkerStatus.DISPROVED,
                    best_plaintext=synthetic_pt,
                    crib_score=1,
                    raw_artifacts={
                        "dispatched_dsl_spec": dict(seed.dsl_spec),
                    },
                ),
            )
            controller.ledger.record_experiment(exp)
            used.append(seed)
        return used

    def test_artifact_contains_every_dispatched_hcc_seed(
        self, bench_controller, tmp_path: Path,
    ):
        """All 8 HCC seeds we plant make it into the artifact, even
        though their crib_score (1) is below the historical top-5 cap.
        """
        from kryptosbot.bench_attempts import emit_attempt_artifact

        used = self._build_dispatched_ledger(bench_controller, n_seeds=8)
        challenge = load_k4bench_challenge(_K4B001_PATH)
        artifact_path = emit_attempt_artifact(
            challenge=challenge,
            ledger_db_path=bench_controller.config.ledger_db_path,
            project_root=tmp_path,
            output_path=tmp_path / "k4b001_artifact.json",
            top_n=5,
        )
        artifact = json.loads(artifact_path.read_text())
        attempts = artifact["attempts"]
        attempt_ids = {a["evidence"]["hypothesis_id"] for a in attempts}
        for seed in used:
            assert seed.hypothesis_id in attempt_ids, (
                f"HCC seed {seed.hypothesis_id} not in attempt artifact; "
                f"found {len(attempts)} attempts (cap was top_n=5 but "
                "seeds should be unconditional)."
            )

    def test_every_hcc_attempt_has_non_empty_coverage_vector(
        self, bench_controller, tmp_path: Path,
    ):
        """Every attempt entry corresponding to an HCC seed has a
        non-empty coverage_vector. The offline evaluator depends on
        this to compute per-class gap analysis.
        """
        from kryptosbot.bench_attempts import emit_attempt_artifact

        self._build_dispatched_ledger(bench_controller, n_seeds=8)
        challenge = load_k4bench_challenge(_K4B001_PATH)
        artifact_path = emit_attempt_artifact(
            challenge=challenge,
            ledger_db_path=bench_controller.config.ledger_db_path,
            project_root=tmp_path,
            output_path=tmp_path / "k4b001_artifact.json",
            top_n=5,
        )
        artifact = json.loads(artifact_path.read_text())
        hcc_attempts = [
            a for a in artifact["attempts"]
            if a["evidence"].get("is_hcc_seed", False)
        ]
        assert len(hcc_attempts) > 0, "no HCC attempts found in artifact"
        for att in hcc_attempts:
            cv = att.get("coverage_vector") or {}
            assert cv, (
                f"HCC attempt {att['evidence']['hypothesis_id']} has "
                f"empty coverage_vector; the bench-mode telemetry "
                "contract requires every HCC seed to carry one."
            )
            # Confirm the canonical fields are present.
            assert "layer_family" in cv
            assert "layer_order" in cv
            assert "role_assignment" in cv

    def test_vig_lantern_col_cedar_in_artifact_despite_low_crib_score(
        self, bench_controller, tmp_path: Path,
    ):
        """The K4B-001 critical candidate appears in the artifact even
        when its crib_score (1, by construction here) is below the
        formerly-applied top-5 cap.

        This is the exact failure mode the user reported: the seed
        was in the dispatched set but did not surface in the
        artifact, so the offline evaluator could not see it.
        """
        from kryptosbot.bench_attempts import emit_attempt_artifact

        # Plant ALL HCC seeds (some 50+) so the Vig(LANTERN)+Col(CEDAR)
        # entry is competing against many others. Every one gets
        # crib_score=1 by construction — only the unconditional HCC
        # inclusion should surface our target.
        self._build_dispatched_ledger(bench_controller, n_seeds=20)

        challenge = load_k4bench_challenge(_K4B001_PATH)
        artifact_path = emit_attempt_artifact(
            challenge=challenge,
            ledger_db_path=bench_controller.config.ledger_db_path,
            project_root=tmp_path,
            output_path=tmp_path / "k4b001_artifact.json",
            top_n=5,  # explicitly small — cap that would otherwise drop seeds
        )
        artifact = json.loads(artifact_path.read_text())

        # Find the Vig(LANTERN) + Col(CEDAR) attempt by its
        # coverage_vector signature.
        target_match = []
        for att in artifact["attempts"]:
            cv = att.get("coverage_vector") or {}
            if cv.get("layer_family") != "columnar_vigenere":
                continue
            if list(cv.get("layer_order", [])) != ["vigenere", "columnar"]:
                continue
            role = cv.get("role_assignment", {})
            if role.get("vigenere") == "LANTERN" and role.get("columnar") == "CEDAR":
                target_match.append(att)
        assert len(target_match) >= 1, (
            "Vigenere(LANTERN) + Columnar(CEDAR) NOT in the K4B-001 "
            "attempt artifact even though it was dispatched. The "
            "top-5 cap is dropping coverage-critical HCC seeds."
        )
        # Confirm the seeded artifact's layers also reference CEDAR
        # via keyword-derived col_order, not identity.
        att = target_match[0]
        col_layer = next(
            (l for l in att["layers"] if l.get("kind") == "columnar"),
            None,
        )
        assert col_layer is not None, "columnar layer missing from artifact"
        col_params = {
            p["name"]: p["values"][0] for p in col_layer["params"]
        }
        assert col_params["width"] == len("CEDAR"), (
            f"width should be len(CEDAR)=5; got {col_params['width']}"
        )

    def test_top_n_still_caps_non_hcc_theories(
        self, bench_controller, tmp_path: Path,
    ):
        """The top_n cap is preserved for non-HCC theories. Plant a
        bunch of fake non-HCC theories and confirm only top_n appear
        in the non-HCC slice of the artifact.
        """
        from kryptosbot.bench_attempts import emit_attempt_artifact
        from kryptosbot.models import TheoryRecord, TheoryStatus

        synthetic_pt = "Q" * 97
        for i in range(10):
            theory = TheoryRecord(
                hypothesis_id=f"non-hcc-{i:02d}",
                title=f"non-HCC #{i}",
                family="legacy_sdk",
                status=TheoryStatus.COMPLETED,
                best_plaintext=synthetic_pt,
                best_score=float(i),  # increasing crib_score
                origin="theorist_agent",  # NOT programmatic_fallback
                # Empty minimal_test_spec → no coverage_vector → not an HCC seed
            )
            bench_controller.ledger.upsert_theory(theory)

        challenge = load_k4bench_challenge(_K4B001_PATH)
        artifact_path = emit_attempt_artifact(
            challenge=challenge,
            ledger_db_path=bench_controller.config.ledger_db_path,
            project_root=tmp_path,
            output_path=tmp_path / "k4b001_artifact.json",
            top_n=3,
        )
        artifact = json.loads(artifact_path.read_text())
        non_hcc = [
            a for a in artifact["attempts"]
            if not a["evidence"].get("is_hcc_seed", False)
        ]
        assert len(non_hcc) == 3, (
            f"non-HCC slice should respect top_n=3; got {len(non_hcc)} "
            f"non-HCC attempts in artifact."
        )
