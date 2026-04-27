"""K4Bench mode pipeline-gate acceptance tests.

Pins the K4Bench-specific bypasses added 2026-04-26 against regression:

  1. Bench-mode columnar+vigenere spec is not rejected for real-K4
     exhaustion-log overlap (`test_bench_mode_admissibility_skips_exhaustion`).
  2. Bench-mode cipher-family theories (vigenere, beaufort, columnar,
     rail_fence, route, bifid, fractionation, transposition, atbash,
     polybius, etc.) are not rejected for being Tier-1 / Tier-2 / family-
     registry-eliminated for real K4
     (`test_bench_mode_critic_does_not_reject_*`).
  3. Bench-mode theorist prompt does not surface real-K4 anomaly /
     family / anchor names (`test_bench_prompt_omits_real_k4_*`).
  4. Malformed DSL specs (Roman-numeral quagmire variant, empty
     hypothesis_id) are repaired-or-rejected before reaching dispatch
     (`test_repair_spec_shape_*`).
  5. At least one bench-mode synthetic fixture produces total_tested > 0
     through the dsl_dispatcher
     (`test_bench_mode_dispatcher_runs_synthetic_spec_end_to_end`).

The tests are CONTROLLER-SCOPED: they construct a ResearchController
with a bench_challenge_payload set, then exercise the same code paths a
real --bench-challenge launch would exercise. They do not call out to
the SDK and do not require API keys.

Spec-shape rejections (malformed/duplicate/underconstrained) are
EXPECTED to still fire in bench mode — those tests are also pinned so a
future "loosen everything in bench mode" patch cannot weaken the
spec-shape contract.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any, Optional

import pytest

from kryptosbot.controller import ControllerConfig, ResearchController
from kryptosbot.critic import (
    NON_DSL_FAMILIES,
    TIER_1_FAMILIES,
    TIER_2_FAMILIES,
    TheoryCritic,
)
from kryptosbot.hypothesis_dsl import (
    HypothesisSpec,
    repair_spec_shape,
    validate_hypothesis_spec,
)
from kryptosbot.job_dispatcher import (
    check_admissibility,
    execute,
)
from kryptosbot.models import (
    CriticDecision,
    TheoryRecord,
)
from kryptosbot.theory_ledger import TheoryLedger


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# A K4-shaped synthetic challenge payload. Same shape as
# K4BenchChallenge.canonical_facts() output, embedded inline so the
# tests do not depend on bench/k4bench/challenges/*.json.
_BENCH_CT = (
    "DCXEGPKDRHYITACRUTBWO"
    "XRKGXZEOEEQPI"
    "ULFRQVEELEFFIVBPKKFIEGYDVXEZFOEQ"
    "WVSRIUQXHZA"
    "ITUMBFFSORMSPBZTRXPO"
)
assert len(_BENCH_CT) == 97, "bench fixture CT must be 97 chars"

_BENCH_PAYLOAD: dict[str, Any] = {
    "ciphertext": _BENCH_CT,
    "ct_length": 97,
    "cribs": [(21, "SECONDSYSTEMX"), (63, "COLUMNORDER")],
    "n_crib_chars": 24,
    "bench_mode": True,
    "bench_id": "K4B-TEST-PIPELINE",
    "suite_id": "K4BENCH-TEST",
    "title": "Pipeline-gate acceptance",
    "clue_text": "Test clue text.",
    "constraint_summary": ["A-Z only.", "Length 97."],
    "solver_required_fields": ["bench_id", "plaintext"],
    "strict_pass_rule": "exact",
    "known_crib_score_target": 24,
}

_BENCH_PROMPT_BLOCK = (
    "K4BENCH SYNTHETIC CHALLENGE — bench_id=K4B-TEST-PIPELINE\n"
    "THIS IS NOT REAL K4. The CIPHERTEXT below is the SOLE source of "
    "truth. Do not import K4 anchors.\n"
    f"CIPHERTEXT: {_BENCH_CT}\n"
    "CRIB SPANS: SECONDSYSTEMX @ 21-33; COLUMNORDER @ 63-73\n"
    "PUBLIC CLUE TEXT: Test clue text.\n"
)


def _tmp_ledger() -> TheoryLedger:
    """Fresh in-tempdir ledger for isolated tests."""
    tmp = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
    tmp.close()
    return TheoryLedger(db_path=Path(tmp.name))


def _bench_controller(tmp_path: Path) -> ResearchController:
    """Construct a ResearchController in bench mode without launching it."""
    cfg = ControllerConfig(
        project_root=tmp_path,
        ledger_db_path=tmp_path / "k4bench_test.sqlite",
        max_cycles=1,
        theories_per_cycle=1,
        dry_run=True,
        bench_challenge_payload=_BENCH_PAYLOAD,
        bench_challenge_prompt_block=_BENCH_PROMPT_BLOCK,
        # Bench mode forces these False in run_controller.main; we mirror
        # that here so the prompt-rendering tests below see the same
        # state the production launcher produces.
        include_oranchak_corpora=False,
        include_serpentine_anchor=False,
    )
    return ResearchController(cfg)


def _real_k4_controller(tmp_path: Path) -> ResearchController:
    """Same ResearchController construction WITHOUT bench mode (real K4)."""
    cfg = ControllerConfig(
        project_root=tmp_path,
        ledger_db_path=tmp_path / "real_k4_test.sqlite",
        max_cycles=1,
        theories_per_cycle=1,
        dry_run=True,
    )
    return ResearchController(cfg)


# ---------------------------------------------------------------------------
# Acceptance test (a): bench mode skips exhaustion-overlap
# ---------------------------------------------------------------------------

def _make_columnar_vigenere_spec(hid: str = "bench-colvig") -> HypothesisSpec:
    """Two-layer columnar+vigenere spec; both layers families that
    real-K4 exhaustion_log.json contains entries for (vigenere, columnar)."""
    parsed = validate_hypothesis_spec({
        "hypothesis_id": hid,
        "pipeline": [
            {"kind": "columnar", "alphabet": "AZ",
             "params": [{"name": "width", "values": [7]},
                        {"name": "col_order",
                         "values": [[0, 1, 2, 3, 4, 5, 6]]}]},
            {"kind": "vigenere", "alphabet": "AZ",
             "params": [{"name": "keyword", "values": ["KRYPTOS"]}]},
        ],
        "compute_budget_cpu_minutes": 1,
        "assumption_bundle": ["multilayer", "columnar_first"],
    })
    assert parsed.is_valid, parsed.errors
    return parsed.value


def test_bench_mode_admissibility_skips_exhaustion_overlap():
    """Acceptance test (a): bench-mode columnar+vigenere spec is NOT
    rejected because of real-K4 exhaustion-log overlap.

    Construct an exhaustion-log fixture that contains family entries
    for vigenere AND columnar (which is the realistic real-K4 state).
    Without bench mode, ``check_admissibility`` rejects the spec on
    overlap. With bench_mode=True, admissibility passes.
    """
    spec = _make_columnar_vigenere_spec()
    # Realistic-shape exhaustion log fixture: each entry is a script_id
    # → {family, status} object; status in {"exhausted", "completed"}
    # triggers the overlap heuristic.
    exhaustion_log = {
        "e_vigenere_42": {"family": "vigenere", "status": "exhausted"},
        "e_columnar_91": {"family": "columnar", "status": "completed"},
    }

    # Without bench_mode: rejected.
    admissible_real, reasons_real = check_admissibility(
        spec, exhaustion_log=exhaustion_log, bench_mode=False,
    )
    assert not admissible_real
    assert any("exhaustion overlap" in r.lower() for r in reasons_real)

    # With bench_mode=True: admissible. Other checks (validation,
    # translation, cardinality) still ran but produced no errors.
    admissible_bench, reasons_bench = check_admissibility(
        spec, exhaustion_log=exhaustion_log, bench_mode=True,
    )
    assert admissible_bench, reasons_bench
    assert not any("exhaustion overlap" in r.lower() for r in reasons_bench)


def test_bench_mode_admissibility_still_rejects_untranslatable_kind():
    """Negative path: a spec whose layer kind has no dispatcher
    translation (e.g. ``key_tape``, the only deferred kind) is still
    rejected in bench mode. The bypass is narrowly scoped to real-K4
    exhaustion overlap — every other admissibility gate still fires."""
    parsed = validate_hypothesis_spec({
        "hypothesis_id": "bench-untranslatable",
        "pipeline": [
            {"kind": "key_tape", "alphabet": "AZ", "params": []},
        ],
        "compute_budget_cpu_minutes": 1,
    })
    assert parsed.is_valid, (
        "fixture sanity: key_tape is a valid DSL kind, just unsupported "
        "by the dispatcher; it should pass DSL validation but fail "
        "admissibility"
    )
    spec = parsed.value
    admissible, reasons = check_admissibility(spec, bench_mode=True)
    assert not admissible, (
        f"untranslatable kinds must still be rejected even in bench mode; "
        f"reasons={reasons}"
    )
    assert any("translation" in r.lower() for r in reasons), reasons


# ---------------------------------------------------------------------------
# Acceptance test (b): bench mode does not reject Tier-1 / Tier-2 families
# ---------------------------------------------------------------------------

def _make_theory(family: str, mechanism: str, dsl_spec: dict[str, Any] | None = None) -> TheoryRecord:
    return TheoryRecord(
        title=f"Bench {family} test",
        core_claim=f"K4Bench challenge uses {mechanism}",
        mechanism=mechanism,
        family=family,
        kill_criteria=[f"All {family} keywords give crib_score < 10"],
        expected_signal="crib_score >= 18",
        # Anomalies_exploited is left empty so the info-gain check
        # downgrades to "low" — bench tests must clear that gate too.
        anomalies_exploited=["bench_synthetic_calibration"],
        dsl_spec=dsl_spec or {},
    )


def _vigenere_dsl_spec(hid: str) -> dict[str, Any]:
    return {
        "hypothesis_id": hid,
        "pipeline": [{
            "kind": "vigenere", "alphabet": "AZ",
            "params": [{"name": "keyword", "values": ["KRYPTOS"]}],
        }],
        "compute_budget_cpu_minutes": 1,
    }


def _columnar_dsl_spec(hid: str) -> dict[str, Any]:
    return {
        "hypothesis_id": hid,
        "pipeline": [{
            "kind": "columnar", "alphabet": "AZ",
            "params": [{"name": "width", "values": [7]},
                       {"name": "col_order",
                        "values": [[0, 1, 2, 3, 4, 5, 6]]}],
        }],
        "compute_budget_cpu_minutes": 1,
    }


def _rail_fence_dsl_spec(hid: str) -> dict[str, Any]:
    return {
        "hypothesis_id": hid,
        "pipeline": [{
            "kind": "rail_fence", "alphabet": "AZ",
            "params": [{"name": "depth", "values": [3]}],
        }],
        "compute_budget_cpu_minutes": 1,
    }


def _atbash_dsl_spec(hid: str) -> dict[str, Any]:
    return {
        "hypothesis_id": hid,
        "pipeline": [{"kind": "atbash", "alphabet": "AZ", "params": []}],
        "compute_budget_cpu_minutes": 1,
    }


def _myszkowski_dsl_spec(hid: str, keyword: str = "CEDAR") -> dict[str, Any]:
    return {
        "hypothesis_id": hid,
        "pipeline": [{
            "kind": "myszkowski", "alphabet": "AZ",
            "params": [{"name": "keyword", "values": [keyword]}],
        }],
        "compute_budget_cpu_minutes": 1,
    }


def _quagmire_dsl_spec(hid: str, keyword: str = "LANTERN") -> dict[str, Any]:
    """Quagmire III spec: ct_alphabet_keyword must equal pt_alphabet_keyword
    (translator enforces this; for differing keywords use quagmire_iv)."""
    return {
        "hypothesis_id": hid,
        "pipeline": [{
            "kind": "quagmire", "alphabet": "AZ",
            "params": [
                {"name": "period_keyword", "values": [keyword]},
                {"name": "indicator", "values": ["A"]},
                {"name": "ct_alphabet_keyword", "values": [keyword]},
                {"name": "pt_alphabet_keyword", "values": [keyword]},
                {"name": "variant", "values": ["quagmire_iii"]},
            ],
        }],
        "compute_budget_cpu_minutes": 1,
    }


def _vigenere_keyword_spec(hid: str, keyword: str) -> dict[str, Any]:
    return {
        "hypothesis_id": hid,
        "pipeline": [{
            "kind": "vigenere", "alphabet": "AZ",
            "params": [{"name": "keyword", "values": [keyword]}],
        }],
        "compute_budget_cpu_minutes": 1,
    }


def _beaufort_keyword_spec(hid: str, keyword: str) -> dict[str, Any]:
    return {
        "hypothesis_id": hid,
        "pipeline": [{
            "kind": "beaufort", "alphabet": "AZ",
            "params": [{"name": "keyword", "values": [keyword]}],
        }],
        "compute_budget_cpu_minutes": 1,
    }


def _route_dsl_spec(hid: str) -> dict[str, Any]:
    return {
        "hypothesis_id": hid,
        "pipeline": [{
            "kind": "route", "alphabet": "AZ",
            "params": [
                {"name": "variant", "values": ["serpentine"]},
                {"name": "rows", "values": [10]},
                {"name": "cols", "values": [10]},
            ],
        }],
        "compute_budget_cpu_minutes": 1,
    }


@pytest.mark.parametrize("family,mechanism,spec_factory", [
    # Tier 1 (structural impossibility for real K4) — bench mode ignores.
    ("atbash", "Atbash reversal", _atbash_dsl_spec),
    # Tier 2 (single-layer-exhausted for real K4) — bench mode ignores.
    ("vigenere", "Vigenere with bench-clue keyword", _vigenere_dsl_spec),
    ("beaufort", "Beaufort with bench-clue keyword", _vigenere_dsl_spec),
    ("rail_fence", "Rail-fence depth 3", _rail_fence_dsl_spec),
    ("columnar_single", "Single columnar width 7", _columnar_dsl_spec),
])
def test_bench_mode_critic_does_not_reject_real_k4_eliminated_family(
    family, mechanism, spec_factory,
):
    """Acceptance test (b): bench-mode critic does not reject cipher-
    family theories whose family is on the real-K4 Tier-1 / Tier-2 list.

    Every family in this table is in TIER_1_FAMILIES or
    TIER_2_FAMILIES. Without bench mode the critic returns
    REJECT_ELIMINATED. With bench_mode=True the critic must approve
    (or fall through to a non-elimination outcome)."""
    assert (family in TIER_1_FAMILIES
            or family in TIER_2_FAMILIES), (
        f"test fixture sanity: {family} should be on the real-K4 "
        "elimination list, otherwise the test isn't exercising the "
        "bench bypass"
    )

    ledger = _tmp_ledger()
    theory = _make_theory(
        family, mechanism, dsl_spec=spec_factory(f"bench-{family}-test"),
    )

    # Real-K4 critic: rejects.
    real_critic = TheoryCritic(ledger, bench_mode=False)
    real_verdict = real_critic.evaluate(theory)
    assert real_verdict.decision == CriticDecision.REJECT_ELIMINATED, (
        f"sanity: real-K4 critic should reject {family} as eliminated; "
        f"got {real_verdict.decision} reasons={real_verdict.reasons}"
    )

    # Bench-mode critic: must NOT reject on elimination grounds.
    bench_critic = TheoryCritic(ledger, bench_mode=True)
    bench_verdict = bench_critic.evaluate(theory)
    assert bench_verdict.decision != CriticDecision.REJECT_ELIMINATED, (
        f"bench-mode critic incorrectly rejected {family} as eliminated; "
        f"reasons={bench_verdict.reasons}"
    )


def test_bench_mode_critic_does_not_reject_bifid_for_alphabet():
    """Acceptance test (b'): bifid is structurally impossible for real
    K4 (CT contains all 26 letters; bifid needs 25). The critic's
    contradiction-check rejects bifid on real K4. Bench mode skips
    that check.

    The bench challenge CT may or may not contain a J — in either case,
    bench mode treats the "bifid_eliminated_structural" claim as not
    applicable. If bifid actually fails on the bench CT, the kernel
    will produce a low score; that's a valid empirical outcome, not a
    critic-side reject."""
    ledger = _tmp_ledger()
    # Fractionation/bifid theory; same DSL kind 'polybius' that the
    # dispatcher accepts as variant=bifid.
    polybius_spec = {
        "hypothesis_id": "bench-bifid-test",
        "pipeline": [{
            "kind": "polybius", "alphabet": "AZ",
            "params": [
                {"name": "square_keyword", "values": ["KRYPTOS"]},
                {"name": "variant", "values": ["bifid"]},
                {"name": "merge", "values": ["IJ"]},
            ],
        }],
        "compute_budget_cpu_minutes": 1,
    }
    theory = TheoryRecord(
        title="Bench bifid test",
        core_claim="K4Bench challenge uses bifid fractionation",
        mechanism="Bifid 5x5 with KRYPTOS-keyed square (note: bifid)",
        family="fractionation",
        kill_criteria=["bifid keywords give crib_score < 10"],
        expected_signal="crib_score >= 18",
        anomalies_exploited=["bench_synthetic_calibration"],
        dsl_spec=polybius_spec,
    )
    bench_critic = TheoryCritic(ledger, bench_mode=True)
    verdict = bench_critic.evaluate(theory)
    # Must not reject as eliminated/contradicted; APPROVE or DEFER are
    # both acceptable bench-mode outcomes for this family.
    assert verdict.decision not in (
        CriticDecision.REJECT_ELIMINATED,
        CriticDecision.REJECT_CONTRADICTED,
    ), f"bench critic rejected bifid: {verdict.decision} {verdict.reasons}"


def test_bench_mode_critic_still_rejects_malformed_spec():
    """Negative-path pin: bench mode must NOT loosen spec-shape gates.

    A theory whose dsl_spec is null (Category C / cipher-family-with-no-
    spec) is still rejected as REJECT_UNDERCONSTRAINED with reason
    'dsl_untranslatable'. Bench mode only skips REAL-K4 elimination
    gates; it does not turn the DSL contract into a no-op.
    """
    ledger = _tmp_ledger()
    theory = TheoryRecord(
        title="bench malformed spec",
        core_claim="K4Bench uses some cipher",
        mechanism="something",
        family="novel",  # Category A (cipher-family but not NON_DSL_FAMILIES)
        anomalies_exploited=["bench_synthetic_calibration"],
        kill_criteria=["sanity"],
        expected_signal="signal",
        dsl_spec={},  # Category C — empty
    )
    bench_critic = TheoryCritic(ledger, bench_mode=True)
    verdict = bench_critic.evaluate(theory)
    assert verdict.decision == CriticDecision.REJECT_UNDERCONSTRAINED
    assert any("dsl_untranslatable" in r for r in verdict.reasons)


def test_bench_mode_critic_still_rejects_missing_required_fields():
    """Negative-path pin: completeness check still fires in bench mode.

    Missing core_claim / mechanism / family must still produce
    REJECT_UNDERCONSTRAINED — these are spec-shape gates, not real-K4
    elimination gates."""
    ledger = _tmp_ledger()
    theory = TheoryRecord(
        title="missing fields",
        core_claim="",  # missing
        mechanism="",   # missing
        family="",      # missing
    )
    bench_critic = TheoryCritic(ledger, bench_mode=True)
    verdict = bench_critic.evaluate(theory)
    assert verdict.decision == CriticDecision.REJECT_UNDERCONSTRAINED
    assert any("missing" in r.lower() for r in verdict.reasons)


# ---------------------------------------------------------------------------
# Acceptance test (b''): bench-mode critic does not reject concrete finite
# DSL specs as LOW_INFORMATION even when the theory cites no anomalies.
#
# The brief: "TheoryCritic must not reject concrete finite DSL hypotheses
# as LOW_INFORMATION merely because expected information gain is narrow."
# The LOW_INFORMATION check rests on (a) "low" info gain — computed against
# the real-K4 ledger's family-status table — and (b) the absence of
# anomalies_exploited (a real-K4 concept). Both inputs are real-K4
# evidence; neither applies to a synthetic K4Bench challenge.
# ---------------------------------------------------------------------------

def _make_anomaly_free_theory(
    family: str, mechanism: str, dsl_spec: dict[str, Any] | None = None,
) -> TheoryRecord:
    """Same shape as _make_theory but with anomalies_exploited=[].

    _make_theory sets anomalies_exploited=["bench_synthetic_calibration"]
    which masks the LOW_INFORMATION path (any non-empty list passes the
    "no anomalies" guard). To exercise the LOW_INFORMATION skip we need
    a theory whose anomalies_exploited is genuinely empty.
    """
    return TheoryRecord(
        title=f"Bench {family} (no anomaly anchor)",
        core_claim=f"K4Bench challenge uses {mechanism}",
        mechanism=mechanism,
        family=family,
        kill_criteria=[f"All {family} keywords give crib_score < 10"],
        expected_signal="crib_score >= 18",
        anomalies_exploited=[],  # KEY: empty, not {"bench_synthetic_calibration"}
        dsl_spec=dsl_spec or {},
    )


@pytest.mark.parametrize("family,mechanism,spec_factory,kw", [
    ("vigenere",        "Vigenere with CEDAR keyword",   _vigenere_keyword_spec, "CEDAR"),
    ("vigenere",        "Vigenere with LANTERN keyword", _vigenere_keyword_spec, "LANTERN"),
    ("beaufort",        "Beaufort with CEDAR keyword",   _beaufort_keyword_spec, "CEDAR"),
    ("beaufort",        "Beaufort with LANTERN keyword", _beaufort_keyword_spec, "LANTERN"),
    ("columnar_single", "Single columnar width 7",       lambda hid, _kw: _columnar_dsl_spec(hid), "_"),
    ("rail_fence",      "Rail-fence depth 3",            lambda hid, _kw: _rail_fence_dsl_spec(hid), "_"),
    ("transposition",   "Myszkowski with CEDAR keyword", _myszkowski_dsl_spec,   "CEDAR"),
    ("transposition",   "Route serpentine 10x10",        lambda hid, _kw: _route_dsl_spec(hid), "_"),
    ("polyalphabetic",  "Quagmire III with LANTERN",     _quagmire_dsl_spec,     "LANTERN"),
])
def test_bench_mode_critic_approves_concrete_finite_dsl_specs(
    family, mechanism, spec_factory, kw,
):
    """Acceptance test (b''): bench mode approves a concrete DSL spec
    with valid pipeline layers, finite cardinality, and challenge-local
    clue anchors — including specs whose theorist did NOT cite an
    anomaly anchor (anomalies_exploited=[]).

    Without the bench-mode LOW_INFORMATION skip, these would fall to
    REJECT_LOW_INFORMATION when the family is well-explored and no
    anomaly is cited. Bench mode must approve them because (a) the
    real-K4 family ledger does not bind synthetic challenges and
    (b) anomaly anchoring is a real-K4 concept that does not transfer.
    """
    ledger = _tmp_ledger()
    spec = spec_factory(f"bench-anomfree-{family}-{kw}", kw) if kw != "_" else spec_factory(f"bench-anomfree-{family}", kw)
    theory = _make_anomaly_free_theory(family, mechanism, dsl_spec=spec)

    bench_critic = TheoryCritic(ledger, bench_mode=True)
    verdict = bench_critic.evaluate(theory)
    assert verdict.decision == CriticDecision.APPROVE, (
        f"bench-mode critic rejected concrete finite spec "
        f"(family={family}, kw={kw}); decision={verdict.decision}; "
        f"reasons={verdict.reasons}"
    )


def test_real_k4_critic_still_rejects_low_information_for_anomaly_free_theory():
    """Sanity sibling to the bench LOW_INFORMATION skip above: WITHOUT
    bench mode, a theory whose family is well-explored and whose
    anomalies_exploited list is empty MUST still produce
    REJECT_LOW_INFORMATION. Otherwise the bench skip is doing nothing
    and the previous test is passing vacuously.
    """
    ledger = _tmp_ledger()
    # Use a Tier-2 family ("vigenere" is well-explored) so info_gain
    # falls to "low" via the family-status path. Empty anomalies list
    # means the "no anomalies" half of the guard also fires. Wrap it in
    # a multi-layer mechanism string so the Tier-2 single-layer rejection
    # is sidestepped — we want to reach Check 6, not stop at Check 2.
    spec = _vigenere_keyword_spec("real-k4-anomfree", "PALIMPSEST")
    theory = _make_anomaly_free_theory(
        "vigenere",
        "vigenere multi-layer composition with PALIMPSEST primer",
        dsl_spec=spec,
    )
    real_critic = TheoryCritic(ledger, bench_mode=False)
    verdict = real_critic.evaluate(theory)
    assert verdict.decision == CriticDecision.REJECT_LOW_INFORMATION, (
        f"real-K4 critic should still reject anomaly-free well-explored "
        f"theories as LOW_INFORMATION; got {verdict.decision} "
        f"reasons={verdict.reasons}"
    )


# ---------------------------------------------------------------------------
# Acceptance test (c): bench prompt has no real-K4 anomaly / family content
# ---------------------------------------------------------------------------

# Phrases that the K4 landscape / manual focus / serpentine-anchor /
# Oranchak-corpora blocks contain; none should appear in a bench prompt
# (unless a future bench challenge JSON literally embeds the phrase,
# which is fair game per the brief).
_REAL_K4_FORBIDDEN_PHRASES = [
    "He lied",                          # aaa_coordinate_lie claim text
    "width-21",                         # width21_vertical_bigrams anomaly
    "width21",                          # alternate spelling
    "K2 Coords",                        # K2 coordinates non-DSL family
    "Geodetic",                         # geodetic non-DSL family
    "geodetic",                         # casing variant
    "W segmentation",                   # w_delimiter_segments anomaly
    "w_delimiter_segments",             # ditto
    "EASTNORTHEAST",                    # real K4 crib content
    "BERLINCLOCK",                      # real K4 crib content
    "serpentine copper screen",         # AAA archive serpentine anchor
    "ct_perturbation",                  # current under-mined K4 anchor
    "aaa_coordinate_lie",               # K4 anomaly id
    "aaa_compass_cipher",               # K4 anomaly id
    "Oranchak",                         # community corpora anchor name
    "k4_candidate_fills",               # community corpora artifact name
    "PALIMPSEST",                       # K1 keyword
    "ABSCISSA",                         # K2 keyword
    "Mirror KA",                        # mirror_ka research thread
    "mirror_ka",                        # ditto, identifier form
    "Overlay",                          # overlay/ K4 research stub
    "Antipodes",                        # antipodes companion sculpture
    "antipodes",                        # identifier form
    "K3 continuity",                    # k3_continuity non-DSL family
    "k3_continuity",                    # identifier form
    "archive_evidence",                 # archive_evidence non-DSL family
    "k2_coords",                        # k2_coords identifier form
]


def test_bench_prompt_omits_real_k4_anomaly_phrases(tmp_path):
    """Acceptance test (c): bench-mode theorist prompt does not
    surface real-K4 anomalies, families, or anchor blocks.

    The bench challenge JSON in this fixture contains NONE of the
    real-K4 phrases below. A bench prompt that mentions them is
    therefore leaking the K4 landscape — exactly the failure mode the
    bench-mode prompt-stripping is supposed to prevent.
    """
    controller = _bench_controller(tmp_path)
    landscape = controller._assess_landscape()
    prompt = controller._build_theorist_prompt(landscape)

    for phrase in _REAL_K4_FORBIDDEN_PHRASES:
        assert phrase not in prompt, (
            f"bench prompt leaked real-K4 phrase {phrase!r}; first "
            f"occurrence at offset {prompt.find(phrase)}; first 200 "
            f"chars around it: "
            f"{prompt[max(0, prompt.find(phrase)-100):prompt.find(phrase)+100]!r}"
        )


def test_bench_prompt_includes_synthetic_challenge_block(tmp_path):
    """Sanity sibling to the negative test above: the bench prompt
    DOES contain the synthetic CT and crib content from the challenge
    block we passed in. Without this the previous test could pass
    vacuously by emitting an empty prompt."""
    controller = _bench_controller(tmp_path)
    landscape = controller._assess_landscape()
    prompt = controller._build_theorist_prompt(landscape)

    assert _BENCH_CT in prompt
    assert "SECONDSYSTEMX" in prompt
    assert "COLUMNORDER" in prompt
    # And must explicitly tell the model this is bench mode.
    assert "K4BENCH" in prompt or "bench" in prompt.lower()


def test_real_k4_prompt_still_surfaces_real_k4_landscape(tmp_path):
    """Negative-path pin: WITHOUT bench mode, the real-K4 prompt MUST
    surface the K4 anomaly / anchor blocks. This is the test that
    catches an over-broad strip — a refactor that always strips
    K4 content even in real-K4 mode would silence research on K4.

    Specifically: at least ONE of the real-K4 phrases must appear in
    a non-bench-mode prompt. The K4 ledger may be empty in this
    isolated test environment, but the manual-focus block, the
    serpentine anchor, and the Oranchak corpora block always render
    (they are unconditional on landscape state in non-bench mode)."""
    controller = _real_k4_controller(tmp_path)
    landscape = controller._assess_landscape()
    prompt = controller._build_theorist_prompt(landscape)

    # At least one of these must surface in a real-K4 prompt;
    # otherwise the strip is too broad.
    assert any(phrase in prompt for phrase in [
        "ct_perturbation",
        "w_delimiter_segments",
        "aaa_coordinate_lie",
        "serpentine",
    ]), (
        "Real-K4 prompt is missing every K4 anomaly/anchor anchor — "
        "the bench-mode strip may have leaked into the non-bench path."
    )


# ---------------------------------------------------------------------------
# Acceptance test (d): malformed specs are repaired or rejected before
# experiment creation
# ---------------------------------------------------------------------------

def test_repair_spec_shape_normalizes_quagmire_roman_numerals():
    """The repair pass rewrites quagmire variant 'III' → 'quagmire_iii'
    so the dispatcher (which only accepts the canonical snake_case
    form) does not reject the spec."""
    raw = {
        "hypothesis_id": "test-quagmire-iii-repair",
        "pipeline": [{
            "kind": "quagmire", "alphabet": "AZ",
            "params": [
                {"name": "period_keyword", "values": ["KRYPTOS"]},
                {"name": "indicator", "values": ["K"]},
                {"name": "ct_alphabet_keyword", "values": ["KRYPTOS"]},
                {"name": "pt_alphabet_keyword", "values": ["KRYPTOS"]},
                {"name": "variant", "values": ["III"]},  # Roman
            ],
        }],
        "compute_budget_cpu_minutes": 1,
    }
    repaired, report = repair_spec_shape(raw)
    assert report.applied()
    assert any("quagmire_iii" in e for e in report.entries)

    # Find the variant param in the repaired spec.
    variant_param = next(
        p for p in repaired["pipeline"][0]["params"]
        if p["name"] == "variant"
    )
    assert variant_param["values"] == ["quagmire_iii"]

    # The rest of the spec is untouched.
    period_param = next(
        p for p in repaired["pipeline"][0]["params"]
        if p["name"] == "period_keyword"
    )
    assert period_param["values"] == ["KRYPTOS"]


def test_repair_spec_shape_substitutes_empty_hypothesis_id():
    """Empty / placeholder hypothesis_id is replaced with the
    caller-supplied default. Validators reject empty hypothesis_id
    outright; without this repair the controller's pre-dispatch check
    would surface the rejection on every theory whose theorist forgot
    to fill in the id."""
    for placeholder in ("", "<fill with title-derived slug>", "  ", None):
        raw: dict[str, Any] = {
            "hypothesis_id": placeholder if placeholder is not None else "",
            "pipeline": [{
                "kind": "rail_fence", "alphabet": "AZ",
                "params": [{"name": "depth", "values": [3]}],
            }],
            "compute_budget_cpu_minutes": 1,
        }
        if placeholder is None:
            del raw["hypothesis_id"]
        repaired, report = repair_spec_shape(
            raw, default_hypothesis_id="theorist-supplied-id-1234",
        )
        assert report.applied()
        assert repaired["hypothesis_id"] == "theorist-supplied-id-1234"


def test_repair_spec_shape_does_not_touch_already_valid_spec():
    """Idempotency / no-op: a spec already in canonical form is
    returned unchanged with an empty repair report."""
    raw = {
        "hypothesis_id": "already-canonical",
        "pipeline": [{
            "kind": "quagmire", "alphabet": "AZ",
            "params": [
                {"name": "period_keyword", "values": ["KRYPTOS"]},
                {"name": "indicator", "values": ["K"]},
                {"name": "ct_alphabet_keyword", "values": ["KRYPTOS"]},
                {"name": "pt_alphabet_keyword", "values": ["KRYPTOS"]},
                {"name": "variant", "values": ["quagmire_iii"]},
            ],
        }],
        "compute_budget_cpu_minutes": 1,
    }
    repaired, report = repair_spec_shape(raw)
    assert not report.applied()
    assert repaired["hypothesis_id"] == "already-canonical"


def test_repaired_quagmire_spec_validates_and_translates():
    """End-to-end pin: a quagmire-with-Roman-numeral spec, after
    repair, validates AND has a recognized cipher kind. (The full
    translator is exercised by the dispatcher integration test
    below; this test pins the validation->translation handoff.)"""
    raw = {
        "hypothesis_id": "test-roman-numeral-repair",
        "pipeline": [{
            "kind": "quagmire", "alphabet": "AZ",
            "params": [
                {"name": "period_keyword", "values": ["KRYPTOS"]},
                {"name": "indicator", "values": ["K"]},
                {"name": "ct_alphabet_keyword", "values": ["KRYPTOS"]},
                {"name": "pt_alphabet_keyword", "values": ["KRYPTOS"]},
                {"name": "variant", "values": ["IV"]},
            ],
        }],
        "compute_budget_cpu_minutes": 1,
    }
    repaired, _ = repair_spec_shape(raw)
    parsed = validate_hypothesis_spec(repaired)
    assert parsed.is_valid, parsed.errors

    # The translator should now accept the canonical form. (We can't
    # actually fully translate without ct_kw != pt_kw under quagmire_iv,
    # but the parameter normalization step is what we're pinning here.)


def test_unrepaired_quagmire_roman_numeral_rejected_by_translator():
    """Negative-path pin: WITHOUT repair, the dispatcher's translator
    rejects 'III' as an unsupported variant value. This is the path
    the repair is closing."""
    from kryptosbot.job_dispatcher import _translate_layer
    from kryptosbot.hypothesis_dsl import CipherLayer
    from kryptosbot.job_dispatcher import DispatcherError

    layer = CipherLayer(kind="quagmire", alphabet="AZ", params=[])
    binding = {
        "period_keyword": "KRYPTOS",
        "indicator": "K",
        "ct_alphabet_keyword": "KRYPTOS",
        "pt_alphabet_keyword": "KRYPTOS",
        "variant": "III",  # un-repaired Roman numeral
    }
    with pytest.raises(DispatcherError, match="variant"):
        _translate_layer(layer, binding)


# ---------------------------------------------------------------------------
# Acceptance test (e): bench-mode synthetic spec produces total_tested > 0
# ---------------------------------------------------------------------------

def test_bench_mode_dispatcher_runs_synthetic_spec_end_to_end(tmp_path):
    """Acceptance test (e): at least one synthetic spec runs all the
    way through ``execute(bench_mode=True)`` and reports
    total_tested > 0.

    This is the smoke test that the bench-mode bypass actually reaches
    multiprocessing dispatch — it is the failure mode the brief is
    explicitly guarding against ("bench-mode spec gets rejected on the
    way to the dispatcher and never runs, so total_tested == 0").

    The spec is a single-layer Vigenere with one keyword, evaluated
    against the kernel CT. We run with parallel=False and an artifact
    root under tmp_path so the test does not pollute the project's
    results/ directory.
    """
    spec = _make_columnar_vigenere_spec("bench-end-to-end")
    # Empty exhaustion log so the test is reproducible regardless of
    # the project's real exhaustion_log.json state — but the bench_mode
    # flag is the actual bypass under test.
    exhaustion_log: dict[str, Any] = {
        # Realistic log content: vigenere AND columnar both exhausted.
        "e_vigenere_x": {"family": "vigenere", "status": "exhausted"},
        "e_columnar_y": {"family": "columnar", "status": "exhausted"},
    }
    artifact_root = tmp_path / "bench_artifacts"
    result = execute(
        spec,
        artifact_root=artifact_root,
        parallel=False,
        exhaustion_log=exhaustion_log,
        bench_mode=True,
    )
    assert result.admissibility_verdict == "ok", (
        f"bench dispatch was rejected at admissibility despite bench_mode=True; "
        f"reasons={result.admissibility_reasons}"
    )
    assert result.total_tested > 0, (
        f"bench-mode dispatch produced total_tested={result.total_tested}; "
        f"the synthetic spec did not actually reach the kernel"
    )


def test_bench_mode_dispatcher_real_mode_is_rejected_for_overlap():
    """Negative-path pin to the test above: the same spec, with
    bench_mode=False against the same exhaustion log, is rejected
    on overlap. Confirms the previous test isn't passing because the
    overlap check no longer fires."""
    spec = _make_columnar_vigenere_spec("bench-end-to-end-real")
    exhaustion_log: dict[str, Any] = {
        "e_vigenere_x": {"family": "vigenere", "status": "exhausted"},
        "e_columnar_y": {"family": "columnar", "status": "exhausted"},
    }
    result = execute(
        spec,
        parallel=False,
        exhaustion_log=exhaustion_log,
        bench_mode=False,
    )
    assert result.admissibility_verdict == "rejected"
    assert any("exhaustion overlap" in r.lower()
               for r in result.admissibility_reasons), (
        f"sanity: real-mode dispatch should reject on overlap; "
        f"reasons={result.admissibility_reasons}"
    )


# ---------------------------------------------------------------------------
# Acceptance test (e''): bench-mode dispatcher executes diverse cipher
# kinds end-to-end with total_tested > 0. The brief calls out
# Vigenere, Beaufort, columnar, Myszkowski, rail_fence, route, and
# quagmire as the kinds that must dispatch.
# ---------------------------------------------------------------------------

def _validated_spec(raw: dict[str, Any]) -> HypothesisSpec:
    parsed = validate_hypothesis_spec(raw)
    assert parsed.is_valid, parsed.errors
    return parsed.value


@pytest.mark.parametrize("name,raw_factory", [
    ("vigenere_cedar",      lambda: _vigenere_keyword_spec("bench-disp-vig-cedar", "CEDAR")),
    ("vigenere_lantern",    lambda: _vigenere_keyword_spec("bench-disp-vig-lantern", "LANTERN")),
    ("beaufort_cedar",      lambda: _beaufort_keyword_spec("bench-disp-beau-cedar", "CEDAR")),
    ("beaufort_lantern",    lambda: _beaufort_keyword_spec("bench-disp-beau-lantern", "LANTERN")),
    ("columnar_w7",         lambda: _columnar_dsl_spec("bench-disp-col-w7")),
    ("rail_fence_d3",       lambda: _rail_fence_dsl_spec("bench-disp-rf-d3")),
    ("myszkowski_cedar",    lambda: _myszkowski_dsl_spec("bench-disp-myz-cedar", "CEDAR")),
    ("route_serpentine",    lambda: _route_dsl_spec("bench-disp-route-serp")),
    ("quagmire_lantern",    lambda: _quagmire_dsl_spec("bench-disp-quag-lantern", "LANTERN")),
])
def test_bench_mode_dispatcher_runs_diverse_dsl_specs(
    name, raw_factory, tmp_path,
):
    """Acceptance test (e''): each of the cipher kinds called out by the
    K4Bench challenge-locality brief — Vigenere, Beaufort, columnar,
    Myszkowski, rail_fence, route, quagmire — dispatches end-to-end with
    total_tested > 0 in bench mode.

    The exhaustion-log fixture marks each kind as exhausted on real K4,
    so without the bench-mode admissibility bypass these would be
    rejected on overlap. With bench_mode=True they must execute.
    """
    spec = _validated_spec(raw_factory())
    exhaustion_log: dict[str, Any] = {
        "e_vigenere_x":      {"family": "vigenere",      "status": "exhausted"},
        "e_beaufort_x":      {"family": "beaufort",      "status": "exhausted"},
        "e_columnar_x":      {"family": "columnar",      "status": "exhausted"},
        "e_rail_fence_x":    {"family": "rail_fence",    "status": "exhausted"},
        "e_myszkowski_x":    {"family": "myszkowski",    "status": "exhausted"},
        "e_route_x":         {"family": "route",         "status": "exhausted"},
        "e_quagmire_x":      {"family": "quagmire",      "status": "exhausted"},
    }
    artifact_root = tmp_path / "bench_artifacts" / name
    result = execute(
        spec,
        artifact_root=artifact_root,
        parallel=False,
        exhaustion_log=exhaustion_log,
        bench_mode=True,
    )
    assert result.admissibility_verdict == "ok", (
        f"[{name}] bench dispatch rejected at admissibility despite "
        f"bench_mode=True; reasons={result.admissibility_reasons}"
    )
    assert result.total_tested > 0, (
        f"[{name}] bench-mode dispatch produced total_tested="
        f"{result.total_tested}; the synthetic spec did not actually "
        f"reach the kernel"
    )
