"""Tests for kryptosbot.synthetic_profiles.

PR 1 (2026-05-17) test surface for the synthetic profile registry. The
tests pin three invariants:

1. The registry exposes the four PR-1 profile IDs explicitly and
   stably.
2. Blocked profiles (T1_TAPE_K3PT in PR 1) are *represented*, not
   silently omitted, and the blocked_reason names the missing dispatcher
   surface so PR 2 can plug it in without confusion.
3. The T1_SERPENTINE_QUAGMIRE profile exposes the structural obligation
   the T1 postmortem identified as unobservable in the prior pipeline:
   a quagmire layer with variant=quagmire_iii AND a period_keyword
   parameter that materializes to SERPENTINE.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from kryptosbot.synthetic_profiles import (
    ParameterObligation,
    SyntheticProfile,
    SyntheticProfileError,
    all_profiles,
    derive_synthetic_profile_ledger_path,
    get_profile,
    is_profile_runnable,
    list_profile_ids,
)


def test_registry_exposes_pr1_profile_ids() -> None:
    """All four PR-1 profile IDs must be registered, in sorted order."""
    ids = list_profile_ids()
    assert ids == [
        "T1_ABSCISSA_ROUTE",
        "T1_BERLINCLOCK_COLUMNAR",
        "T1_SERPENTINE_QUAGMIRE",
        "T1_TAPE_K3PT",
    ]


def test_get_profile_unknown_raises_with_help() -> None:
    with pytest.raises(KeyError) as exc_info:
        get_profile("DEFINITELY_NOT_A_PROFILE")
    msg = str(exc_info.value)
    # Error message must list the valid IDs so a typo is recoverable.
    assert "T1_SERPENTINE_QUAGMIRE" in msg


def test_serpentine_quagmire_obligation_shape() -> None:
    """T1_SERPENTINE_QUAGMIRE pins the postmortem-identified obligation.

    The obligation requires:
      - layer kind == "quagmire"
      - layer variant == "quagmire_iii" (canonical lowercase form)
      - parameter axis == "period_keyword"
      - parameter value == "SERPENTINE"

    Any spec lacking ANY of these does NOT satisfy the obligation. This
    is the structural shape the prior pipeline failed to pin.
    """
    profile = get_profile("T1_SERPENTINE_QUAGMIRE")
    assert profile.status == "available"
    assert len(profile.obligations) == 1
    ob = profile.obligations[0]
    assert ob.expected_layer_kind == "quagmire"
    assert ob.expected_layer_variant == "quagmire_iii"
    assert ob.expected_parameter_axis == "period_keyword"
    assert ob.expected_parameter_value == "SERPENTINE"
    assert ob.minimum_expected_dispatch >= 1


def test_serpentine_quagmire_uses_canonical_variant_not_roman() -> None:
    """Variant string is "quagmire_iii", NOT "III".

    The DSL canonical form is snake_case lowercase. ``repair_spec_shape``
    normalizes "III" to "quagmire_iii" at dispatcher entry, but the
    obligation matcher inspects the post-repair layer surface. Pinning
    the canonical form here prevents a future regression from masking
    the postmortem failure mode by accepting only the un-repaired
    Roman-numeral string.
    """
    profile = get_profile("T1_SERPENTINE_QUAGMIRE")
    ob = profile.obligations[0]
    assert ob.expected_layer_variant == "quagmire_iii"
    assert ob.expected_layer_variant != "III"
    assert ob.expected_layer_variant != "iii"


def test_blocked_profile_is_represented_not_omitted() -> None:
    """T1_TAPE_K3PT MUST be in the registry as 'blocked', not omitted.

    Silently omitting it would degrade the registry to "profiles we
    happen to support today", which is exactly the failure mode the
    PR-1 brief is built to prevent.
    """
    profile = get_profile("T1_TAPE_K3PT")
    assert profile.status == "blocked"
    assert profile.blocked_reason.strip()


def test_tape_profile_blocked_reason_names_missing_dispatcher_model() -> None:
    """The blocked_reason MUST name the tape-consumption/null-insertion
    dispatcher search model rather than launder through vigenere.

    From the user brief: "if key_tape profile is blocked, blocked_reason
    mentions the missing tape-consumption/null-insertion dispatcher
    model rather than laundering it through vigenere."
    """
    profile = get_profile("T1_TAPE_K3PT")
    reason = profile.blocked_reason.lower()
    # Must reference both the tape-consumption AND the null-insertion
    # concepts so PR 2's coverage scheduler knows exactly what it must
    # implement.
    assert "tape" in reason and ("consumption" in reason or "consum" in reason)
    assert "null" in reason and ("insertion" in reason or "insert" in reason)
    # Must NOT silently downgrade to vigenere.
    assert "vigenere" not in reason or "rather than" in reason or "instead" in reason or "launder" in reason


def test_runnable_status_blocked_profile() -> None:
    """is_profile_runnable returns (False, reason) for a blocked profile."""
    runnable, reason = is_profile_runnable("T1_TAPE_K3PT")
    assert runnable is False
    # The reason must include the profile_id so the operator can
    # identify which profile was rejected.
    assert "T1_TAPE_K3PT" in reason


def test_runnable_status_available_profile() -> None:
    """T1_SERPENTINE_QUAGMIRE is runnable iff dispatcher supports quagmire."""
    runnable, reason = is_profile_runnable("T1_SERPENTINE_QUAGMIRE")
    # Today the dispatcher supports quagmire — confirmed via grep at
    # PR-1 author time. If a later refactor removes quagmire support,
    # this test fires loudly.
    assert runnable is True, f"unexpected refusal: {reason}"


def test_available_profile_must_have_obligations() -> None:
    """Constructor: an available profile without obligations is invalid.

    Vacuous pass-by-default would defeat the purpose of the registry.
    """
    with pytest.raises(ValueError):
        SyntheticProfile(
            profile_id="X_EMPTY",
            description="bogus",
            status="available",
            obligations=(),
        )


def test_blocked_profile_must_have_reason() -> None:
    """Constructor: a blocked profile requires a non-empty blocked_reason."""
    with pytest.raises(ValueError):
        SyntheticProfile(
            profile_id="X_BAD_BLOCK",
            description="bogus",
            status="blocked",
            blocked_reason="   ",
            obligations=(),
        )


def test_obligation_matcher_membership_match() -> None:
    """ParameterObligation.matches handles list-valued params.

    A ParamRange enumerated as ``values=['SERPENTINE','LIGHT']``
    materializes into the layer record as ``params['period_keyword'] =
    ['SERPENTINE', 'LIGHT']``. The matcher MUST recognize this as
    satisfying the obligation expected_parameter_value='SERPENTINE'
    (membership), not require literal equality.
    """
    ob = ParameterObligation(
        expected_family="quagmire_iii",
        expected_layer_kind="quagmire",
        expected_layer_variant="quagmire_iii",
        expected_parameter_axis="period_keyword",
        expected_parameter_value="SERPENTINE",
    )
    # List-of-enumerated-values form
    assert ob.matches(
        layer_kind="quagmire",
        layer_variant="quagmire_iii",
        params={"period_keyword": ["SERPENTINE", "LIGHT"]},
    )
    # Scalar form
    assert ob.matches(
        layer_kind="quagmire",
        layer_variant="quagmire_iii",
        params={"period_keyword": "SERPENTINE"},
    )
    # Wrong variant
    assert not ob.matches(
        layer_kind="quagmire",
        layer_variant="quagmire_iv",
        params={"period_keyword": "SERPENTINE"},
    )
    # Wrong axis
    assert not ob.matches(
        layer_kind="quagmire",
        layer_variant="quagmire_iii",
        params={"substitution_keyword": "SERPENTINE"},
    )
    # Wrong kind
    assert not ob.matches(
        layer_kind="vigenere",
        layer_variant=None,
        params={"period_keyword": "SERPENTINE"},
    )


def test_ledger_path_default_isolates_under_synthetic_profiles_dir(tmp_path: Path) -> None:
    """Default path for a profile lives under db/synthetic_profiles/."""
    path = derive_synthetic_profile_ledger_path(
        "T1_SERPENTINE_QUAGMIRE", project_root=tmp_path,
    )
    assert path.name == "T1_SERPENTINE_QUAGMIRE.sqlite"
    assert "synthetic_profiles" in path.parts


def test_ledger_path_refuses_real_k4_default(tmp_path: Path) -> None:
    """Refusing the real-K4 default ledger is structural, not advisory."""
    # The real-K4 default lives at db/theory_ledger.sqlite — explicitly
    # outside any synthetic isolation directory.
    requested = tmp_path / "db" / "theory_ledger.sqlite"
    with pytest.raises(SyntheticProfileError):
        derive_synthetic_profile_ledger_path(
            "T1_SERPENTINE_QUAGMIRE",
            project_root=tmp_path,
            requested=requested,
        )


def test_ledger_path_accepts_synthetic_segment(tmp_path: Path) -> None:
    """A path with a 'synthetic' segment is accepted."""
    requested = tmp_path / "db" / "synthetic" / "custom.sqlite"
    path = derive_synthetic_profile_ledger_path(
        "T1_SERPENTINE_QUAGMIRE",
        project_root=tmp_path,
        requested=requested,
    )
    assert path == requested.resolve()


def test_ledger_path_accepts_synthetic_substring_in_filename(tmp_path: Path) -> None:
    """A filename like ``synthetic_t1_smoke.sqlite`` is accepted.

    The user's smoke command uses ``db/synthetic_t1_smoke.sqlite`` —
    "synthetic" appears in the filename, not as a directory segment.
    Must be accepted because the safety markers are substring matches
    on path components (not equality matches).
    """
    requested = tmp_path / "db" / "synthetic_t1_smoke.sqlite"
    path = derive_synthetic_profile_ledger_path(
        "T1_SERPENTINE_QUAGMIRE",
        project_root=tmp_path,
        requested=requested,
    )
    assert path == requested.resolve()


def test_ledger_path_accepts_k4bench_segment(tmp_path: Path) -> None:
    """db/k4bench/ is considered safe (a different synthetic surface)."""
    requested = tmp_path / "db" / "k4bench" / "smoke.sqlite"
    path = derive_synthetic_profile_ledger_path(
        "T1_SERPENTINE_QUAGMIRE",
        project_root=tmp_path,
        requested=requested,
    )
    assert path == requested.resolve()


def test_all_profiles_returns_in_stable_order() -> None:
    """all_profiles() returns SyntheticProfile objects in sorted-id order."""
    profiles = all_profiles()
    assert [p.profile_id for p in profiles] == list_profile_ids()
    assert all(isinstance(p, SyntheticProfile) for p in profiles)


def test_available_profiles_carry_closing_spec() -> None:
    from kryptosbot.synthetic_profiles import all_profiles
    for p in all_profiles():
        if p.status == "available":
            assert p.closing_spec, (
                f"available profile {p.profile_id} must carry a closing_spec"
            )
            assert isinstance(p.closing_spec, dict)
            assert p.closing_spec.get("pipeline"), (
                f"{p.profile_id} closing_spec needs a non-empty pipeline"
            )


def test_blocked_profile_has_no_closing_spec() -> None:
    from kryptosbot.synthetic_profiles import get_profile
    p = get_profile("T1_TAPE_K3PT")
    assert p.status == "blocked"
    assert not p.closing_spec


def test_available_without_closing_spec_raises() -> None:
    from kryptosbot.synthetic_profiles import (
        SyntheticProfile, ParameterObligation,
    )
    import pytest
    with pytest.raises(ValueError):
        SyntheticProfile(
            profile_id="X", description="d", status="available",
            obligations=(ParameterObligation(
                expected_family="f", expected_layer_kind="columnar",
                expected_parameter_axis="keyword",
                expected_parameter_value="K",
            ),),
            closing_spec=None,
        )


def test_recovery_targets_are_quagmire_and_columnar() -> None:
    from kryptosbot.synthetic_profiles import all_profiles
    targets = {p.profile_id for p in all_profiles() if p.recovery_target}
    assert targets == {"T1_SERPENTINE_QUAGMIRE", "T1_BERLINCLOCK_COLUMNAR"}


def test_recovery_target_implies_available_with_closing_spec() -> None:
    from kryptosbot.synthetic_profiles import all_profiles
    for p in all_profiles():
        if p.recovery_target:
            assert p.status == "available"
            assert p.closing_spec


def test_blocked_profile_cannot_be_recovery_target() -> None:
    from kryptosbot.synthetic_profiles import SyntheticProfile
    import pytest
    with pytest.raises(ValueError):
        SyntheticProfile(
            profile_id="X", description="d", status="blocked",
            blocked_reason="r", recovery_target=True,
        )


def test_columnar_closing_spec_carries_executable_params() -> None:
    from kryptosbot.synthetic_profiles import get_profile
    p = get_profile("T1_BERLINCLOCK_COLUMNAR")
    layer = p.closing_spec["pipeline"][0]
    names = {pr["name"]: pr for pr in layer["params"]}
    assert names["keyword"]["values"] == ["BERLINCLOCK"]
    assert names["width"]["values"] == [11]
    assert names["col_order"]["values"] == [[0, 3, 10, 6, 4, 8, 1, 7, 9, 2, 5]]


def test_profile_to_dict_round_trips_serializable() -> None:
    """SyntheticProfile.to_dict() must produce a JSON-serializable shape.

    Coverage reports embed the profile description, so a non-trivial
    nested obligation must serialize cleanly.
    """
    import json
    profile = get_profile("T1_SERPENTINE_QUAGMIRE")
    payload = profile.to_dict()
    # Round-trip through JSON to confirm no surprise objects.
    parsed = json.loads(json.dumps(payload))
    assert parsed["profile_id"] == "T1_SERPENTINE_QUAGMIRE"
    # Obligation describe() captured for human readability.
    assert any(
        "SERPENTINE" in ob["describe"] for ob in parsed["obligations"]
    )
