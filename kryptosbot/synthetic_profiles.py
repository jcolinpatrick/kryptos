"""Synthetic signal-profile registry for the controller.

PR 1 (2026-05-17) scope: a *structured* description of every synthetic
challenge the controller is expected to be able to recover. Each profile
declares (a) the cipher mechanism we want the controller to dispatch and
(b) the structural obligation that must be satisfied for the run to count
as "the mechanism was at least attempted, not just paraphrased into
something else."

The registry is a separate concept from K4Bench challenges. K4Bench
challenges supply a synthetic *ciphertext + sealed answer* and live in
``bench/k4bench/``. A SyntheticProfile supplies a *mechanism contract*:
the controller may dispatch any number of theories, but a profile passes
only if its mandatory obligations (e.g. "at least one dispatched spec
included a quagmire layer with variant=quagmire_iii and
period_keyword=SERPENTINE") are met.

The T1 postmortem
(`docs/maturation/round3/K4_SYNTHETIC_T1_POSTMORTEM_CHECKLIST.md`) is the
motivation: the theorist had the right hypothesis (Quagmire III with
SERPENTINE) in the proposal distribution, but every emitted spec routed
SERPENTINE through a different parameter axis (substitution_keyword on a
vigenere layer, columnar keyword, etc.) so the obligation "dispatch a
quagmire_iii period_keyword SERPENTINE spec" was never observed. The
synthetic profile registry is the structural pin for that obligation.

This module is intentionally a data-only registry. The coverage scheduler
(PR 2) is separate. PR 1 only makes coverage failure mechanically
observable — see ``coverage_audit.py``.

Posture notes (do not weaken):
- key_tape stays blocked for synthetic profiles. The kernel translator
  for key_tape exists (landed 2026-05-03), but the coverage scheduler
  for deterministic enumeration over (tape_seed, null_positions,
  null_rule, alphabet) does not. T1_TAPE_K3PT therefore declares status
  "blocked" with a blocked_reason that names the missing
  tape-consumption / null-insertion dispatcher search model directly,
  rather than laundering the profile into a vigenere fallback that
  would silently mask the gap.
- Profile IDs are stable: external runners and CI artifacts key off
  them. Renaming requires an explicit deprecation entry.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


# ─── Status sentinel ─────────────────────────────────────────────────────────

# A profile is either runnable now ("available") or explicitly blocked
# with a reason. We never silently omit a profile from the registry just
# because its mechanism is undispatchable; the blocked state must be
# representable so that --synthetic-profile <blocked_id> exits with a
# clear message rather than a silent fall-through.
ProfileStatus = str  # Literal["available", "blocked"] -- kept str so JSON round-trips trivially


_VALID_STATUSES: frozenset[str] = frozenset({"available", "blocked"})


# ─── Obligation clauses ──────────────────────────────────────────────────────


@dataclass(frozen=True)
class ParameterObligation:
    """One mandatory parameter requirement for a profile.

    A profile passes only if at least one *dispatched* HypothesisSpec
    contains a layer whose ``kind`` equals ``expected_layer_kind`` and
    whose parameter named ``expected_parameter_axis`` materializes to a
    value satisfying ``matches(value)``.

    The matcher is value-equality by default; subclasses may override.

    The expected_parameter_value is preserved on the dataclass so the
    coverage report can describe the obligation in a human-readable
    line such as
    ``"expected obligation not emitted: quagmire.period_keyword=SERPENTINE"``.
    """

    expected_family: str                # ledger-family the obligation lives under
    expected_layer_kind: str            # DSL CipherKind, e.g. "quagmire"
    expected_layer_variant: Optional[str] = None  # e.g. "quagmire_iii"; None == any
    expected_parameter_axis: str = ""   # e.g. "period_keyword"; "" == kind-only obligation
    # The value the obligation matches against. May be:
    #   - a scalar (str / int / bool): equality match
    #   - a list / tuple: membership match (any element equal)
    #   - a dict with a 'oneof' key (advanced future use)
    expected_parameter_value: Any = None
    minimum_expected_dispatch: int = 1  # how many distinct specs must satisfy

    def describe(self) -> str:
        """Human-readable summary, e.g.
        ``"quagmire.period_keyword=SERPENTINE (variant=quagmire_iii)"``.
        """
        lhs = self.expected_layer_kind
        if self.expected_layer_variant:
            lhs = f"{self.expected_layer_kind}[variant={self.expected_layer_variant}]"
        if not self.expected_parameter_axis:
            return f"{lhs}.<layer-only>"
        val = self._value_repr()
        return f"{lhs}.{self.expected_parameter_axis}={val}"

    def _value_repr(self) -> str:
        v = self.expected_parameter_value
        if isinstance(v, (list, tuple, set, frozenset)):
            return "{" + ",".join(str(x) for x in v) + "}"
        return str(v)

    def matches(self, *, layer_kind: str, layer_variant: Optional[str],
                params: dict[str, Any]) -> bool:
        """True iff this layer + params satisfies the obligation.

        ``params`` is a flat dict of parameter-name → resolved value (or
        list of enumerated values from a ParamRange — we check both
        membership and equality).
        """
        if layer_kind != self.expected_layer_kind:
            return False
        if self.expected_layer_variant is not None:
            if (layer_variant or "") != self.expected_layer_variant:
                return False
        if not self.expected_parameter_axis:
            return True  # layer-only obligation
        if self.expected_parameter_axis not in params:
            return False
        actual = params[self.expected_parameter_axis]
        return self._value_compare(actual, self.expected_parameter_value)

    @staticmethod
    def _value_compare(actual: Any, expected: Any) -> bool:
        """True iff `actual` satisfies `expected`.

        ``actual`` may be a scalar (resolved value) or a list/tuple
        (enumerated values from a ParamRange). ``expected`` may be a
        scalar (equality), a list/tuple (any-of membership), or any
        combination.
        """
        actual_iter: list[Any]
        if isinstance(actual, (list, tuple, set, frozenset)):
            actual_iter = list(actual)
        else:
            actual_iter = [actual]
        expected_iter: list[Any]
        if isinstance(expected, (list, tuple, set, frozenset)):
            expected_iter = list(expected)
        else:
            expected_iter = [expected]
        # Case-insensitive comparison for strings — DSL keywords are
        # canonicalized upper-case, but a defensive comparison is cheap.
        def _norm(x: Any) -> Any:
            if isinstance(x, str):
                return x.upper()
            return x
        norm_actual = {_norm(a) for a in actual_iter}
        norm_expected = {_norm(e) for e in expected_iter}
        return bool(norm_actual & norm_expected)


# ─── Profile dataclass ───────────────────────────────────────────────────────


@dataclass(frozen=True)
class SyntheticProfile:
    """A single registry entry.

    A profile is uniquely identified by ``profile_id``. The registry
    keeps profiles even when their mechanism cannot yet be dispatched —
    such profiles set ``status="blocked"`` and populate
    ``blocked_reason`` and ``required_kinds`` so the operator gets an
    explicit message rather than a "no such profile" 404.
    """

    profile_id: str
    description: str
    status: ProfileStatus               # "available" | "blocked"
    blocked_reason: str = ""            # required when status="blocked"
    required_kinds: tuple[str, ...] = ()  # DSL cipher kinds the profile needs supported
    obligations: tuple[ParameterObligation, ...] = ()
    # PR 2: explicit, auditable closing spec for the coverage scheduler.
    # A DSL HypothesisSpec in dict form (round-trips via
    # HypothesisSpec.from_dict). The obligation-relevant axis is pinned
    # to the required value so the scheduler can emit+admit a spec that
    # closes the obligation deterministically, independent of the LLM.
    # Required for "available" profiles; forbidden for "blocked".
    # NOTE: kept as a raw dict to preserve this module's data-only,
    # dependency-free posture. Structural consistency (the spec actually
    # satisfies the obligation) is verified by
    # coverage_scheduler.verify_profile_closing_spec, NOT here, to avoid
    # importing the DSL into the registry module.
    closing_spec: Optional[dict[str, Any]] = None
    # PR 3: when True, the coverage scheduler generates a synthetic CT from
    # this profile's mechanism, dispatches the closing_spec against it, and
    # requires real recovery (crib_score >= SIGNAL) — not just admissibility.
    # Fail-closed: a recovery target whose CT generation/dispatch fails is a
    # hard failure, never a silent downgrade to emitted_and_admissible.
    recovery_target: bool = False
    notes: str = ""

    def __post_init__(self) -> None:
        if self.status not in _VALID_STATUSES:
            raise ValueError(
                f"SyntheticProfile {self.profile_id!r}: status must be in "
                f"{sorted(_VALID_STATUSES)}, got {self.status!r}"
            )
        if self.status == "blocked" and not self.blocked_reason.strip():
            raise ValueError(
                f"SyntheticProfile {self.profile_id!r}: blocked status "
                f"requires a non-empty blocked_reason"
            )
        if self.status == "available" and not self.obligations:
            # Hard rule: an available profile with no obligations would
            # pass vacuously the moment any spec is dispatched. That
            # defeats the whole point of the registry.
            raise ValueError(
                f"SyntheticProfile {self.profile_id!r}: available status "
                f"requires at least one obligation"
            )
        if self.status == "available" and not self.closing_spec:
            raise ValueError(
                f"SyntheticProfile {self.profile_id!r}: available status "
                f"requires a closing_spec (PR 2 coverage scheduler)"
            )
        if self.status == "blocked" and self.closing_spec:
            raise ValueError(
                f"SyntheticProfile {self.profile_id!r}: blocked status "
                f"must NOT carry a closing_spec"
            )
        if self.recovery_target:
            if self.status != "available":
                raise ValueError(
                    f"SyntheticProfile {self.profile_id!r}: recovery_target "
                    f"requires status=='available'"
                )
            if not self.closing_spec:
                raise ValueError(
                    f"SyntheticProfile {self.profile_id!r}: recovery_target "
                    f"requires a closing_spec"
                )

    def pass_condition_summary(self) -> str:
        """One-line description of what must be observed to pass."""
        if not self.obligations:
            return f"(blocked: {self.blocked_reason})"
        parts = []
        for ob in self.obligations:
            n = ob.minimum_expected_dispatch
            parts.append(
                f"{ob.describe()} (>= {n} dispatch{'es' if n != 1 else ''})"
            )
        return " AND ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "description": self.description,
            "status": self.status,
            "blocked_reason": self.blocked_reason,
            "required_kinds": list(self.required_kinds),
            "closing_spec": self.closing_spec,
            "recovery_target": self.recovery_target,
            "notes": self.notes,
            "obligations": [
                {
                    "expected_family": ob.expected_family,
                    "expected_layer_kind": ob.expected_layer_kind,
                    "expected_layer_variant": ob.expected_layer_variant,
                    "expected_parameter_axis": ob.expected_parameter_axis,
                    "expected_parameter_value": ob.expected_parameter_value,
                    "minimum_expected_dispatch": ob.minimum_expected_dispatch,
                    "describe": ob.describe(),
                }
                for ob in self.obligations
            ],
            "pass_condition_summary": self.pass_condition_summary(),
        }


# ─── Helper: dispatcher-support discovery (deferred import) ──────────────────


class SyntheticProfileError(Exception):
    """Raised when a synthetic profile request is malformed or unsafe."""


def derive_synthetic_profile_ledger_path(
    profile_id: str,
    *,
    project_root: Any,        # Path; typed Any to keep this module dep-free
    requested: Optional[Any] = None,
) -> Any:
    """Return the resolved ledger path to use for a synthetic profile run.

    Safety contract (mirrors ``bench_loader.derive_synthetic_ledger_path``):

      - If ``requested`` is None, default to
        ``<project_root>/db/synthetic_profiles/<profile_id>.sqlite``.
      - If ``requested`` is provided, it MUST live under
        ``<project_root>/db/synthetic_profiles/`` OR contain a path
        segment indicating synthetic isolation (``synthetic``,
        ``k4bench``). Anything else (notably ``db/theory_ledger.sqlite``
        — the real-K4 default) is refused with SyntheticProfileError.

    The point is to make accidental contamination of the real-K4 ledger
    structurally impossible from the CLI surface.
    """
    from pathlib import Path
    root = Path(project_root).resolve()
    default_dir = root / "db" / "synthetic_profiles"
    if requested is None:
        return default_dir / f"{profile_id}.sqlite"
    req = Path(requested)
    if not req.is_absolute():
        req = (root / req).resolve()
    # Acceptable: any path component containing 'synthetic' or 'k4bench'
    # as a substring (case-insensitive). This deliberately accepts
    # 'synthetic_profiles/', 'synthetic/', 'db/synthetic_t1_smoke.sqlite'
    # (filename match), 'db/k4bench/'. Real-K4 default is
    # 'db/theory_ledger.sqlite' — no part contains the markers, so it
    # is structurally refused.
    parts_lower = [p.lower() for p in req.parts]
    safe_markers = ("synthetic", "k4bench")
    has_marker = any(
        any(marker in part for marker in safe_markers)
        for part in parts_lower
    )
    if not has_marker:
        raise SyntheticProfileError(
            f"refusing synthetic-profile run against ledger {req}: "
            f"path must live under db/synthetic_profiles/, db/k4bench/, "
            f"or contain a 'synthetic' / 'k4bench' substring in any "
            f"path component to avoid contaminating the real-K4 ledger. "
            f"Default for profile {profile_id!r} is "
            f"{default_dir / (profile_id + '.sqlite')}."
        )
    return req


def _dispatcher_supported_kinds() -> frozenset[str]:
    """Snapshot the dispatcher's currently-supported kinds.

    Deferred import so test environments that monkey-patch the
    dispatcher pick up the current snapshot. We do NOT cache the result
    at module-import time.
    """
    from kryptosbot.job_dispatcher import _SUPPORTED_KINDS
    return frozenset(_SUPPORTED_KINDS)


# ─── Registry definitions ────────────────────────────────────────────────────


# T1_SERPENTINE_QUAGMIRE
#
# The T1 postmortem profile (`docs/maturation/round3/
# K4_SYNTHETIC_T1_POSTMORTEM_CHECKLIST.md`). A Quagmire III synthetic
# with SERPENTINE as the period_keyword. The theorist had SERPENTINE in
# the proposal distribution under the AAA-archive serpentine-Vigenère
# anchor, but every emitted spec routed SERPENTINE through a different
# parameter (substitution_keyword on a vigenere layer, columnar keyword,
# etc.). Coverage failed silently because no single spec satisfied the
# specific "quagmire layer / variant=quagmire_iii / period_keyword
# contains SERPENTINE" structural pin.
#
# Variant naming: DSL canonical is "quagmire_iii" (lowercase + underscore).
# Roman-numeral "III" is normalized by ``repair_spec_shape`` but the
# obligation pins the canonical form so a downstream spec inspection
# (which sees the post-repair value) matches.
_T1_SERPENTINE_QUAGMIRE = SyntheticProfile(
    profile_id="T1_SERPENTINE_QUAGMIRE",
    description=(
        "T1 postmortem profile. Synthetic Quagmire III ciphertext keyed "
        "with SERPENTINE. Passes when at least one dispatched "
        "HypothesisSpec includes a quagmire layer (variant=quagmire_iii) "
        "whose period_keyword parameter materializes to SERPENTINE."
    ),
    status="available",
    blocked_reason="",
    required_kinds=("quagmire",),
    obligations=(
        ParameterObligation(
            expected_family="quagmire_iii",
            expected_layer_kind="quagmire",
            expected_layer_variant="quagmire_iii",
            expected_parameter_axis="period_keyword",
            expected_parameter_value="SERPENTINE",
            minimum_expected_dispatch=1,
        ),
    ),
    closing_spec={
        "hypothesis_id": "T1_SERPENTINE_QUAGMIRE__closing",
        "pipeline": [
            {
                "kind": "quagmire",
                "alphabet": "KA",
                "params": [
                    {"name": "variant", "values": ["quagmire_iii"]},
                    {"name": "period_keyword", "values": ["SERPENTINE"]},
                    {"name": "ct_alphabet_keyword", "values": ["KRYPTOS"]},
                    {"name": "pt_alphabet_keyword", "values": ["KRYPTOS"]},
                ],
            }
        ],
        "null_baseline": {"method": "random_text", "n_samples": 10000},
        "compute_budget_cpu_minutes": 30,
        "notes": "PR2 closing spec for T1_SERPENTINE_QUAGMIRE obligation.",
    },
    recovery_target=True,
    notes=(
        "Postmortem reference: SERPENTINE existed in the proposal "
        "distribution but never reached the dispatcher under the "
        "quagmire_iii / period_keyword axis. Coverage scheduler (PR 2) "
        "will close this by deterministic enumeration; PR 1 only "
        "*detects* the gap."
    ),
)


# T1_BERLINCLOCK_COLUMNAR
#
# Synthetic columnar transposition keyed with BERLINCLOCK (Berlin Clock
# anchor). Available because columnar is a supported dispatcher kind.
# Obligation is on the columnar layer with a keyword parameter
# materializing to BERLINCLOCK.
_T1_BERLINCLOCK_COLUMNAR = SyntheticProfile(
    profile_id="T1_BERLINCLOCK_COLUMNAR",
    description=(
        "Synthetic columnar transposition keyed with BERLINCLOCK. "
        "Passes when at least one dispatched HypothesisSpec includes a "
        "columnar layer whose keyword parameter materializes to "
        "BERLINCLOCK."
    ),
    status="available",
    blocked_reason="",
    required_kinds=("columnar",),
    obligations=(
        ParameterObligation(
            expected_family="transposition_columnar",
            expected_layer_kind="columnar",
            expected_layer_variant=None,
            expected_parameter_axis="keyword",
            expected_parameter_value="BERLINCLOCK",
            minimum_expected_dispatch=1,
        ),
    ),
    closing_spec={
        "hypothesis_id": "T1_BERLINCLOCK_COLUMNAR__closing",
        "pipeline": [
            {
                "kind": "columnar",
                "alphabet": "AZ",
                # Dual-purpose: `keyword` pins the obligation (the matcher
                # reads the keyword axis); `width`/`col_order` make the spec
                # executable for PR3 real-recovery dispatch (the dispatcher's
                # columnar translator reads width/col_order and ignores keyword).
                "params": [
                    {"name": "keyword", "values": ["BERLINCLOCK"]},
                    {"name": "width", "values": [11]},
                    # col_order == keyword_to_order("BERLINCLOCK", 11). Written
                    # as a literal because this module is intentionally
                    # dependency-free (no kernel import). If BERLINCLOCK or
                    # width changes, re-derive this permutation.
                    {"name": "col_order",
                     "values": [[0, 3, 10, 6, 4, 8, 1, 7, 9, 2, 5]]},
                ],
            }
        ],
        "null_baseline": {"method": "random_text", "n_samples": 10000},
        "compute_budget_cpu_minutes": 30,
        "notes": "PR2 closing spec for T1_BERLINCLOCK_COLUMNAR obligation.",
    },
    recovery_target=True,
    notes=(
        "Berlin Clock anchor exposure check. BERLINCLOCK is the canonical "
        "English crib token (see kryptosbot.constants CRIBS, positions "
        "63-73). The columnar keyword axis is the natural target; alternate "
        "spellings (e.g. the German WELTZEITUHR) would be separate profiles."
    ),
)


# T1_ABSCISSA_ROUTE
#
# Synthetic route transposition keyed by ABSCISSA. Available because
# `route` is a supported dispatcher kind. Obligation pins the route layer
# with a keyword (or, equivalently, the ``variant`` axis if route uses
# variant strings). We use ``keyword`` as the canonical axis name to
# match the existing K4Bench/HCC seed conventions.
_T1_ABSCISSA_ROUTE = SyntheticProfile(
    profile_id="T1_ABSCISSA_ROUTE",
    description=(
        "Synthetic route transposition keyed with ABSCISSA. Passes "
        "when at least one dispatched HypothesisSpec includes a route "
        "layer whose keyword parameter materializes to ABSCISSA."
    ),
    status="available",
    blocked_reason="",
    required_kinds=("route",),
    obligations=(
        ParameterObligation(
            expected_family="transposition_route",
            expected_layer_kind="route",
            expected_layer_variant=None,
            expected_parameter_axis="keyword",
            expected_parameter_value="ABSCISSA",
            minimum_expected_dispatch=1,
        ),
    ),
    closing_spec={
        "hypothesis_id": "T1_ABSCISSA_ROUTE__closing",
        "pipeline": [
            {
                "kind": "route",
                "alphabet": "AZ",
                "params": [
                    {"name": "keyword", "values": ["ABSCISSA"]},
                ],
            }
        ],
        "null_baseline": {"method": "random_text", "n_samples": 10000},
        "compute_budget_cpu_minutes": 30,
        "notes": "PR2 closing spec for T1_ABSCISSA_ROUTE obligation.",
    },
    notes=(
        "ABSCISSA is one of the AAA-archive procedural terms. The "
        "obligation pins it on the route layer; vigenere-keyword "
        "ABSCISSA on a substitution layer would NOT satisfy this "
        "profile (that conflation is exactly the T1 postmortem failure "
        "mode and the registry deliberately refuses to launder it)."
    ),
)


# T1_TAPE_K3PT
#
# Synthetic finite-tape additive cipher with the K3 plaintext prefix as
# the tape, exercised under the M4 SKIP null-rule (M1-M5 keystream-
# forensics class). Blocked because PR 1 has no synthetic profile
# scheduler for the (tape_seed × null_positions × null_rule × alphabet)
# search universe, even though the kernel translator (apply_key_tape)
# itself is supported.
#
# blocked_reason MUST mention the missing tape-consumption / null-
# insertion *search* model explicitly, NOT launder the profile through
# a vigenere fallback. The honesty discipline here is documented in
# CLAUDE.md and feedback_pt_length_open_question.md.
_T1_TAPE_K3PT = SyntheticProfile(
    profile_id="T1_TAPE_K3PT",
    description=(
        "Synthetic finite-tape additive cipher with the K3 plaintext "
        "prefix as the tape, exercised under the M4 SKIP null-rule. "
        "Pass condition would require at least one dispatched "
        "HypothesisSpec to include a key_tape layer with tape derived "
        "from the K3 prefix, null_rule='skip', and a non-empty "
        "null_positions tuple."
    ),
    status="blocked",
    blocked_reason=(
        "Synthetic profile requires a deterministic tape-consumption "
        "and null-insertion search scheduler over the "
        "(tape_seed, null_positions, null_rule, alphabet) universe. "
        "The kernel translator for the key_tape DSL kind exists "
        "(apply_key_tape, landed 2026-05-03), but PR 1 does NOT supply "
        "the coverage scheduler that enumerates these axes "
        "deterministically. PR 2 scope. This profile is intentionally "
        "kept in the registry as 'blocked' rather than silently "
        "rerouted through a vigenere fallback — that conflation would "
        "launder away the M1-M5 keystream-forensics class entirely."
    ),
    required_kinds=("key_tape",),
    obligations=(),
    notes=(
        "Honesty discipline: do NOT downgrade this profile to a "
        "vigenere obligation just to make the registry 'work'. The "
        "registry is structured precisely so PR 2 can plug in the "
        "missing scheduler without rewriting the obligation surface."
    ),
)


# ─── Public registry surface ─────────────────────────────────────────────────


_REGISTRY: dict[str, SyntheticProfile] = {
    _T1_SERPENTINE_QUAGMIRE.profile_id: _T1_SERPENTINE_QUAGMIRE,
    _T1_BERLINCLOCK_COLUMNAR.profile_id: _T1_BERLINCLOCK_COLUMNAR,
    _T1_ABSCISSA_ROUTE.profile_id: _T1_ABSCISSA_ROUTE,
    _T1_TAPE_K3PT.profile_id: _T1_TAPE_K3PT,
}


def list_profile_ids() -> list[str]:
    """Return all registered profile IDs in stable sort order."""
    return sorted(_REGISTRY.keys())


def get_profile(profile_id: str) -> SyntheticProfile:
    """Look up a profile by ID.

    Raises KeyError with a helpful message listing the valid IDs.
    """
    if profile_id not in _REGISTRY:
        raise KeyError(
            f"Unknown synthetic profile {profile_id!r}; "
            f"valid: {list_profile_ids()}"
        )
    return _REGISTRY[profile_id]


def is_profile_runnable(profile_id: str) -> tuple[bool, str]:
    """Return (runnable, reason) for a profile.

    A profile is runnable iff:
      - it exists in the registry
      - its status is "available"
      - every kind in required_kinds is currently in the dispatcher's
        _SUPPORTED_KINDS

    The dispatcher-support check is dynamic (it imports the live
    _SUPPORTED_KINDS) so a profile that depends on a kind which lands in
    a later PR becomes runnable without a registry change.
    """
    try:
        profile = get_profile(profile_id)
    except KeyError as exc:
        return (False, str(exc))
    if profile.status == "blocked":
        return (False, f"profile {profile_id!r} is blocked: {profile.blocked_reason}")
    supported = _dispatcher_supported_kinds()
    missing = [k for k in profile.required_kinds if k not in supported]
    if missing:
        return (
            False,
            f"profile {profile_id!r} requires unsupported dispatcher "
            f"kinds: {missing}",
        )
    return (True, "")


def all_profiles() -> list[SyntheticProfile]:
    """Return every registered profile in sorted order."""
    return [_REGISTRY[pid] for pid in list_profile_ids()]


__all__ = [
    "ParameterObligation",
    "SyntheticProfile",
    "SyntheticProfileError",
    "all_profiles",
    "derive_synthetic_profile_ledger_path",
    "get_profile",
    "is_profile_runnable",
    "list_profile_ids",
]
