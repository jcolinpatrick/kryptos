"""ProblemContext — single funnel for which problem the controller is solving.

Purpose
-------
KryptosBot can run against two problems:

  - **real K4** — the live Kryptos K4 cipher with its accumulated
    research history, anomaly registry, family registry, exhaustion
    log, and disclosed cribs.
  - **K4Bench** — a synthetic, K4-shaped calibration challenge from
    the K4Bench public-challenge suite.

Real-K4 state must NOT leak into a K4Bench run. Prior to ProblemContext
the controller threaded a ``bench_mode`` boolean through ~20 call
sites, with each site responsible for remembering to gate its own
registry / anomaly / exhaustion / family access. That pattern is
fragile — a single missed gate re-contaminates the bench run.

ProblemContext consolidates the gating into one object that every
real-K4 surface MUST read through. The accessors below are the ONLY
sanctioned way to reach the K4 registries / exhaustion log / anomaly
IDs / standing constraints from the controller, critic, dispatcher,
display, prompt builders, fallback, and synthesis paths.

Contract
--------
For ``mode == "real_k4"``:
  - All accessor methods return the live registry data.
  - ``bench_payload`` and ``bench_prompt_block`` are ``None``.

For ``mode == "k4bench"``:
  - All real-K4 accessor methods return empty containers
    (``[]`` / ``frozenset()`` / ``{}`` / ``""``).
  - ``bench_payload`` carries the canonical facts dict from
    ``K4BenchChallenge.canonical_facts()``.
  - ``bench_prompt_block`` carries the self-contained bench prompt
    block from ``K4BenchChallenge.prompt_block()``.
  - ``bench_context_dict()`` returns the structured bench context
    (bench_id, suite_id, title, ct_length, n_cribs, ledger pin) that
    the bench landscape and bench display consume.

Allow-list (the ONLY bench context that may surface in prompts /
display / synthesis):

  * bench_id, suite_id, title
  * challenge ciphertext (carried in bench_prompt_block)
  * crib positions and crib text (carried in bench_prompt_block)
  * clue_text, constraint summary (carried in bench_prompt_block)
  * synthetic_ledger_pin (mode marker on the bench ledger)
  * prior attempts for THIS bench_id (computed from the bench
    ledger by the caller — ProblemContext does not query ledgers)

Anything else from real-K4 (anomalies, families, exhaustion log
entries, retired claims, anchors, Oranchak corpora, serpentine
anchor) MUST go through a ProblemContext accessor, which returns
empty in bench mode.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Optional

# Sentinel mode strings. Kept as module constants so call sites can
# reference them without re-typing the literal (and so a typo at a
# call site fails type-checking instead of silently mis-comparing).
MODE_REAL_K4: str = "real_k4"
MODE_K4BENCH: str = "k4bench"
_VALID_MODES: frozenset[str] = frozenset({MODE_REAL_K4, MODE_K4BENCH})


@dataclass(frozen=True)
class ProblemContext:
    """The single source of truth for which problem we are solving.

    Frozen so a downstream consumer cannot mutate the mode mid-run.
    Construct via ``ProblemContext.real_k4()`` or
    ``ProblemContext.k4bench(payload, prompt_block)``; the raw
    constructor is reserved for tests that need explicit control.
    """

    mode: str
    bench_payload: Optional[Mapping[str, Any]] = None
    bench_prompt_block: Optional[str] = None

    def __post_init__(self) -> None:
        if self.mode not in _VALID_MODES:
            raise ValueError(
                f"ProblemContext.mode must be one of {_VALID_MODES}; "
                f"got {self.mode!r}"
            )
        if self.mode == MODE_REAL_K4:
            if self.bench_payload is not None or self.bench_prompt_block is not None:
                raise ValueError(
                    "ProblemContext(mode='real_k4') must not carry "
                    "bench_payload or bench_prompt_block; got "
                    f"bench_payload={'set' if self.bench_payload else 'None'}, "
                    f"bench_prompt_block={'set' if self.bench_prompt_block else 'None'}"
                )
        else:
            if self.bench_payload is None:
                raise ValueError(
                    "ProblemContext(mode='k4bench') requires bench_payload "
                    "(canonical facts dict from K4BenchChallenge)."
                )
            if self.bench_prompt_block is None:
                raise ValueError(
                    "ProblemContext(mode='k4bench') requires bench_prompt_block "
                    "(self-contained challenge prompt from K4BenchChallenge)."
                )

    # ------------------------------------------------------------------
    # Constructors
    # ------------------------------------------------------------------

    @classmethod
    def real_k4(cls) -> "ProblemContext":
        """Construct the real-K4 ProblemContext.

        The default mode for any controller launch without
        ``--bench-challenge``. All real-K4 registry/anomaly/exhaustion
        accessors return live data; bench accessors return None /
        empty.
        """
        return cls(mode=MODE_REAL_K4)

    @classmethod
    def k4bench(
        cls,
        payload: Mapping[str, Any],
        prompt_block: str,
    ) -> "ProblemContext":
        """Construct a K4Bench ProblemContext.

        ``payload`` is the canonical facts dict from
        ``K4BenchChallenge.canonical_facts()``. ``prompt_block`` is
        the self-contained challenge prompt from
        ``K4BenchChallenge.prompt_block()``. Both are required;
        passing either as None makes mode-detection ambiguous.
        """
        return cls(
            mode=MODE_K4BENCH,
            bench_payload=payload,
            bench_prompt_block=prompt_block,
        )

    # ------------------------------------------------------------------
    # Mode predicates
    # ------------------------------------------------------------------

    @property
    def is_real_k4(self) -> bool:
        """True iff this controller run targets the real Kryptos K4."""
        return self.mode == MODE_REAL_K4

    @property
    def is_bench(self) -> bool:
        """True iff this controller run targets a K4Bench challenge."""
        return self.mode == MODE_K4BENCH

    # ------------------------------------------------------------------
    # Real-K4 registry accessors. All return EMPTY in bench mode so
    # the caller does not need a separate ``if not is_bench:`` check.
    # ------------------------------------------------------------------

    def standing_constraints(self) -> list[dict[str, str]]:
        """Standing constraints (PUBLIC FACTs / DERIVED FACTs) for the
        landscape. Empty in bench mode."""
        if not self.is_real_k4:
            return []
        from kryptosbot.registries import STANDING_CONSTRAINTS
        return list(STANDING_CONSTRAINTS)

    def known_anomalies(self) -> list[dict[str, Any]]:
        """Live anomaly registry (KNOWN_ANOMALIES). Empty in bench
        mode — bench challenges have no anomaly registry."""
        if not self.is_real_k4:
            return []
        from kryptosbot.registries import KNOWN_ANOMALIES
        return list(KNOWN_ANOMALIES)

    def known_families(self) -> list[dict[str, Any]]:
        """Live cipher family registry (KNOWN_FAMILIES). Empty in
        bench mode."""
        if not self.is_real_k4:
            return []
        from kryptosbot.registries import KNOWN_FAMILIES
        return list(KNOWN_FAMILIES)

    def externally_evidenced_families(self) -> frozenset[str]:
        """Family IDs with external campaign / kernel-level evidence.
        Empty in bench mode."""
        if not self.is_real_k4:
            return frozenset()
        from kryptosbot.registries import EXTERNALLY_EVIDENCED_FAMILIES
        return EXTERNALLY_EVIDENCED_FAMILIES

    def admissible_prompt_anomaly_ids(self) -> frozenset[str]:
        """Anomaly IDs whose claims are admissible in the theorist
        prompt. Empty in bench mode."""
        if not self.is_real_k4:
            return frozenset()
        from kryptosbot.registries import ADMISSIBLE_PROMPT_ANOMALY_IDS
        return ADMISSIBLE_PROMPT_ANOMALY_IDS

    def known_anomaly_ids(self) -> set[str]:
        """Set of canonical anomaly IDs for theory-proposal validation.

        Used by ``contracts.parse_theories`` to reject theories whose
        ``anomalies_exploited`` field references a non-canonical id.
        Empty in bench mode — a bench challenge defines no anomaly
        ids, so any reference IS a contamination signal.
        """
        if not self.is_real_k4:
            return set()
        from kryptosbot.registries import KNOWN_ANOMALIES
        return {
            str(item.get("anomaly_id", "")).strip()
            for item in KNOWN_ANOMALIES
            if str(item.get("anomaly_id", "")).strip()
        }

    # ------------------------------------------------------------------
    # Exhaustion log accessor. Empty in bench mode — bench runs have
    # no real-K4 elimination history that applies to a synthetic
    # challenge.
    # ------------------------------------------------------------------

    def exhaustion_log(self) -> dict[str, dict[str, Any]]:
        """The repo-root ``exhaustion_log.json`` parsed as a dict.

        Empty in bench mode: real-K4 elimination history does not
        apply to a synthetic K4Bench challenge. The job dispatcher's
        admissibility-overlap check already short-circuits in bench
        mode; this accessor keeps the same invariant for any other
        consumer (DSL tools, theorist prompt enrichment).
        """
        if not self.is_real_k4:
            return {}
        from kryptosbot.job_dispatcher import _load_exhaustion_log
        return _load_exhaustion_log()

    # ------------------------------------------------------------------
    # Bench-only accessors
    # ------------------------------------------------------------------

    def bench_context_dict(self) -> dict[str, Any]:
        """Return the structured bench context for landscape /
        display / theorist prompt.

        Returns an empty dict in real-K4 mode. In bench mode returns:
          - bench_id
          - suite_id
          - title
          - ct_length
          - n_cribs
          - synthetic_ledger_pin (filled by the controller; this
            accessor leaves it None — the controller injects the
            pinned mode after constructing the dict, since the pin
            lives on the bench ledger and not on the challenge JSON)
        """
        if not self.is_bench:
            return {}
        payload = self.bench_payload or {}
        return {
            "bench_id": payload.get("bench_id"),
            "suite_id": payload.get("suite_id"),
            "title": payload.get("title"),
            "ct_length": payload.get("ct_length"),
            "n_cribs": payload.get("n_crib_chars"),
            "synthetic_ledger_pin": None,
        }

    def bench_prompt(self) -> str:
        """Return the self-contained bench challenge prompt block.

        Empty string in real-K4 mode. In bench mode returns the
        challenge prompt (CT, cribs, clue text, solver contract,
        procedural policy) generated by
        ``K4BenchChallenge.prompt_block()``.
        """
        if not self.is_bench:
            return ""
        return self.bench_prompt_block or ""

    @property
    def bench_id(self) -> Optional[str]:
        """Bench ID (None in real-K4 mode)."""
        if not self.is_bench:
            return None
        return (self.bench_payload or {}).get("bench_id")
