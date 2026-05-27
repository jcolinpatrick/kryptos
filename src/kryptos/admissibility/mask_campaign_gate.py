"""Known-answer gate for real-K4 mask search (admissibility layer).

Binds the canonical K1/K2/K3 readiness gate to the launch of a real-K4 mask
search.  The gate outcome is produced upstream by the canonical command
(``kryptosbot/self_test.py --panel all --mode dry-run --cycles 20000``) and
passed in here as a plain ReadinessFact, so the core ``kryptos`` package never
imports ``kryptosbot``.

Doctrine (see the ``known-answer-validation`` skill):
- Known-answer readiness is NECESSARY, not sufficient.  A GREEN gate proves the
  harness can rediscover three solved panels under the documented cap; it does
  NOT prove K4 is solvable.
- The guard reads only the boolean outcome, never the K1/K2/K3 panel contents.
  Panel keys / plaintexts / cribs must never flow into K4 search paths.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

from kryptos.admissibility.mask_hypothesis import (
    MaskHypothesis, validate_mask_hypothesis,
)
from kryptos.kernel.alphabet import AZ, Alphabet
from kryptos.kernel.masking.solve import MaskedCandidate, solve_periodic
from kryptos.kernel.transforms.vigenere import CipherVariant


class K4MaskSearchBlocked(RuntimeError):
    """Raised when a real-K4 mask search is launched without a GREEN gate."""


@dataclass(frozen=True)
class ReadinessFact:
    """The known-answer gate outcome, mirroring the skill's output contract."""

    readiness_gate: str          # "GREEN" | "RED"
    block_k4_campaign: bool
    doctor_passed: bool
    summary_line: str


def require_known_answer_ready(fact: ReadinessFact) -> None:
    """Raise K4MaskSearchBlocked unless the gate is GREEN, doctor passed, and
    the campaign is not flagged blocked."""
    reasons = []
    if fact.readiness_gate != "GREEN":
        reasons.append(f"readiness_gate={fact.readiness_gate!r} (need GREEN)")
    if fact.block_k4_campaign:
        reasons.append("block_k4_campaign=True")
    if not fact.doctor_passed:
        reasons.append("doctor pre-flight did not pass")
    if reasons:
        raise K4MaskSearchBlocked(
            "real-K4 mask search blocked by known-answer gate: "
            + "; ".join(reasons)
            + f" (summary: {fact.summary_line!r})"
        )


def run_guarded_mask_search(
    ct: str,
    hypothesis: MaskHypothesis,
    *,
    readiness: ReadinessFact,
    crib_dict: Mapping[int, str],
    periods: Iterable[int],
    variants: Iterable[CipherVariant] | None = None,
    alphabet: Alphabet = AZ,
    ngram_scorer=None,
    require_bean: bool = True,
    max_free_exhaustive: int = 4,
) -> list[MaskedCandidate]:
    """Launch a real-K4 mask search only behind the known-answer gate.

    Order is deliberate: the known-answer gate is checked FIRST (no search runs
    on a RED gate), then the mask hypothesis admissibility (bounded universe,
    alignment model, stop rule, provenance for primary tier), and only then the
    pure solver.
    """
    require_known_answer_ready(readiness)

    errors = validate_mask_hypothesis(hypothesis)
    if errors:
        raise ValueError("inadmissible mask hypothesis: " + "; ".join(errors))

    kwargs = {}
    if variants is not None:
        kwargs["variants"] = list(variants)
    return solve_periodic(
        ct,
        hypothesis.mask_universe.masks,
        periods=periods,
        crib_dict=crib_dict,
        alphabet=alphabet,
        ngram_scorer=ngram_scorer,
        require_bean=require_bean,
        max_free_exhaustive=max_free_exhaustive,
        **kwargs,
    )
