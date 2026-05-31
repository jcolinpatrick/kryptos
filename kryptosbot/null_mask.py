"""Null-mask-aware scoring scaffolding (Lever B2, safe increment).

A ``NullMask`` marks which of the 97 carved positions are NULLS (filler); the
"real message" is the remaining positions in order. This module is the
NON-DESTRUCTIVE foundation for null-mask-aware decryption:

  * it never mutates ``kryptos.kernel.constants`` and never rewrites Bean;
  * it re-derives the crib score from each (candidate, mask) pair via the
    kernel's free scorer (real-K4 cribs matched anywhere in the real message);
  * it pairs scoring with a REQUIRED matched-null gate, because "which
    positions are null" is a pile of free parameters that can fit cribs by
    chance — a raw crib hit under a mask is meaningless without it.

The specific null GENERATING model (fixed positions vs a residue/placement
rule vs key-tape null insertion), per-mask Bean re-derivation, and dispatch
wiring are deliberately LEFT OUT of this increment — they are the heavier,
gated steps that build on this foundation.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class NullMask:
    """A set of null (filler) positions over a length-``length`` text."""

    null_positions: frozenset[int]
    length: int = 97

    @property
    def n_nulls(self) -> int:
        return len(self.null_positions)

    @property
    def real_length(self) -> int:
        return self.length - self.n_nulls

    def validate(self) -> list[str]:
        errors: list[str] = []
        if self.length <= 0:
            errors.append(f"length must be positive; got {self.length}")
        for p in self.null_positions:
            if not isinstance(p, int) or p < 0 or p >= self.length:
                errors.append(f"null position {p!r} out of range [0, {self.length})")
        if self.n_nulls >= self.length:
            errors.append("mask marks every position null — no real message remains")
        return errors


def apply_null_mask(text: str, mask: NullMask) -> str:
    """Return the real message: ``text`` with null positions removed, in order."""
    nulls = mask.null_positions
    return "".join(c for i, c in enumerate(text) if i not in nulls)


def score_under_null_mask(candidate_pt: str, mask: NullMask) -> dict[str, Any]:
    """Score a candidate plaintext under a null mask.

    Removes the null positions, then scores the disclosed real-K4 cribs against
    the real message with the kernel's position-free scorer. Re-derives
    everything from the inputs — no global state, no Bean (Bean is N/A until
    per-mask re-derivation is built). The crib_score is meaningless on its own;
    gate it with ``matched_null_pvalue``.
    """
    from kryptos.kernel.scoring.aggregate import score_candidate_free

    real = apply_null_mask(candidate_pt, mask)
    fb = score_candidate_free(real)
    return {
        "crib_score": int(fb.crib_score),
        "real_message": real,
        "real_length": len(real),
        "n_nulls": mask.n_nulls,
        "scoring_mode": "null_mask_free",
        "ene_found": bool(getattr(fb, "ene_found", False)),
        "bc_found": bool(getattr(fb, "bc_found", False)),
    }


def matched_null_pvalue(
    candidate_pt: str,
    mask: NullMask,
    *,
    n_trials: int = 1000,
    seed: int = 0,
) -> dict[str, Any]:
    """REQUIRED gate: is ``mask`` special, or does any same-size mask do as well?

    Holds the candidate fixed and samples ``n_trials`` random masks of the SAME
    size, scoring each. ``p_value`` = fraction reaching >= the observed mask's
    crib_score. Low p => the mask carries real information; high p => the free
    parameters are fitting noise (the observed score is unremarkable for a mask
    of this size). A null-mask result must clear this gate to count.
    """
    observed = score_under_null_mask(candidate_pt, mask)["crib_score"]
    n = mask.n_nulls
    L = mask.length
    rng = random.Random(seed)
    ge = 0
    for _ in range(n_trials):
        rand = NullMask(frozenset(rng.sample(range(L), n)), length=L)
        if score_under_null_mask(candidate_pt, rand)["crib_score"] >= observed:
            ge += 1
    return {
        "observed_crib_score": observed,
        "n_trials": n_trials,
        "p_value": ge / n_trials if n_trials else 1.0,
        "matched_null": "random_same_size_mask",
        "n_nulls": n,
    }


_VARIANT_MAP: dict[str, Any] = {}  # lazily populated to avoid eager kernel import


def _resolve_variant(variant: Any) -> Any:
    """Map a variant string ('beaufort'/'vigenere'/'var_beaufort') to the kernel
    CipherVariant enum; pass an enum through unchanged."""
    from kryptos.kernel.transforms.vigenere import CipherVariant

    if not isinstance(variant, str):
        return variant
    table = {
        "vigenere": CipherVariant.VIGENERE,
        "beaufort": CipherVariant.BEAUFORT,
        "var_beaufort": CipherVariant.VAR_BEAUFORT,
    }
    try:
        return table[variant]
    except KeyError:
        raise ValueError(
            f"variant {variant!r} must be one of {sorted(table)} (the key_tape DSL set)"
        )


def _tape_index_map(
    null_positions: frozenset[int], null_rule: str, length: int = 97,
) -> dict[int, int]:
    """Map each non-null CT position to its key-tape index.

    SKIP    — nulls do NOT consume a key position; the tape advances only at
              non-null positions. tape_idx(i) = #non-null positions before i.
    CONSUME — nulls DO consume a key position; the tape advances everywhere.
              tape_idx(i) = i.

    Both reduce to the identity when there are no nulls — the property the
    regression anchor relies on.
    """
    nulls = frozenset(null_positions)
    if null_rule == "consume":
        return {i: i for i in range(length) if i not in nulls}
    if null_rule == "skip":
        mapping: dict[int, int] = {}
        t = 0
        for i in range(length):
            if i in nulls:
                continue
            mapping[i] = t
            t += 1
        return mapping
    raise ValueError(f"null_rule must be 'skip' or 'consume'; got {null_rule!r}")


def rederive_bean_under_null(
    ct: str,
    *,
    null_positions: frozenset[int],
    null_rule: str,
    crib_dict: dict[int, str],
    alphabet: Any = None,
):
    """Re-derive Bean constraints in null-shifted KEY-TAPE index space.

    Under the anchored key-tape null model, the Bean equality / inequality /
    linear sets are first re-derived from ``ct`` + ``crib_dict`` in CT-position
    space by the kernel (``derive_bean_constraints`` — never reads the frozen
    constants), then each referenced index is translated CT-position ->
    tape-index via the SKIP/CONSUME consumption rule. The returned sets index a
    finite key tape directly, so ``check_bean(tape, *sets)`` verifies the tape.

    With no nulls the index map is the identity, so this reproduces the kernel's
    canonical Bean exactly (eq=((27,65),), 242 ineq, 101 linear) — the
    regression anchor. A null that coincides with a crib position erases a known
    letter and is rejected. Bean is variant-independent, so no variant arg.
    """
    from kryptos.kernel.alphabet import AZ
    from kryptos.kernel.constraints.bean import derive_bean_constraints

    nulls = frozenset(null_positions)
    for p in crib_dict:
        if p in nulls:
            raise ValueError(
                f"null position {p} coincides with crib position {p} — a null "
                f"cannot erase a known crib letter"
            )
    alpha = alphabet if alphabet is not None else AZ
    eq, ineq, linear = derive_bean_constraints(ct, dict(crib_dict), alphabet=alpha)
    tmap = _tape_index_map(nulls, null_rule, length=len(ct))
    # SKIP/CONSUME index maps are monotone in CT position, so a<b => map[a]<map[b]
    # and the canonical (low, high) pair ordering is preserved without renorm.
    eq2 = tuple((tmap[a], tmap[b]) for a, b in eq)
    ineq2 = tuple((tmap[a], tmap[b]) for a, b in ineq)
    lin2 = tuple((tmap[a], tmap[b], tmap[c], tmap[d]) for a, b, c, d in linear)
    return eq2, ineq2, lin2


def bean_admissible_under_null(
    ct: str,
    tape: tuple[int, ...],
    *,
    null_positions: frozenset[int],
    null_rule: str,
    crib_dict: dict[int, str],
    alphabet: Any = None,
) -> bool:
    """Is ``tape`` Bean-admissible under this null placement + consumption rule?

    Re-derives the null-shifted Bean sets (tape-index space) and checks the tape
    against them via the kernel's length-agnostic ``check_bean``. The tape *is*
    the keystream in tape-index space: ``tape[t]`` is the key value at tape
    index ``t``. A finite tape too short to reach a referenced tape index is
    inadmissible (exhausted), returned as ``False`` rather than raising — the
    same convention the placement gate uses.
    """
    from kryptos.kernel.constraints.bean import check_bean

    eq, ineq, linear = rederive_bean_under_null(
        ct, null_positions=null_positions, null_rule=null_rule,
        crib_dict=crib_dict, alphabet=alphabet,
    )
    refs: set[int] = set()
    for a, b in eq:
        refs.add(a); refs.add(b)
    for a, b in ineq:
        refs.add(a); refs.add(b)
    for a, b, c, d in linear:
        refs.update((a, b, c, d))
    if refs and max(refs) >= len(tape):
        return False  # finite tape exhausted before a referenced index
    return check_bean(list(tape), eq, ineq, linear).passed


def tape_search(
    ct: str,
    candidates,
    *,
    crib_dict: dict[int, str],
    null_rule: str = "skip",
    alphabet: Any = None,
) -> dict[str, Any]:
    """Bean-prefiltered key-tape search.

    ``candidates`` is any iterable of ``(tape, null_positions, variant)`` tuples
    (the caller's generator / LLM-proposed family decides what tapes to try).
    Each candidate is first checked with the CHEAP, decrypt-free
    ``bean_admissible_under_null`` prefilter; only Bean-admissible candidates are
    then decrypted (``apply_key_tape``) and crib-scored. This is where per-mask
    Bean pays off: it collapses the candidate-tape universe before the expensive
    scoring step and shrinks the multiple-testing denominator to the Bean
    survivors — and because admissibility is computed from (ct, crib_dict)
    without looking at plaintext quality, it is a legitimate pre-registered
    filter (no peeking).

    Returns prune statistics plus survivors ranked by anchored ``crib_score``.
    NOTE: a survivor's ``crib_score`` is still only meaningful after a matched
    null (see ``matched_null_placement_pvalue``) — Bean admissibility is
    necessary, not sufficient. Bean prunes; it does not confer significance.
    """
    from kryptos.kernel.transforms.key_tape import apply_key_tape

    n_candidates = 0
    n_bean_admissible = 0
    survivors: list[dict[str, Any]] = []

    for cand in candidates:
        tape, nulls, variant = _as_tape_candidate(cand)
        n_candidates += 1
        try:
            ok = bean_admissible_under_null(
                ct, tuple(tape), null_positions=frozenset(nulls),
                null_rule=null_rule, crib_dict=crib_dict, alphabet=alphabet,
            )
        except Exception:
            ok = False
        if not ok:
            continue
        n_bean_admissible += 1
        cv = _resolve_variant(variant)
        try:
            pt = apply_key_tape(
                ct, tuple(tape), variant=cv, direction="decrypt",
                null_positions=frozenset(nulls), null_rule=null_rule,
            )
        except Exception:
            # Bean-admissible but the finite tape exhausts at a non-crib
            # position -> cannot produce a full plaintext; not a survivor.
            continue
        crib_score = sum(
            1 for pos, ch in crib_dict.items()
            if 0 <= pos < len(pt) and pt[pos] == ch
        )
        survivors.append({
            "tape": tuple(tape),
            "null_positions": frozenset(nulls),
            "variant": variant,
            "crib_score": crib_score,
            "plaintext": pt,
        })

    survivors.sort(key=lambda s: -s["crib_score"])
    return {
        "n_candidates": n_candidates,
        "n_bean_admissible": n_bean_admissible,
        "n_scored": len(survivors),
        "best": survivors[0] if survivors else None,
        "survivors": survivors,
    }


def _as_tape_candidate(cand) -> tuple[tuple[int, ...], frozenset[int], str]:
    """Normalize a candidate to (tape, null_positions, variant). Accepts a
    3-tuple or a mapping with those keys."""
    if isinstance(cand, dict):
        return (
            tuple(cand["tape"]),
            frozenset(cand.get("null_positions", ())),
            cand["variant"],
        )
    tape, nulls, variant = cand
    return tuple(tape), frozenset(nulls), variant


def matched_null_placement_pvalue(
    ct: str,
    *,
    tape: tuple[int, ...],
    variant: Any,
    null_rule: str,
    observed_null_positions: frozenset[int],
    crib_dict: dict[int, str],
    n_trials: int = 1000,
    seed: int = 0,
    forbidden_positions: frozenset[int] | None = None,
    bean_prune: bool = False,
) -> dict[str, Any]:
    """REQUIRED gate for null-bearing key_tape hypotheses (anchored model).

    Holds the cipher and finite tape fixed and randomizes the NULL POSITIONS
    (the free-parameter surface), decrypting via the kernel ``apply_key_tape``
    and scoring the disclosed cribs at their canonical positions. ``p_value`` =
    fraction of random same-size null placements whose anchored crib_score
    reaches the observed placement's. Low p => the placement carries real
    information; high p => the null positions are fitting noise. A null-tape
    crib hit must clear this gate to count as anything.

    ``forbidden_positions`` (e.g. the crib indices) are excluded from random
    placements when supplied.

    ``bean_prune`` computes a CONDITIONAL null over Bean-admissible placements
    only — the correct denominator if Bean is used as a cheap prefilter before
    scoring (it reports ``n_bean_admissible`` and ``observed_bean_admissible``).
    NOTE — it does NOT sharpen the raw crib-score gate: a placement that scores
    24/24 is ALWAYS Bean-admissible ({score 24} subset of {Bean-admissible},
    because a perfect crib match makes the implied keystream crib-consistent and
    Bean is derived from those same (ct, crib) pairs), so conditioning on Bean
    can only drop low scorers from the denominator and therefore RAISES p. The
    real leverage of per-mask Bean is tape-space pruning (collapsing the tape
    universe before scoring), not placement-gate sharpening. Crib positions are
    forbidden automatically under ``bean_prune`` (a null cannot sit on a crib).
    """
    from kryptos.kernel.transforms.key_tape import apply_key_tape

    cv = _resolve_variant(variant)
    n = len(observed_null_positions)
    L = len(ct)

    def _score(null_pos: frozenset[int]) -> int:
        try:
            pt = apply_key_tape(
                ct, tuple(tape), variant=cv, direction="decrypt",
                null_positions=frozenset(null_pos), null_rule=null_rule,
            )
        except Exception:
            # A placement that exhausts the finite tape (non-null count > tape
            # length) is an invalid configuration -> score 0.
            return 0
        return sum(
            1 for pos, ch in crib_dict.items()
            if 0 <= pos < len(pt) and pt[pos] == ch
        )

    def _bean_ok(null_pos: frozenset[int]) -> bool:
        try:
            return bean_admissible_under_null(
                ct, tuple(tape), null_positions=frozenset(null_pos),
                null_rule=null_rule, crib_dict=crib_dict,
            )
        except Exception:
            # null-on-crib or other invalid placement -> not admissible
            return False

    observed = _score(observed_null_positions)
    forbidden = set(forbidden_positions or ())
    if bean_prune:
        forbidden |= set(crib_dict.keys())
    pool = [p for p in range(L) if p not in forbidden]
    rng = random.Random(seed)

    if not bean_prune:
        ge = 0
        for _ in range(n_trials):
            rand = frozenset(rng.sample(pool, n)) if n <= len(pool) else frozenset(pool)
            if _score(rand) >= observed:
                ge += 1
        return {
            "observed_crib_score": observed,
            "n_trials": n_trials,
            "p_value": ge / n_trials if n_trials else 1.0,
            "matched_null": "random_null_placement",
            "n_nulls": n,
        }

    # bean_prune: conditional null over Bean-admissible placements only.
    ge = 0
    n_admissible = 0
    for _ in range(n_trials):
        rand = frozenset(rng.sample(pool, n)) if n <= len(pool) else frozenset(pool)
        if not _bean_ok(rand):
            continue
        n_admissible += 1
        if _score(rand) >= observed:
            ge += 1
    return {
        "observed_crib_score": observed,
        "observed_bean_admissible": _bean_ok(observed_null_positions),
        "n_trials": n_trials,
        "n_bean_admissible": n_admissible,
        "p_value": ge / n_admissible if n_admissible else 1.0,
        "matched_null": "random_null_placement_bean_pruned",
        "n_nulls": n,
    }
