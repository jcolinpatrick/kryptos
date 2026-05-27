"""Joint mask x mechanism solver (periodic-substitution family, first cut).

solve_periodic enumerates a bounded mask universe x {variant, period} and uses
the cribs as hard constraints to FORCE key residues rather than enumerate keys:
crib positions project onto residue classes mod p, a class with conflicting
forced values prunes the (mask, variant, period) instantly, and a fully-forced
key is verified against the per-mask Bean sets.  Free-residue (n-gram-driven)
search is deferred to a later cycle; this cut emits only fully-forced keys.

Scope: mask + periodic substitution under the extract-then-decrypt-in-place
model, where the post-extraction CT' is a direct-positional additive layer and
per-mask Bean re-derivation is legitimate.  Transposition-bearing and
non-direct-alignment mechanisms are out of scope (separate spec).
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass
from statistics import NormalDist
from typing import Iterable, Mapping, Optional, Sequence

from kryptos.kernel.alphabet import AZ, Alphabet
from kryptos.kernel.constants import MOD
from kryptos.kernel.constraints.bean import check_bean, derive_bean_constraints
from kryptos.kernel.masking.mask import (
    NullMask, extract_ct, remap_crib_dict, validate_mask,
)
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, KEY_RECOVERY, decrypt_text,
)

_DEFAULT_VARIANTS = (
    CipherVariant.VIGENERE,
    CipherVariant.BEAUFORT,
    CipherVariant.VAR_BEAUFORT,
)


@dataclass(frozen=True)
class MaskedCandidate:
    mask: NullMask
    variant: CipherVariant
    period: int
    key: tuple[int, ...]
    plaintext: str
    crib_score: int
    bean_passed: bool
    ngram_score: Optional[float]


def calibrated_ngram_floor(
    mask_universe_size: int,
    *,
    null_mean: float,
    null_std: float,
    alpha: float = 0.01,
    candidates_per_mask: int = 1,
) -> float:
    """Mask-universe-aware n-gram floor under a Gaussian per-candidate null.

    Controls family-wise error at ``alpha`` over N = mask_universe_size *
    candidates_per_mask candidates via the max-of-N order statistic: each
    candidate's admissible tail probability is p_N = 1 - (1 - alpha)**(1/N),
    which shrinks as N grows, so the per-candidate floor RISES with N.  This is
    the multiplicity penalty: a larger (less constrained) mask universe demands
    a higher language bar, so breadth cannot be laundered into significance.

    The floor is one-sided (upper tail): the returned value is the null-score
    quantile at survival probability p_N.  The caller supplies the null
    (mean, std); a real campaign estimates it from coincidental decryptions
    under the same mask universe, not from the candidate set being judged.
    """
    n = max(1, int(mask_universe_size) * int(candidates_per_mask))
    p_tail = 1.0 - (1.0 - alpha) ** (1.0 / n)
    return NormalDist(null_mean, null_std).inv_cdf(1.0 - p_tail)


def select_solves(
    candidates: Sequence[MaskedCandidate],
    *,
    ngram_floor: float,
) -> list[MaskedCandidate]:
    """Apply the solve gate: Bean PASS and n-gram quality at or above a floor.

    In the masked + crib-forcing regime Bean is auto-satisfied for any
    crib-forced key (the constraints are derived from the same cribs), so the
    n-gram floor is the operative discriminator.  The floor itself must come
    from a mask-universe-aware null calibration, not from the candidate set;
    this function only applies a supplied floor.
    """
    return [
        c
        for c in candidates
        if c.bean_passed
        and c.ngram_score is not None
        and c.ngram_score >= ngram_floor
    ]


def solve_periodic(
    ct: str,
    mask_universe: Sequence[NullMask],
    *,
    periods: Iterable[int],
    crib_dict: Mapping[int, str],
    variants: Iterable[CipherVariant] = _DEFAULT_VARIANTS,
    alphabet: Alphabet = AZ,
    ngram_scorer=None,
    require_bean: bool = True,
    max_free_exhaustive: int = 4,
) -> list[MaskedCandidate]:
    """Recover (mask, variant, period, key) candidates.

    Cribs FORCE the key residues they cover.  Residue classes with no crib are
    FREE; when an n-gram scorer is supplied they are searched exhaustively (up
    to ``max_free_exhaustive`` free residues) and the highest-scoring fill is
    emitted.  Larger free spaces are skipped here (SA/local search deferred).

    Args:
        ct: carved (full-length) ciphertext.
        mask_universe: bounded sequence of NullMasks to test.
        periods: candidate key periods.
        crib_dict: cribs in CARVED coordinates.
        variants: additive variants to try.
        alphabet: index alphabet (AZ identity by default).
        ngram_scorer: language scorer; required to resolve FREE residues.
        require_bean: drop candidates that fail the per-mask Bean check.
        max_free_exhaustive: max free residues to brute-force (26**k fills).

    Returns:
        List of MaskedCandidate, one per crib-consistent (and Bean-passing, if
        required) (mask, variant, period): the forced key when fully covered,
        else the n-gram-best free-residue fill.
    """
    idx = alphabet.index_table
    crib_positions = frozenset(crib_dict)
    period_list = [p for p in periods if p > 0]
    variant_list = list(variants)

    out: list[MaskedCandidate] = []
    for mask in mask_universe:
        validate_mask(mask, len(ct), crib_positions=crib_positions)
        ct_prime = extract_ct(ct, mask)
        cribs = remap_crib_dict(crib_dict, mask)
        eq, ineq, linear = derive_bean_constraints(ct_prime, cribs, alphabet)
        ct_idx = [idx[ord(ch) - 65] for ch in ct_prime]

        for variant in variant_list:
            recover = KEY_RECOVERY[variant]
            for p in period_list:
                forced: dict[int, int] = {}
                feasible = True
                for pos, letter in cribs.items():
                    r = pos % p
                    kval = recover(ct_idx[pos], idx[ord(letter) - 65])
                    if forced.get(r, kval) != kval:
                        feasible = False
                        break
                    forced[r] = kval
                if not feasible:
                    continue
                free = [r for r in range(p) if r not in forced]

                if not free:
                    key = tuple(forced[r] for r in range(p))
                elif ngram_scorer is None:
                    # Free residues cannot be disambiguated without a scorer.
                    continue
                elif len(free) > max_free_exhaustive:
                    # Larger free spaces need SA/local search (deferred).
                    continue
                else:
                    best_key = None
                    best_score = None
                    for combo in itertools.product(range(MOD), repeat=len(free)):
                        trial = dict(forced)
                        for r, v in zip(free, combo):
                            trial[r] = v
                        cand_key = tuple(trial[r] for r in range(p))
                        cand_pt = decrypt_text(
                            ct_prime, list(cand_key), variant, alphabet=alphabet
                        )
                        s = ngram_scorer.score(cand_pt)
                        if best_score is None or s > best_score:
                            best_score = s
                            best_key = cand_key
                    key = best_key

                pt = decrypt_text(ct_prime, list(key), variant, alphabet=alphabet)
                keystream = [
                    recover(ct_idx[i], idx[ord(pt[i]) - 65])
                    for i in range(len(ct_prime))
                ]
                bean = check_bean(keystream, eq, ineq, linear, MOD)
                if require_bean and not bean.passed:
                    continue
                breakdown = score_candidate(
                    pt, bean_result=bean, ngram_scorer=ngram_scorer,
                    crib_dict=cribs,
                )
                out.append(
                    MaskedCandidate(
                        mask=mask,
                        variant=variant,
                        period=p,
                        key=key,
                        plaintext=pt,
                        crib_score=breakdown.crib_score,
                        bean_passed=bean.passed,
                        ngram_score=breakdown.ngram_score,
                    )
                )
    return out
