"""Mask-aware candidate verification (the constraint oracle).

verify_masked_candidate evaluates ONE (mask, variant, key) tuple: extract CT',
decrypt, re-derive Bean for the mask, recover the implied keystream at all CT'
positions, check Bean, and crib-score the plaintext at remapped positions.  It
carries the calibration inputs a mask-universe-aware null model needs.

solve(...) is the joint mask x mechanism search INTERFACE only; the algorithm
is deferred to a follow-on spec.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable, Iterator, Mapping, Optional, Sequence

from kryptos.kernel.alphabet import AZ, Alphabet
from kryptos.kernel.constants import CRIB_DICT, MOD
from kryptos.kernel.constraints.bean import check_bean, derive_bean_constraints
from kryptos.kernel.masking.mask import (
    NullMask, extract_ct, remap_crib_dict, validate_mask,
)
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, KEY_RECOVERY, decrypt_text,
)


@dataclass(frozen=True)
class MaskedVerification:
    mask: NullMask
    crib_score: int
    bean_passed: bool
    ngram_score: Optional[float]
    pt_len: int
    mask_universe_size: int
    candidates_evaluated: int


def verify_masked_candidate(
    ct: str,
    mask: NullMask,
    variant: CipherVariant,
    key: Sequence[int],
    *,
    crib_dict: Mapping[int, str] = CRIB_DICT,
    alphabet: Alphabet = AZ,
    ngram_scorer=None,
    allow_crib_nulls: bool = False,
    mask_universe_size: int = 1,
    candidates_evaluated: int = 1,
) -> MaskedVerification:
    """Evaluate a single (mask, variant, key) candidate.

    Steps:
      1. Validate the mask against the carved CT.
      2. Extract CT' (null positions removed).
      3. Remap the crib dict from carved coordinates to CT' coordinates.
      4. Re-derive Bean constraints from CT' and the remapped cribs.
      5. Decrypt CT' with the given key.
      6. Recover the implied keystream at every CT' position.
      7. Check Bean constraints on the recovered keystream.
      8. Crib-score the plaintext with the remapped crib dict.

    All operations are pure: no global state, no env overrides.

    Args:
        ct: The carved (full-length) ciphertext string.
        mask: frozenset of carved positions that are null characters.
        variant: CipherVariant for decrypt and key-recovery.
        key: Numeric key values (indexed in the given alphabet); applied
            cyclically so len(key) need not equal len(CT').
        crib_dict: Cribs in CARVED coordinate space.  Defaults to the
            canonical CRIB_DICT; pass a custom dict for synthetic tests or
            non-standard crib hypotheses.
        alphabet: Alphabet singleton used for index lookup and decryption.
        ngram_scorer: Optional scorer for language quality.
        allow_crib_nulls: Passed to validate_mask; relax only with provenance.
        mask_universe_size: Total masks evaluated in the enclosing sweep
            (calibration metadata only).
        candidates_evaluated: Running count of candidates evaluated
            (calibration metadata only).

    Returns:
        MaskedVerification dataclass with crib_score, bean_passed, etc.
    """
    validate_mask(mask, len(ct), allow_crib_nulls=allow_crib_nulls)
    ct_prime = extract_ct(ct, mask)
    cribs = remap_crib_dict(crib_dict, mask)

    eq, ineq, linear = derive_bean_constraints(ct_prime, cribs, alphabet)
    pt = decrypt_text(ct_prime, list(key), variant, alphabet=alphabet)

    idx = alphabet.index_table
    recover = KEY_RECOVERY[variant]
    keystream = [
        recover(idx[ord(ct_prime[i]) - 65], idx[ord(pt[i]) - 65])
        for i in range(len(ct_prime))
    ]
    bean = check_bean(keystream, eq, ineq, linear, MOD)
    breakdown = score_candidate(
        pt, bean_result=bean, ngram_scorer=ngram_scorer, crib_dict=cribs,
    )
    return MaskedVerification(
        mask=mask,
        crib_score=breakdown.crib_score,
        bean_passed=bean.passed,
        ngram_score=breakdown.ngram_score,
        pt_len=len(ct_prime),
        mask_universe_size=mask_universe_size,
        candidates_evaluated=candidates_evaluated,
    )


def solve(
    mask_universe: Iterable[NullMask],
    mechanism_family,
    constraint_oracle: Callable[..., MaskedVerification],
) -> Iterator[MaskedVerification]:
    """Joint mask x mechanism search.  INTERFACE ONLY -- algorithm deferred.

    A follow-on spec implements constraint-propagation / SAT pruning over the
    per-mask Bean sets and crib equations.  Until then this raises so callers
    cannot mistake the stub for a working solver.
    """
    raise NotImplementedError(
        "solve() is an interface stub; the search algorithm is a separate spec "
        "(efficacy review item #2)."
    )
    yield  # pragma: no cover  (marks this a generator for the interface contract)
