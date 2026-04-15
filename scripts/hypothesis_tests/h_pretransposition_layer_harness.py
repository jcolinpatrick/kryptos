"""Deterministic finite harness for the pre-transposition layer hypothesis.

Drops H1 from the previous two harnesses by inserting a transposition layer
between the additive cipher and the null-mask insertion.

Model
-----
    PT73 --additive_encrypt(K)--> CT73_additive --transpose(T)--> CT73
         --insert_nulls--> CT97

Inversion for the harness:
    CT97 --mask(M)--> CT73 --inverse_transpose(T^-1)--> CT73_additive
         --additive_decrypt(K)--> PT73

Under this model the cribs still live at REDUCED crib positions in PT73 (they
sit at canonical positions in the underlying plaintext, the null mask
preserves them, the transposition only acts on the additive ciphertext
between encrypt and null insertion). So H1-style crib-position checking
remains valid; the "drop H1" part is that the transposition decouples WHICH
original CT position produces each crib's keystream value.

Critical shape difference from the previous harnesses
-----------------------------------------------------
Under this model there is NO outer key search. For each (mask, transposition,
variant) triple, the implied keystream at the 24 reduced crib positions is
determined by the cribs themselves:

    k_r = recover_key(CT73_additive[r], crib_letter[r], variant)

That 24-vector is then Bean-checked. Since crib_score is trivially 24 by
construction, the discriminating signal is NOT crib_score -- it is
`bean_passed` AND the per-char ngram score of a best-effort filled plaintext.

The search dimension is `mask x transposition x variant`, not
`mask x transposition x variant x key`. This converts a naively ~10^10 search
into a ~10^6 search.

Search universe
---------------
Mask family: reused from h_624_73_nullmask_harness (75 crib-preserving masks).
Transposition family: columnar width 2..7 (all permutations), canonical
constant-parameter transpositions (identity, reverse, block reversal,
boustrophedon), plus width-W grid transformations. Roughly 6000 entries.
Variant family: 3 (vigenere, beaufort, varbeau).

Expected configs: 75 x ~6000 x 3 = ~1.35M. Each config is ~10 us of pure
Python; total pool wall time on 24 workers is single-digit seconds.

Epistemic scope
---------------
Any ELIMINATED status is conditional on:
  A1: canonical 97-char K4 CT
  A2: 73 real + 24 null positional model
  A4: additive cipher family (Vig/Beau/VarBeau)
  A5-mod: key schedule need not act on reduced space; instead the additive
          layer is wrapped by an outer transposition
  B1: transposition is one of the enumerated ~6000 structured families

The hypothesis "H1 is wrong, transposition sits between additive and null
mask" is TESTED within this universe. It is not tested outside it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import multiprocessing as mp
import os
import sys
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterator, Optional

from kryptos.kernel.constants import (
    ALPH,
    ALPH_IDX,
    BREAKTHROUGH_THRESHOLD,
    CRIB_DICT,
    CRIB_POSITIONS,
    CT,
    CT_LEN,
    MOD,
    NOISE_FLOOR,
    SIGNAL_THRESHOLD,
    STORE_THRESHOLD,
)
from kryptos.kernel.constraints.bean import verify_bean_simple
from kryptos.kernel.transforms.vigenere import (
    beau_decrypt,
    beau_recover_key,
    varbeau_decrypt,
    varbeau_recover_key,
    vig_decrypt,
    vig_recover_key,
)

# Reuse mask universe + Mask dataclass from companion harness.
_THIS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_THIS_DIR))
import h_624_73_nullmask_harness as companion  # noqa: E402

CAMPAIGN_ID = "h_pretransposition_layer"
CAMPAIGN_VERSION = "1.0.0"
REDUCED_LEN = 73

CIPHER_VARIANTS = ("vigenere", "beaufort", "varbeau")
CT_NUMS = tuple(ALPH_IDX[c] for c in CT)


# =============================================================================
# Assumption bundle
# =============================================================================


def build_assumptions() -> dict:
    return {
        "assumes_canonical_97_ct": True,
        "assumes_73_real_24_null_model": True,
        "assumes_additive_cipher_family": True,
        "assumes_direct_positional_crib_mapping": False,
        "assumes_pre_transposition_layer": True,
        "assumes_transposition_between_additive_and_null_mask": True,
        "notes": [
            "H1 (direct positional crib mapping after null mask alone) is DROPPED.",
            "A transposition T is assumed to sit between the additive cipher and "
            "the null-mask insertion: CT97 = insert_nulls(T(additive_encrypt(PT73, K))).",
            "Key is NOT searched; it is IMPLIED at crib positions via key recovery.",
            "Bean constraints on the implied 24-vector are the primary filter.",
            "Search is finite within the enumerated ~6000 transposition family.",
            "Candidate signals from this harness are NOT solutions; they are (mask, T, variant) "
            "triples whose implied keystream is Bean-admissible. Each must still be "
            "checked for English-like plaintext elsewhere.",
        ],
    }


def hash_dict(d: dict) -> str:
    return hashlib.sha256(
        json.dumps(d, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


# =============================================================================
# Transposition model
# =============================================================================


@dataclass(frozen=True)
class Transposition:
    """A forward transposition permutation on the reduced 73-char space.

    `perm` is a length-73 tuple of ints such that `output[i] = input[perm[i]]`.
    Equivalently, if Sanborn had written the additive ciphertext as `input`
    and read out `output = T(input)`, then `input[perm[i]] = output[i]`.

    For inversion during decryption (i.e. going from observed CT73 back to
    the pre-transposition additive ciphertext), we need `inverse_perm`, which
    is computed lazily. If CT73 is the observed output and we want the
    pre-transposition input at position j, the answer is
    `input[j] = output[inverse_perm[j]]`.

    Convention matches `kryptos.kernel.transforms.transposition` docs.
    """

    transposition_id: str
    family: str
    description: str
    perm: tuple[int, ...]  # length REDUCED_LEN
    is_exhaustive_within_family: bool
    generation_parameters: dict

    def __post_init__(self) -> None:
        if len(self.perm) != REDUCED_LEN:
            raise ValueError(
                f"Transposition {self.transposition_id}: perm length {len(self.perm)} != {REDUCED_LEN}"
            )
        if sorted(self.perm) != list(range(REDUCED_LEN)):
            raise ValueError(
                f"Transposition {self.transposition_id}: perm is not a permutation of 0..72"
            )

    def inverse_perm(self) -> tuple[int, ...]:
        inv = [0] * REDUCED_LEN
        for i, j in enumerate(self.perm):
            inv[j] = i
        return tuple(inv)


def _t_fingerprint(family: str, perm: tuple[int, ...]) -> str:
    payload = f"{family}|" + ",".join(str(p) for p in perm)
    return hashlib.sha1(payload.encode("ascii")).hexdigest()[:12]


# --- Constant-shape transpositions ------------------------------------------


def gen_identity() -> list[Transposition]:
    perm = tuple(range(REDUCED_LEN))
    return [
        Transposition(
            transposition_id=f"identity-{_t_fingerprint('identity', perm)}",
            family="identity",
            description="Identity transposition (baseline sanity check).",
            perm=perm,
            is_exhaustive_within_family=True,
            generation_parameters={},
        )
    ]


def gen_full_reverse() -> list[Transposition]:
    perm = tuple(range(REDUCED_LEN - 1, -1, -1))
    return [
        Transposition(
            transposition_id=f"reverse-{_t_fingerprint('full_reverse', perm)}",
            family="full_reverse",
            description="Full reversal of the 73-char reduced ciphertext.",
            perm=perm,
            is_exhaustive_within_family=True,
            generation_parameters={},
        )
    ]


def gen_block_reversals() -> list[Transposition]:
    """Reverse each block of size W within the 73-char sequence."""
    out: list[Transposition] = []
    for W in range(2, 21):
        perm = []
        for start in range(0, REDUCED_LEN, W):
            end = min(start + W, REDUCED_LEN)
            perm.extend(range(end - 1, start - 1, -1))
        p = tuple(perm)
        if sorted(p) != list(range(REDUCED_LEN)):
            continue
        out.append(
            Transposition(
                transposition_id=f"blkrev-W{W}-{_t_fingerprint('block_reverse', p)}",
                family="block_reverse",
                description=f"Reverse each block of size {W}.",
                perm=p,
                is_exhaustive_within_family=True,
                generation_parameters={"block_size": W},
            )
        )
    return out


def gen_boustrophedon() -> list[Transposition]:
    """Width-W grid, read rows alternating direction."""
    out: list[Transposition] = []
    for W in range(2, 21):
        rows = math.ceil(REDUCED_LEN / W)
        # Write input linearly into a row-major grid, read out in boustrophedon.
        # perm[i] = input index that lands at output position i.
        out_seq: list[int] = []
        for r in range(rows):
            row_start = r * W
            row_end = min(row_start + W, REDUCED_LEN)
            row_indices = list(range(row_start, row_end))
            if r % 2 == 1:
                row_indices.reverse()
            out_seq.extend(row_indices)
        p = tuple(out_seq)
        if sorted(p) != list(range(REDUCED_LEN)):
            continue
        out.append(
            Transposition(
                transposition_id=f"bous-W{W}-{_t_fingerprint('boustrophedon', p)}",
                family="boustrophedon",
                description=f"Width-{W} row-major write, boustrophedon read.",
                perm=p,
                is_exhaustive_within_family=True,
                generation_parameters={"width": W},
            )
        )
    return out


# --- Columnar transposition family ------------------------------------------


def _columnar_perm(W: int, col_order: tuple[int, ...]) -> tuple[int, ...]:
    """Construct the forward transposition for a columnar writeup.

    The plaintext is written row-major into a grid of width W. Then columns
    are read in the order given by `col_order` (a permutation of [0, W)).
    Partial last row is handled: some columns are 1 shorter than others.
    """
    N = REDUCED_LEN
    # Determine the column length for each column index.
    col_len = [0] * W
    for i in range(N):
        col_len[i % W] += 1
    out_seq: list[int] = []
    for col in col_order:
        # The col-th column's input indices, top to bottom.
        for r in range(col_len[col]):
            out_seq.append(r * W + col)
    return tuple(out_seq)


def _all_permutations(n: int) -> Iterator[tuple[int, ...]]:
    """Deterministic lexicographic permutations of [0, n)."""
    from itertools import permutations

    yield from permutations(range(n))


def gen_columnar(max_full_width: int = 7, wider_sample_cap: int = 40) -> list[Transposition]:
    """Columnar transpositions.

    For widths 2..max_full_width, enumerate every column ordering (W! total).
    For widths max_full_width+1..14, sample a canonical set: identity,
    reverse, even-odd, odd-even, block-swapped, right-rotated-by-one,
    left-rotated-by-one, and the first wider_sample_cap lex permutations.
    """
    out: list[Transposition] = []
    seen_perms: set[tuple[int, ...]] = set()
    # Full enumerations
    for W in range(2, max_full_width + 1):
        for col_order in _all_permutations(W):
            p = _columnar_perm(W, col_order)
            if p in seen_perms:
                continue
            seen_perms.add(p)
            out.append(
                Transposition(
                    transposition_id=f"col-W{W}-{''.join(str(c) for c in col_order)}-{_t_fingerprint('columnar', p)}",
                    family="columnar",
                    description=f"Width-{W} columnar, column order {list(col_order)}.",
                    perm=p,
                    is_exhaustive_within_family=True,
                    generation_parameters={"width": W, "col_order": list(col_order)},
                )
            )

    # Wider columnar: sampled set
    for W in range(max_full_width + 1, 15):
        canonical = [
            tuple(range(W)),
            tuple(range(W - 1, -1, -1)),  # reverse
            tuple(list(range(0, W, 2)) + list(range(1, W, 2))),  # evens then odds
            tuple(list(range(1, W, 2)) + list(range(0, W, 2))),  # odds then evens
            tuple(list(range(W // 2, W)) + list(range(0, W // 2))),  # block-swap halves
            tuple(((i + 1) % W) for i in range(W)),  # rotated by 1
            tuple(((i - 1) % W) for i in range(W)),  # rotated by -1
        ]
        # Add the first wider_sample_cap lexicographic permutations as stride breadth.
        lex_sample = []
        for col_order in _all_permutations(W):
            lex_sample.append(col_order)
            if len(lex_sample) >= wider_sample_cap:
                break
        for col_order in canonical + lex_sample:
            if not (sorted(col_order) == list(range(W))):
                continue
            p = _columnar_perm(W, col_order)
            if p in seen_perms:
                continue
            seen_perms.add(p)
            out.append(
                Transposition(
                    transposition_id=f"col-W{W}-{'-'.join(str(c) for c in col_order)[:40]}-{_t_fingerprint('columnar', p)}",
                    family="columnar_wide",
                    description=f"Width-{W} columnar, column order {list(col_order)}.",
                    perm=p,
                    is_exhaustive_within_family=False,
                    generation_parameters={"width": W, "col_order": list(col_order)},
                )
            )
    return out


# --- Universe assembly ------------------------------------------------------


def build_transposition_universe(
    include_identity: bool = True,
    include_full_reverse: bool = True,
    include_block_reverse: bool = True,
    include_boustrophedon: bool = True,
    include_columnar: bool = True,
    max_full_col_width: int = 7,
    wider_col_sample_cap: int = 40,
) -> list[Transposition]:
    out: list[Transposition] = []
    if include_identity:
        out.extend(gen_identity())
    if include_full_reverse:
        out.extend(gen_full_reverse())
    if include_block_reverse:
        out.extend(gen_block_reversals())
    if include_boustrophedon:
        out.extend(gen_boustrophedon())
    if include_columnar:
        out.extend(gen_columnar(max_full_width=max_full_col_width, wider_sample_cap=wider_col_sample_cap))
    # Dedupe by perm.
    seen: dict[tuple[int, ...], Transposition] = {}
    for t in out:
        if t.perm not in seen:
            seen[t.perm] = t
    deduped = list(seen.values())
    deduped.sort(key=lambda t: (t.family, t.transposition_id))
    return deduped


# =============================================================================
# Evaluation core
# =============================================================================


def _recover_fn(variant: str) -> Callable[[int, int], int]:
    if variant == "vigenere":
        return vig_recover_key
    if variant == "beaufort":
        return beau_recover_key
    if variant == "varbeau":
        return varbeau_recover_key
    raise ValueError(variant)


def _decrypt_fn(variant: str) -> Callable[[int, int], int]:
    if variant == "vigenere":
        return vig_decrypt
    if variant == "beaufort":
        return beau_decrypt
    if variant == "varbeau":
        return varbeau_decrypt
    raise ValueError(variant)


@dataclass
class EvalResult:
    mask_id: str
    mask_family: str
    transposition_id: str
    transposition_family: str
    variant: str
    bean_passed: bool
    bean_applicable: bool
    implied_keystream_24: tuple[int, ...]
    # Best-effort plaintext produced with a simple fill rule, for ngram scoring.
    best_plaintext_73: str
    best_fill_rule: str
    best_ngram_per_char: float


# Fill rules for the non-crib positions of the 73-keystream when we want to
# render a full plaintext for ngram scoring. Deterministic, bounded.
def _fill_zero(k24: tuple[int, ...], crib_reduced_positions: list[int]) -> tuple[int, ...]:
    key73 = [0] * REDUCED_LEN
    for i, r in enumerate(crib_reduced_positions):
        key73[r] = k24[i]
    return tuple(key73)


def _fill_repeat_first(k24: tuple[int, ...], crib_reduced_positions: list[int]) -> tuple[int, ...]:
    # Fill non-crib positions by repeating k24[0] everywhere.
    key73 = [k24[0]] * REDUCED_LEN
    for i, r in enumerate(crib_reduced_positions):
        key73[r] = k24[i]
    return tuple(key73)


def _fill_cyclic_24(k24: tuple[int, ...], crib_reduced_positions: list[int]) -> tuple[int, ...]:
    # Tile k24 over 73 positions regardless of crib placement.
    return tuple(k24[i % 24] for i in range(REDUCED_LEN))


def _fill_linear_interp(k24: tuple[int, ...], crib_reduced_positions: list[int]) -> tuple[int, ...]:
    """Linear interpolation in reduced-position space between consecutive
    crib positions, using mod-26 arithmetic on the key values."""
    if not crib_reduced_positions:
        return tuple([0] * REDUCED_LEN)
    # Pair each crib reduced position with its implied keystream value.
    pts = sorted(zip(crib_reduced_positions, k24))
    key73 = [0] * REDUCED_LEN
    for idx, (r, v) in enumerate(pts):
        key73[r] = v
    # Fill between consecutive crib anchors with step-wise linear interpolation.
    for j in range(len(pts) - 1):
        r0, v0 = pts[j]
        r1, v1 = pts[j + 1]
        gap = r1 - r0
        if gap <= 1:
            continue
        # Compute the mod-26 delta
        delta = (v1 - v0) % MOD
        for step in range(1, gap):
            frac = step / gap
            interp = int(round(v0 + delta * frac)) % MOD
            key73[r0 + step] = interp
    # Before first and after last anchor: constant extension.
    first_r, first_v = pts[0]
    last_r, last_v = pts[-1]
    for i in range(0, first_r):
        key73[i] = first_v
    for i in range(last_r + 1, REDUCED_LEN):
        key73[i] = last_v
    return tuple(key73)


FILL_RULES: dict[str, Callable[[tuple[int, ...], list[int]], tuple[int, ...]]] = {
    "zero_fill": _fill_zero,
    "repeat_first": _fill_repeat_first,
    "cyclic_24": _fill_cyclic_24,
    "linear_interp": _fill_linear_interp,
}


def evaluate_triple(
    mask: "companion.Mask",
    transposition: Transposition,
    variant: str,
    ngram_scorer=None,
) -> EvalResult:
    recover = _recover_fn(variant)
    decrypt = _decrypt_fn(variant)

    kept = mask.kept_positions  # sorted tuple of length 73
    # CT73 as numeric vector (this is the observed output-of-transposition)
    ct73_observed = tuple(CT_NUMS[p] for p in kept)

    # Compute the inverse transposition. Apply it to CT73_observed to
    # recover CT73_additive (the input to the transposition during encryption).
    # We actually only need values at crib positions, so we avoid constructing
    # the full 73-length CT73_additive and instead look up positions on demand.
    inv_perm = transposition.inverse_perm()  # length 73: inv[j] = i means output[i] contained input[j]
    # input[j] = output[inv[j]], so CT73_additive[j] = CT73[inv[j]].

    # Reduced crib positions (sorted by original crib position).
    crib_map = mask.crib_to_reduced()  # {orig_pos: reduced_pos}
    if not mask.preserves_cribs():
        return EvalResult(
            mask_id=mask.mask_id,
            mask_family=mask.family,
            transposition_id=transposition.transposition_id,
            transposition_family=transposition.family,
            variant=variant,
            bean_passed=False,
            bean_applicable=False,
            implied_keystream_24=tuple([0] * 24),
            best_plaintext_73="",
            best_fill_rule="",
            best_ngram_per_char=0.0,
        )

    # Compute implied keystream at each of the 24 reduced crib positions
    # (sorted by the CANONICAL original crib ordering 21..33, 63..73).
    orig_crib_positions = sorted(CRIB_POSITIONS)
    k24_list = []
    crib_reduced = []
    for orig_pos in orig_crib_positions:
        r = crib_map[orig_pos]
        crib_reduced.append(r)
        # CT73_additive at reduced position r is CT73[inv_perm[r]].
        c_val = ct73_observed[inv_perm[r]]
        p_val = ALPH_IDX[CRIB_DICT[orig_pos]]
        k_val = recover(c_val, p_val)
        k24_list.append(k_val)
    k24 = tuple(k24_list)

    # Build virtual 97-length keystream at original crib positions for Bean.
    virt = [0] * CT_LEN
    for i, orig_pos in enumerate(orig_crib_positions):
        virt[orig_pos] = k24[i]
    bean_passed = verify_bean_simple(virt)

    best_plaintext = ""
    best_rule = ""
    best_ngram = 0.0
    if bean_passed and ngram_scorer is not None:
        # Try each fill rule and score the resulting decrypted plaintext.
        # We decrypt the INVERSE-TRANSPOSED ct73 (= ct73_additive) under the
        # filled 73-keystream. This gives the candidate PT73.
        ct73_additive = [ct73_observed[inv_perm[j]] for j in range(REDUCED_LEN)]
        for rule_name, fill_fn in FILL_RULES.items():
            key73 = fill_fn(k24, crib_reduced)
            pt_nums = [decrypt(ct73_additive[j], key73[j]) for j in range(REDUCED_LEN)]
            pt73 = "".join(ALPH[v] for v in pt_nums)
            try:
                score = float(ngram_scorer.score_per_char(pt73))
            except Exception:
                score = -10.0
            if score > best_ngram or not best_rule:
                best_ngram = score
                best_plaintext = pt73
                best_rule = rule_name

    return EvalResult(
        mask_id=mask.mask_id,
        mask_family=mask.family,
        transposition_id=transposition.transposition_id,
        transposition_family=transposition.family,
        variant=variant,
        bean_passed=bean_passed,
        bean_applicable=True,
        implied_keystream_24=k24,
        best_plaintext_73=best_plaintext,
        best_fill_rule=best_rule,
        best_ngram_per_char=best_ngram,
    )


# =============================================================================
# Multiprocessing worker
# =============================================================================


_WORKER_NGRAM = None
NEAR_MISS_PER_WORKER = 50
PT73_SAMPLE_PER_WORKER = 20
# Bean-fail near-miss: track how many of the 242 inequalities were satisfied.
# A "near miss" is a 24-vector that passes all except a few ineq constraints.


def _worker_init() -> None:
    global _WORKER_NGRAM
    try:
        from kryptos.kernel.scoring.ngram import get_default_scorer

        _WORKER_NGRAM = get_default_scorer()
    except Exception:
        _WORKER_NGRAM = None


def _worker_eval_chunk(
    payload: tuple[int, int, "companion.Mask", tuple[str, ...], tuple[Transposition, ...]],
) -> dict:
    mask_idx, chunk_id, mask, variants, t_chunk = payload
    survivors: list[dict] = []
    tallies: Counter = Counter()
    bean_histogram: Counter = Counter()  # 0 = fail, 1 = pass
    bean_invocations = 0
    bean_pass = 0
    bean_fail = 0
    ngram_invocations = 0
    pt73_seen: dict[str, None] = {}
    pt73_sample_fingerprints: list[str] = []
    local_near_misses: list[dict] = []

    for variant in variants:
        for t in t_chunk:
            tallies["evaluated"] += 1
            try:
                r = evaluate_triple(mask, t, variant, ngram_scorer=_WORKER_NGRAM)
            except Exception as exc:
                tallies["worker_error"] += 1
                survivors.append(
                    {
                        "_error": True,
                        "mask_id": mask.mask_id,
                        "variant": variant,
                        "transposition_id": t.transposition_id,
                        "exc": repr(exc)[:200],
                    }
                )
                continue

            bean_histogram[1 if r.bean_passed else 0] += 1
            bean_invocations += 1
            if r.bean_passed:
                bean_pass += 1
            else:
                bean_fail += 1

            # Sample the best fill plaintext when available, to populate the
            # forensic pt73 histogram.
            if r.best_plaintext_73 and len(pt73_seen) < PT73_SAMPLE_PER_WORKER:
                if r.best_plaintext_73 not in pt73_seen:
                    pt73_seen[r.best_plaintext_73] = None
                    pt73_sample_fingerprints.append(
                        hashlib.sha1(r.best_plaintext_73.encode("ascii")).hexdigest()[:12]
                    )
            if r.best_ngram_per_char != 0.0 and _WORKER_NGRAM is not None:
                ngram_invocations += 1

            if r.bean_passed:
                tallies["bean_pass"] += 1
                survivors.append(
                    {
                        "mask_id": r.mask_id,
                        "mask_family": r.mask_family,
                        "transposition_id": r.transposition_id,
                        "transposition_family": r.transposition_family,
                        "variant": r.variant,
                        "bean_passed": True,
                        "bean_applicable": True,
                        "implied_keystream_24": list(r.implied_keystream_24),
                        "best_plaintext_73": r.best_plaintext_73,
                        "best_fill_rule": r.best_fill_rule,
                        "best_ngram_per_char": r.best_ngram_per_char,
                    }
                )
            else:
                tallies["bean_fail"] += 1
                # Near-miss: track by how many ineq violations (not computed
                # here to stay fast; we use the implied 24-vector for sort key).
                _insert_near_miss(
                    local_near_misses,
                    {
                        "mask_id": r.mask_id,
                        "mask_family": r.mask_family,
                        "transposition_id": r.transposition_id,
                        "transposition_family": r.transposition_family,
                        "variant": r.variant,
                        "implied_keystream_24": list(r.implied_keystream_24),
                    },
                    NEAR_MISS_PER_WORKER,
                )

    return {
        "mask_idx": int(mask_idx),
        "chunk_id": int(chunk_id),
        "processed_count": int(tallies["evaluated"]),
        "survivors": survivors,
        "tallies": dict(tallies),
        "audit": {
            "worker_pid": os.getpid(),
            "mask_idx": int(mask_idx),
            "chunk_id": int(chunk_id),
            "processed_count": int(tallies["evaluated"]),
            "bean_invocations": bean_invocations,
            "bean_pass": bean_pass,
            "bean_fail": bean_fail,
            "bean_not_applicable": 0,
            "ngram_invocations": ngram_invocations,
            "pt73_distinct_sampled": len(pt73_seen),
            "pt73_sample_fingerprints": pt73_sample_fingerprints,
            "bean_histogram": {int(k): int(v) for k, v in bean_histogram.items()},
        },
        "near_misses": local_near_misses,
    }


def _near_miss_sort_key(entry: dict) -> tuple:
    return (
        str(entry.get("mask_id", "")),
        str(entry.get("variant", "")),
        str(entry.get("transposition_id", "")),
    )


def _insert_near_miss(bucket: list[dict], entry: dict, cap: int) -> None:
    bucket.append(entry)
    bucket.sort(key=_near_miss_sort_key)
    if len(bucket) > cap:
        del bucket[cap:]


def _chunk(seq: list[Transposition], size: int) -> Iterator[tuple[Transposition, ...]]:
    for i in range(0, len(seq), size):
        yield tuple(seq[i : i + size])


# =============================================================================
# Campaign + IO
# =============================================================================


NEAR_MISS_GLOBAL_CAP = 200


@dataclass
class Campaign:
    campaign_id: str = CAMPAIGN_ID
    campaign_version: str = CAMPAIGN_VERSION
    mode: str = "smoke"
    status: str = "PENDING"
    started_at: str = ""
    completed_at: str = ""
    assumptions: dict = field(default_factory=dict)
    assumptions_hash: str = ""
    universe_hash: str = ""
    inventory: dict = field(default_factory=dict)
    coverage: dict = field(
        default_factory=lambda: {"tested": 0, "total": 0, "coverage_fraction": 0.0}
    )
    best: list[dict] = field(default_factory=list)
    survivors: list[dict] = field(default_factory=list)
    near_misses: list[dict] = field(default_factory=list)
    rejection_counts: dict = field(default_factory=dict)
    audit_counters: dict = field(default_factory=dict)
    per_worker_audit: list[dict] = field(default_factory=list)
    tooling_gaps: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    completed_mask_indices: list[int] = field(default_factory=list)
    completed_chunk_ids: dict[str, list[int]] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def compute_universe_hash(
    masks: list["companion.Mask"],
    transpositions: list[Transposition],
    variants: tuple[str, ...],
) -> str:
    h = hashlib.sha256()
    h.update(CAMPAIGN_VERSION.encode())
    h.update(f"masks={len(masks)}".encode())
    for m in masks:
        h.update(m.mask_id.encode())
    h.update(f"trans={len(transpositions)}".encode())
    for t in transpositions:
        h.update(t.transposition_id.encode())
    h.update(f"variants={','.join(variants)}".encode())
    return h.hexdigest()


def write_json_atomic(path: Path, doc: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(doc, indent=2, default=str))
    tmp.replace(path)


def _absorb_chunk(chunk_out: dict, rej: Counter, camp: Campaign) -> None:
    for k, v in chunk_out.get("tallies", {}).items():
        rej[k] += int(v)
    for e in chunk_out.get("survivors", []):
        if e.get("_error"):
            camp.tooling_gaps.append(
                {
                    "kind": "worker_error",
                    "mask_id": e.get("mask_id"),
                    "variant": e.get("variant"),
                    "transposition_id": e.get("transposition_id"),
                    "exc": e.get("exc"),
                }
            )
            continue
        camp.survivors.append(e)

    audit = chunk_out.get("audit")
    if audit:
        pid = int(audit.get("worker_pid", 0))
        ac = camp.audit_counters
        for k in (
            "processed_count",
            "bean_invocations",
            "bean_pass",
            "bean_fail",
            "bean_not_applicable",
            "ngram_invocations",
        ):
            ac[k] = int(ac.get(k, 0)) + int(audit.get(k, 0))
        bh = ac.setdefault("bean_histogram", {0: 0, 1: 0})
        for k, v in audit.get("bean_histogram", {}).items():
            bh[int(k)] = int(bh.get(int(k), 0)) + int(v)
        fps = ac.setdefault("pt73_fingerprints", [])
        fp_set = dict.fromkeys(fps)
        for fp in audit.get("pt73_sample_fingerprints", []):
            fp_set[fp] = None
        ac["pt73_fingerprints"] = list(fp_set.keys())
        ac["pt73_distinct_total"] = len(fp_set)
        pw_map = {e["worker_pid"]: e for e in camp.per_worker_audit}
        existing = pw_map.get(pid)
        if existing is None:
            existing = {
                "worker_pid": pid,
                "processed_count": 0,
                "bean_invocations": 0,
                "bean_pass": 0,
                "bean_fail": 0,
                "bean_not_applicable": 0,
                "ngram_invocations": 0,
                "chunks": 0,
            }
            camp.per_worker_audit.append(existing)
        for k in (
            "processed_count",
            "bean_invocations",
            "bean_pass",
            "bean_fail",
            "bean_not_applicable",
            "ngram_invocations",
        ):
            existing[k] = int(existing.get(k, 0)) + int(audit.get(k, 0))
        existing["chunks"] = int(existing.get("chunks", 0)) + 1

    for nm in chunk_out.get("near_misses", []):
        camp.near_misses.append(nm)
    if camp.near_misses:
        camp.near_misses.sort(key=_near_miss_sort_key)
        del camp.near_misses[NEAR_MISS_GLOBAL_CAP:]


def _persist_checkpoint(
    ckpt: Path,
    camp: Campaign,
    completed: set[int],
    completed_chunks: dict[int, set[int]],
    rej: Counter,
) -> None:
    doc = camp.to_dict()
    doc["completed_mask_indices"] = sorted(completed)
    doc["completed_chunk_ids"] = {
        str(mi): sorted(chunks) for mi, chunks in sorted(completed_chunks.items())
    }
    doc["rejection_counts"] = dict(rej)
    write_json_atomic(ckpt, doc)


def render_markdown_report(camp: Campaign, out_path: Path, cmd_line: str) -> None:
    L: list[str] = []
    L.append(f"# {camp.campaign_id} {camp.campaign_version} -- {camp.status}")
    L.append("")
    L.append(f"- started: `{camp.started_at}`")
    L.append(f"- completed: `{camp.completed_at}`")
    L.append(f"- mode: `{camp.mode}`")
    L.append(f"- assumptions_hash: `{camp.assumptions_hash[:16]}`")
    L.append(f"- universe_hash: `{camp.universe_hash[:16]}`")
    L.append("")
    L.append("## Assumption bundle")
    L.append("")
    for k, v in camp.assumptions.items():
        if k == "notes":
            continue
        L.append(f"- `{k}`: **{v}**")
    L.append("")
    for n in camp.assumptions.get("notes", []):
        L.append(f"- {n}")
    L.append("")
    L.append("## Inventory")
    L.append("")
    for k, v in camp.inventory.items():
        L.append(f"- `{k}`: {v}")
    L.append("")
    L.append("## Coverage")
    L.append("")
    cov = camp.coverage
    L.append(f"- tested: `{cov.get('tested', 0)}`")
    L.append(f"- total: `{cov.get('total', 0)}`")
    L.append(f"- fraction: `{cov.get('coverage_fraction', 0.0):.6f}`")
    L.append("")
    L.append("## Audit counters")
    L.append("")
    ac = camp.audit_counters or {}
    L.append(f"- processed_count: `{ac.get('processed_count', 0)}`")
    L.append(f"- bean_invocations: `{ac.get('bean_invocations', 0)}`")
    L.append(f"- bean_pass / fail: `{ac.get('bean_pass', 0)}` / `{ac.get('bean_fail', 0)}`")
    L.append(f"- ngram_invocations (on Bean-pass only): `{ac.get('ngram_invocations', 0)}`")
    L.append(f"- pt73_distinct_total (Bean-pass plaintexts sampled): `{ac.get('pt73_distinct_total', 0)}`")
    L.append("")
    if camp.per_worker_audit:
        L.append("## Per-worker audit")
        L.append("")
        L.append("| pid | chunks | processed | bean_inv | bean_pass | bean_fail | ngram_inv |")
        L.append("|---|---|---|---|---|---|---|")
        for e in camp.per_worker_audit:
            L.append(
                f"| {e['worker_pid']} | {e['chunks']} | {e['processed_count']} | "
                f"{e['bean_invocations']} | {e['bean_pass']} | {e['bean_fail']} | "
                f"{e['ngram_invocations']} |"
            )
        L.append("")
    L.append("## Bean-pass survivors")
    L.append("")
    if camp.survivors:
        total = len(camp.survivors)
        baseline_eq = sum(1 for s in camp.survivors if s.get("baseline_equivalent"))
        novel = total - baseline_eq
        distinct_total = int(ac.get("distinct_implied_vectors", 0))
        distinct_novel = int(ac.get("distinct_novel_vectors", 0))
        L.append(f"Found **{total}** Bean-passing `(mask, transposition, variant)` triples.")
        L.append("")
        L.append(f"- **baseline-equivalent** (identity-at-cribs, canonical keystream reproduction): `{baseline_eq}`")
        L.append(f"- **novel-signal** (transposition moves at least one crib position): `{novel}`")
        L.append(f"- distinct implied 24-vectors total: `{distinct_total}`")
        L.append(f"- distinct novel 24-vectors (not produced by baseline-equivalent passes): `{distinct_novel}`")
        L.append("")
        if novel == 0:
            L.append(
                "Every Bean-passing triple is **baseline-equivalent** -- the transposition "
                "happens to leave all reduced crib positions fixed, so the implied keystream "
                "reduces to the canonical direct-crib-recovery values (same as H1). These are "
                "sanity-baseline confirmations that the harness plumbing is correct, NOT novel "
                "candidate signals."
            )
            L.append("")
        L.append("Top 30 baseline-equivalent (sanity-only) by best ngram per char:")
        L.append("")
        base_srt = sorted(
            [s for s in camp.survivors if s.get("baseline_equivalent")],
            key=lambda s: (s.get("best_ngram_per_char", -10.0)),
            reverse=True,
        )
        for s in base_srt[:10]:
            L.append(
                f"- ngram=`{s.get('best_ngram_per_char', 0.0):.3f}`  "
                f"variant=`{s['variant']}`  "
                f"T=`{s['transposition_id'][:40]}` ({s['transposition_family']})  "
                f"mask=`{s['mask_id'][:30]}` ({s['mask_family']})"
            )
        L.append("")
        if novel > 0:
            L.append("### Novel-signal survivors (these are the interesting ones)")
            L.append("")
            novel_srt = sorted(
                [s for s in camp.survivors if not s.get("baseline_equivalent")],
                key=lambda s: (s.get("best_ngram_per_char", -10.0)),
                reverse=True,
            )
            for s in novel_srt[:30]:
                L.append(
                    f"- ngram=`{s.get('best_ngram_per_char', 0.0):.3f}`  "
                    f"variant=`{s['variant']}`  "
                    f"T=`{s['transposition_id'][:40]}` ({s['transposition_family']})  "
                    f"mask=`{s['mask_id'][:30]}` ({s['mask_family']})"
                )
            L.append("")
    else:
        L.append("- (no Bean-passing configurations found)")
    L.append("")
    L.append("## Reproduction")
    L.append("")
    L.append("```bash")
    L.append(cmd_line)
    L.append("```")
    L.append("")
    L.append("## Epistemic reading")
    L.append("")
    if camp.status == "ELIMINATED":
        L.append(
            "Full finite coverage completed under the stated assumption bundle "
            "AND within the stated transposition universe; no NOVEL "
            "Bean-passing configurations. Any baseline-equivalent passes are "
            "sanity-check artifacts (transposition is identity at crib "
            "positions) and do not constitute new signal. CONDITIONAL "
            "elimination within this harness's ~6000-entry structured "
            "transposition family. Exotic grilles, non-structured "
            "permutations, or transpositions that happen to fix crib positions "
            "while scrambling others are NOT tested as candidates."
        )
    elif camp.status == "CANDIDATE_SIGNAL":
        L.append(
            "At least one NOVEL Bean-passing `(mask, transposition, variant)` triple "
            "where the transposition moves at least one reduced crib position. "
            "This is NOT a solution claim. Each novel survivor's implied 24-vector "
            "is a candidate Bean-admissible keystream under the pre-transposition "
            "layer hypothesis. Route through normal Day 5/6 alert + stat-audit "
            "+ provenance gates before any promotion. Baseline-equivalent passes "
            "are also listed but are sanity-only (they reproduce the canonical "
            "H1 direct-crib keystream)."
        )
    elif camp.status == "INCONCLUSIVE_BUDGET":
        L.append("Partial coverage -- not elimination.")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(L))


# =============================================================================
# Run loop
# =============================================================================


def run_campaign(
    mode: str,
    masks: list["companion.Mask"],
    transpositions: list[Transposition],
    variants: tuple[str, ...],
    workers: int,
    max_configs: Optional[int],
    checkpoint_path: Path,
    output_path: Path,
    resume: bool,
    chunk_size: int,
    cmd_line: str,
    force_resume: bool = False,
) -> Campaign:
    assumptions = build_assumptions()
    a_hash = hash_dict(assumptions)
    u_hash = compute_universe_hash(masks, transpositions, variants)
    total_configs = len(masks) * len(transpositions) * len(variants)

    inventory = {
        "canonical_ct_length": CT_LEN,
        "assumed_real_length": REDUCED_LEN,
        "null_count": 24,
        "n_masks": len(masks),
        "n_masks_by_family": dict(Counter(m.family for m in masks)),
        "n_transpositions": len(transpositions),
        "n_transpositions_by_family": dict(Counter(t.family for t in transpositions)),
        "n_variants": len(variants),
        "variants": list(variants),
        "total_configs": total_configs,
        "signal_criteria": {
            "primary": "bean_passed == True",
            "secondary_rank": "best_ngram_per_char descending",
        },
    }

    camp = Campaign(
        mode=mode,
        status="RUNNING",
        started_at=datetime.now(timezone.utc).isoformat(),
        assumptions=assumptions,
        assumptions_hash=a_hash,
        universe_hash=u_hash,
        inventory=inventory,
        coverage={"tested": 0, "total": total_configs, "coverage_fraction": 0.0},
    )

    # Resume
    if resume and checkpoint_path.exists():
        try:
            prior = json.loads(checkpoint_path.read_text())
            if (
                prior.get("assumptions_hash") == a_hash
                and prior.get("universe_hash") == u_hash
                and prior.get("campaign_version") == CAMPAIGN_VERSION
            ) or force_resume:
                camp.completed_mask_indices = list(prior.get("completed_mask_indices", []))
                camp.survivors = list(prior.get("survivors", []))
                camp.rejection_counts = dict(prior.get("rejection_counts", {}))
                camp.audit_counters = dict(prior.get("audit_counters", {}))
                camp.per_worker_audit = list(prior.get("per_worker_audit", []))
                camp.near_misses = list(prior.get("near_misses", []))
                camp.completed_chunk_ids = {
                    str(k): list(v)
                    for k, v in prior.get("completed_chunk_ids", {}).items()
                }
                camp.started_at = prior.get("started_at", camp.started_at)
                camp.notes.append(
                    f"resumed from checkpoint with {len(camp.completed_mask_indices)} mask(s) already complete"
                )
            else:
                camp.notes.append(
                    "checkpoint hash mismatch; refusing to resume (use --force to override)"
                )
                if not force_resume:
                    camp.status = "ERROR"
                    camp.completed_at = datetime.now(timezone.utc).isoformat()
                    write_json_atomic(output_path, camp.to_dict())
                    return camp
        except Exception as exc:
            camp.notes.append(f"checkpoint read failed: {exc!r}")

    if mode == "inventory":
        camp.status = "INVENTORY"
        camp.completed_at = datetime.now(timezone.utc).isoformat()
        write_json_atomic(output_path, camp.to_dict())
        render_markdown_report(camp, output_path.with_suffix(".md"), cmd_line)
        return camp

    if total_configs == 0:
        camp.status = "INCONCLUSIVE_TOOLING"
        camp.notes.append("empty universe")
        camp.completed_at = datetime.now(timezone.utc).isoformat()
        write_json_atomic(output_path, camp.to_dict())
        render_markdown_report(camp, output_path.with_suffix(".md"), cmd_line)
        return camp

    completed_set = set(camp.completed_mask_indices)
    completed_chunks: dict[int, set[int]] = {
        int(mi): {int(ci) for ci in chunk_ids}
        for mi, chunk_ids in camp.completed_chunk_ids.items()
    }
    rej = Counter(camp.rejection_counts)
    tested = int(camp.audit_counters.get("processed_count", 0))
    max_cfg = max_configs if max_configs is not None else total_configs

    chunks_per_mask = list(_chunk(transpositions, chunk_size))
    pending: list[tuple[int, tuple]] = []
    for mi, m in enumerate(masks):
        if mi in completed_set:
            continue
        for ci, ch in enumerate(chunks_per_mask):
            if ci in completed_chunks.get(mi, set()):
                continue
            pending.append((mi, (mi, ci, m, tuple(variants), ch)))

    mask_task_count: Counter = Counter()
    mask_task_done: Counter = Counter()
    for mi, _ in pending:
        mask_task_count[mi] += 1

    def _record_result(out: dict) -> int:
        """Attribute an unordered worker result to its echoed mask index."""
        mi = int(out.get("mask_idx", -1))
        if mi < 0:
            raise RuntimeError(
                "worker result missing mask_idx; parallel identity contract broken"
            )
        processed = int(out.get("processed_count", 0))
        ci = int(out.get("chunk_id", -1))
        if ci < 0:
            raise RuntimeError(
                "worker result missing chunk_id; parallel identity contract broken"
            )
        mask_task_done[mi] += 1
        _absorb_chunk(out, rej, camp)
        completed_chunks.setdefault(mi, set()).add(ci)
        if len(completed_chunks.get(mi, set())) == len(chunks_per_mask):
            completed_set.add(mi)
        return processed

    if pending:
        if workers > 1:
            ctx = mp.get_context("spawn")
            pool = ctx.Pool(processes=workers, initializer=_worker_init)
        else:
            _worker_init()
            pool = None

        try:
            if pool is not None:
                payload_only = [p for _, p in pending]
                results_received = 0
                for out in pool.imap_unordered(_worker_eval_chunk, payload_only):
                    delta = _record_result(out)
                    tested += delta
                    camp.coverage["tested"] = tested
                    camp.coverage["coverage_fraction"] = tested / total_configs
                    results_received += 1
                    if results_received % 16 == 0 or tested >= max_cfg:
                        _persist_checkpoint(checkpoint_path, camp, completed_set, completed_chunks, rej)
                    if tested >= max_cfg:
                        break
            else:
                for i, (_mi, payload) in enumerate(pending):
                    out = _worker_eval_chunk(payload)
                    delta = _record_result(out)
                    tested += delta
                    camp.coverage["tested"] = tested
                    camp.coverage["coverage_fraction"] = tested / total_configs
                    if (i + 1) % 16 == 0 or tested >= max_cfg:
                        _persist_checkpoint(checkpoint_path, camp, completed_set, completed_chunks, rej)
                    if tested >= max_cfg:
                        break
        finally:
            if pool is not None:
                pool.close()
                pool.join()
    else:
        camp.coverage["tested"] = tested
        camp.coverage["coverage_fraction"] = tested / total_configs if total_configs else 1.0

    camp.completed_mask_indices = sorted(completed_set)
    camp.rejection_counts = dict(rej)
    camp.completed_at = datetime.now(timezone.utc).isoformat()

    # Reconciliation
    ac = camp.audit_counters
    global_processed = int(ac.get("processed_count", 0))
    per_worker_sum = sum(int(e.get("processed_count", 0)) for e in camp.per_worker_audit)
    if global_processed != per_worker_sum:
        camp.notes.append(
            f"audit mismatch: global processed={global_processed} vs per_worker sum={per_worker_sum}"
        )
    bean_sum = int(ac.get("bean_pass", 0)) + int(ac.get("bean_fail", 0)) + int(ac.get("bean_not_applicable", 0))
    if bean_sum != global_processed:
        camp.notes.append(
            f"audit mismatch: bean_pass+fail+na={bean_sum} vs processed={global_processed}"
        )

    # Classify Bean-pass survivors into two buckets:
    #
    #   baseline_equivalent: transposition acts as the identity AT ALL
    #       reduced crib positions (inverse_perm[r] == r for every r). These
    #       necessarily produce the same implied 24-vector as identity and
    #       reproduce the canonical VIGENERE/BEAUFORT/VAR-BEAU key at crib
    #       positions. They are sanity-baseline confirmations, NOT new
    #       signals.
    #
    #   novel_signal: transposition DOES move at least one crib position in
    #       the reduced space, yet the implied 24-vector STILL lands in the
    #       624 Bean-valid set. These are the genuine pre-transposition
    #       hypothesis candidates. Any novel_signal promotes status to
    #       CANDIDATE_SIGNAL.
    #
    # We need mask/transposition lookup to determine identity-at-cribs.
    mask_lookup = {m.mask_id: m for m in masks}
    trans_lookup = {t.transposition_id: t for t in transpositions}
    baseline_equivalent_count = 0
    novel_signal_count = 0
    for s in camp.survivors:
        mask = mask_lookup.get(s.get("mask_id"))
        trans = trans_lookup.get(s.get("transposition_id"))
        if mask is None or trans is None:
            continue
        inv = trans.inverse_perm()
        crib_reduced = mask.crib_to_reduced().values()
        is_identity_at_cribs = all(inv[r] == r for r in crib_reduced)
        s["baseline_equivalent"] = bool(is_identity_at_cribs)
        if is_identity_at_cribs:
            baseline_equivalent_count += 1
        else:
            novel_signal_count += 1

    ac["baseline_equivalent_passes"] = baseline_equivalent_count
    ac["novel_signal_passes"] = novel_signal_count
    # Distinct implied-keystream vector count across all survivors.
    distinct_vecs = {tuple(s.get("implied_keystream_24", ())) for s in camp.survivors}
    ac["distinct_implied_vectors"] = len(distinct_vecs)
    # Distinct vectors that are NOT produced by any baseline-equivalent pass.
    baseline_vecs = {
        tuple(s.get("implied_keystream_24", ()))
        for s in camp.survivors
        if s.get("baseline_equivalent")
    }
    novel_vecs = distinct_vecs - baseline_vecs
    ac["distinct_novel_vectors"] = len(novel_vecs)

    worker_errors = int(rej.get("worker_error", 0))
    has_novel_signal = novel_signal_count > 0 and len(novel_vecs) > 0
    if worker_errors:
        camp.status = "ERROR"
        camp.notes.append(
            f"worker_error count={worker_errors}; refusing to classify partial "
            "worker failures as ELIMINATED or CANDIDATE_SIGNAL"
        )
    elif has_novel_signal:
        camp.status = "CANDIDATE_SIGNAL"
    elif tested < total_configs and max_configs is not None and tested >= max_configs:
        camp.status = "INCONCLUSIVE_BUDGET"
    elif len(completed_set) == len(masks):
        if baseline_equivalent_count > 0:
            camp.notes.append(
                f"ELIMINATED for novel signals; {baseline_equivalent_count} "
                f"baseline-equivalent Bean-passing triples reproduce the canonical "
                f"keystream (identity-at-cribs), which is the expected sanity baseline."
            )
        camp.status = "ELIMINATED"
    else:
        camp.status = "INCONCLUSIVE_BUDGET"

    camp.best = sorted(
        camp.survivors,
        key=lambda s: (s.get("best_ngram_per_char", -10.0)),
        reverse=True,
    )[:20]

    camp.per_worker_audit.sort(
        key=lambda e: (-int(e.get("processed_count", 0)), int(e.get("worker_pid", 0)))
    )

    camp.completed_chunk_ids = {
        str(mi): sorted(chunks) for mi, chunks in sorted(completed_chunks.items())
    }
    _persist_checkpoint(checkpoint_path, camp, completed_set, completed_chunks, rej)
    write_json_atomic(output_path, camp.to_dict())
    render_markdown_report(camp, output_path.with_suffix(".md"), cmd_line)
    return camp


# =============================================================================
# CLI
# =============================================================================


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Deterministic finite harness for the pre-transposition layer "
            "hypothesis (drops H1). Searches mask x transposition x variant "
            "with implied keystream from cribs. Bean-pass is the primary "
            "signal."
        )
    )
    p.add_argument("--mode", choices=("inventory", "smoke", "full"), default="smoke")
    p.add_argument("--max-configs", type=int, default=None)
    p.add_argument("--limit-masks", type=int, default=None)
    p.add_argument("--limit-transpositions", type=int, default=None)
    p.add_argument("--max-full-col-width", type=int, default=7)
    p.add_argument("--wider-col-sample-cap", type=int, default=40)
    p.add_argument("--random-masks", type=int, default=0)
    p.add_argument("--random-seed", type=int, default=1337)
    p.add_argument("--workers", type=int, default=max(1, mp.cpu_count() - 2))
    p.add_argument("--chunk-size", type=int, default=64)
    p.add_argument(
        "--checkpoint",
        type=Path,
        default=Path("results/h_pretransposition_layer/checkpoint.json"),
    )
    p.add_argument(
        "--output",
        type=Path,
        default=Path("results/h_pretransposition_layer/result.json"),
    )
    p.add_argument("--resume", action="store_true")
    p.add_argument("--force", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)

    masks = companion.build_mask_universe(
        include_random=args.random_masks, random_seed=args.random_seed
    )
    if args.limit_masks is not None:
        masks = masks[: args.limit_masks]

    transpositions = build_transposition_universe(
        max_full_col_width=args.max_full_col_width,
        wider_col_sample_cap=args.wider_col_sample_cap,
    )
    if args.limit_transpositions is not None:
        transpositions = transpositions[: args.limit_transpositions]

    if args.mode == "smoke":
        if args.limit_masks is None:
            masks = masks[:4]
        if args.limit_transpositions is None:
            transpositions = transpositions[:60]

    variants = tuple(CIPHER_VARIANTS)

    cmd_line = (
        "PYTHONPATH=src python3 "
        + " ".join([sys.argv[0], *map(str, (argv or sys.argv[1:]))])
    )

    mode = "inventory" if (args.dry_run or args.mode == "inventory") else args.mode

    camp = run_campaign(
        mode=mode,
        masks=masks,
        transpositions=transpositions,
        variants=variants,
        workers=max(1, args.workers),
        max_configs=args.max_configs,
        checkpoint_path=args.checkpoint,
        output_path=args.output,
        resume=args.resume,
        chunk_size=max(1, args.chunk_size),
        cmd_line=cmd_line,
        force_resume=args.force,
    )

    print(f"{camp.campaign_id} {camp.campaign_version}  status={camp.status}")
    print(f"  mode: {mode}  workers: {args.workers}")
    print(f"  masks: {len(masks)}  transpositions: {len(transpositions)}  variants: {len(variants)}")
    print(f"  total configs: {camp.inventory.get('total_configs')}")
    print(f"  tested: {camp.coverage.get('tested')}")
    print(f"  survivors (Bean-pass): {len(camp.survivors)}")
    print(f"  output: {args.output}")
    print(f"  checkpoint: {args.checkpoint}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
