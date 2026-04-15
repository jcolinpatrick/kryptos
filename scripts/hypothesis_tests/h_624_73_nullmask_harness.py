"""Deterministic finite harness for the 73-real / 24-null / Bean-admissibility family.

Goal
----
Convert the repeated 30-minute worker timeouts on "624-Bean exhaustive extension"
style theories into a bounded, reproducible, checkpointed cryptanalytic campaign
with explicit epistemic outcomes.

This harness does NOT claim to solve K4. It does NOT promote anything to
BREAKTHROUGH. It enumerates a **finite** universe of candidates under a
**clearly stated** assumption set, applies kernel-verified Bean and crib-score
checks, and returns one of:

- ELIMINATED            full finite coverage completed, zero survivors
- INCONCLUSIVE_BUDGET   partial coverage (limit hit), residual space untested
- INCONCLUSIVE_TOOLING  required tooling unavailable (e.g. quadgram file missing)
- CANDIDATE_SIGNAL      at least one survivor >= SIGNAL_THRESHOLD
- ERROR                 unhandled failure

Assumption set (H1 is *explicit*)
---------------------------------
The harness operates under a single, deliberately narrow assumption bundle.
All outputs are labelled as conditional on this bundle. Any elimination
produced by this harness is an elimination WITHIN these assumptions, not a
global elimination of K4.

  A1: canonical 97-char K4 CT exactly as in kryptos.kernel.constants.CT
  A2: 73 real ciphertext positions + 24 "null" positions, additive model
  A3: direct positional crib mapping (EASTNORTHEAST at 21-33, BERLINCLOCK at
      63-73), 0-indexed in the 97-char CT, preserved through the null mask
  A4: additive cipher family (Vigenere / Beaufort / Variant Beaufort)
  A5: key schedule is a function of REDUCED-space position (keyword repeats
      over the 73 kept positions)

Any result depending on A1-A5 is conditional on A1-A5. A3 in particular is
the H1-style claim the memo flagged — we *assume* it for the primary run and
expose the flag in every output artifact.

Mask model
----------
A mask M is a set of 24 positions in [0, 97) marked as "nulls" (deleted).
Kept positions K = sorted({0..96} \\ M); |K| = 73.

Crib-preserving masks satisfy M intersect CRIB_POSITIONS == empty. Under A3
the primary run uses only crib-preserving masks. Non-crib-preserving masks
are supported but are labelled ASSUMPTION_VIOLATED in the rejection counter
and emit zero-score entries.

Bean admissibility
------------------
Bean constraints (BEAN_EQ + BEAN_INEQ + BEAN_LINEAR) reference 97-space
positions 21-33 and 63-73. For a crib-preserving mask, every Bean-referenced
position is still present, so Bean is FULLY APPLICABLE. The harness builds a
"virtual 97-length" keystream whose crib-position entries come from the
reduced-space keystream at the mapped reduced position, and feeds that to
kryptos.kernel.constraints.bean.verify_bean_simple. Non-crib positions in the
virtual keystream are unused by the Bean check (the check only reads indices
inside CRIB_POSITIONS).

For non-crib-preserving masks the Bean check is not well-defined and is
labelled BEAN_NOT_APPLICABLE.

CLI
---
    PYTHONPATH=src python3 scripts/hypothesis_tests/h_624_73_nullmask_harness.py --help

Modes:
    inventory  print and write the candidate universe, no evaluation
    smoke      tiny bounded run (small mask + key limits, in-process)
    full       full structured enumeration up to --max-configs

Determinism
-----------
- masks enumerated in stable sort order: (family, generation_params, mask_id)
- keys iterated from sorted wordlists (thematic first, then short periodic)
- random mask family uses an explicit --random-seed
- campaign_version and universe_hash pinned into every artifact
- resume validates assumptions_hash + universe_hash or refuses

Parallelization
---------------
multiprocessing.Pool with imap_unordered over (mask_index, key_chunk) tasks.
Default workers = max(1, cpu_count() - 2). Ngram scorer is loaded once per
worker via the pool initializer, not per task. Bean and crib-score are
kernel-pure functions, pickling-safe, zero shared state.

No writes to exhaustion_log.json, docs/elimination_tiers.md, or the
internalledger. The controller interprets results via the output JSON.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import multiprocessing as mp
import os
import random
import signal
import sys
import time
import traceback
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

# --- Kernel imports (stdlib-only in core) -----------------------------------

from kryptos.kernel.constants import (
    ALPH,
    ALPH_IDX,
    BEAN_EQ,
    BEAN_INEQ,
    BEAN_LINEAR,
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
    varbeau_decrypt,
    vig_decrypt,
)

CAMPAIGN_ID = "h_624_73_nullmask"
CAMPAIGN_VERSION = "1.0.0"

# =============================================================================
# Assumption bundle
# =============================================================================


def build_assumptions() -> dict:
    """The single authoritative assumption bundle for this harness run.

    Every output artifact embeds this verbatim. Any change to this dict
    invalidates checkpoint resume (by design).
    """
    return {
        "assumes_direct_positional_crib_mapping": True,
        "assumes_canonical_97_ct": True,
        "assumes_additive_cipher_family": True,
        "assumes_73_real_24_null_model": True,
        "notes": [
            "H1 (direct positional crib mapping) is ASSUMED, not proven.",
            "Any elimination produced is conditional on this assumption bundle.",
            "Bean constraints are applied ONLY to crib-preserving masks under A3.",
            "Key schedule operates in REDUCED 73-space (keyword repeats over kept positions).",
            "Non-crib-preserving masks are labeled ASSUMPTION_VIOLATED and contribute zero score.",
        ],
    }


def hash_dict(d: dict) -> str:
    """Stable sha256 of a JSON-serialized dict."""
    payload = json.dumps(d, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# =============================================================================
# Startup validation
# =============================================================================


def validate_kernel_constants() -> None:
    """Sanity-check that the kernel constants match this harness's assumptions.

    kryptos.kernel.constants already runs _verify() at import time; this is
    a second belt-and-suspenders check anchored to THIS harness's specific
    expectations (Bean-set sizes, CT boundary, crib layout).
    """
    assert len(CT) == CT_LEN == 97, f"CT length sanity {len(CT)} != 97"
    assert CT.isalpha() and CT.isupper(), "CT must be uppercase A-Z"
    assert len(CRIB_POSITIONS) == 24, f"Expected 24 crib positions, got {len(CRIB_POSITIONS)}"
    assert len(BEAN_EQ) == 1 and len(BEAN_INEQ) == 242 and len(BEAN_LINEAR) == 101, (
        f"Bean set size mismatch: eq={len(BEAN_EQ)} ineq={len(BEAN_INEQ)} lin={len(BEAN_LINEAR)}"
    )
    assert CRIB_DICT[21] == "E" and CRIB_DICT[33] == "T", "ENE crib layout"
    assert CRIB_DICT[63] == "B" and CRIB_DICT[73] == "K", "BC crib layout"
    assert MOD == 26


# =============================================================================
# Mask model
# =============================================================================

CRIB_SET = frozenset(CRIB_POSITIONS)
NON_CRIB_POSITIONS = tuple(p for p in range(CT_LEN) if p not in CRIB_SET)
# 97 - 24 = 73 non-crib positions.
assert len(NON_CRIB_POSITIONS) == 73


@dataclass(frozen=True)
class Mask:
    """A null-mask: 24 deleted positions in the 97-char CT space.

    Fields are read-only / hashable so masks can live inside tuples, be used
    as dict keys, and survive pickling without mutation risk.
    """

    mask_id: str
    family: str
    description: str
    deleted_positions: tuple[int, ...]  # length 24, sorted
    kept_positions: tuple[int, ...]  # length 73, sorted
    is_exhaustive_within_family: bool
    generation_parameters: dict

    def preserves_cribs(self) -> bool:
        return CRIB_SET.isdisjoint(self.deleted_positions)

    def crib_to_reduced(self) -> dict[int, int]:
        """For each original crib position that is KEPT, its index in kept_positions."""
        rank: dict[int, int] = {}
        for idx, orig in enumerate(self.kept_positions):
            if orig in CRIB_SET:
                rank[orig] = idx
        return rank


def _validate_mask(deleted: Iterable[int]) -> tuple[tuple[int, ...], tuple[int, ...]]:
    d = tuple(sorted(set(int(p) for p in deleted)))
    assert len(d) == 24, f"mask must delete exactly 24 positions, got {len(d)}"
    assert all(0 <= p < CT_LEN for p in d), "mask positions must be in [0, 97)"
    kept = tuple(p for p in range(CT_LEN) if p not in set(d))
    assert len(kept) == 73
    return d, kept


def _mask_fingerprint(family: str, deleted: tuple[int, ...]) -> str:
    payload = f"{family}|" + ",".join(str(p) for p in deleted)
    return hashlib.sha1(payload.encode("ascii")).hexdigest()[:12]


# --- Mask family generators -------------------------------------------------


def gen_tail_block_masks() -> list[Mask]:
    """Single canonical baseline mask: delete the last 24 non-crib positions."""
    deleted = tuple(sorted(NON_CRIB_POSITIONS[-24:]))
    d, k = _validate_mask(deleted)
    return [
        Mask(
            mask_id=f"tail24-{_mask_fingerprint('tail_block', d)}",
            family="tail_block",
            description="Delete the last 24 non-crib positions (baseline).",
            deleted_positions=d,
            kept_positions=k,
            is_exhaustive_within_family=True,
            generation_parameters={"variant": "last_24_non_crib"},
        )
    ]


def gen_head_block_masks() -> list[Mask]:
    """Single canonical baseline mask: delete the first 24 non-crib positions."""
    deleted = tuple(sorted(NON_CRIB_POSITIONS[:24]))
    d, k = _validate_mask(deleted)
    return [
        Mask(
            mask_id=f"head24-{_mask_fingerprint('head_block', d)}",
            family="head_block",
            description="Delete the first 24 non-crib positions (baseline).",
            deleted_positions=d,
            kept_positions=k,
            is_exhaustive_within_family=True,
            generation_parameters={"variant": "first_24_non_crib"},
        )
    ]


def gen_periodic_step_masks() -> list[Mask]:
    """Periodic "delete every k-th non-crib position starting at phase p".

    Enumerates (step k, phase p) for small k, accepts only those pairs that
    produce exactly 24 deletions. The enumeration is exhaustive within the
    parameter range and deterministic.
    """
    masks: list[Mask] = []
    non_crib = NON_CRIB_POSITIONS  # len 73
    for k in range(2, 11):
        for phase in range(k):
            picked = tuple(non_crib[i] for i in range(phase, len(non_crib), k))
            if len(picked) != 24:
                continue
            if not CRIB_SET.isdisjoint(picked):
                continue
            d, kept = _validate_mask(picked)
            masks.append(
                Mask(
                    mask_id=f"pstep-k{k}p{phase}-{_mask_fingerprint('periodic_step', d)}",
                    family="periodic_step",
                    description=f"Every {k}th non-crib position, phase {phase}.",
                    deleted_positions=d,
                    kept_positions=kept,
                    is_exhaustive_within_family=True,
                    generation_parameters={"step": k, "phase": phase},
                )
            )
    return masks


def gen_residue_class_masks() -> list[Mask]:
    """Residue-class masks: delete positions p where p mod W in S.

    For each width W and each subset S of {0..W-1} whose induced deletion
    count is exactly 24 AND misses all crib positions, emit one mask. Only
    singleton S and pair S are enumerated to keep the family bounded.
    """
    masks: list[Mask] = []
    for W in (3, 4, 5, 6, 7, 8, 11, 13, 14, 21, 24):
        # singleton residue classes
        for r in range(W):
            picked = tuple(p for p in range(CT_LEN) if p % W == r)
            if len(picked) != 24:
                continue
            if not CRIB_SET.isdisjoint(picked):
                continue
            d, kept = _validate_mask(picked)
            masks.append(
                Mask(
                    mask_id=f"res-W{W}r{r}-{_mask_fingerprint('residue_class', d)}",
                    family="residue_class",
                    description=f"Positions p where p mod {W} == {r}.",
                    deleted_positions=d,
                    kept_positions=kept,
                    is_exhaustive_within_family=True,
                    generation_parameters={"width": W, "residues": [r]},
                )
            )
        # pair residue classes (union of two singleton classes), ordered
        for r1 in range(W):
            for r2 in range(r1 + 1, W):
                picked = tuple(p for p in range(CT_LEN) if p % W in (r1, r2))
                if len(picked) != 24:
                    continue
                if not CRIB_SET.isdisjoint(picked):
                    continue
                d, kept = _validate_mask(picked)
                masks.append(
                    Mask(
                        mask_id=f"res-W{W}r{r1},{r2}-{_mask_fingerprint('residue_class', d)}",
                        family="residue_class",
                        description=f"Positions p where p mod {W} in {{{r1},{r2}}}.",
                        deleted_positions=d,
                        kept_positions=kept,
                        is_exhaustive_within_family=True,
                        generation_parameters={"width": W, "residues": [r1, r2]},
                    )
                )
    return masks


def gen_width_row_masks() -> list[Mask]:
    """Width-derived row masks: for each W, delete an entire row of the WxH grid.

    The grid is row-major, written across then wrapping. If row R has exactly
    24 cells and none are cribs, it is a valid mask.
    """
    masks: list[Mask] = []
    for W in (7, 8, 14, 21, 24):
        rows_total = math.ceil(CT_LEN / W)
        for r in range(rows_total):
            row_positions = tuple(
                p for p in range(r * W, min((r + 1) * W, CT_LEN))
            )
            if len(row_positions) != 24:
                continue
            if not CRIB_SET.isdisjoint(row_positions):
                continue
            d, kept = _validate_mask(row_positions)
            masks.append(
                Mask(
                    mask_id=f"wrow-W{W}r{r}-{_mask_fingerprint('width_row', d)}",
                    family="width_row",
                    description=f"Width-{W} grid row {r} (24 cells).",
                    deleted_positions=d,
                    kept_positions=kept,
                    is_exhaustive_within_family=True,
                    generation_parameters={"width": W, "row": r},
                )
            )
    return masks


def gen_width_column_masks() -> list[Mask]:
    """Width-derived column masks: for each W, delete an entire column.

    The column at index c in a WxH grid selects positions c, c+W, c+2W, ...
    If exactly 24 and no cribs, emit a mask.
    """
    masks: list[Mask] = []
    for W in (3, 4, 5, 6, 7, 8, 11, 13, 14, 21, 24):
        for c in range(W):
            col_positions = tuple(range(c, CT_LEN, W))
            if len(col_positions) != 24:
                continue
            if not CRIB_SET.isdisjoint(col_positions):
                continue
            d, kept = _validate_mask(col_positions)
            masks.append(
                Mask(
                    mask_id=f"wcol-W{W}c{c}-{_mask_fingerprint('width_column', d)}",
                    family="width_column",
                    description=f"Width-{W} grid column {c} (24 cells).",
                    deleted_positions=d,
                    kept_positions=kept,
                    is_exhaustive_within_family=True,
                    generation_parameters={"width": W, "column": c},
                )
            )
    return masks


def gen_non_crib_contiguous_masks() -> list[Mask]:
    """Contiguous non-crib blocks.

    Within the 73 non-crib positions (indexed 0..72 in non-crib order), a
    contiguous 24-block starts at non-crib index s for s in 0..49. Each such
    block maps back to a concrete set of 24 original-CT positions.
    """
    masks: list[Mask] = []
    non_crib = NON_CRIB_POSITIONS
    for s in range(0, len(non_crib) - 24 + 1):
        picked = tuple(non_crib[s : s + 24])
        d, kept = _validate_mask(picked)
        masks.append(
            Mask(
                mask_id=f"ncblk-s{s}-{_mask_fingerprint('non_crib_contig', d)}",
                family="non_crib_contig",
                description=f"Contiguous non-crib block starting at non-crib index {s}.",
                deleted_positions=d,
                kept_positions=kept,
                is_exhaustive_within_family=True,
                generation_parameters={"start_non_crib_idx": s},
            )
        )
    return masks


def gen_non_crib_split_masks() -> list[Mask]:
    """Split-block masks: first N non-crib + last (24-N) non-crib positions."""
    masks: list[Mask] = []
    non_crib = NON_CRIB_POSITIONS
    for n_head in range(1, 24):
        n_tail = 24 - n_head
        if n_head + n_tail > len(non_crib):
            continue
        head = non_crib[:n_head]
        tail = non_crib[-n_tail:]
        # Skip if head and tail overlap (shouldn't happen given 24 < 73, but be safe)
        if set(head) & set(tail):
            continue
        picked = tuple(sorted(set(head) | set(tail)))
        if len(picked) != 24:
            continue
        d, kept = _validate_mask(picked)
        masks.append(
            Mask(
                mask_id=f"ncsplit-h{n_head}t{n_tail}-{_mask_fingerprint('non_crib_split', d)}",
                family="non_crib_split",
                description=f"First {n_head} + last {n_tail} non-crib positions.",
                deleted_positions=d,
                kept_positions=kept,
                is_exhaustive_within_family=True,
                generation_parameters={"n_head": n_head, "n_tail": n_tail},
            )
        )
    return masks


def gen_non_crib_stride_masks() -> list[Mask]:
    """Stride-over-non-crib-indices: delete every k-th non-crib position.

    Differs from gen_periodic_step_masks in that k and phase are indexed
    over the compacted 73-element non-crib sequence rather than the 97-element
    original sequence. Many more valid (k, phase) pairs exist here.
    """
    masks: list[Mask] = []
    non_crib = NON_CRIB_POSITIONS
    for k in range(2, 11):
        for phase in range(k):
            picked = tuple(non_crib[i] for i in range(phase, len(non_crib), k))
            if len(picked) != 24:
                continue
            d, kept = _validate_mask(picked)
            masks.append(
                Mask(
                    mask_id=f"ncstride-k{k}p{phase}-{_mask_fingerprint('non_crib_stride', d)}",
                    family="non_crib_stride",
                    description=f"Every {k}th non-crib position, phase {phase}.",
                    deleted_positions=d,
                    kept_positions=kept,
                    is_exhaustive_within_family=True,
                    generation_parameters={"step_in_non_crib_space": k, "phase": phase},
                )
            )
    return masks


def gen_random_sampled_masks(n: int, seed: int) -> list[Mask]:
    """Seeded stochastic sampling of crib-preserving masks.

    Explicitly labelled NON-exhaustive. Used only as a tiebreaker/smoke
    family; not suitable as the basis of any elimination claim.
    """
    rng = random.Random(seed)
    pool = list(NON_CRIB_POSITIONS)
    masks: list[Mask] = []
    seen: set[tuple[int, ...]] = set()
    tries = 0
    max_tries = max(n * 20, 1000)
    while len(masks) < n and tries < max_tries:
        tries += 1
        picked = tuple(sorted(rng.sample(pool, 24)))
        if picked in seen:
            continue
        seen.add(picked)
        d, kept = _validate_mask(picked)
        masks.append(
            Mask(
                mask_id=f"rand-s{seed}n{len(masks)}-{_mask_fingerprint('random_sampled', d)}",
                family="random_sampled",
                description=f"Random sample (seed={seed}, idx={len(masks)}).",
                deleted_positions=d,
                kept_positions=kept,
                is_exhaustive_within_family=False,
                generation_parameters={"seed": seed, "idx": len(masks)},
            )
        )
    return masks


def build_mask_universe(
    include_random: int = 0,
    random_seed: int = 1337,
) -> list[Mask]:
    """Build the full deterministic mask universe.

    Order is stable: (family, fingerprint). Random masks, if requested, are
    appended last and marked non-exhaustive.
    """
    masks: list[Mask] = []
    masks.extend(gen_head_block_masks())
    masks.extend(gen_tail_block_masks())
    masks.extend(gen_periodic_step_masks())
    masks.extend(gen_residue_class_masks())
    masks.extend(gen_width_row_masks())
    masks.extend(gen_width_column_masks())
    masks.extend(gen_non_crib_contiguous_masks())
    masks.extend(gen_non_crib_split_masks())
    masks.extend(gen_non_crib_stride_masks())
    if include_random > 0:
        masks.extend(gen_random_sampled_masks(include_random, random_seed))
    # Dedupe by deleted_positions (different families can produce the same mask).
    seen: dict[tuple[int, ...], Mask] = {}
    for m in masks:
        if m.deleted_positions not in seen:
            seen[m.deleted_positions] = m
    result = list(seen.values())
    result.sort(key=lambda m: (m.family, m.mask_id))
    return result


# =============================================================================
# Key model
# =============================================================================


def load_thematic_keywords(max_len: int = 12) -> list[str]:
    """Read wordlists/thematic_keywords.txt, return A-Z uppercase strings,
    length-filtered and deduped, preserving sort order for determinism.
    """
    path = Path("wordlists/thematic_keywords.txt")
    if not path.exists():
        return []
    seen: set[str] = set()
    result: list[str] = []
    for raw in path.read_text().splitlines():
        w = raw.strip().upper()
        if not w:
            continue
        if not w.isalpha() or not w.isascii():
            continue
        if len(w) < 3 or len(w) > max_len:
            continue
        if w in seen:
            continue
        seen.add(w)
        result.append(w)
    result.sort()
    return result


def load_english_short_keywords(min_len: int = 4, max_len: int = 8, cap: int = 5000) -> list[str]:
    """Length-bounded slice of wordlists/english.txt for breadth without blowup."""
    path = Path("wordlists/english.txt")
    if not path.exists():
        return []
    seen: set[str] = set()
    result: list[str] = []
    with path.open() as f:
        for raw in f:
            w = raw.strip().upper()
            if not w or not w.isalpha() or not w.isascii():
                continue
            if len(w) < min_len or len(w) > max_len:
                continue
            if w in seen:
                continue
            seen.add(w)
            result.append(w)
            if len(result) >= cap:
                break
    result.sort()
    return result


@dataclass(frozen=True)
class Key:
    """A keystream generator operating in REDUCED 73-space.

    The keyword repeats positionally: reduced_key[i] = AZ_IDX[keyword[i % L]].
    """

    key_id: str
    family: str
    keyword: str
    period: int
    source: str

    def to_numeric(self) -> tuple[int, ...]:
        return tuple(ALPH_IDX[c] for c in self.keyword)


def build_key_universe(
    limit_thematic: Optional[int] = None,
    include_english: bool = False,
    english_min: int = 4,
    english_max: int = 8,
    limit_english: int = 5000,
) -> list[Key]:
    """Build deterministic key universe. Thematic first, then optional english."""
    keys: list[Key] = []
    thematic = load_thematic_keywords(max_len=12)
    if limit_thematic is not None:
        thematic = thematic[:limit_thematic]
    for kw in thematic:
        keys.append(
            Key(
                key_id=f"thm:{kw}",
                family="thematic",
                keyword=kw,
                period=len(kw),
                source="wordlists/thematic_keywords.txt",
            )
        )
    if include_english:
        english = load_english_short_keywords(english_min, english_max, limit_english)
        for kw in english:
            keys.append(
                Key(
                    key_id=f"eng:{kw}",
                    family="english_short",
                    keyword=kw,
                    period=len(kw),
                    source=f"wordlists/english.txt[{english_min}..{english_max}]",
                )
            )
    return keys


# =============================================================================
# Evaluation core
# =============================================================================


CIPHER_VARIANTS = ("vigenere", "beaufort", "varbeau")


def _ct_to_nums() -> tuple[int, ...]:
    return tuple(ALPH_IDX[c] for c in CT)


CT_NUMS = _ct_to_nums()


@dataclass
class EvalResult:
    """Outcome of evaluating one (mask, variant, key) triple."""

    mask_id: str
    family: str
    variant: str
    key_id: str
    keyword: str
    crib_score: int
    bean_passed: bool
    bean_applicable: bool
    ngram_per_char: float
    assumption_violated: bool
    rejection_reason: str  # "" if accepted as survivor
    pt73: str  # reduced-space plaintext (may be truncated in storage)


def _decrypt_fn(variant: str):
    if variant == "vigenere":
        return vig_decrypt
    if variant == "beaufort":
        return beau_decrypt
    if variant == "varbeau":
        return varbeau_decrypt
    raise ValueError(f"unknown variant {variant}")


def evaluate_triple(
    mask: Mask,
    variant: str,
    key: Key,
    ngram_scorer=None,
) -> EvalResult:
    """Pure function: evaluate one (mask, variant, key) triple.

    No side effects. No IO. No LLM. Safe to call from a worker subprocess.
    """
    if not mask.preserves_cribs():
        return EvalResult(
            mask_id=mask.mask_id,
            family=mask.family,
            variant=variant,
            key_id=key.key_id,
            keyword=key.keyword,
            crib_score=0,
            bean_passed=False,
            bean_applicable=False,
            ngram_per_char=0.0,
            assumption_violated=True,
            rejection_reason="assumption_violated_non_crib_preserving",
            pt73="",
        )

    key_nums = key.to_numeric()
    L = len(key_nums)
    fn = _decrypt_fn(variant)

    kept = mask.kept_positions  # length 73
    pt_nums: list[int] = []
    for i, orig in enumerate(kept):
        c = CT_NUMS[orig]
        k = key_nums[i % L]
        pt_nums.append(fn(c, k))
    pt73 = "".join(ALPH[v] for v in pt_nums)

    # Crib score against the reduced-position mapping of original cribs.
    crib_map = mask.crib_to_reduced()  # {orig_pos -> reduced_idx}
    matches = 0
    for orig_pos, expected in CRIB_DICT.items():
        r = crib_map.get(orig_pos)
        if r is None:
            continue
        if pt_nums[r] == ALPH_IDX[expected]:
            matches += 1
    crib_score = matches

    # Bean admissibility: build virtual 97-length keystream using
    # reduced-space keystream values at kept positions, and feed to
    # verify_bean_simple. Bean only reads crib indices; under a
    # crib-preserving mask every crib position is kept, so the check
    # is fully applicable.
    virt_key: list[int] = [0] * CT_LEN
    for i, orig in enumerate(kept):
        virt_key[orig] = key_nums[i % L]
    # Under Vigenere: K = C - P ; under Beaufort: K = C + P ;
    # under VarBeaufort: K = P - C . Bean sits over whichever K we USED
    # which means our virtual key is (for the kept positions) the actual
    # additive key the cipher applied at those positions.
    bean_applicable = True
    bean_passed = verify_bean_simple(virt_key)

    # Ngram score on the reduced plaintext, if scorer available.
    ngram_per_char = 0.0
    if ngram_scorer is not None:
        try:
            ngram_per_char = float(ngram_scorer.score_per_char(pt73))
        except Exception:
            ngram_per_char = 0.0

    # Classify.
    rejection = ""
    if crib_score < NOISE_FLOOR:
        rejection = "crib_score_below_noise"

    return EvalResult(
        mask_id=mask.mask_id,
        family=mask.family,
        variant=variant,
        key_id=key.key_id,
        keyword=key.keyword,
        crib_score=crib_score,
        bean_passed=bean_passed,
        bean_applicable=bean_applicable,
        ngram_per_char=ngram_per_char,
        assumption_violated=False,
        rejection_reason=rejection,
        pt73=pt73,
    )


# =============================================================================
# Multiprocessing worker harness
# =============================================================================


_WORKER_NGRAM = None  # module-level handle per worker process


def _worker_init() -> None:
    """Pool initializer: load the quadgram scorer once per worker process."""
    global _WORKER_NGRAM
    try:
        from kryptos.kernel.scoring.ngram import get_default_scorer

        _WORKER_NGRAM = get_default_scorer()
    except Exception:
        _WORKER_NGRAM = None


NEAR_MISS_PER_WORKER = 50
PT73_SAMPLE_PER_WORKER = 20


def _worker_eval_chunk(
    payload: tuple[int, int, Mask, tuple[str, ...], tuple[Key, ...]],
) -> dict:
    """Evaluate a (mask_idx, chunk_id, mask, variants, key_chunk) block.

    Returns a dict with these fields:
      - mask_idx: echoed from input so the controller can attribute the result
                  to the correct mask regardless of imap_unordered arrival order
      - chunk_id: per-mask chunk identifier echoed from input
      - processed_count: number of triples actually evaluated by this worker;
                         the controller charges `tested` by this value, not by
                         any input-order assumption
      - survivors: list of survivor record dicts (crossed STORE_THRESHOLD or
                   Bean-passed above NOISE_FLOOR)
      - tallies: dict of rejection-reason and accepted-category counts
      - audit: forensic audit counters proving this worker actually did work
      - near_misses: local top-K near-misses below STORE_THRESHOLD

    The audit dict is the evidence Colin requested: every counter should
    reconcile against the total number of evaluated triples so a future
    review can prove no chunk short-circuited.
    """
    mask_idx, chunk_id, mask, variants, key_chunk = payload
    survivors: list[dict] = []
    tallies: Counter = Counter()
    crib_histogram: Counter = Counter()
    bean_invocations = 0
    bean_pass = 0
    bean_fail = 0
    bean_not_applicable = 0
    ngram_invocations = 0
    pt73_seen: dict[str, None] = {}  # ordered dict, deterministic sampling
    pt73_sample_fingerprints: list[str] = []
    # local top-K near-miss heap (below STORE_THRESHOLD), keyed by (crib_score,
    # lex tiebreakers). We use a simple sorted list kept at size K because K
    # is small (50) and insertion cost is negligible vs the inner loop.
    local_near_misses: list[dict] = []

    for variant in variants:
        for key in key_chunk:
            tallies["evaluated"] += 1
            try:
                r = evaluate_triple(mask, variant, key, ngram_scorer=_WORKER_NGRAM)
            except Exception as exc:
                tallies["worker_error"] += 1
                survivors.append(
                    {
                        "_error": True,
                        "mask_id": mask.mask_id,
                        "variant": variant,
                        "key_id": key.key_id,
                        "exc": repr(exc)[:200],
                    }
                )
                continue

            # Audit bookkeeping — runs for EVERY evaluated triple so sums
            # reconcile cleanly.
            crib_histogram[int(r.crib_score)] += 1
            if r.bean_applicable:
                bean_invocations += 1
                if r.bean_passed:
                    bean_pass += 1
                else:
                    bean_fail += 1
            else:
                bean_not_applicable += 1
            if _WORKER_NGRAM is not None and not r.assumption_violated:
                # evaluate_triple always calls score_per_char when scorer is
                # present and the triple is not assumption-violated (which
                # short-circuits before scoring).
                ngram_invocations += 1
            # pt73 distinct-sample: cap to PT73_SAMPLE_PER_WORKER unique values.
            if r.pt73 and len(pt73_seen) < PT73_SAMPLE_PER_WORKER:
                if r.pt73 not in pt73_seen:
                    pt73_seen[r.pt73] = None
                    pt73_sample_fingerprints.append(
                        hashlib.sha1(r.pt73.encode("ascii")).hexdigest()[:12]
                    )

            if r.assumption_violated:
                tallies["assumption_violated_non_crib_preserving"] += 1
                continue

            cs = r.crib_score
            is_store = cs >= STORE_THRESHOLD
            is_bean_above_noise = r.bean_passed and cs >= NOISE_FLOOR

            if cs < NOISE_FLOOR:
                tallies["crib_score_below_noise"] += 1
                continue
            if cs < STORE_THRESHOLD:
                tallies["crib_score_sub_store"] += 1
                if r.bean_passed:
                    tallies["bean_pass_sub_store"] += 1
                # Near-miss tracking for below-STORE results.
                _insert_near_miss(
                    local_near_misses,
                    {
                        "mask_id": r.mask_id,
                        "family": r.family,
                        "variant": r.variant,
                        "key_id": r.key_id,
                        "keyword": r.keyword,
                        "crib_score": cs,
                        "bean_passed": r.bean_passed,
                        "ngram_per_char": r.ngram_per_char,
                    },
                    NEAR_MISS_PER_WORKER,
                )
                if not is_bean_above_noise:
                    continue
            if cs >= BREAKTHROUGH_THRESHOLD and r.bean_passed:
                tallies["accepted_breakthrough"] += 1
            elif cs >= SIGNAL_THRESHOLD and r.bean_passed:
                tallies["accepted_signal_bean_pass"] += 1
            elif cs >= SIGNAL_THRESHOLD:
                tallies["accepted_signal_no_bean"] += 1
            elif is_store:
                tallies["accepted_store"] += 1
                if not r.bean_passed:
                    tallies["accepted_store_bean_fail"] += 1
            else:
                tallies["accepted_bean_subsignal"] += 1

            survivors.append(
                {
                    "mask_id": r.mask_id,
                    "family": r.family,
                    "variant": r.variant,
                    "key_id": r.key_id,
                    "keyword": r.keyword,
                    "crib_score": cs,
                    "bean_passed": r.bean_passed,
                    "bean_applicable": r.bean_applicable,
                    "ngram_per_char": r.ngram_per_char,
                    "pt73": r.pt73,
                    "assumption_violated": False,
                }
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
            "crib_histogram": {int(k): int(v) for k, v in crib_histogram.items()},
            "bean_invocations": bean_invocations,
            "bean_pass": bean_pass,
            "bean_fail": bean_fail,
            "bean_not_applicable": bean_not_applicable,
            "ngram_invocations": ngram_invocations,
            "pt73_distinct_sampled": len(pt73_seen),
            "pt73_sample_fingerprints": pt73_sample_fingerprints,
        },
        "near_misses": local_near_misses,
    }


def _near_miss_sort_key(entry: dict) -> tuple:
    # Stable desc-by-crib-score, then lex by mask/key/variant for tie-break.
    return (
        -int(entry.get("crib_score", 0)),
        -float(entry.get("ngram_per_char", 0.0)),
        str(entry.get("mask_id", "")),
        str(entry.get("variant", "")),
        str(entry.get("key_id", "")),
    )


def _insert_near_miss(bucket: list[dict], entry: dict, cap: int) -> None:
    """Insert with top-K trimming. O(log K) would need heapq; at K=50 the
    linear insort is faster in practice and keeps ordering explicit."""
    bucket.append(entry)
    bucket.sort(key=_near_miss_sort_key)
    if len(bucket) > cap:
        del bucket[cap:]


def _chunk(seq: list[Key], size: int) -> Iterator[tuple[Key, ...]]:
    for i in range(0, len(seq), size):
        yield tuple(seq[i : i + size])


# =============================================================================
# Checkpoint + output
# =============================================================================


NEAR_MISS_GLOBAL_CAP = 100


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
    coverage: dict = field(default_factory=lambda: {"tested": 0, "total": 0, "coverage_fraction": 0.0})
    best: list[dict] = field(default_factory=list)
    survivors: list[dict] = field(default_factory=list)
    near_misses: list[dict] = field(default_factory=list)
    rejection_counts: dict = field(default_factory=dict)
    audit_counters: dict = field(default_factory=dict)
    per_worker_audit: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    # Resume state:
    completed_mask_indices: list[int] = field(default_factory=list)
    completed_chunk_ids: dict[str, list[int]] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def compute_universe_hash(masks: list[Mask], keys: list[Key], variants: tuple[str, ...]) -> str:
    h = hashlib.sha256()
    h.update(CAMPAIGN_VERSION.encode())
    h.update(f"masks={len(masks)}".encode())
    for m in masks:
        h.update(m.mask_id.encode())
    h.update(f"keys={len(keys)}".encode())
    for k in keys:
        h.update(k.key_id.encode())
    h.update(f"variants={','.join(variants)}".encode())
    h.update(
        f"thresh={NOISE_FLOOR},{STORE_THRESHOLD},{SIGNAL_THRESHOLD},{BREAKTHROUGH_THRESHOLD}".encode()
    )
    return h.hexdigest()


def write_json_atomic(path: Path, doc: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(doc, indent=2, default=str))
    tmp.replace(path)


def render_markdown_report(camp: Campaign, out_path: Path, cmd_line: str) -> None:
    lines: list[str] = []
    lines.append(f"# {camp.campaign_id} {camp.campaign_version} -- {camp.status}")
    lines.append("")
    lines.append(f"- started: `{camp.started_at}`")
    lines.append(f"- completed: `{camp.completed_at}`")
    lines.append(f"- mode: `{camp.mode}`")
    lines.append(f"- assumptions_hash: `{camp.assumptions_hash[:16]}`")
    lines.append(f"- universe_hash: `{camp.universe_hash[:16]}`")
    lines.append("")
    lines.append("## Assumption bundle")
    lines.append("")
    for k, v in camp.assumptions.items():
        if k == "notes":
            continue
        lines.append(f"- `{k}`: **{v}**")
    lines.append("")
    lines.append("**Notes**:")
    for n in camp.assumptions.get("notes", []):
        lines.append(f"- {n}")
    lines.append("")
    lines.append("## Inventory")
    lines.append("")
    for k, v in camp.inventory.items():
        lines.append(f"- `{k}`: {v}")
    lines.append("")
    lines.append("## Coverage")
    lines.append("")
    cov = camp.coverage
    lines.append(f"- tested: `{cov.get('tested', 0)}`")
    lines.append(f"- total: `{cov.get('total', 0)}`")
    lines.append(f"- fraction: `{cov.get('coverage_fraction', 0.0):.6f}`")
    lines.append("")
    lines.append("## Rejection counts")
    lines.append("")
    if camp.rejection_counts:
        for k, v in sorted(camp.rejection_counts.items(), key=lambda kv: -kv[1]):
            lines.append(f"- `{k}`: {v}")
    else:
        lines.append("- (none)")
    lines.append("")
    # Forensic audit section: evidence every worker actually did work.
    lines.append("## Audit counters (forensic)")
    lines.append("")
    ac = camp.audit_counters or {}
    if ac:
        lines.append(f"- processed_count: `{ac.get('processed_count', 0)}`")
        lines.append(f"- bean_invocations: `{ac.get('bean_invocations', 0)}`")
        lines.append(
            f"- bean_pass / fail / n/a: "
            f"`{ac.get('bean_pass', 0)}` / "
            f"`{ac.get('bean_fail', 0)}` / "
            f"`{ac.get('bean_not_applicable', 0)}`"
        )
        lines.append(f"- ngram_invocations: `{ac.get('ngram_invocations', 0)}`")
        lines.append(f"- pt73_distinct_total (sampled): `{ac.get('pt73_distinct_total', 0)}`")
        lines.append("")
        lines.append("### Global crib-score histogram")
        lines.append("")
        hist = ac.get("crib_histogram", {})
        if hist:
            for k in sorted((int(x) for x in hist.keys())):
                lines.append(f"- `{k}`: {hist[k] if k in hist else hist.get(str(k), 0)}")
        lines.append("")
    else:
        lines.append("- (no audit data — inventory-only or pre-run)")
        lines.append("")

    if camp.per_worker_audit:
        lines.append("## Per-worker audit")
        lines.append("")
        lines.append("| pid | chunks | processed | bean_inv | bean_pass | bean_fail | bean_na | ngram_inv |")
        lines.append("|---|---|---|---|---|---|---|---|")
        for e in camp.per_worker_audit:
            lines.append(
                f"| {e.get('worker_pid')} | {e.get('chunks', 0)} | "
                f"{e.get('processed_count', 0)} | {e.get('bean_invocations', 0)} | "
                f"{e.get('bean_pass', 0)} | {e.get('bean_fail', 0)} | "
                f"{e.get('bean_not_applicable', 0)} | {e.get('ngram_invocations', 0)} |"
            )
        lines.append("")

    lines.append("## Top near-misses (below STORE threshold)")
    lines.append("")
    if camp.near_misses:
        for nm in camp.near_misses[:20]:
            lines.append(
                f"- crib=`{nm.get('crib_score')}`  "
                f"bean=`{nm.get('bean_passed')}`  "
                f"ngram=`{nm.get('ngram_per_char'):.3f}`  "
                f"variant=`{nm.get('variant')}`  "
                f"mask=`{nm.get('mask_id')}`  "
                f"key=`{nm.get('key_id')}`"
            )
    else:
        lines.append("- (no near-misses below STORE recorded)")
    lines.append("")

    lines.append("## Top survivors")
    lines.append("")
    if camp.survivors:
        sorted_survivors = sorted(
            camp.survivors,
            key=lambda s: (s.get("crib_score", 0), s.get("ngram_per_char", 0.0)),
            reverse=True,
        )
        for s in sorted_survivors[:20]:
            lines.append(
                f"- crib={s.get('crib_score')}  bean={s.get('bean_passed')}  "
                f"variant={s.get('variant')}  mask={s.get('mask_id')}  key={s.get('key_id')}"
            )
    else:
        lines.append("- (no survivors above STORE threshold)")
    lines.append("")
    lines.append("## Reproduction")
    lines.append("")
    lines.append("```bash")
    lines.append(cmd_line)
    lines.append("```")
    lines.append("")
    lines.append("## Epistemic reading")
    lines.append("")
    if camp.status == "ELIMINATED":
        lines.append(
            "Full finite coverage completed under the stated assumption bundle; "
            "zero survivors at or above STORE_THRESHOLD. This is a **conditional** "
            "elimination: it rules out the enumerated mask/key universe under the "
            "H1 null-mask assumption only. It does NOT eliminate K4 globally and "
            "does NOT rule out mask or key families outside the enumerated set."
        )
    elif camp.status == "INCONCLUSIVE_BUDGET":
        lines.append(
            "Budget limit hit before full coverage. Untested residual space "
            "remains. Interpret as INCONCLUSIVE, not as elimination."
        )
    elif camp.status == "INCONCLUSIVE_TOOLING":
        lines.append(
            "Required tooling unavailable (see notes). No epistemic conclusion "
            "can be drawn from this run."
        )
    elif camp.status == "CANDIDATE_SIGNAL":
        lines.append(
            "At least one survivor at or above SIGNAL_THRESHOLD. This is NOT a "
            "solution claim. Route through normal Day 5/6 alert + stat-audit + "
            "provenance gates before any promotion."
        )
    else:
        lines.append(f"Status: {camp.status}")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines))


# =============================================================================
# Run loop
# =============================================================================


def run_campaign(
    mode: str,
    masks: list[Mask],
    keys: list[Key],
    variants: tuple[str, ...],
    workers: int,
    max_configs: Optional[int],
    checkpoint_path: Path,
    output_path: Path,
    resume: bool,
    key_chunk_size: int,
    cmd_line: str,
    force_resume: bool = False,
) -> Campaign:
    """Main execution loop. Multiprocessing, checkpointed, resumable."""
    assumptions = build_assumptions()
    a_hash = hash_dict(assumptions)
    u_hash = compute_universe_hash(masks, keys, variants)

    total_configs = len(masks) * len(keys) * len(variants)
    inventory = {
        "canonical_ct_length": CT_LEN,
        "assumed_real_length": 73,
        "null_count": 24,
        "crib_positions": sorted(CRIB_POSITIONS),
        "direct_positional_crib_mapping": True,
        "additive_cipher_family": True,
        "n_masks": len(masks),
        "n_masks_by_family": dict(Counter(m.family for m in masks)),
        "n_keys": len(keys),
        "n_keys_by_family": dict(Counter(k.family for k in keys)),
        "n_variants": len(variants),
        "variants": list(variants),
        "total_configs": total_configs,
        "pruning_rules": [
            "mask must delete exactly 24 positions",
            "mask must not delete any crib position (crib-preserving)",
            "crib_score < NOISE_FLOOR is a rejection (unless bean_passed AND crib_score >= NOISE_FLOOR)",
        ],
        "kill_criteria": [
            "zero survivors at or above STORE_THRESHOLD under full finite coverage => ELIMINATED (conditional)",
        ],
        "signal_criteria": {
            "NOISE_FLOOR": NOISE_FLOOR,
            "STORE_THRESHOLD": STORE_THRESHOLD,
            "SIGNAL_THRESHOLD": SIGNAL_THRESHOLD,
            "BREAKTHROUGH_THRESHOLD": BREAKTHROUGH_THRESHOLD,
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
    camp.rejection_counts = {}

    # Resume check
    resumed_from: Optional[dict] = None
    if resume and checkpoint_path.exists():
        try:
            prior = json.loads(checkpoint_path.read_text())
            if (
                prior.get("assumptions_hash") == a_hash
                and prior.get("universe_hash") == u_hash
                and prior.get("campaign_version") == CAMPAIGN_VERSION
            ) or force_resume:
                resumed_from = prior
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
                    f"resumed from checkpoint with {len(camp.completed_mask_indices)} "
                    f"mask(s) already complete"
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

    # Inventory-only mode exits here.
    if mode == "inventory":
        camp.status = "INVENTORY"
        camp.completed_at = datetime.now(timezone.utc).isoformat()
        write_json_atomic(output_path, camp.to_dict())
        md_path = output_path.with_suffix(".md")
        render_markdown_report(camp, md_path, cmd_line)
        return camp

    # Tooling check: ngram scorer.
    #
    # Policy (2026-04-14): for THIS harness, the ngram scorer is ADVISORY,
    # not gating. The discriminator is Bean PASS + crib_score >= SIGNAL,
    # which is genuinely strong evidence under the wordlist key universe
    # (no schedule in this harness can synthesize a Bean PASS by
    # construction; only the variant-correct crib keystream can).
    # Therefore ngram unavailability does NOT force INCONCLUSIVE_TOOLING
    # here — we proceed with ngram=0.0 per triple and append an advisory
    # note. Contrast with the companion nonword harness, where the
    # bean624_crib_anchored_extension family forces Bean PASS by
    # construction and ngram IS the discriminator.
    try:
        from kryptos.kernel.scoring.ngram import get_default_scorer

        _ = get_default_scorer()
    except Exception as exc:
        camp.notes.append(
            f"ngram scorer unavailable: {exc!r} -- "
            f"ngram is ADVISORY in this harness (Bean+crib is the gating "
            f"discriminator under the wordlist key universe); proceeding "
            f"with ngram=0.0 per triple"
        )

    completed_set = set(camp.completed_mask_indices)
    completed_chunks: dict[int, set[int]] = {
        int(mi): {int(ci) for ci in chunk_ids}
        for mi, chunk_ids in camp.completed_chunk_ids.items()
    }
    rej_counter: Counter = Counter(camp.rejection_counts)

    tested = int(camp.audit_counters.get("processed_count", 0))
    max_cfg = max_configs if max_configs is not None else total_configs

    # Prepare tasks (mask-scoped; one task per mask * key_chunk).
    # Each payload carries (mask_idx, chunk_id, mask, variants, key_chunk) so
    # the worker can echo the identity of the chunk it processed. This is the
    # fix for the imap_unordered mis-mapping bug: arrival order is not input
    # order, so the controller must read identity from the worker's output
    # instead of indexing back into the input list.
    chunks_per_mask: list[tuple[Key, ...]] = list(_chunk(keys, key_chunk_size))

    pending_payloads: list[tuple[int, int, Mask, tuple[str, ...], tuple[Key, ...]]] = []
    for mi, m in enumerate(masks):
        if mi in completed_set:
            continue
        for ci, ch in enumerate(chunks_per_mask):
            if ci in completed_chunks.get(mi, set()):
                continue
            pending_payloads.append((mi, ci, m, tuple(variants), ch))

    if not pending_payloads:
        camp.status = "ELIMINATED" if not any(
            s.get("crib_score", 0) >= SIGNAL_THRESHOLD for s in camp.survivors
        ) else "CANDIDATE_SIGNAL"
        camp.completed_at = datetime.now(timezone.utc).isoformat()
        camp.coverage["tested"] = tested
        camp.coverage["coverage_fraction"] = tested / total_configs if total_configs else 1.0
        camp.rejection_counts = dict(rej_counter)
        write_json_atomic(output_path, camp.to_dict())
        render_markdown_report(camp, output_path.with_suffix(".md"), cmd_line)
        return camp

    pool_ctx = mp.get_context("spawn") if workers > 1 else None
    if workers > 1:
        pool = pool_ctx.Pool(processes=workers, initializer=_worker_init)
    else:
        # Single-process: initialize ngram directly.
        _worker_init()
        pool = None

    mask_task_count: Counter = Counter()
    mask_task_done: Counter = Counter()
    for mi, _ci, _m, _v, _ch in pending_payloads:
        mask_task_count[mi] += 1

    def _record_result(out: dict) -> int:
        """Attribute a worker result to its mask using the echoed mask_idx.

        Returns the number of triples charged to `tested`. Uses the worker's
        own `processed_count` so that resume state and coverage accounting
        are correct regardless of imap_unordered arrival order.
        """
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
        _absorb_chunk(out, rej_counter, camp)
        completed_chunks.setdefault(mi, set()).add(ci)
        if len(completed_chunks.get(mi, set())) == len(chunks_per_mask):
            completed_set.add(mi)
        return processed

    try:
        if pool is not None:
            results_received = 0
            for out in pool.imap_unordered(_worker_eval_chunk, pending_payloads):
                delta = _record_result(out)
                tested += delta
                camp.coverage["tested"] = tested
                camp.coverage["coverage_fraction"] = tested / total_configs
                results_received += 1
                if results_received % 8 == 0 or tested >= max_cfg:
                    _persist_checkpoint(
                        checkpoint_path, camp, completed_set, completed_chunks, rej_counter
                    )
                if tested >= max_cfg:
                    break
        else:
            for idx, payload in enumerate(pending_payloads):
                out = _worker_eval_chunk(payload)
                delta = _record_result(out)
                tested += delta
                camp.coverage["tested"] = tested
                camp.coverage["coverage_fraction"] = tested / total_configs
                if (idx + 1) % 8 == 0 or tested >= max_cfg:
                    _persist_checkpoint(
                        checkpoint_path, camp, completed_set, completed_chunks, rej_counter
                    )
                if tested >= max_cfg:
                    break
    finally:
        if pool is not None:
            pool.close()
            pool.join()

    # Final status classification.
    camp.completed_mask_indices = sorted(completed_set)
    camp.rejection_counts = dict(rej_counter)
    camp.completed_at = datetime.now(timezone.utc).isoformat()

    has_signal = any(
        s.get("crib_score", 0) >= SIGNAL_THRESHOLD for s in camp.survivors
    )
    if has_signal:
        camp.status = "CANDIDATE_SIGNAL"
    elif tested < total_configs and max_configs is not None and tested >= max_configs:
        camp.status = "INCONCLUSIVE_BUDGET"
    elif len(completed_set) == len(masks):
        camp.status = "ELIMINATED"
    else:
        camp.status = "INCONCLUSIVE_BUDGET"

    # best = top 10 survivors by (crib_score, ngram_per_char)
    camp.best = sorted(
        camp.survivors,
        key=lambda s: (s.get("crib_score", 0), s.get("ngram_per_char", 0.0)),
        reverse=True,
    )[:10]

    # Deterministic per-worker audit sort: by processed_count desc, then pid.
    camp.per_worker_audit.sort(
        key=lambda e: (-int(e.get("processed_count", 0)), int(e.get("worker_pid", 0)))
    )
    # Global audit reconciliation sanity note: if any mismatch, record in notes.
    ac = camp.audit_counters
    global_processed = int(ac.get("processed_count", 0))
    per_worker_sum = sum(int(e.get("processed_count", 0)) for e in camp.per_worker_audit)
    if global_processed != per_worker_sum:
        camp.notes.append(
            f"audit mismatch: global processed={global_processed} "
            f"vs per_worker sum={per_worker_sum}"
        )
    bean_sum = (
        int(ac.get("bean_pass", 0))
        + int(ac.get("bean_fail", 0))
        + int(ac.get("bean_not_applicable", 0))
    )
    if bean_sum != global_processed:
        camp.notes.append(
            f"audit mismatch: bean_pass+bean_fail+bean_na={bean_sum} "
            f"vs processed={global_processed}"
        )

    camp.completed_chunk_ids = {
        str(mi): sorted(chunks) for mi, chunks in sorted(completed_chunks.items())
    }
    _persist_checkpoint(checkpoint_path, camp, completed_set, completed_chunks, rej_counter)
    write_json_atomic(output_path, camp.to_dict())
    render_markdown_report(camp, output_path.with_suffix(".md"), cmd_line)
    return camp


def _absorb_chunk(chunk_out: dict, rej_counter: Counter, camp: Campaign) -> None:
    """Merge a worker chunk's tallies + survivors + audit + near_misses into
    the campaign state. All aggregation uses commutative+associative ops so
    the final counters are deterministic regardless of worker order.
    """
    tallies = chunk_out.get("tallies", {})
    for k, v in tallies.items():
        rej_counter[k] += int(v)
    for entry in chunk_out.get("survivors", []):
        if entry.get("_error"):
            continue
        camp.survivors.append(entry)

    audit = chunk_out.get("audit")
    if audit:
        pid = int(audit.get("worker_pid", 0))
        ac = camp.audit_counters
        # Cumulative global audit counters.
        for k in (
            "processed_count",
            "bean_invocations",
            "bean_pass",
            "bean_fail",
            "bean_not_applicable",
            "ngram_invocations",
        ):
            ac[k] = int(ac.get(k, 0)) + int(audit.get(k, 0))
        # Global crib histogram.
        gh = ac.setdefault("crib_histogram", {})
        for k, v in audit.get("crib_histogram", {}).items():
            gh[int(k)] = int(gh.get(int(k), 0)) + int(v)
        # Distinct plaintext fingerprints merged into a global set.
        fps = ac.setdefault("pt73_fingerprints", [])
        # Use a dict as an ordered set to preserve determinism without a
        # separate set() (which is unordered in Python < 3.7 contract).
        fp_set = dict.fromkeys(fps)
        for fp in audit.get("pt73_sample_fingerprints", []):
            fp_set[fp] = None
        ac["pt73_fingerprints"] = list(fp_set.keys())
        ac["pt73_distinct_total"] = len(fp_set)
        # Per-worker audit entry (merged on pid — a single worker may emit
        # multiple chunks, so sum rather than replace).
        pw_map: dict[int, dict] = {e["worker_pid"]: e for e in camp.per_worker_audit}
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

    # Near-miss merge: append and re-trim to global cap.
    for nm in chunk_out.get("near_misses", []):
        camp.near_misses.append(nm)
    if camp.near_misses:
        camp.near_misses.sort(key=_near_miss_sort_key)
        del camp.near_misses[NEAR_MISS_GLOBAL_CAP:]


def _persist_checkpoint(
    checkpoint_path: Path,
    camp: Campaign,
    completed_set: set[int],
    completed_chunks: dict[int, set[int]],
    rej_counter: Counter,
) -> None:
    doc = camp.to_dict()
    doc["completed_mask_indices"] = sorted(completed_set)
    doc["completed_chunk_ids"] = {
        str(mi): sorted(chunks) for mi, chunks in sorted(completed_chunks.items())
    }
    doc["rejection_counts"] = dict(rej_counter)
    write_json_atomic(checkpoint_path, doc)


# =============================================================================
# CLI
# =============================================================================


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Deterministic finite harness for the 73-real / 24-null / Bean "
            "family. Converts repeated worker timeouts into a bounded, "
            "reproducible, checkpointed campaign with explicit epistemic "
            "outcomes. Does NOT claim to solve K4."
        ),
    )
    p.add_argument(
        "--mode",
        choices=("inventory", "smoke", "full"),
        default="smoke",
        help="inventory prints the universe without evaluating; smoke runs a bounded subset; full runs everything up to --max-configs",
    )
    p.add_argument("--max-configs", type=int, default=None, help="hard cap on evaluated (mask, variant, key) triples")
    p.add_argument("--limit-masks", type=int, default=None, help="truncate mask universe after construction")
    p.add_argument("--limit-keys", type=int, default=None, help="truncate key universe after construction")
    p.add_argument(
        "--include-english-keys",
        action="store_true",
        help="also include short english wordlist keys (adds breadth, not exhaustive)",
    )
    p.add_argument("--random-masks", type=int, default=0, help="number of random sampled masks to append")
    p.add_argument("--random-seed", type=int, default=1337, help="seed for random mask sampling")
    p.add_argument("--workers", type=int, default=max(1, mp.cpu_count() - 2), help="pool size")
    p.add_argument("--key-chunk-size", type=int, default=64, help="keys per pool task")
    p.add_argument(
        "--checkpoint",
        type=Path,
        default=Path("results/h_624_73_nullmask/checkpoint.json"),
        help="checkpoint file (resumable)",
    )
    p.add_argument(
        "--output",
        type=Path,
        default=Path("results/h_624_73_nullmask/result.json"),
        help="final output JSON path",
    )
    p.add_argument("--resume", action="store_true", help="resume from checkpoint if assumption + universe hashes match")
    p.add_argument(
        "--force",
        action="store_true",
        help="allow resume even if assumption or universe hashes changed (DANGEROUS)",
    )
    p.add_argument("--dry-run", action="store_true", help="build universe, validate, write inventory, exit without evaluating")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    validate_kernel_constants()

    # Build mask universe
    masks = build_mask_universe(
        include_random=args.random_masks, random_seed=args.random_seed
    )
    if args.limit_masks is not None:
        masks = masks[: args.limit_masks]

    # Build key universe
    # Smoke mode uses a tiny tight bound unless user overrides.
    if args.mode == "smoke" and args.limit_keys is None:
        keys = build_key_universe(limit_thematic=20, include_english=False)
    else:
        keys = build_key_universe(
            limit_thematic=args.limit_keys,
            include_english=args.include_english_keys,
            english_min=4,
            english_max=8,
            limit_english=args.limit_keys or 2000,
        )
        if args.limit_keys is not None:
            keys = keys[: args.limit_keys]

    if args.mode == "smoke" and args.limit_masks is None:
        # smoke mask limit: tail + head + first 8 of each structured family
        want_families = ("head_block", "tail_block", "periodic_step", "residue_class", "width_row", "width_column")
        chosen: list[Mask] = []
        seen: Counter = Counter()
        for m in masks:
            if m.family in want_families and seen[m.family] < 6:
                chosen.append(m)
                seen[m.family] += 1
        masks = chosen

    variants = tuple(CIPHER_VARIANTS)

    cmd_line = "PYTHONPATH=src python3 " + " ".join([sys.argv[0], *map(str, (argv or sys.argv[1:]))])

    if args.dry_run or args.mode == "inventory":
        mode = "inventory"
    else:
        mode = args.mode

    camp = run_campaign(
        mode=mode,
        masks=masks,
        keys=keys,
        variants=variants,
        workers=max(1, args.workers),
        max_configs=args.max_configs,
        checkpoint_path=args.checkpoint,
        output_path=args.output,
        resume=args.resume,
        key_chunk_size=max(1, args.key_chunk_size),
        cmd_line=cmd_line,
        force_resume=args.force,
    )

    print(f"{camp.campaign_id} {camp.campaign_version}  status={camp.status}")
    print(f"  mode: {mode}  workers: {args.workers}")
    print(f"  masks: {len(masks)}  keys: {len(keys)}  variants: {len(variants)}")
    print(f"  total configs: {camp.inventory.get('total_configs')}")
    print(f"  tested: {camp.coverage.get('tested')}")
    print(f"  survivors: {len(camp.survivors)}")
    print(f"  output: {args.output}")
    print(f"  checkpoint: {args.checkpoint}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
