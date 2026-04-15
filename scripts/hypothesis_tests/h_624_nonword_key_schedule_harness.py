"""Deterministic finite harness for non-wordlist key schedules on the
73-real / 24-null / Bean family.

Scope and intent
----------------
Companion to `h_624_73_nullmask_harness.py`. Tests the SAME assumption bundle
(73/24 positional null mask, direct crib mapping, additive cipher) against
KEY-SCHEDULE families that are NOT periodic wordlist keys. The target is
specifically the "624-Bean exhaustive extension" family that has caused the
keystream-review agent worker to time out twice at 30 minutes (cycles 65
and 72). Converting this into a deterministic bounded harness replaces that
timeout-prone path with a reproducible, auditable campaign.

Key-schedule families implemented
---------------------------------
1. `bean624_crib_anchored_extension` -- the 624 Bean-valid 24-vectors
   (enumerated via mod-2/mod-13 kernel + CRT over BEAN_EQ + BEAN_INEQ +
   BEAN_LINEAR) anchored to the reduced crib indices via policy (b)
   override. Each schedule carries a bean24_anchor vector; at evaluation
   time, evaluate_triple writes the 24 anchor values into the mask's
   reduced crib positions, leaving the extension rule's fill in the 49
   non-crib positions. By construction Bean PASSES for every config in
   this family, so the discriminator is the ngram score on the full
   pt73. SUPERSEDES the retired `bean624_extension` family which tiled
   the 24-vector into reduced indices 0..23 without mask awareness.
2. `linear_recurrence` -- mod-26 linear recurrences of order 2..3 with
   bounded parameter and seed sets. Deterministic enumeration.
3. `coordinate_tape` -- tapes derived from the K2 coordinate digit
   sequences documented in `docs/anomaly_registry.md` and
   `<historical-planning>/specs/2026-03-18-isbn-hunt-design.md` with modular
   reduction and letter-offset variants.
4. `vimark` -- primer-expansion via kernel's `expand_keystream_vimark`
   with bounded primer length and seed set.
5. `segmented_two_key` -- NOT implemented; documented as separate harness.

Epistemic discipline
--------------------
- Every key record includes key_id, family, description, length=73,
  generation_parameters, source_basis, is_exhaustive_within_family.
- Missing tooling -> `INCONCLUSIVE_TOOLING`, never `ELIMINATED`.
- Partial coverage -> `INCONCLUSIVE_BUDGET`, never `ELIMINATED`.
- Full finite coverage + zero survivors -> `ELIMINATED` WITHIN the stated
  assumption bundle and the stated key-schedule universe only.
- Candidate signals -> `CANDIDATE_SIGNAL`, route through Day 5/6 gates.
- ngram policy (2026-04-14): the ngram scorer is REQUIRED when the
  bean624_crib_anchored_extension family is enabled, because that
  family forces Bean PASS by construction (anchor override) and ngram
  becomes the actual discriminator. If ngram is unavailable AND the
  anchored family is enabled, the harness refuses to run with status
  INCONCLUSIVE_TOOLING. For runs with --no-bean624, ngram is advisory
  and the harness proceeds with ngram=0.0 per triple.
- bean624_crib_anchored_extension produces structurally-guaranteed
  BREAKTHROUGH events: 1 crib-valid 24-vector per cipher variant ×
  2 extension rules × 75 masks × 3 variants = 450 BREAKTHROUGH-class
  configs that are NOT discoveries — they are the algebraic identity
  "the variant-correct keystream produces the correct plaintext at
  the crib positions." The discriminator for THIS family is the ngram
  score on the full 73-character pt73 (i.e. whether the extension
  rule's fill produces English-looking text in the 49 non-crib
  positions). The harness will report CANDIDATE_SIGNAL whenever this
  family is enabled; the human-readable interpretation is the ngram
  histogram and the best-survivor ngram_per_char.

CLI
---
    PYTHONPATH=src python3 scripts/hypothesis_tests/h_624_nonword_key_schedule_harness.py --help
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import multiprocessing as mp
import os
import sys
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Optional

# Reuse kernel primitives.
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
from kryptos.kernel.constraints.bean import (
    expand_keystream_vimark,
    verify_bean_simple,
)
from kryptos.kernel.transforms.vigenere import (
    beau_decrypt,
    varbeau_decrypt,
    vig_decrypt,
)

# Reuse mask universe + audit machinery from the companion harness.
_THIS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_THIS_DIR))
import h_624_73_nullmask_harness as companion  # noqa: E402

CAMPAIGN_ID = "h_624_nonword_key_schedule"
CAMPAIGN_VERSION = "1.0.0"
REDUCED_LEN = 73

CIPHER_VARIANTS = ("vigenere", "beaufort", "varbeau")

CT_NUMS = tuple(ALPH_IDX[c] for c in CT)


# =============================================================================
# Assumption bundle
# =============================================================================


def build_assumptions() -> dict:
    return {
        "assumes_direct_positional_crib_mapping": True,
        "assumes_canonical_97_ct": True,
        "assumes_additive_cipher_family": True,
        "assumes_73_real_24_null_model": True,
        "assumes_key_schedule_acts_on_reduced_73_space": True,
        "notes": [
            "Same H1 bundle as h_624_73_nullmask_harness.",
            "Every generated keystream is a 73-length vector indexed in reduced space.",
            "Bean is verified via a virtual 97-length keystream constructed from the",
            "  reduced-space values at kept positions (kept positions include all cribs",
            "  since the mask universe is crib-preserving).",
            "Missing tooling for a family produces INCONCLUSIVE_TOOLING, never elimination.",
        ],
    }


def hash_dict(d: dict) -> str:
    return hashlib.sha256(
        json.dumps(d, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


# =============================================================================
# Bean-valid 24-vector enumerator
# =============================================================================


def _build_constraint_buckets(n: int):
    """Pre-index Bean constraints by max referenced position index.

    At level i in a depth-first assignment, we only need to check
    constraints whose maximum-indexed position equals i -- constraints with
    smaller max were already checked at earlier levels, and constraints
    with larger max still have unassigned positions.
    """
    positions = sorted(CRIB_POSITIONS)
    idx_of = {p: i for i, p in enumerate(positions)}

    eq_by_max: list[list[tuple[int, int]]] = [[] for _ in range(n)]
    ineq_by_max: list[list[tuple[int, int]]] = [[] for _ in range(n)]
    lin_by_max: list[list[tuple[int, int, int, int]]] = [[] for _ in range(n)]

    for a, b in BEAN_EQ:
        ia, ib = idx_of[a], idx_of[b]
        eq_by_max[max(ia, ib)].append((ia, ib))
    for a, b in BEAN_INEQ:
        ia, ib = idx_of[a], idx_of[b]
        ineq_by_max[max(ia, ib)].append((ia, ib))
    for a, b, c, d in BEAN_LINEAR:
        ia, ib, ic, id_ = idx_of[a], idx_of[b], idx_of[c], idx_of[d]
        lin_by_max[max(ia, ib, ic, id_)].append((ia, ib, ic, id_))

    return positions, eq_by_max, ineq_by_max, lin_by_max


_BEAN624_CACHE: Optional[list[tuple[int, ...]]] = None
_BEAN624_CACHE_FILE = Path("data/bean_valid_24_vectors.json")


def _bean_index_constraints():
    """Pre-index constraints over crib-index space (0..23) for the
    constraint-propagation enumerator. Returns:
      positions: sorted crib position list
      eq_pairs: list of (i, j) index pairs
      ineq_pairs: list of (i, j) index pairs
      lin_tuples: list of (i, j, k, l) index 4-tuples
      lin_constraints_by_position: dict pos_idx -> list of constraint indices
    """
    positions = sorted(CRIB_POSITIONS)
    idx_of = {p: i for i, p in enumerate(positions)}
    eq_pairs = [(idx_of[a], idx_of[b]) for a, b in BEAN_EQ]
    ineq_pairs = [(idx_of[a], idx_of[b]) for a, b in BEAN_INEQ]
    lin_tuples = [
        (idx_of[a], idx_of[b], idx_of[c], idx_of[d]) for a, b, c, d in BEAN_LINEAR
    ]
    lin_by_pos: dict[int, list[int]] = {i: [] for i in range(24)}
    for ci, (i, j, k, l) in enumerate(lin_tuples):
        for p in (i, j, k, l):
            lin_by_pos[p].append(ci)
    return positions, eq_pairs, ineq_pairs, lin_tuples, lin_by_pos


def enumerate_bean_valid_24_vectors() -> list[tuple[int, ...]]:
    """Enumerate all 24-vectors at crib positions that satisfy the full Bean
    constraint set (1 equality + 242 inequalities + 101 linear constraints).

    Algorithm
    ---------
    The 1 equality + 101 linear constraints form a homogeneous system A*k = 0
    over Z_26. We solve this via linear algebra:

      1. Build A as a 102x24 integer matrix (rows are constraint coefficients).
      2. Row-reduce mod 2 and mod 13 separately (both are fields, Gaussian
         elimination is straightforward).
      3. Find the kernel basis over GF(2) and GF(13).
      4. Enumerate the full kernel mod 26 by combining via CRT: a vector x is
         in the kernel mod 26 iff x mod 2 is in ker(A mod 2) and x mod 13 is in
         ker(A mod 13).
      5. Filter the kernel elements by the 242 inequality constraints.

    The canonical count is 624. Result is cached in-process and on-disk.
    """
    global _BEAN624_CACHE
    if _BEAN624_CACHE is not None:
        return _BEAN624_CACHE
    if _BEAN624_CACHE_FILE.exists():
        try:
            data = json.loads(_BEAN624_CACHE_FILE.read_text())
            if isinstance(data, list) and all(len(v) == 24 for v in data):
                _BEAN624_CACHE = [tuple(int(x) for x in v) for v in data]
                return _BEAN624_CACHE
        except Exception:
            pass

    n = 24
    _, eq_pairs, ineq_pairs, lin_tuples, _ = _bean_index_constraints()

    # Build constraint matrix (integer coefficients, dense rows).
    rows: list[list[int]] = []
    for ia, ib in eq_pairs:
        row = [0] * n
        row[ia] = 1
        row[ib] = -1
        rows.append(row)
    for ia, ib, ic, id_ in lin_tuples:
        row = [0] * n
        row[ia] += 1
        row[ib] -= 1
        row[ic] -= 1
        row[id_] += 1
        rows.append(row)

    def kernel_basis_mod_p(matrix_rows: list[list[int]], p: int) -> list[list[int]]:
        """Return a basis for the null space of the matrix mod p (p prime).

        Returns a list of basis vectors (each a list of length n) such that
        the null space mod p is their span. For a zero matrix the basis is
        the full identity. Standard Gaussian elimination over GF(p).
        """
        # Copy rows mod p.
        m = [[x % p for x in row] for row in matrix_rows]
        rank = 0
        pivots: list[int] = []  # column indices of pivot columns
        col = 0
        row_idx = 0
        num_rows = len(m)
        while col < n and row_idx < num_rows:
            # Find a row with nonzero entry in column `col` at or below row_idx.
            pivot_row = None
            for r in range(row_idx, num_rows):
                if m[r][col] != 0:
                    pivot_row = r
                    break
            if pivot_row is None:
                col += 1
                continue
            # Swap.
            m[row_idx], m[pivot_row] = m[pivot_row], m[row_idx]
            # Normalize pivot to 1.
            inv = pow(m[row_idx][col], -1, p)
            m[row_idx] = [(x * inv) % p for x in m[row_idx]]
            # Eliminate above and below.
            for r in range(num_rows):
                if r != row_idx and m[r][col] != 0:
                    factor = m[r][col]
                    m[r] = [(m[r][j] - factor * m[row_idx][j]) % p for j in range(n)]
            pivots.append(col)
            row_idx += 1
            col += 1
        # Free columns:
        pivot_set = set(pivots)
        free_cols = [c for c in range(n) if c not in pivot_set]
        # For each free column f, build a basis vector with x[f] = 1 and
        # x[pivot_col] = -coefficient(pivot_row, f) for each pivot.
        basis: list[list[int]] = []
        for f in free_cols:
            v = [0] * n
            v[f] = 1
            for i, pc in enumerate(pivots):
                v[pc] = (-m[i][f]) % p
            basis.append(v)
        return basis

    basis2 = kernel_basis_mod_p(rows, 2)
    basis13 = kernel_basis_mod_p(rows, 13)

    def enumerate_span(basis: list[list[int]], p: int) -> list[tuple[int, ...]]:
        """Enumerate all linear combinations of basis vectors over Z_p."""
        if not basis:
            return [tuple([0] * n)]
        d = len(basis)
        out: list[tuple[int, ...]] = []
        for coeffs in range(p ** d):
            vec = [0] * n
            c = coeffs
            for b in range(d):
                ci = c % p
                c //= p
                if ci:
                    row = basis[b]
                    for j in range(n):
                        vec[j] = (vec[j] + ci * row[j]) % p
            out.append(tuple(vec))
        return out

    ker2 = enumerate_span(basis2, 2)
    ker13 = enumerate_span(basis13, 13)

    # CRT combination: for each (v2, v13), compute the unique x mod 26 with
    # x ≡ v2 (mod 2) and x ≡ v13 (mod 13). Precompute the CRT constants:
    #   x = (13 * v2 * inv(13, 2) + 2 * v13 * inv(2, 13)) mod 26
    # inv(13, 2) = 1 (13 is odd), inv(2, 13) = 7 (since 2*7=14≡1 mod 13).
    inv_13_mod_2 = 1
    inv_2_mod_13 = pow(2, -1, 13)
    c2 = 13 * inv_13_mod_2  # 13
    c13 = 2 * inv_2_mod_13  # 14

    linear_solutions: list[tuple[int, ...]] = []
    for v2 in ker2:
        for v13 in ker13:
            x = tuple((c2 * v2[j] + c13 * v13[j]) % MOD for j in range(n))
            linear_solutions.append(x)

    # Filter by the 242 inequality constraints.
    ineq_idx_pairs = ineq_pairs
    results: list[tuple[int, ...]] = []
    for vec in linear_solutions:
        ok = True
        for ia, ib in ineq_idx_pairs:
            if vec[ia] == vec[ib]:
                ok = False
                break
        if ok:
            results.append(vec)

    results.sort()
    _BEAN624_CACHE = results

    try:
        _BEAN624_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _BEAN624_CACHE_FILE.write_text(
            json.dumps([list(v) for v in results], separators=(",", ":"))
        )
    except Exception:
        pass

    return results


# =============================================================================
# Key-schedule record model
# =============================================================================


@dataclass(frozen=True)
class KeySchedule:
    """A non-wordlist key schedule.

    The schedule materializes as a 73-length vector of integers in [0, 26).
    The vector is stored directly so workers can apply it without re-running
    the generator. Metadata is preserved for provenance.

    bean24_anchor (optional, set for the bean624_crib_anchored_extension
    family only): a 24-length vector of Bean-valid keystream values indexed
    by sorted(CRIB_POSITIONS). When set, evaluate_triple overrides the 24
    reduced-crib positions of values_73 with these values *at evaluation
    time*, using the mask's crib_to_reduced() mapping. This anchors the
    Bean-valid 24-vector to the actual reduced crib indices, which depend
    on the mask. The values_73 field then represents the *fill* used for
    the 49 non-crib reduced positions; the value-override semantics are
    documented as policy (b) in project_h_624_nonword_harness.md.
    """

    key_id: str
    family: str
    description: str
    values_73: tuple[int, ...]  # length 73
    source_basis: str
    is_exhaustive_within_family: bool
    generation_parameters: dict
    bean24_anchor: Optional[tuple[int, ...]] = None

    def __post_init__(self) -> None:
        if len(self.values_73) != REDUCED_LEN:
            raise ValueError(
                f"KeySchedule {self.key_id}: expected length {REDUCED_LEN}, got {len(self.values_73)}"
            )
        for v in self.values_73:
            if not (0 <= v < MOD):
                raise ValueError(f"KeySchedule {self.key_id}: value out of range: {v}")
        if self.bean24_anchor is not None:
            if len(self.bean24_anchor) != 24:
                raise ValueError(
                    f"KeySchedule {self.key_id}: bean24_anchor must be length 24, "
                    f"got {len(self.bean24_anchor)}"
                )
            for v in self.bean24_anchor:
                if not (0 <= v < MOD):
                    raise ValueError(
                        f"KeySchedule {self.key_id}: bean24_anchor value out of range: {v}"
                    )


def _schedule_id(family: str, params: dict) -> str:
    payload = f"{family}|" + json.dumps(params, sort_keys=True, separators=(",", ":"))
    return f"{family}:{hashlib.sha1(payload.encode()).hexdigest()[:10]}"


# =============================================================================
# Family 1: 624 Bean-valid extensions
# =============================================================================


def _extend_cyclic(vec24: tuple[int, ...]) -> tuple[int, ...]:
    """Cyclically tile the 24-vector over 73 reduced-space positions."""
    out = [vec24[i % 24] for i in range(REDUCED_LEN)]
    return tuple(out)


def _extend_reflected(vec24: tuple[int, ...]) -> tuple[int, ...]:
    """Mirror-reflect: 0..23, 22..0, 1..23, ... pattern.

    Deterministic, distinct from cyclic_24, bounded.
    """
    base = list(vec24)
    palette: list[int] = []
    forward = True
    i = 0
    while len(palette) < REDUCED_LEN:
        palette.append(base[i])
        if forward:
            if i == 23:
                forward = False
                i -= 1
            else:
                i += 1
        else:
            if i == 0:
                forward = True
                i += 1
            else:
                i -= 1
    return tuple(palette[:REDUCED_LEN])


def gen_bean624_schedules(*_args, **_kwargs) -> list[KeySchedule]:
    """RETIRED 2026-04-14.

    The original `bean624_extension` family tiled the Bean-valid 24-vector
    into reduced-space indices 0..23, NOT into the mask's reduced crib
    indices. This silently tested an unintended universe ("Bean-valid 24-
    vectors interpreted as arbitrary 73-space offsets") rather than the
    intended one ("Bean-valid 24-vectors anchored to crib positions and
    extended outward"). The 36 'structural degenerates' previously stored
    by this family are artifacts of that mis-anchoring and are NOT valid
    evidence of anything.

    Use `gen_bean624_crib_anchored_extension_schedules()` instead. That
    function implements policy (b): override the reduced crib indices with
    the Bean-valid values at evaluation time, leaving the extension fill
    in the 49 non-crib positions as the actual discriminator.
    """
    raise NotImplementedError(
        "gen_bean624_schedules() is retired (mask-anchoring bug, 2026-04-14). "
        "Use gen_bean624_crib_anchored_extension_schedules() instead. See "
        "project_h_624_nonword_harness.md SUSPENDED banner for details."
    )


def gen_bean624_crib_anchored_extension_schedules(
    limit_vectors: Optional[int] = None,
) -> list[KeySchedule]:
    """Enumerate Bean-valid 24-vectors as crib-anchored extension schedules.

    Each schedule carries:
      - values_73: a 73-length BASE FILL produced by an extension rule
        (`cyclic_24` or `reflected_24`). The base fill is mask-independent
        and serves as the value at the 49 non-crib reduced positions.
      - bean24_anchor: the canonical Bean-valid 24-vector, indexed by
        sorted(CRIB_POSITIONS).

    At evaluation time, `evaluate_triple` overrides the 24 reduced crib
    positions of values_73 with the corresponding bean24_anchor values
    using the mask's crib_to_reduced() mapping. By construction, every
    config in this family has the Bean-valid keystream at the crib
    positions; Bean PASSES for every config; the discriminator becomes
    the ngram score on the full 73-character plaintext (i.e., whether
    the extension rule's fill produces English-looking text in the 49
    non-crib positions).

    This is policy (b) — see project_h_624_nonword_harness.md SUSPENDED
    banner for the policy choice rationale (rejected: (a) reject-on-
    conflict, too degenerate; (c) generate-outward from anchors, open-
    ended rule design — deferred to a future harness).
    """
    vectors = enumerate_bean_valid_24_vectors()
    if limit_vectors is not None:
        vectors = vectors[:limit_vectors]
    schedules: list[KeySchedule] = []
    rules = (("cyclic_24", _extend_cyclic), ("reflected_24", _extend_reflected))
    for vec_idx, vec in enumerate(vectors):
        for rule_name, fn in rules:
            base_fill = fn(vec)
            params = {
                "vector_index": vec_idx,
                "vector_prefix": list(vec[:6]),
                "rule": rule_name,
                "anchoring": "crib_anchored_override_b",
            }
            schedules.append(
                KeySchedule(
                    key_id=_schedule_id("bean624cae", params),
                    family="bean624_crib_anchored_extension",
                    description=(
                        f"Bean-valid 24-vector #{vec_idx} crib-anchored "
                        f"with {rule_name} fill in non-crib positions"
                    ),
                    values_73=base_fill,
                    source_basis=(
                        "enumerate_bean_valid_24_vectors + kernel "
                        "BEAN_EQ/BEAN_INEQ/BEAN_LINEAR + policy (b) override"
                    ),
                    is_exhaustive_within_family=True,
                    generation_parameters=params,
                    bean24_anchor=tuple(vec),
                )
            )
    return schedules


# =============================================================================
# Family 2: Linear recurrence tapes (mod-26)
# =============================================================================


def _lrec_order2(a: int, b: int, k0: int, k1: int) -> tuple[int, ...]:
    vals = [k0 % MOD, k1 % MOD]
    while len(vals) < REDUCED_LEN:
        vals.append((a * vals[-1] + b * vals[-2]) % MOD)
    return tuple(vals[:REDUCED_LEN])


def _lrec_order3(a: int, b: int, c: int, k0: int, k1: int, k2: int) -> tuple[int, ...]:
    vals = [k0 % MOD, k1 % MOD, k2 % MOD]
    while len(vals) < REDUCED_LEN:
        vals.append((a * vals[-1] + b * vals[-2] + c * vals[-3]) % MOD)
    return tuple(vals[:REDUCED_LEN])


def gen_linear_recurrence_schedules() -> list[KeySchedule]:
    """Bounded enumeration of mod-26 linear recurrences.

    Order 2: (a, b) in small-coefficient grid, (k0, k1) seeds in a bounded set.
    Order 3: (a, b, c) in tighter grid, seeds bounded.
    """
    schedules: list[KeySchedule] = []

    # Order 2 -- classical families
    order2_coeffs = (
        (1, 1),  # Fibonacci
        (1, 2),
        (2, 1),
        (1, -1),
        (-1, 1),
        (1, 0),  # trivial k[i]=k[i-1]
        (0, 1),  # k[i]=k[i-2]
        (2, 2),
        (3, 1),
        (1, 3),
        (25, 1),  # -1, 1
        (1, 25),  # 1, -1
    )
    # Compact seed grid: 9 seeds covering small non-trivial pairs.
    order2_seeds = tuple(
        (k0, k1)
        for k0 in (0, 1, 2, 3)
        for k1 in (0, 1, 2, 3)
        if (k0, k1) != (0, 0)
    )
    for (a, b) in order2_coeffs:
        for (k0, k1) in order2_seeds:
            values = _lrec_order2(a % MOD, b % MOD, k0, k1)
            params = {"order": 2, "a": a, "b": b, "k0": k0, "k1": k1}
            schedules.append(
                KeySchedule(
                    key_id=_schedule_id("lrec2", params),
                    family="linear_recurrence",
                    description=f"Order-2 recurrence k[i]=({a}*k[i-1]+{b}*k[i-2]) mod 26, seed ({k0},{k1})",
                    values_73=values,
                    source_basis="in-harness mod-26 linear recurrence enumerator",
                    is_exhaustive_within_family=True,
                    generation_parameters=params,
                )
            )

    # Order 3 -- tighter grid
    order3_coeffs = (
        (1, 1, 1),
        (1, 0, 1),
        (1, 1, 0),
        (0, 1, 1),
        (1, -1, 1),
        (1, 1, -1),
        (2, 1, 1),
        (1, 2, 1),
    )
    order3_seeds = tuple(
        (k0, k1, k2)
        for k0 in (0, 1, 2)
        for k1 in (0, 1, 2)
        for k2 in (0, 1, 2)
        if (k0, k1, k2) != (0, 0, 0)
    )
    for (a, b, c) in order3_coeffs:
        for (k0, k1, k2) in order3_seeds:
            values = _lrec_order3(a % MOD, b % MOD, c % MOD, k0, k1, k2)
            params = {"order": 3, "a": a, "b": b, "c": c, "k0": k0, "k1": k1, "k2": k2}
            schedules.append(
                KeySchedule(
                    key_id=_schedule_id("lrec3", params),
                    family="linear_recurrence",
                    description=f"Order-3 recurrence coefficients ({a},{b},{c}), seed ({k0},{k1},{k2})",
                    values_73=values,
                    source_basis="in-harness mod-26 linear recurrence enumerator",
                    is_exhaustive_within_family=True,
                    generation_parameters=params,
                )
            )

    return schedules


# =============================================================================
# Family 3: Coordinate-derived tapes
# =============================================================================

# Source: docs/anomaly_registry.md line 249 and <historical-planning>/specs/2026-03-18-isbn-hunt-design.md.
# These are documented digit strings, not hand-fabricated numbers.
K2_COORD_STANDARD = (38, 57, 6, 5, 77, 8, 44)
K2_COORD_SPLIT = (30, 8, 50, 7, 6, 5, 70, 7, 8, 40, 4)
K2_COORD_SHORT = (38, 57, 6, 77, 8, 44)


def _cycle_to_73(seq: tuple[int, ...]) -> tuple[int, ...]:
    return tuple(seq[i % len(seq)] for i in range(REDUCED_LEN))


def gen_coordinate_tape_schedules() -> list[KeySchedule]:
    """Small family: documented K2 coordinate digit sequences with modular
    reduction and letter-offset variants, cycled over 73 positions.
    """
    schedules: list[KeySchedule] = []
    bases = (
        ("standard", K2_COORD_STANDARD, "docs/anomaly_registry.md:249 standard reading (38,57,6,5,77,8,44)"),
        ("split", K2_COORD_SPLIT, "<historical-planning>/specs/2026-03-18-isbn-hunt-design.md split reading"),
        ("short", K2_COORD_SHORT, "<historical-planning>/specs/2026-03-18-sculpture-path-search-design.md short reading"),
    )
    transforms = (
        ("mod26_identity", lambda s: tuple(x % MOD for x in s)),
        ("mod26_reversed", lambda s: tuple(x % MOD for x in reversed(s))),
        ("mod26_plus1", lambda s: tuple((x + 1) % MOD for x in s)),
        ("digit_sum_mod26", lambda s: tuple(sum(int(d) for d in str(x)) % MOD for x in s)),
    )
    for base_name, base_seq, basis in bases:
        for tx_name, tx_fn in transforms:
            reduced = tx_fn(base_seq)
            values = _cycle_to_73(reduced)
            params = {"base": base_name, "transform": tx_name, "reduced": list(reduced)}
            schedules.append(
                KeySchedule(
                    key_id=_schedule_id("coord", params),
                    family="coordinate_tape",
                    description=f"K2 coordinate {base_name} sequence, transform {tx_name}, cycled",
                    values_73=values,
                    source_basis=basis,
                    is_exhaustive_within_family=True,
                    generation_parameters=params,
                )
            )
    return schedules


# =============================================================================
# Family 4: Vimark primer expansion (reuses kernel function)
# =============================================================================


def gen_vimark_schedules(limit: int = 500) -> list[KeySchedule]:
    """Vimark-style primer expansion using kernel `expand_keystream_vimark`.

    k[i] = k[i-period] + k[i-(period-1)] mod 26, seeded with a small primer.

    Enumerates primers of length 2..3 with small-value entries, bounded by
    `limit` to keep the family finite and deterministic.
    """
    schedules: list[KeySchedule] = []
    # Length-2 primers: 26 * 26 = 676 total; we enumerate all of them.
    # Length-3 primers: 26^3 = 17576; we sample a deterministic stride to fit limit.
    produced = 0
    for k0 in range(MOD):
        for k1 in range(MOD):
            if produced >= limit:
                break
            try:
                values = expand_keystream_vimark((k0, k1), length=REDUCED_LEN)
            except Exception:
                continue
            if len(values) != REDUCED_LEN:
                continue
            params = {"primer_length": 2, "primer": [k0, k1]}
            schedules.append(
                KeySchedule(
                    key_id=_schedule_id("vimark2", params),
                    family="vimark",
                    description=f"Vimark primer (length 2) ({k0},{k1})",
                    values_73=tuple(values),
                    source_basis="kryptos.kernel.constraints.bean.expand_keystream_vimark",
                    is_exhaustive_within_family=False,
                    generation_parameters=params,
                )
            )
            produced += 1
        if produced >= limit:
            break
    return schedules


# =============================================================================
# Tooling gap: segmented two-key schedule
# =============================================================================


def tooling_gap_for_segmented() -> dict:
    return {
        "family": "segmented_two_key",
        "reason": "Not implemented in this harness by design.",
        "detail": (
            "A segmented two-key schedule (k1 for EASTNORTHEAST region, k2 for "
            "BERLINCLOCK region, null mask bridging between) is a distinct "
            "search topology with ~10^4 configs. It belongs to a separate "
            "harness to keep this one focused."
        ),
        "next_action": "Build h_624_segmented_twokey_harness.py if needed.",
    }


# =============================================================================
# Universe assembly
# =============================================================================


def build_key_schedule_universe(
    include_bean624: bool = True,
    limit_bean624_vectors: Optional[int] = None,
    include_linear_recurrence: bool = True,
    include_coordinate: bool = True,
    include_vimark: bool = True,
    vimark_limit: int = 500,
) -> tuple[list[KeySchedule], list[dict]]:
    schedules: list[KeySchedule] = []
    tooling_gaps: list[dict] = []

    if include_bean624:
        try:
            schedules.extend(
                gen_bean624_crib_anchored_extension_schedules(
                    limit_vectors=limit_bean624_vectors
                )
            )
        except Exception as exc:
            tooling_gaps.append(
                {
                    "family": "bean624_crib_anchored_extension",
                    "reason": "enumerator raised",
                    "detail": repr(exc)[:300],
                }
            )
    else:
        tooling_gaps.append(
            {
                "family": "bean624_crib_anchored_extension",
                "reason": "disabled via flag",
                "detail": "--no-bean624",
            }
        )

    if include_linear_recurrence:
        schedules.extend(gen_linear_recurrence_schedules())

    if include_coordinate:
        schedules.extend(gen_coordinate_tape_schedules())

    if include_vimark:
        schedules.extend(gen_vimark_schedules(limit=vimark_limit))

    # Always document segmented as a gap.
    tooling_gaps.append(tooling_gap_for_segmented())
    # Dedupe by (family, values_73).
    seen: set[tuple[str, tuple[int, ...]]] = set()
    deduped: list[KeySchedule] = []
    for s in schedules:
        k = (s.family, s.values_73)
        if k in seen:
            continue
        seen.add(k)
        deduped.append(s)
    deduped.sort(key=lambda s: (s.family, s.key_id))
    return deduped, tooling_gaps


# =============================================================================
# Evaluation
# =============================================================================


@dataclass
class EvalResult:
    mask_id: str
    family: str
    variant: str
    key_id: str
    key_family: str
    crib_score: int
    bean_passed: bool
    bean_applicable: bool
    ngram_per_char: float
    pt73: str


def _decrypt_fn(variant: str) -> Callable[[int, int], int]:
    if variant == "vigenere":
        return vig_decrypt
    if variant == "beaufort":
        return beau_decrypt
    if variant == "varbeau":
        return varbeau_decrypt
    raise ValueError(variant)


def evaluate_triple(
    mask: "companion.Mask",
    variant: str,
    schedule: KeySchedule,
    ngram_scorer=None,
) -> EvalResult:
    fn = _decrypt_fn(variant)
    kept = mask.kept_positions
    # Start from the schedule's base fill. For crib-anchored extension
    # schedules, override the reduced crib indices with the Bean-valid
    # 24-vector values BEFORE decryption. This is policy (b) — the anchor
    # is mask-aware, applied at evaluation time, and is the fix for the
    # 2026-04-14 Bean624 mask-anchoring bug. By construction every config
    # in the bean624_crib_anchored_extension family has the Bean-valid
    # keystream at the crib positions, so Bean PASSES for every such
    # config and the discriminator is the ngram score on the full pt73.
    if schedule.bean24_anchor is not None:
        vals_list = list(schedule.values_73)
        crib_map = mask.crib_to_reduced()
        crib_positions_sorted = sorted(crib_map.keys())
        # Sanity: an anchored schedule should only ever be paired with a
        # crib-preserving mask. crib_to_reduced() returns only the kept
        # crib positions, so on a non-preserving mask the anchor would be
        # silently partially applied — refuse loudly.
        if len(crib_positions_sorted) != 24:
            raise RuntimeError(
                f"bean624_crib_anchored_extension schedule {schedule.key_id} "
                f"paired with non-crib-preserving mask {mask.mask_id}: "
                f"crib_to_reduced returned {len(crib_positions_sorted)} positions, "
                f"expected 24"
            )
        for crib_ord, orig_pos in enumerate(crib_positions_sorted):
            r = crib_map[orig_pos]
            vals_list[r] = int(schedule.bean24_anchor[crib_ord])
        vals: tuple[int, ...] = tuple(vals_list)
    else:
        vals = schedule.values_73  # 73-length numeric keystream
    pt_nums = [fn(CT_NUMS[orig], vals[i]) for i, orig in enumerate(kept)]
    pt73 = "".join(ALPH[v] for v in pt_nums)

    # crib score in reduced space
    crib_map = mask.crib_to_reduced()
    matches = 0
    for orig_pos, expected in CRIB_DICT.items():
        r = crib_map.get(orig_pos)
        if r is None:
            continue
        if pt_nums[r] == ALPH_IDX[expected]:
            matches += 1

    # Bean via virtual 97-length keystream at crib positions
    virt = [0] * CT_LEN
    for i, orig in enumerate(kept):
        virt[orig] = vals[i]
    bean_applicable = mask.preserves_cribs()
    bean_passed = verify_bean_simple(virt) if bean_applicable else False

    ngram = 0.0
    if ngram_scorer is not None:
        try:
            ngram = float(ngram_scorer.score_per_char(pt73))
        except Exception:
            ngram = 0.0

    return EvalResult(
        mask_id=mask.mask_id,
        family=mask.family,
        variant=variant,
        key_id=schedule.key_id,
        key_family=schedule.family,
        crib_score=matches,
        bean_passed=bean_passed,
        bean_applicable=bean_applicable,
        ngram_per_char=ngram,
        pt73=pt73,
    )


# =============================================================================
# Multiprocessing worker harness
# =============================================================================


_WORKER_NGRAM = None
NEAR_MISS_PER_WORKER = 50
PT73_SAMPLE_PER_WORKER = 20


def _worker_init() -> None:
    global _WORKER_NGRAM
    try:
        from kryptos.kernel.scoring.ngram import get_default_scorer

        _WORKER_NGRAM = get_default_scorer()
    except Exception:
        _WORKER_NGRAM = None


def _worker_eval_chunk(
    payload: tuple[int, int, "companion.Mask", tuple[str, ...], tuple[KeySchedule, ...]],
) -> dict:
    """Evaluate a (mask_idx, chunk_id, mask, variants, sched_chunk) block.

    The worker echoes `mask_idx`, `chunk_id`, and its own `processed_count`
    back to the controller. This is the fix for the imap_unordered result
    mis-mapping bug: arrival order is not input order, so identity must come
    from the worker's output, not the controller's enumerate() index.
    """
    mask_idx, chunk_id, mask, variants, sched_chunk = payload
    survivors: list[dict] = []
    tallies: Counter = Counter()
    crib_histogram: Counter = Counter()
    bean_invocations = 0
    bean_pass = 0
    bean_fail = 0
    bean_not_applicable = 0
    ngram_invocations = 0
    pt73_seen: dict[str, None] = {}
    pt73_sample_fingerprints: list[str] = []
    local_near_misses: list[dict] = []

    for variant in variants:
        for sched in sched_chunk:
            tallies["evaluated"] += 1
            try:
                r = evaluate_triple(mask, variant, sched, ngram_scorer=_WORKER_NGRAM)
            except Exception as exc:
                tallies["worker_error"] += 1
                survivors.append(
                    {
                        "_error": True,
                        "mask_id": mask.mask_id,
                        "variant": variant,
                        "key_id": sched.key_id,
                        "exc": repr(exc)[:200],
                    }
                )
                continue

            crib_histogram[int(r.crib_score)] += 1
            if r.bean_applicable:
                bean_invocations += 1
                if r.bean_passed:
                    bean_pass += 1
                else:
                    bean_fail += 1
            else:
                bean_not_applicable += 1
            if _WORKER_NGRAM is not None:
                ngram_invocations += 1
            if r.pt73 and len(pt73_seen) < PT73_SAMPLE_PER_WORKER:
                if r.pt73 not in pt73_seen:
                    pt73_seen[r.pt73] = None
                    pt73_sample_fingerprints.append(
                        hashlib.sha1(r.pt73.encode("ascii")).hexdigest()[:12]
                    )

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
                _insert_near_miss(
                    local_near_misses,
                    {
                        "mask_id": r.mask_id,
                        "mask_family": r.family,
                        "variant": r.variant,
                        "key_id": r.key_id,
                        "key_family": r.key_family,
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
                    "mask_family": r.family,
                    "variant": r.variant,
                    "key_id": r.key_id,
                    "key_family": r.key_family,
                    "crib_score": cs,
                    "bean_passed": r.bean_passed,
                    "bean_applicable": r.bean_applicable,
                    "ngram_per_char": r.ngram_per_char,
                    "pt73": r.pt73,
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
    return (
        -int(entry.get("crib_score", 0)),
        -float(entry.get("ngram_per_char", 0.0)),
        str(entry.get("mask_id", "")),
        str(entry.get("variant", "")),
        str(entry.get("key_id", "")),
    )


def _insert_near_miss(bucket: list[dict], entry: dict, cap: int) -> None:
    bucket.append(entry)
    bucket.sort(key=_near_miss_sort_key)
    if len(bucket) > cap:
        del bucket[cap:]


def _chunk(seq: list[KeySchedule], size: int) -> Iterator[tuple[KeySchedule, ...]]:
    for i in range(0, len(seq), size):
        yield tuple(seq[i : i + size])


# =============================================================================
# Campaign state + IO
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

    def to_dict(self) -> dict:
        return asdict(self)


def compute_universe_hash(
    masks: list["companion.Mask"],
    schedules: list[KeySchedule],
    variants: tuple[str, ...],
) -> str:
    h = hashlib.sha256()
    h.update(CAMPAIGN_VERSION.encode())
    h.update(f"masks={len(masks)}".encode())
    for m in masks:
        h.update(m.mask_id.encode())
    h.update(f"keys={len(schedules)}".encode())
    for s in schedules:
        h.update(s.key_id.encode())
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


def _absorb_chunk(chunk_out: dict, rej: Counter, camp: Campaign) -> None:
    for k, v in chunk_out.get("tallies", {}).items():
        rej[k] += int(v)
    for e in chunk_out.get("survivors", []):
        if e.get("_error"):
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
        gh = ac.setdefault("crib_histogram", {})
        for k, v in audit.get("crib_histogram", {}).items():
            gh[int(k)] = int(gh.get(int(k), 0)) + int(v)
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


def _persist_checkpoint(ckpt: Path, camp: Campaign, completed: set[int], rej: Counter) -> None:
    doc = camp.to_dict()
    doc["completed_mask_indices"] = sorted(completed)
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
    L.append("## Tooling gaps")
    L.append("")
    if camp.tooling_gaps:
        for g in camp.tooling_gaps:
            L.append(f"- **{g.get('family')}** -- {g.get('reason')}: {g.get('detail','')}")
    else:
        L.append("- (none)")
    L.append("")
    L.append("## Coverage")
    L.append("")
    cov = camp.coverage
    L.append(f"- tested: `{cov.get('tested', 0)}`")
    L.append(f"- total: `{cov.get('total', 0)}`")
    L.append(f"- fraction: `{cov.get('coverage_fraction', 0.0):.6f}`")
    L.append("")
    L.append("## Rejection counts")
    L.append("")
    if camp.rejection_counts:
        for k, v in sorted(camp.rejection_counts.items(), key=lambda kv: -kv[1]):
            L.append(f"- `{k}`: {v}")
    else:
        L.append("- (none)")
    L.append("")
    L.append("## Audit counters")
    L.append("")
    ac = camp.audit_counters or {}
    L.append(f"- processed_count: `{ac.get('processed_count', 0)}`")
    L.append(f"- bean_invocations: `{ac.get('bean_invocations', 0)}`")
    L.append(
        f"- bean_pass / fail / n/a: `{ac.get('bean_pass', 0)}` / "
        f"`{ac.get('bean_fail', 0)}` / `{ac.get('bean_not_applicable', 0)}`"
    )
    L.append(f"- ngram_invocations: `{ac.get('ngram_invocations', 0)}`")
    L.append(f"- pt73_distinct_total (sampled): `{ac.get('pt73_distinct_total', 0)}`")
    L.append("")
    if "crib_histogram" in ac and ac["crib_histogram"]:
        L.append("### Global crib-score histogram")
        L.append("")
        hist = ac["crib_histogram"]
        for k in sorted(int(x) for x in hist.keys()):
            L.append(f"- `{k}`: {hist.get(k, hist.get(str(k), 0))}")
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
    L.append("## Top survivors")
    L.append("")
    if camp.survivors:
        srt = sorted(
            camp.survivors,
            key=lambda s: (s.get("crib_score", 0), s.get("ngram_per_char", 0.0)),
            reverse=True,
        )
        for s in srt[:20]:
            L.append(
                f"- crib=`{s['crib_score']}`  bean=`{s['bean_passed']}`  "
                f"variant=`{s['variant']}`  mask=`{s['mask_id']}`  "
                f"key=`{s['key_id']}` ({s.get('key_family')})"
            )
    else:
        L.append("- (no survivors above STORE threshold)")
    L.append("")
    L.append("## Top near-misses (below STORE)")
    L.append("")
    if camp.near_misses:
        for nm in camp.near_misses[:20]:
            L.append(
                f"- crib=`{nm['crib_score']}`  bean=`{nm['bean_passed']}`  "
                f"ngram=`{nm['ngram_per_char']:.3f}`  variant=`{nm['variant']}`  "
                f"mask=`{nm['mask_id']}`  key=`{nm['key_id']}`"
            )
    else:
        L.append("- (none recorded)")
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
            "AND within the stated key-schedule universe; zero survivors at or "
            "above STORE_THRESHOLD. **Conditional** elimination -- rules out the "
            "enumerated key-schedule families, not the hypothesis globally."
        )
    elif camp.status == "INCONCLUSIVE_BUDGET":
        L.append("Partial coverage -- not elimination.")
    elif camp.status == "INCONCLUSIVE_TOOLING":
        L.append("Required tooling missing for one or more families -- not elimination.")
    elif camp.status == "CANDIDATE_SIGNAL":
        L.append("Candidate signal present. Route through Day 5/6 gates before any claim.")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(L))


# =============================================================================
# Run loop
# =============================================================================


def run_campaign(
    mode: str,
    masks: list["companion.Mask"],
    schedules: list[KeySchedule],
    variants: tuple[str, ...],
    workers: int,
    max_configs: Optional[int],
    checkpoint_path: Path,
    output_path: Path,
    resume: bool,
    key_chunk_size: int,
    cmd_line: str,
    tooling_gaps: list[dict],
    force_resume: bool = False,
) -> Campaign:
    assumptions = build_assumptions()
    a_hash = hash_dict(assumptions)
    u_hash = compute_universe_hash(masks, schedules, variants)
    total_configs = len(masks) * len(schedules) * len(variants)

    key_fam_breakdown = dict(Counter(s.family for s in schedules))

    inventory = {
        "canonical_ct_length": CT_LEN,
        "assumed_real_length": REDUCED_LEN,
        "null_count": 24,
        "n_masks": len(masks),
        "n_masks_by_family": dict(Counter(m.family for m in masks)),
        "n_schedules": len(schedules),
        "n_schedules_by_family": key_fam_breakdown,
        "n_variants": len(variants),
        "variants": list(variants),
        "total_configs": total_configs,
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
        tooling_gaps=tooling_gaps,
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

    # Inventory mode early exit
    if mode == "inventory":
        camp.status = "INVENTORY"
        camp.completed_at = datetime.now(timezone.utc).isoformat()
        write_json_atomic(output_path, camp.to_dict())
        render_markdown_report(camp, output_path.with_suffix(".md"), cmd_line)
        return camp

    # Empty-universe guard
    if total_configs == 0:
        camp.status = "INCONCLUSIVE_TOOLING"
        camp.notes.append("no schedules generated -- tooling gap across all enabled families")
        camp.completed_at = datetime.now(timezone.utc).isoformat()
        write_json_atomic(output_path, camp.to_dict())
        render_markdown_report(camp, output_path.with_suffix(".md"), cmd_line)
        return camp

    # Tooling check: ngram scorer.
    #
    # Policy (2026-04-14): in this harness the ngram scorer's gating
    # status depends on which families are enabled. The
    # `bean624_crib_anchored_extension` family forces Bean PASS by
    # construction (the anchor overwrite guarantees the variant-correct
    # keystream lands at the reduced crib indices), so for that family
    # the bean+crib gate is structurally satisfied and ngram is the
    # ACTUAL discriminator between English-looking plaintext and
    # noise. Without ngram, the harness cannot distinguish a meaningful
    # candidate from a structurally-required identity hit. Therefore:
    #
    #   - If bean624_crib_anchored_extension is enabled AND ngram is
    #     unavailable, refuse to run with status INCONCLUSIVE_TOOLING.
    #   - Otherwise (only non-anchored families enabled), ngram is
    #     advisory and proceeding with ngram=0.0 is acceptable.
    has_anchored_family = any(
        s.family == "bean624_crib_anchored_extension" for s in schedules
    )
    try:
        from kryptos.kernel.scoring.ngram import get_default_scorer

        _ = get_default_scorer()
        ngram_available = True
    except Exception as exc:
        ngram_available = False
        ngram_error_repr = repr(exc)[:200]
    if not ngram_available:
        if has_anchored_family:
            camp.status = "INCONCLUSIVE_TOOLING"
            camp.notes.append(
                f"ngram scorer unavailable: {ngram_error_repr} -- "
                f"bean624_crib_anchored_extension family is enabled and "
                f"ngram is REQUIRED as the discriminator for that family "
                f"(Bean PASS is structurally guaranteed by the crib-anchor "
                f"override). Refusing to run; rerun with --no-bean624 to "
                f"score the non-anchored families only, or install the "
                f"quadgram data file."
            )
            camp.tooling_gaps.append(
                {
                    "family": "bean624_crib_anchored_extension",
                    "reason": "ngram scorer required but unavailable",
                    "detail": ngram_error_repr,
                }
            )
            camp.completed_at = datetime.now(timezone.utc).isoformat()
            write_json_atomic(output_path, camp.to_dict())
            render_markdown_report(camp, output_path.with_suffix(".md"), cmd_line)
            return camp
        else:
            camp.notes.append(
                f"ngram scorer unavailable: {ngram_error_repr} -- "
                f"only non-anchored families enabled, so ngram is ADVISORY "
                f"(crib + Bean is the gating discriminator); proceeding "
                f"with ngram=0.0 per triple"
            )

    completed_set = set(camp.completed_mask_indices)
    rej = Counter(camp.rejection_counts)
    tested = int(camp.audit_counters.get("processed_count", 0))
    max_cfg = max_configs if max_configs is not None else total_configs

    # Each payload carries (mask_idx, chunk_id, mask, variants, sched_chunk)
    # so the worker can echo the identity of the chunk it processed. The
    # controller must read identity from the worker's output rather than
    # enumerating imap_unordered results, which arrive in completion order.
    chunks_per_mask = list(_chunk(schedules, key_chunk_size))
    pending: list[tuple[int, int, "companion.Mask", tuple[str, ...], tuple[KeySchedule, ...]]] = []
    for mi, m in enumerate(masks):
        if mi in completed_set:
            continue
        for ci, ch in enumerate(chunks_per_mask):
            pending.append((mi, ci, m, tuple(variants), ch))

    if not pending:
        camp.status = "ELIMINATED" if not any(
            s.get("crib_score", 0) >= SIGNAL_THRESHOLD for s in camp.survivors
        ) else "CANDIDATE_SIGNAL"
        camp.completed_at = datetime.now(timezone.utc).isoformat()
        camp.coverage["tested"] = tested
        camp.coverage["coverage_fraction"] = tested / total_configs if total_configs else 1.0
        write_json_atomic(output_path, camp.to_dict())
        render_markdown_report(camp, output_path.with_suffix(".md"), cmd_line)
        return camp

    if workers > 1:
        ctx = mp.get_context("spawn")
        pool = ctx.Pool(processes=workers, initializer=_worker_init)
    else:
        _worker_init()
        pool = None

    mask_task_count: Counter = Counter()
    mask_task_done: Counter = Counter()
    for mi, _ci, _m, _v, _ch in pending:
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
        mask_task_done[mi] += 1
        _absorb_chunk(out, rej, camp)
        if mask_task_done[mi] == mask_task_count[mi]:
            completed_set.add(mi)
        return processed

    try:
        if pool is not None:
            results_received = 0
            for out in pool.imap_unordered(_worker_eval_chunk, pending):
                delta = _record_result(out)
                tested += delta
                camp.coverage["tested"] = tested
                camp.coverage["coverage_fraction"] = tested / total_configs
                results_received += 1
                if results_received % 8 == 0 or tested >= max_cfg:
                    _persist_checkpoint(checkpoint_path, camp, completed_set, rej)
                if tested >= max_cfg:
                    break
        else:
            for idx, payload in enumerate(pending):
                out = _worker_eval_chunk(payload)
                delta = _record_result(out)
                tested += delta
                camp.coverage["tested"] = tested
                camp.coverage["coverage_fraction"] = tested / total_configs
                if (idx + 1) % 8 == 0 or tested >= max_cfg:
                    _persist_checkpoint(checkpoint_path, camp, completed_set, rej)
                if tested >= max_cfg:
                    break
    finally:
        if pool is not None:
            pool.close()
            pool.join()

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
    bean_sum = (
        int(ac.get("bean_pass", 0))
        + int(ac.get("bean_fail", 0))
        + int(ac.get("bean_not_applicable", 0))
    )
    if bean_sum != global_processed:
        camp.notes.append(
            f"audit mismatch: bean_pass+fail+na={bean_sum} vs processed={global_processed}"
        )

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

    camp.best = sorted(
        camp.survivors,
        key=lambda s: (s.get("crib_score", 0), s.get("ngram_per_char", 0.0)),
        reverse=True,
    )[:10]

    camp.per_worker_audit.sort(
        key=lambda e: (-int(e.get("processed_count", 0)), int(e.get("worker_pid", 0)))
    )

    _persist_checkpoint(checkpoint_path, camp, completed_set, rej)
    write_json_atomic(output_path, camp.to_dict())
    render_markdown_report(camp, output_path.with_suffix(".md"), cmd_line)
    return camp


# =============================================================================
# CLI
# =============================================================================


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Deterministic finite harness for non-wordlist key schedules "
            "(bean624 extensions, linear recurrences, coordinate tapes, vimark) "
            "on the 73-real / 24-null / Bean family. Conditional under H1."
        )
    )
    p.add_argument("--mode", choices=("inventory", "smoke", "full"), default="smoke")
    p.add_argument("--max-configs", type=int, default=None)
    p.add_argument("--limit-masks", type=int, default=None)
    p.add_argument("--limit-schedules", type=int, default=None)
    p.add_argument("--limit-bean624-vectors", type=int, default=None)
    p.add_argument("--vimark-limit", type=int, default=500)
    p.add_argument("--no-bean624", action="store_true")
    p.add_argument("--no-linear-recurrence", action="store_true")
    p.add_argument("--no-coordinate", action="store_true")
    p.add_argument("--no-vimark", action="store_true")
    p.add_argument("--random-masks", type=int, default=0)
    p.add_argument("--random-seed", type=int, default=1337)
    p.add_argument("--workers", type=int, default=max(1, mp.cpu_count() - 2))
    p.add_argument("--key-chunk-size", type=int, default=64)
    p.add_argument(
        "--checkpoint",
        type=Path,
        default=Path("results/h_624_nonword_key_schedule/checkpoint.json"),
    )
    p.add_argument(
        "--output",
        type=Path,
        default=Path("results/h_624_nonword_key_schedule/result.json"),
    )
    p.add_argument("--resume", action="store_true")
    p.add_argument("--force", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)

    # Masks from companion harness.
    masks = companion.build_mask_universe(
        include_random=args.random_masks, random_seed=args.random_seed
    )
    if args.limit_masks is not None:
        masks = masks[: args.limit_masks]

    # Key schedules
    schedules, tooling_gaps = build_key_schedule_universe(
        include_bean624=(not args.no_bean624),
        limit_bean624_vectors=args.limit_bean624_vectors,
        include_linear_recurrence=(not args.no_linear_recurrence),
        include_coordinate=(not args.no_coordinate),
        include_vimark=(not args.no_vimark),
        vimark_limit=args.vimark_limit,
    )
    if args.limit_schedules is not None:
        schedules = schedules[: args.limit_schedules]

    # Smoke mode trims both dims hard unless user overrides.
    if args.mode == "smoke":
        if args.limit_masks is None:
            masks = masks[:4]
        if args.limit_schedules is None:
            schedules = schedules[:50]

    variants = tuple(CIPHER_VARIANTS)

    cmd_line = (
        "PYTHONPATH=src python3 "
        + " ".join([sys.argv[0], *map(str, (argv or sys.argv[1:]))])
    )

    mode = "inventory" if (args.dry_run or args.mode == "inventory") else args.mode

    camp = run_campaign(
        mode=mode,
        masks=masks,
        schedules=schedules,
        variants=variants,
        workers=max(1, args.workers),
        max_configs=args.max_configs,
        checkpoint_path=args.checkpoint,
        output_path=args.output,
        resume=args.resume,
        key_chunk_size=max(1, args.key_chunk_size),
        cmd_line=cmd_line,
        tooling_gaps=tooling_gaps,
        force_resume=args.force,
    )

    print(f"{camp.campaign_id} {camp.campaign_version}  status={camp.status}")
    print(f"  mode: {mode}  workers: {args.workers}")
    print(f"  masks: {len(masks)}  schedules: {len(schedules)}  variants: {len(variants)}")
    print(f"  total configs: {camp.inventory.get('total_configs')}")
    print(f"  tested: {camp.coverage.get('tested')}")
    print(f"  survivors: {len(camp.survivors)}")
    print(f"  tooling gaps: {len(camp.tooling_gaps)}")
    print(f"  output: {args.output}")
    print(f"  checkpoint: {args.checkpoint}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
