# Null-Mask-Aware Kernel Substrate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the K4 kernel a pure, CT-explicit substrate for null-mask / variable-plaintext-length hypotheses — single canonical Bean re-derivation, mask extraction, mask-aware verification, and provenance-gated mask hypotheses — without changing any canonical (empty-mask) behavior.

**Architecture:** A low-level pure derivation core (`constraints/derive.py`, imports nothing from the kernel) becomes the single source of Bean constraints; `constants.py` and an alphabet-aware wrapper in `bean.py` both call it. A new `kernel/masking/` package adds mask extraction + position remapping + a masked-candidate verifier. Hypothesis gating (provenance, bounded universe, two-tier) lives one layer up in `admissibility/`. The empty-mask path reduces byte-for-byte to today's kernel, enforced by regression tests.

**Tech Stack:** Python 3.11+, stdlib only (kernel), `pytest`. All commands require `PYTHONPATH=src`. Reference spec: `docs/specs/2026-05-25-null-mask-aware-kernel-design.md`.

---

## File Structure

| Path | Responsibility | Status |
|---|---|---|
| `src/kryptos/kernel/constraints/derive.py` | Pure Bean-constraint derivation core (ct, crib_dict, index_table, mod) → (eq, ineq, linear). No kernel imports. | Create |
| `src/kryptos/kernel/constants.py` | Call the core for canonical `BEAN_EQ/INEQ/LINEAR`; keep import self-verify. | Modify |
| `src/kryptos/kernel/constraints/bean.py` | Add alphabet-aware `derive_bean_constraints` wrapper + parameterized `check_bean`; make `verify_bean` call it. | Modify |
| `src/kryptos/kernel/scoring/crib_score.py` | `score_cribs_detailed(text, crib_dict=None)` parameterized. | Modify |
| `src/kryptos/kernel/scoring/aggregate.py` | `score_candidate(..., crib_dict=None)` threads to crib scorer. | Modify |
| `src/kryptos/kernel/masking/__init__.py` | Package marker. | Create |
| `src/kryptos/kernel/masking/mask.py` | `NullMask`, `validate_mask`, `extract_ct`, `remap_position`, `remap_crib_dict`. | Create |
| `src/kryptos/kernel/masking/verify.py` | `MaskedVerification`, `verify_masked_candidate`, `solve` interface stub. | Create |
| `src/kryptos/admissibility/mask_hypothesis.py` | `MaskUniverse`, `MaskHypothesis`, `validate_mask_hypothesis`. | Create |
| `kryptosbot/ct_perturbation.py` | `derive_bean_constraints` becomes a thin re-export. | Modify |
| `tests/test_bean_derive.py` | Core derivation + empty-mask parity + `check_bean`. | Create |
| `tests/test_masking_mask.py` | Extraction / remap / validation. | Create |
| `tests/test_masking_verify.py` | Masked verification + synthetic sealed challenge. | Create |
| `tests/test_mask_hypothesis.py` | Gating validator. | Create |

---

## Task 1: Promote the Bean derivation core

**Files:**
- Create: `src/kryptos/kernel/constraints/derive.py`
- Test: `tests/test_bean_derive.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_bean_derive.py
from kryptos.kernel.constraints.derive import derive_bean_constraints
from kryptos.kernel.constants import CT, CRIB_DICT, MOD, BEAN_EQ, BEAN_INEQ, BEAN_LINEAR

IDENTITY = list(range(26))  # AZ index table: index_table[ord(ch)-65] == position

def test_core_reproduces_canonical_bean_sets():
    eq, ineq, linear = derive_bean_constraints(CT, CRIB_DICT, IDENTITY, MOD)
    assert eq == BEAN_EQ
    assert ineq == BEAN_INEQ
    assert linear == BEAN_LINEAR
    assert (len(eq), len(ineq), len(linear)) == (1, 242, 101)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src pytest tests/test_bean_derive.py::test_core_reproduces_canonical_bean_sets -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'kryptos.kernel.constraints.derive'`

- [ ] **Step 3: Write the core derivation**

```python
# src/kryptos/kernel/constraints/derive.py
"""Pure, dependency-free Bean-constraint derivation.

Imports NOTHING from the kernel so that constants.py can call it without a
circular import. Operates entirely on explicit arguments: the ciphertext, a
crib mapping (0-indexed position -> uppercase letter), a 26-entry index table
(index_table[ord(ch)-65] -> position-in-alphabet), and the modulus.

Variant-independent: a pair/tuple is admitted only when the relation holds for
ALL three additive variants (Vigenere k=c-p, Beaufort k=c+p, VarBeaufort k=p-c).
Output sets are in 0-indexed CT coordinates.
"""
from __future__ import annotations

from typing import Mapping, Sequence, Tuple

BeanConstraints = Tuple[
    Tuple[Tuple[int, int], ...],
    Tuple[Tuple[int, int], ...],
    Tuple[Tuple[int, int, int, int], ...],
]


def derive_bean_constraints(
    ct: str,
    crib_dict: Mapping[int, str],
    index_table: Sequence[int],
    mod: int = 26,
) -> BeanConstraints:
    positions = sorted(crib_dict.keys())
    n = len(positions)

    def cp(pos: int) -> Tuple[int, int]:
        return index_table[ord(ct[pos]) - 65], index_table[ord(crib_dict[pos]) - 65]

    eq: list[Tuple[int, int]] = []
    ineq: list[Tuple[int, int]] = []
    linear: list[Tuple[int, int, int, int]] = []

    for i in range(n):
        for j in range(i + 1, n):
            a, b = positions[i], positions[j]
            ca, pa = cp(a)
            cb, pb = cp(b)
            vig = (ca - pa) % mod == (cb - pb) % mod
            beau = (ca + pa) % mod == (cb + pb) % mod
            vbeau = (pa - ca) % mod == (pb - cb) % mod
            if vig and beau and vbeau:
                eq.append((a, b))
            elif not vig and not beau and not vbeau:
                ineq.append((a, b))

    for i in range(n):
        for j in range(i + 1, n):
            for k in range(j + 1, n):
                for l in range(k + 1, n):
                    a, b, c, d = positions[i], positions[j], positions[k], positions[l]
                    for p1, p2, p3, p4 in ((a, b, c, d), (a, c, b, d), (a, d, b, c)):
                        ca, pa = cp(p1)
                        cb, pb = cp(p2)
                        cc, pc = cp(p3)
                        cd, pd = cp(p4)
                        vig = ((ca - pa) - (cb - pb) - (cc - pc) + (cd - pd)) % mod
                        beau = ((ca + pa) - (cb + pb) - (cc + pc) + (cd + pd)) % mod
                        vbeau = ((pa - ca) - (pb - cb) - (pc - cc) + (pd - cd)) % mod
                        if vig == 0 and beau == 0 and vbeau == 0:
                            linear.append((p1, p2, p3, p4))

    return tuple(eq), tuple(ineq), tuple(linear)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `PYTHONPATH=src pytest tests/test_bean_derive.py::test_core_reproduces_canonical_bean_sets -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/kryptos/kernel/constraints/derive.py tests/test_bean_derive.py
git commit -m "feat(kernel): pure Bean-constraint derivation core"
```

---

## Task 2: Route constants.py through the core (single derivation path)

**Files:**
- Modify: `src/kryptos/kernel/constants.py:196-296`
- Test: `tests/test_bean_derive.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_bean_derive.py  (append)
import kryptos.kernel.constants as K

def test_constants_use_the_shared_core():
    # The private per-set derivers are gone; one shared call remains.
    assert not hasattr(K, "_derive_bean_eq")
    assert (len(K.BEAN_EQ), len(K.BEAN_INEQ), len(K.BEAN_LINEAR)) == (1, 242, 101)
    assert K.BEAN_EQ == ((27, 65),)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src pytest tests/test_bean_derive.py::test_constants_use_the_shared_core -v`
Expected: FAIL on `assert not hasattr(K, "_derive_bean_eq")` (the private deriver still exists).

- [ ] **Step 3: Replace the three derivers with one shared call**

In `src/kryptos/kernel/constants.py`, delete the three functions `_derive_bean_eq`, `_derive_bean_ineq`, `_derive_bean_linear` and their three assignment lines (currently lines ~198-296). Replace the whole `# ── Bean constraints ──` block body with:

```python
# ── Bean constraints ──────────────────────────────────────────────────────
# Single canonical derivation via the dependency-free core. AZ indexing here
# is the identity table because ALPH == "ABC...Z"; a masked / KA derivation
# supplies its own index table (see kernel.constraints.bean.derive_bean_constraints).
from kryptos.kernel.constraints.derive import (  # noqa: E402
    derive_bean_constraints as _derive_bean_constraints,
)

_AZ_INDEX_TABLE: Tuple[int, ...] = tuple(range(MOD))

BEAN_EQ, BEAN_INEQ, BEAN_LINEAR = _derive_bean_constraints(
    CT, CRIB_DICT, _AZ_INDEX_TABLE, MOD
)
```

Leave the existing import-time `_verify()` (which asserts the 1/242/101 counts and `BEAN_EQ == ((27,65),)`) unchanged — it now guards the shared core.

- [ ] **Step 4: Run tests to verify they pass**

Run: `PYTHONPATH=src pytest tests/test_bean_derive.py -v && PYTHONPATH=src python3 -m kryptos doctor`
Expected: tests PASS; `doctor` reports Bean checks OK (`bean_eq_count == 1`, `bean_ineq_count == 242`, `bean_linear_count == 101`).

- [ ] **Step 5: Run the standing fitness check + broad import smoke**

Run: `PYTHONPATH=src python3 kryptosbot/self_test.py --panel all --mode dry-run && PYTHONPATH=src pytest tests/test_scoring.py tests/test_transforms.py -q`
Expected: K1/K2 still rediscoverable; existing tests green (no behavior change).

- [ ] **Step 6: Commit**

```bash
git add src/kryptos/kernel/constants.py tests/test_bean_derive.py
git commit -m "refactor(kernel): constants.py derives Bean via shared core"
```

---

## Task 3: Alphabet-aware wrapper + parameterized check_bean

**Files:**
- Modify: `src/kryptos/kernel/constraints/bean.py:15-125`
- Test: `tests/test_bean_derive.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_bean_derive.py  (append)
from kryptos.kernel.constraints.bean import derive_bean_constraints, check_bean, verify_bean
from kryptos.kernel.alphabet import AZ
from kryptos.kernel.constants import CT, CRIB_DICT, BEAN_EQ, BEAN_INEQ, BEAN_LINEAR

def test_alphabet_wrapper_matches_canonical():
    eq, ineq, linear = derive_bean_constraints(CT, CRIB_DICT, AZ)
    assert (eq, ineq, linear) == (BEAN_EQ, BEAN_INEQ, BEAN_LINEAR)

def test_check_bean_parameterized_matches_verify_bean():
    ks = list(range(97))  # arbitrary keystream
    full = verify_bean(ks)
    param = check_bean(ks, BEAN_EQ, BEAN_INEQ, BEAN_LINEAR)
    assert param.passed == full.passed
    assert (param.eq_satisfied, param.ineq_satisfied, param.linear_satisfied) == \
           (full.eq_satisfied, full.ineq_satisfied, full.linear_satisfied)

def test_check_bean_accepts_short_keystream_for_masked_use():
    # Per-mask keystreams are shorter than 97; check_bean must not hard-require 97.
    eq, ineq, linear = ((0, 1),), (), ()
    assert check_bean([5, 5, 9], eq, ineq, linear).passed is True
    assert check_bean([5, 7, 9], eq, ineq, linear).passed is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src pytest tests/test_bean_derive.py -k "alphabet_wrapper or check_bean" -v`
Expected: FAIL with `ImportError: cannot import name 'derive_bean_constraints'` / `'check_bean'`.

- [ ] **Step 3: Add the wrapper and parameterized checker; refactor verify_bean**

In `src/kryptos/kernel/constraints/bean.py`, add to the import block:

```python
from kryptos.kernel.alphabet import AZ, Alphabet
from kryptos.kernel.constraints.derive import (
    BeanConstraints,
    derive_bean_constraints as _derive_core,
)
```

Add after `BeanResult`:

```python
def derive_bean_constraints(
    ct: str,
    crib_dict: Optional[Dict[int, str]] = None,
    alphabet: Alphabet = AZ,
) -> BeanConstraints:
    """Alphabet-aware Bean derivation. Canonical args reproduce the kernel's
    frozen sets; masked / KA callers pass their own ct/crib_dict/alphabet."""
    cribs = dict(crib_dict) if crib_dict is not None else dict(CRIB_DICT)
    return _derive_core(ct, cribs, alphabet.index_table, MOD)


def check_bean(
    keystream: List[int],
    eq: Tuple[Tuple[int, int], ...],
    ineq: Tuple[Tuple[int, int], ...],
    linear: Tuple[Tuple[int, int, int, int], ...],
    mod: int = MOD,
) -> BeanResult:
    """Verify a keystream against EXPLICIT constraint sets (any length).

    Used for per-mask verification where the keystream length is 97-|mask|
    and the constraint sets are re-derived for that mask. Positions referenced
    by the sets must be in range for `keystream`.
    """
    eq_failures: list[tuple[int, int, int, int]] = []
    ineq_failures: list[tuple[int, int, int]] = []
    linear_failures: list[tuple[int, int, int, int, int]] = []
    for a, b in eq:
        if keystream[a] != keystream[b]:
            eq_failures.append((a, b, keystream[a], keystream[b]))
    for a, b in ineq:
        if keystream[a] == keystream[b]:
            ineq_failures.append((a, b, keystream[a]))
    for a, b, c, d in linear:
        residue = (keystream[a] - keystream[b] - keystream[c] + keystream[d]) % mod
        if residue != 0:
            linear_failures.append((a, b, c, d, residue))
    return BeanResult(
        passed=(not eq_failures and not ineq_failures and not linear_failures),
        eq_satisfied=len(eq) - len(eq_failures), eq_total=len(eq),
        ineq_satisfied=len(ineq) - len(ineq_failures), ineq_total=len(ineq),
        linear_satisfied=len(linear) - len(linear_failures), linear_total=len(linear),
        eq_failures=eq_failures, ineq_failures=ineq_failures,
        linear_failures=linear_failures,
    )
```

Then change the body of `verify_bean` (keep its `len(keystream) != CT_LEN` guard and docstring) so that after the guard it delegates:

```python
    return check_bean(keystream, BEAN_EQ, BEAN_INEQ, BEAN_LINEAR, MOD)
```

(Delete the now-duplicated failure-collection loops inside `verify_bean`.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `PYTHONPATH=src pytest tests/test_bean_derive.py tests/test_constraints.py -q`
Expected: PASS (existing Bean tests unchanged; new ones green).

- [ ] **Step 5: Commit**

```bash
git add src/kryptos/kernel/constraints/bean.py tests/test_bean_derive.py
git commit -m "feat(kernel): alphabet-aware derive + parameterized check_bean"
```

---

## Task 4: Re-export in ct_perturbation (kill the drift risk)

**Files:**
- Modify: `kryptosbot/ct_perturbation.py:228-292`
- Test: existing `kryptosbot/tests/` for ct_perturbation.

- [ ] **Step 1: Run the existing ct_perturbation tests to establish the baseline (green)**

Run: `PYTHONPATH=src python3 -m pytest kryptosbot/tests/ -k ct_perturbation -q`
Expected: PASS (record the count).

- [ ] **Step 2: Replace the local derivation with a re-export**

In `kryptosbot/ct_perturbation.py`, delete the local `def derive_bean_constraints(...)` body (lines ~228-292) and replace with:

```python
# Bean derivation now lives in the core kernel (single source of truth).
# Re-exported here so existing call sites keep their import path.
from kryptos.kernel.constraints.bean import derive_bean_constraints  # noqa: E402,F401
```

Keep `_validate_ct` and all other functions. The kernel wrapper validates inputs differently (no `_validate_ct`); add a one-line guard inside callers only if a test requires the old ValueError — otherwise leave as is.

- [ ] **Step 3: Run the existing tests to verify they still pass**

Run: `PYTHONPATH=src python3 -m pytest kryptosbot/tests/ -k ct_perturbation -q`
Expected: PASS, same count as Step 1.

- [ ] **Step 4: Commit**

```bash
git add kryptosbot/ct_perturbation.py
git commit -m "refactor(bot): ct_perturbation re-exports kernel Bean derivation"
```

---

## Task 5: Mask extraction + position remapping

**Files:**
- Create: `src/kryptos/kernel/masking/__init__.py`
- Create: `src/kryptos/kernel/masking/mask.py`
- Test: `tests/test_masking_mask.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_masking_mask.py
import pytest
from kryptos.kernel.masking.mask import (
    validate_mask, extract_ct, remap_position, remap_crib_dict,
)
from kryptos.kernel.constants import CT, CRIB_DICT, CT_LEN

def test_empty_mask_is_identity():
    assert extract_ct(CT, frozenset()) == CT
    assert remap_position(50, frozenset()) == 50
    assert remap_crib_dict(CRIB_DICT, frozenset()) == CRIB_DICT

def test_extract_removes_null_positions_and_shrinks_length():
    mask = frozenset({0, 1, 2})
    out = extract_ct(CT, mask)
    assert out == CT[3:]
    assert len(out) == CT_LEN - 3

def test_remap_shifts_by_nulls_before_position():
    mask = frozenset({5, 10})
    assert remap_position(4, mask) == 4     # no nulls before
    assert remap_position(7, mask) == 6     # one null (5) before
    assert remap_position(11, mask) == 9    # two nulls (5,10) before

def test_remap_crib_dict_relocates_cribs_into_extracted_coords():
    mask = frozenset({0})  # one null before everything
    remapped = remap_crib_dict(CRIB_DICT, mask)
    # carved 21 -> 20, carved 63 -> 62; letters unchanged
    assert remapped[20] == CRIB_DICT[21]
    assert remapped[62] == CRIB_DICT[63]
    assert len(remapped) == len(CRIB_DICT)

def test_validate_rejects_null_on_crib_position_by_default():
    with pytest.raises(ValueError):
        validate_mask(frozenset({21}), CT_LEN)

def test_validate_allows_crib_null_when_explicitly_relaxed():
    validate_mask(frozenset({21}), CT_LEN, allow_crib_nulls=True)  # no raise

def test_validate_rejects_out_of_range():
    with pytest.raises(ValueError):
        validate_mask(frozenset({CT_LEN}), CT_LEN)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src pytest tests/test_masking_mask.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'kryptos.kernel.masking'`.

- [ ] **Step 3: Create the package and mask module**

```python
# src/kryptos/kernel/masking/__init__.py
"""Null-mask-aware substrate for variable-plaintext-length K4 hypotheses."""
```

```python
# src/kryptos/kernel/masking/mask.py
"""Null-mask representation and pure extraction / remap helpers.

A NullMask is a frozenset of carved-CT positions that are NULLS (filler, not
cipher output). Extracting the non-null positions yields the implied
ciphertext CT' of length 97-|mask|; its decryption is the plaintext, so the
plaintext length is variable and equal to len(CT'). All functions are pure and
take CT / crib_dict explicitly — no global state, no env overrides.
"""
from __future__ import annotations

from typing import FrozenSet, Mapping

from kryptos.kernel.constants import CRIB_POSITIONS, CT_LEN

NullMask = FrozenSet[int]


def validate_mask(
    mask: NullMask,
    ct_len: int = CT_LEN,
    crib_positions: FrozenSet[int] = CRIB_POSITIONS,
    allow_crib_nulls: bool = False,
) -> None:
    """Raise ValueError if the mask is malformed.

    Default invariant (overridable): crib positions are NOT nulls — cribs are
    CT-position-anchored disclosures (feedback_pt_length_open_question). This is
    a declared assumption, not proven law; relax only with explicit provenance.
    """
    for p in mask:
        if p < 0 or p >= ct_len:
            raise ValueError(f"mask position {p} out of range [0,{ct_len})")
    if not allow_crib_nulls:
        hit = sorted(mask & crib_positions)
        if hit:
            raise ValueError(
                f"mask intersects crib positions {hit}; cribs are not nulls by "
                f"default (pass allow_crib_nulls=True with provenance to relax)"
            )


def extract_ct(ct: str, mask: NullMask) -> str:
    """Return ct with all null positions removed (length len(ct)-|mask|)."""
    return "".join(ch for i, ch in enumerate(ct) if i not in mask)


def remap_position(pos: int, mask: NullMask) -> int:
    """Map a carved (non-null) position to its index in the extracted CT'."""
    return pos - sum(1 for m in mask if m < pos)


def remap_crib_dict(crib_dict: Mapping[int, str], mask: NullMask) -> dict[int, str]:
    """Relocate cribs from carved coordinates to extracted-CT' coordinates."""
    return {remap_position(p, mask): ch for p, ch in crib_dict.items()}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `PYTHONPATH=src pytest tests/test_masking_mask.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/kryptos/kernel/masking/__init__.py src/kryptos/kernel/masking/mask.py tests/test_masking_mask.py
git commit -m "feat(kernel): null-mask extraction and position remapping"
```

---

## Task 6: Parameterize crib scoring through the masked path

**Files:**
- Modify: `src/kryptos/kernel/scoring/crib_score.py:38-67`
- Modify: `src/kryptos/kernel/scoring/aggregate.py:110-132`
- Test: `tests/test_masking_verify.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_masking_verify.py
from kryptos.kernel.scoring.crib_score import score_cribs_detailed
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.constants import CRIB_DICT

def test_crib_scorer_default_unchanged():
    # 'A'*97 matches no cribs -> 0
    assert score_cribs_detailed("A" * 97)["score"] == 0

def test_crib_scorer_accepts_custom_crib_dict():
    text = "SE"            # positions 0,1
    cd = {0: "S", 1: "E"}  # both match
    assert score_cribs_detailed(text, crib_dict=cd)["score"] == 2

def test_score_candidate_threads_crib_dict():
    text = "SE"
    cd = {0: "S", 1: "X"}  # one match
    assert score_candidate(text, crib_dict=cd).crib_score == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src pytest tests/test_masking_verify.py -k crib -v`
Expected: FAIL — `score_cribs_detailed()` / `score_candidate()` got an unexpected keyword argument `crib_dict`.

- [ ] **Step 3: Add the parameter to both functions**

In `src/kryptos/kernel/scoring/crib_score.py`, change the signature and the dict it iterates:

```python
def score_cribs_detailed(text: str, crib_dict: "Optional[Dict[int, str]]" = None) -> Dict[str, object]:
```

Immediately inside the body, before the loop, add:

```python
    cribs = CRIB_DICT if crib_dict is None else crib_dict
```

and change the loop header from `for pos, expected in CRIB_DICT.items():` to `for pos, expected in cribs.items():`. Change the `"total"` field from `N_CRIBS` to `len(cribs)` so the denominator is correct for masked crib sets. (The 21<=pos<=33 / 63<=pos<=73 ene/bc split is canonical-only diagnostic; leave it — it simply reports 0 for remapped positions, which is acceptable for masked runs.)

In `src/kryptos/kernel/scoring/aggregate.py`, change the signature:

```python
def score_candidate(
    plaintext: str,
    bean_result: Optional[BeanResult] = None,
    ngram_scorer=None,
    word_scorer=None,
    include_p_values: bool = False,
    crib_dict: Optional[Dict[int, str]] = None,
) -> ScoreBreakdown:
```

and change line ~131 from `detail = score_cribs_detailed(plaintext)` to:

```python
    detail = score_cribs_detailed(plaintext, crib_dict=crib_dict)
    crib_total = len(crib_dict) if crib_dict is not None else N_CRIBS
```

and change the returned `crib_total=N_CRIBS` to `crib_total=crib_total`. Ensure `Dict` is imported in aggregate.py (`from typing import ... Dict`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `PYTHONPATH=src pytest tests/test_masking_verify.py -k crib tests/test_scoring.py -q`
Expected: PASS (default behavior unchanged; custom crib_dict honored).

- [ ] **Step 5: Commit**

```bash
git add src/kryptos/kernel/scoring/crib_score.py src/kryptos/kernel/scoring/aggregate.py tests/test_masking_verify.py
git commit -m "feat(kernel): parameterize crib scoring by crib_dict"
```

---

## Task 7: Masked candidate verification + solver interface stub

**Files:**
- Create: `src/kryptos/kernel/masking/verify.py`
- Test: `tests/test_masking_verify.py`

- [ ] **Step 1: Write the failing test (synthetic sealed masked challenge)**

```python
# tests/test_masking_verify.py  (append)
import pytest
from kryptos.kernel.alphabet import AZ
from kryptos.kernel.transforms.vigenere import CipherVariant, encrypt_text
from kryptos.kernel.masking.verify import verify_masked_candidate, solve

def _build_masked_ct():
    # Known PT of length 5, Vigenere key, then insert 2 nulls -> carved CT of len 7.
    pt = "SXEYZ"
    key = [1, 2, 3, 4, 5]
    core_ct = encrypt_text(pt, key, CipherVariant.VIGENERE, alphabet=AZ)  # len 5
    # Insert nulls 'Q' at carved positions 2 and 5 -> CT' recovers core_ct.
    carved = core_ct[:2] + "Q" + core_ct[2:4] + "Q" + core_ct[4:]
    true_mask = frozenset({2, 5})
    crib_dict = {0: "S", 3: "Y"}  # carved positions of two PT letters (pre-null-shift)
    return carved, key, true_mask, crib_dict

def test_true_mask_recovers_cribs():
    carved, key, true_mask, crib_dict = _build_masked_ct()
    res = verify_masked_candidate(
        carved, true_mask, CipherVariant.VIGENERE, key,
        crib_dict=crib_dict, alphabet=AZ,
    )
    assert res.pt_len == len(carved) - len(true_mask)
    assert res.crib_score == 2  # both cribs satisfied at the true mask

def test_wrong_mask_fails_cribs():
    carved, key, _true, crib_dict = _build_masked_ct()
    res = verify_masked_candidate(
        carved, frozenset({0, 1}), CipherVariant.VIGENERE, key,
        crib_dict=crib_dict, alphabet=AZ,
    )
    assert res.crib_score < 2

def test_solve_interface_is_defined_but_deferred():
    with pytest.raises(NotImplementedError):
        next(solve(mask_universe=[frozenset()], mechanism_family=None,
                   constraint_oracle=verify_masked_candidate))
```

> Note: this test references `encrypt_text` from `transforms/vigenere.py`. Confirm its exact name first with `PYTHONPATH=src python3 -c "import kryptos.kernel.transforms.vigenere as v; print([n for n in dir(v) if 'crypt' in n])"`. If the encrypt helper has a different name, adjust the import; do not invent one.

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src pytest tests/test_masking_verify.py -k "mask or solve" -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'kryptos.kernel.masking.verify'`.

- [ ] **Step 3: Implement the verifier and solver stub**

```python
# src/kryptos/kernel/masking/verify.py
"""Mask-aware candidate verification (the constraint oracle).

verify_masked_candidate evaluates ONE (mask, variant, key) tuple: extract CT',
decrypt, re-derive Bean for the mask, recover the implied keystream at remapped
crib positions, check Bean, and crib-score the plaintext at remapped positions.
It carries the calibration inputs a mask-universe-aware null model needs.

solve(...) is the joint mask x mechanism search INTERFACE only; the algorithm
is deferred to a follow-on spec (see docs/specs/2026-05-25-null-mask-aware-kernel-design.md).
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

NullMaskT = NullMask


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
    validate_mask(mask, len(ct), allow_crib_nulls=allow_crib_nulls)
    ct_prime = extract_ct(ct, mask)
    cribs = remap_crib_dict(crib_dict, mask)
    eq, ineq, linear = derive_bean_constraints(ct_prime, cribs, alphabet)
    pt = decrypt_text(ct_prime, list(key), variant, alphabet=alphabet)

    # Recover the implied keystream over CT' (length len(ct_prime)).
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
    """Joint mask x mechanism search. INTERFACE ONLY — algorithm deferred.

    A follow-on spec implements constraint-propagation / SAT pruning over the
    per-mask Bean sets and crib equations. Until then this raises so callers
    cannot mistake the stub for a working solver.
    """
    raise NotImplementedError(
        "solve() is an interface stub; the search algorithm is a separate spec "
        "(efficacy review item #2)."
    )
    yield  # pragma: no cover  (marks this a generator for the interface contract)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `PYTHONPATH=src pytest tests/test_masking_verify.py -v`
Expected: PASS (true mask scores 2; wrong mask < 2; `solve` raises NotImplementedError).

- [ ] **Step 5: Commit**

```bash
git add src/kryptos/kernel/masking/verify.py tests/test_masking_verify.py
git commit -m "feat(kernel): masked candidate verification + solver interface stub"
```

---

## Task 8: Mask hypothesis gating (provenance, bounded universe, two-tier)

**Files:**
- Create: `src/kryptos/admissibility/mask_hypothesis.py`
- Test: `tests/test_mask_hypothesis.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_mask_hypothesis.py
import pytest
from kryptos.admissibility.mask_hypothesis import (
    MaskUniverse, MaskHypothesis, validate_mask_hypothesis, ALIGNMENT_MODEL_KEYS,
)

def _universe():
    return MaskUniverse(masks=(frozenset(), frozenset({0})), description="demo")

def test_primary_requires_provenance():
    h = MaskHypothesis(
        mask_universe=_universe(), alignment_model="arbitrary_null_mask",
        provenance="", assumption_bundle=("cribs_not_null",),
        tier="primary_evidentiary", stop_rule="enumerate all",
    )
    errs = validate_mask_hypothesis(h)
    assert any("provenance" in e for e in errs)

def test_secondary_allowed_without_provenance():
    h = MaskHypothesis(
        mask_universe=_universe(), alignment_model="arbitrary_null_mask",
        provenance="", assumption_bundle=("cribs_not_null",),
        tier="secondary_exploratory", stop_rule="enumerate all",
    )
    assert validate_mask_hypothesis(h) == []

def test_unknown_alignment_model_rejected():
    h = MaskHypothesis(
        mask_universe=_universe(), alignment_model="made_up",
        provenance="GAP-09 note", assumption_bundle=(),
        tier="secondary_exploratory", stop_rule="x",
    )
    errs = validate_mask_hypothesis(h)
    assert any("alignment_model" in e for e in errs)

def test_universe_hash_is_deterministic_and_present():
    u = _universe()
    assert u.universe_hash == _universe().universe_hash
    assert len(u.universe_hash) == 64  # sha256 hex
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src pytest tests/test_mask_hypothesis.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'kryptos.admissibility.mask_hypothesis'`.

- [ ] **Step 3: Implement the gating types and validator**

```python
# src/kryptos/admissibility/mask_hypothesis.py
"""Provenance-gated, bounded, two-tier mask hypotheses.

Mirrors the disproof-protocol / dispatcher-dsl-contract discipline: a mask
search is admissible only as a bounded, hashed universe with a declared
alignment model and (for primary tier) a provenance artifact. Exploratory
masks are allowed but quarantined and never promotable to a global K4 fact.
The alignment_model keys match the session-briefing assumption-boundary taxonomy.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import FrozenSet, Literal, Sequence, Tuple

ALIGNMENT_MODEL_KEYS: FrozenSet[str] = frozenset({
    "direct_ct_pt", "fixed_len_97", "ct73_null_extracted",
    "arbitrary_null_mask", "non_direct_alignment", "joint_mask_mechanism",
})

Tier = Literal["primary_evidentiary", "secondary_exploratory"]


@dataclass(frozen=True)
class MaskUniverse:
    masks: Tuple[FrozenSet[int], ...]
    description: str

    @property
    def universe_hash(self) -> str:
        payload = "|".join(
            ",".join(str(p) for p in sorted(m)) for m in self.masks
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class MaskHypothesis:
    mask_universe: MaskUniverse
    alignment_model: str
    provenance: str
    assumption_bundle: Tuple[str, ...]
    tier: Tier
    stop_rule: str


def validate_mask_hypothesis(h: MaskHypothesis) -> list[str]:
    """Return a list of admissibility errors (empty == admissible)."""
    errors: list[str] = []
    if h.alignment_model not in ALIGNMENT_MODEL_KEYS:
        errors.append(f"unknown alignment_model {h.alignment_model!r}")
    if not h.mask_universe.masks:
        errors.append("mask_universe is empty (no bounded universe)")
    if not h.stop_rule:
        errors.append("missing stop_rule")
    if h.tier == "primary_evidentiary" and not h.provenance.strip():
        errors.append("primary_evidentiary tier requires a provenance artifact")
    if h.tier not in ("primary_evidentiary", "secondary_exploratory"):
        errors.append(f"unknown tier {h.tier!r}")
    return errors
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `PYTHONPATH=src pytest tests/test_mask_hypothesis.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/kryptos/admissibility/mask_hypothesis.py tests/test_mask_hypothesis.py
git commit -m "feat(admissibility): provenance-gated two-tier mask hypotheses"
```

---

## Task 9: Known-answer gate + full regression sweep

**Files:**
- Test: `tests/test_masking_verify.py` (append)

- [ ] **Step 1: Write the empty-mask known-answer test**

```python
# tests/test_masking_verify.py  (append)
from kryptos.kernel.constants import CT, CRIB_DICT
from kryptos.kernel.transforms.vigenere import CipherVariant
from kryptos.kernel.masking.verify import verify_masked_candidate

def test_empty_mask_matches_unmasked_crib_score():
    # With the empty mask, verifying with the canonical Vigenere crib keystream
    # reproduces the same crib outcome as the unmasked kernel path.
    # Use the known ENE/BC Vigenere key vectors assembled into a 97-int key is
    # out of scope here; this test asserts the empty-mask path runs and that an
    # all-'A' key yields the SAME crib_score as score_candidate on the same PT.
    from kryptos.kernel.transforms.vigenere import decrypt_text
    from kryptos.kernel.alphabet import AZ
    from kryptos.kernel.scoring.aggregate import score_candidate
    key = [0] * 97
    pt = decrypt_text(CT, key, CipherVariant.VIGENERE, alphabet=AZ)
    ref = score_candidate(pt).crib_score
    res = verify_masked_candidate(CT, frozenset(), CipherVariant.VIGENERE, key,
                                  crib_dict=CRIB_DICT, alphabet=AZ)
    assert res.crib_score == ref
    assert res.pt_len == 97
```

- [ ] **Step 2: Run test to verify it fails (or passes meaningfully)**

Run: `PYTHONPATH=src pytest tests/test_masking_verify.py::test_empty_mask_matches_unmasked_crib_score -v`
Expected: PASS (the substrate's empty-mask path equals the canonical scorer). If it FAILS, the empty-mask reduction invariant is broken — stop and fix the mask/verify code, do not adjust the test.

- [ ] **Step 3: Run the full kernel test suite + fitness gate**

Run:
```bash
PYTHONPATH=src pytest tests/ -q
PYTHONPATH=src python3 kryptosbot/self_test.py --panel all --mode dry-run
PYTHONPATH=src python3 -m kryptos doctor
PYTHONPATH=src python3 scripts/_infra/session_briefing.py --strict >/dev/null && echo "briefing OK"
```
Expected: all green; no new failures; `doctor` Bean counts 1/242/101; briefing not degraded.

- [ ] **Step 4: Commit**

```bash
git add tests/test_masking_verify.py
git commit -m "test(kernel): empty-mask known-answer reduction guard"
```

---

## Self-Review

**Spec coverage:**
- Conceptual model (§3) → Task 5 (extract/remap) + Task 9 (empty-mask reduction).
- Per-mask Bean re-derivation (§4) → Tasks 1-4 (core + constants + wrapper + re-export).
- Mask-aware verification interface (§5.1-5.2) → Tasks 6-7.
- Joint-solver interface deferred (§5.3) → Task 7 Step 3 stub + test.
- Gating (§6) → Task 8.
- Invariants (§7): empty-mask reduction → Tasks 2,9; cribs-not-null overridable → Task 5; no global mutation → all tasks use explicit args; known-answer gate → Task 9; mask-universe-aware null inputs carried → Task 7 `MaskedVerification` fields; stdlib only → no third-party imports introduced.
- Module layout (§8) and build sequence (§10) → Tasks 1-9 in order. All covered.

**Placeholder scan:** No TBD/TODO. Every code step shows real code. The one external-name check (`encrypt_text`) is flagged with a verification command rather than assumed silently.

**Type consistency:** `derive_bean_constraints` core signature `(ct, crib_dict, index_table, mod)` (Task 1) vs alphabet wrapper `(ct, crib_dict, alphabet)` (Task 3) — intentionally two layers, both named in their tasks. `check_bean(keystream, eq, ineq, linear, mod)` used identically in Task 3 and Task 7. `MaskedVerification` fields defined in Task 7 match the test references. `validate_mask(mask, ct_len, crib_positions, allow_crib_nulls)` consistent Task 5 ↔ Task 7. `remap_crib_dict` / `extract_ct` / `remap_position` names consistent across Tasks 5 and 7.

**Known risk flagged for the implementer:** Task 7's synthetic test assumes an `encrypt_text` helper exists in `transforms/vigenere.py`; Step 1 includes a one-liner to confirm the real name before relying on it. If only `decrypt_text` exists, build the synthetic CT by encrypting manually (`(p+k) % 26`) rather than inventing an import.
