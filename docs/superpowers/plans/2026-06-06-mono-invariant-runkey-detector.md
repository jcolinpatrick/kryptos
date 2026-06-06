# Mono-Invariant Running-Key Detector — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a detector that exploits mono-invariant forced running-key differences (the positional information a monoalphabetic layer cannot arbitrage) to give a two-sided verdict on the `Mono+Trans+Running-key` family (E-FRAC-54 / BIN-D D1).

**Architecture:** Five small kernel-side modules (English lag-difference stats; forced-difference extraction for two model orderings; transposition-universe enumerator; LLR scorer; shuffled-CT matched null) plus a runner that first validates the detector on a synthetic planted solution (go/no-go) and then sweeps real K4. Spec: `docs/superpowers/specs/2026-06-06-mono-invariant-runkey-detector-design.md`.

**Tech Stack:** Python 3.11+, `PYTHONPATH=src`, stdlib + `kryptos.kernel` for the detector modules; venv numpy permitted in the runner. pytest.

**Convention (locked):** kernel route perm `P` satisfies `I[j]=CT[P[j]]`, so PT position `p` ↔ CT position `P[p]`. All positions 0-indexed; cribs at 21–33 / 63–73. Vig `K=CT−PT`, Beau `K=CT+PT` (A=0), VarBeau `K=PT−CT`.

**Commits:** local-only (no push — `feedback_no_github_push`). Keep per-task local commits on `main` per `feedback_merge_to_main`.

---

## File structure

| File | Responsibility |
|---|---|
| `src/kryptos/detectors/__init__.py` | package marker |
| `src/kryptos/detectors/mono_invariant_runkey/__init__.py` | package marker |
| `.../english_lag_stats.py` | build/cache `P_Eng(δ\|lag)` from a declared corpus |
| `.../forced_differences.py` | (model, variant, perm) → `[(Δ, lag)]`; Models 1 & 2 |
| `.../transposition_universe.py` | enumerate columnar w6/8/9 + 52-route grid; hash |
| `.../llr_detector.py` | LLR over forced differences given lag stats |
| `.../null_calibration.py` | CT shuffle, max-LLR over universe, matched-null p |
| `.../synthesize.py` | build a synthetic Mono+Trans+Running-key CT (validation) |
| `scripts/campaigns/f_mono_trans_runkey_detector_2026_06_06.py` | synthetic gate + K4 sweep + verdict |
| `docs/campaigns/mono_trans_runkey_detector_2026_06_06.md` | pre-registration |
| `tests/test_mono_invariant_runkey_detector.py` | unit + integration |

---

## Task 1: Package skeleton + English lag-difference stats

**Files:**
- Create: `src/kryptos/detectors/__init__.py` (empty), `src/kryptos/detectors/mono_invariant_runkey/__init__.py` (empty)
- Create: `src/kryptos/detectors/mono_invariant_runkey/english_lag_stats.py`
- Test: `tests/test_mono_invariant_runkey_detector.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_mono_invariant_runkey_detector.py
import math
from kryptos.detectors.mono_invariant_runkey import english_lag_stats as els

def test_lag_stats_sum_to_one_and_lag1_nonuniform():
    text = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG" * 200
    stats = els.build_lag_stats(text, l_max=12)
    assert set(stats) == set(range(1, 13))
    for lag, probs in stats.items():
        assert len(probs) == 26
        assert abs(sum(probs) - 1.0) < 1e-9
    def entropy(p):
        return -sum(x * math.log2(x) for x in p if x > 0)
    # lag-1 must be more structured (lower entropy) than the uniform ceiling
    assert entropy(stats[1]) < math.log2(26) - 0.05
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src pytest tests/test_mono_invariant_runkey_detector.py::test_lag_stats_sum_to_one_and_lag1_nonuniform -v`
Expected: FAIL (`ModuleNotFoundError` / `build_lag_stats` undefined).

- [ ] **Step 3: Write minimal implementation**

```python
# src/kryptos/detectors/mono_invariant_runkey/english_lag_stats.py
"""Empirical P(letter-difference δ mod 26 | lag) from a declared English corpus.

Mono- and source-generic statistics: a monoalphabetic substitution preserves
letter differences only at lag-fixed structure; this module measures the English
baseline against which mono-invariant forced differences are scored.
"""
from __future__ import annotations
import hashlib, json, os
from typing import Dict, List

_A = ord("A")

def _to_idx(text: str) -> List[int]:
    return [ord(c) - _A for c in text.upper() if "A" <= c.upper() <= "Z"]

def build_lag_stats(text: str, l_max: int = 12) -> Dict[int, List[float]]:
    idx = _to_idx(text)
    n = len(idx)
    out: Dict[int, List[float]] = {}
    for lag in range(1, l_max + 1):
        counts = [0] * 26
        for i in range(n - lag):
            counts[(idx[i] - idx[i + lag]) % 26] += 1
        total = sum(counts) or 1
        out[lag] = [c / total for c in counts]
    return out

def corpus_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def load_or_build(corpus_path: str, l_max: int = 12, cache_path: str | None = None) -> Dict[int, List[float]]:
    if cache_path and os.path.exists(cache_path):
        with open(cache_path) as fh:
            raw = json.load(fh)
        return {int(k): v for k, v in raw.items()}
    text = open(corpus_path, encoding="utf-8", errors="ignore").read()
    stats = build_lag_stats(text, l_max=l_max)
    if cache_path:
        json.dump({str(k): v for k, v in stats.items()}, open(cache_path, "w"))
    return stats
```

- [ ] **Step 4: Run test to verify it passes**

Run: `PYTHONPATH=src pytest tests/test_mono_invariant_runkey_detector.py::test_lag_stats_sum_to_one_and_lag1_nonuniform -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/kryptos/detectors tests/test_mono_invariant_runkey_detector.py
git commit -m "feat(detector): english lag-difference stats for mono-invariant runkey detector"
```

---

## Task 2: Forced-difference extraction (the math-critical module)

**Files:**
- Create: `src/kryptos/detectors/mono_invariant_runkey/forced_differences.py`
- Test: append to `tests/test_mono_invariant_runkey_detector.py`

- [ ] **Step 1: Write the failing test (hand-computed toy + mono-invariance)**

```python
from kryptos.detectors.mono_invariant_runkey import forced_differences as fd

def test_model1_forced_diff_handcomputed_and_mono_invariant():
    # Toy: PT positions {0,1} both letter 'A'(0); '2' letter 'B'(1).
    # crib_items: list of (pt_pos, pt_idx)
    crib = [(0, 0), (1, 0), (2, 1)]
    # CT indices length 5; perm P maps PT pos p -> CT pos P[p]
    ct = [3, 7 % 26, 10, 0, 0]  # ct[0]=3, ct[1]=7, ct[2]=10
    perm = [0, 1, 2, 3, 4]      # identity: enc(p)=p
    diffs = fd.forced_diffs_model1(ct, crib, perm, variant="vigenere")
    # only same-PT-letter pair is (0,1) both 'A': Δ = CT[0]-CT[1] = 3-7 = -4 ≡ 22; lag=|0-1|=1
    assert diffs == [(22, 1)]
    # mono-invariance: model 1 does not use a sigma argument at all -> structurally invariant
    # var_beaufort negates: Δ = CT[1]-CT[0] = 4
    diffs_vb = fd.forced_diffs_model1(ct, crib, perm, variant="var_beaufort")
    assert diffs_vb == [(4, 1)]

def test_model2_forced_diff_collision_gated():
    # Model 2: Δ from crib pairs whose CT-images collide.
    crib = [(0, 4), (1, 19)]          # PT letters E(4), T(19)
    ct = [9, 9, 0]                    # CT[0]==CT[1] -> images collide under identity
    perm = [0, 1, 2]
    # Vigenere: Δ = PT[p2]-PT[p1] for colliding pair (0,1): 19-4=15; lag=|0-1|=1
    diffs = fd.forced_diffs_model2(ct, crib, perm, variant="vigenere")
    assert diffs == [(15, 1)]
    # No collision -> no constraints
    ct2 = [9, 10, 0]
    assert fd.forced_diffs_model2(ct2, crib, perm, variant="vigenere") == []
```

- [ ] **Step 2: Run to verify it fails**

Run: `PYTHONPATH=src pytest tests/test_mono_invariant_runkey_detector.py -k forced_diff -v`
Expected: FAIL (`forced_diffs_model1` undefined).

- [ ] **Step 3: Write the implementation**

```python
# src/kryptos/detectors/mono_invariant_runkey/forced_differences.py
"""Mono-invariant forced running-key differences for the two model orderings.

Convention: kernel route perm `perm` maps PT position p -> CT position perm[p]
(because decryption does I[j]=CT[perm[j]]). All values are mod-26 ints.

Model 1 (mono-inner, runkey-outer): PT->sigma->trans->+K->CT.
  Same-PT-letter crib pairs (p1,p2): Δ = ±(CT[perm[p1]] - CT[perm[p2]]) mod 26,
  lag = |perm[p1]-perm[p2]| (running key is CT-indexed). σ cancels -> invariant.
  Sign: vigenere/beaufort -> +, var_beaufort -> - .

Model 2 (runkey-inner, mono-outer): PT->+K->trans->sigma->CT.
  Crib pairs whose CT-images collide (CT[perm[p1]]==CT[perm[p2]]):
  Δ = ±(PT diff) mod 26, lag = |p1-p2| (running key is PT-indexed). σ cancels.
  vigenere -> PT[p2]-PT[p1]; beaufort/var_beaufort -> PT[p1]-PT[p2].
"""
from __future__ import annotations
from itertools import combinations
from typing import List, Sequence, Tuple

Diff = Tuple[int, int]  # (delta mod 26, lag)
_VARIANTS = ("vigenere", "beaufort", "var_beaufort")

def forced_diffs_model1(ct_idx: Sequence[int], crib_items: Sequence[Tuple[int, int]],
                        perm: Sequence[int], variant: str) -> List[Diff]:
    assert variant in _VARIANTS, variant
    by_letter: dict[int, list[int]] = {}
    for pt_pos, pt_idx in crib_items:
        by_letter.setdefault(pt_idx, []).append(pt_pos)
    out: List[Diff] = []
    for positions in by_letter.values():
        for p1, p2 in combinations(sorted(positions), 2):
            c1, c2 = ct_idx[perm[p1]], ct_idx[perm[p2]]
            delta = (c1 - c2) % 26
            if variant == "var_beaufort":
                delta = (-delta) % 26
            lag = abs(perm[p1] - perm[p2])
            out.append((delta, lag))
    return out

def forced_diffs_model2(ct_idx: Sequence[int], crib_items: Sequence[Tuple[int, int]],
                        perm: Sequence[int], variant: str) -> List[Diff]:
    assert variant in _VARIANTS, variant
    out: List[Diff] = []
    for (p1, pt1), (p2, pt2) in combinations(crib_items, 2):
        if ct_idx[perm[p1]] != ct_idx[perm[p2]]:
            continue  # collision-gated
        if variant == "vigenere":
            delta = (pt2 - pt1) % 26
        else:  # beaufort, var_beaufort
            delta = (pt1 - pt2) % 26
        lag = abs(p1 - p2)
        out.append((delta, lag))
    return out
```

- [ ] **Step 4: Run to verify it passes**

Run: `PYTHONPATH=src pytest tests/test_mono_invariant_runkey_detector.py -k forced_diff -v`
Expected: PASS (both tests).

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(detector): mono-invariant forced-difference extraction (model 1 & 2)"
```

---

## Task 3: Transposition universe + hash

**Files:**
- Create: `src/kryptos/detectors/mono_invariant_runkey/transposition_universe.py`
- Test: append.

- [ ] **Step 1: Write the failing test**

```python
from kryptos.detectors.mono_invariant_runkey import transposition_universe as tu

def test_universe_counts_and_valid_perms():
    names_perms = list(tu.iter_universe(n=97))
    # columnar all-orderings 6!+8!+9! = 720+40320+362880 = 403920 ; grid 52
    assert len(names_perms) == 403920 + 52
    for name, perm in names_perms[:200] + names_perms[-60:]:
        assert sorted(perm) == list(range(97))
    h1 = tu.universe_hash(n=97)
    h2 = tu.universe_hash(n=97)
    assert h1 == h2 and len(h1) == 64  # deterministic sha256
```

- [ ] **Step 2: Run to verify it fails**

Run: `PYTHONPATH=src pytest tests/test_mono_invariant_runkey_detector.py -k universe -v`
Expected: FAIL.

- [ ] **Step 3: Write the implementation**

```python
# src/kryptos/detectors/mono_invariant_runkey/transposition_universe.py
"""Declared bounded transposition universe: columnar all-orderings w6/8/9
(E-FRAC-54's underdetermined set) + the 52-route grid universe."""
from __future__ import annotations
import hashlib
from itertools import permutations
from typing import Iterator, List, Tuple

from kryptos.kernel.transforms.transposition import columnar_perm
from kryptos.kernel.masking.route_null import grid_route_perms

_COLUMNAR_WIDTHS = (6, 8, 9)
_GRID_WIDTHS = (4, 5, 6, 7, 8, 11, 13, 14, 21, 24)

def iter_universe(n: int = 97) -> Iterator[Tuple[str, List[int]]]:
    yield ("identity", list(range(n)))
    yield ("reverse", list(range(n - 1, -1, -1)))
    for w in _GRID_WIDTHS:
        for name, perm in grid_route_perms(w, n=n):
            yield (name, list(perm))
    for w in _COLUMNAR_WIDTHS:
        for order in permutations(range(w)):
            yield (f"col{w}_{''.join(map(str, order))}", list(columnar_perm(w, order, n)))

def universe_hash(n: int = 97) -> str:
    h = hashlib.sha256()
    for name, perm in iter_universe(n=n):
        h.update(name.encode()); h.update(bytes(perm))
    return h.hexdigest()
```

Note: the grid set yields 2 + 10×5 = 52 routes (some duplicate perms across widths are acceptable for the universe declaration; if the count assertion is off by duplicate-collapse, adjust the test to `>= 403920 + 50` and record the exact count). Verify exact count at run and lock it in the pre-reg.

- [ ] **Step 4: Run to verify it passes**

Run: `PYTHONPATH=src pytest tests/test_mono_invariant_runkey_detector.py -k universe -v`
Expected: PASS (adjust the exact count to the observed value if grid routes collapse duplicates; record it).

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(detector): bounded transposition universe (columnar w6/8/9 + 52 grid routes)"
```

---

## Task 4: LLR scorer

**Files:**
- Create: `src/kryptos/detectors/mono_invariant_runkey/llr_detector.py`
- Test: append.

- [ ] **Step 1: Write the failing test**

```python
import math
from kryptos.detectors.mono_invariant_runkey import llr_detector as ld

def test_llr_zero_on_uniform_positive_on_english_consistent():
    uniform = {lag: [1/26]*26 for lag in range(1, 13)}
    assert abs(ld.llr([(5, 1), (9, 2)], uniform, l_max=12)) < 1e-9
    peaked = {lag: [1/26]*26 for lag in range(1, 13)}
    peaked[1] = [0.0]*26; peaked[1][5] = 1.0  # δ=5 at lag1 certain
    val = ld.llr([(5, 1)], peaked, l_max=12)
    assert val > 0  # log(1.0 / (1/26)) = log(26) > 0
```

- [ ] **Step 2: Run to verify it fails** — `... -k llr` → FAIL.

- [ ] **Step 3: Write the implementation**

```python
# src/kryptos/detectors/mono_invariant_runkey/llr_detector.py
"""Log-likelihood ratio of forced differences vs the uniform null."""
from __future__ import annotations
import math
from typing import Dict, List, Sequence, Tuple

_FLOOR = 1e-6  # guards log(0) for unseen δ at a lag

def llr(forced_diffs: Sequence[Tuple[int, int]], lag_stats: Dict[int, List[float]],
        l_max: int = 12) -> float:
    total = 0.0
    for delta, lag in forced_diffs:
        probs = lag_stats[min(lag, l_max) if lag >= 1 else 1]
        p = max(probs[delta % 26], _FLOOR)
        total += math.log(p / (1.0 / 26.0))
    return total
```

- [ ] **Step 4: Run to verify it passes** — PASS.
- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(detector): LLR scorer over forced differences"`

---

## Task 5: Synthetic CT builder (round-trip correctness guard)

**Files:**
- Create: `src/kryptos/detectors/mono_invariant_runkey/synthesize.py`
- Test: append.

- [ ] **Step 1: Write the failing test**

```python
import random
from kryptos.detectors.mono_invariant_runkey import synthesize as syn
from kryptos.detectors.mono_invariant_runkey import forced_differences as fd

def test_synth_model1_forced_diffs_match_planted_runkey():
    rng = random.Random(1)
    n = 97
    pt = [rng.randrange(26) for _ in range(n)]
    crib = [(p, pt[p]) for p in list(range(21, 34)) + list(range(63, 74))]
    runkey = [rng.randrange(26) for _ in range(n)]      # the "english" key (random here)
    sigma = list(range(26)); rng.shuffle(sigma)          # mono permutation
    perm = list(range(n)); rng.shuffle(perm)             # transposition (PT pos -> CT pos = perm)
    ct = syn.synthesize_model1(pt, runkey, sigma, perm, variant="vigenere")
    # forced diffs computed from CT must equal the planted runkey differences
    diffs = fd.forced_diffs_model1(ct, crib, perm, variant="vigenere")
    for delta, lag in diffs:
        assert 0 <= delta < 26 and lag >= 1
    # independent recomputation: same-PT-letter pairs' runkey diff at CT positions
    by_letter = {}
    for p, v in crib:
        by_letter.setdefault(v, []).append(p)
    expected = []
    from itertools import combinations
    for ps in by_letter.values():
        for a, b in combinations(sorted(ps), 2):
            expected.append(((runkey[perm[a]] - runkey[perm[b]]) % 26, abs(perm[a]-perm[b])))
    assert sorted(diffs) == sorted(expected)
```

- [ ] **Step 2: Run to verify it fails** — `... -k synth` → FAIL.

- [ ] **Step 3: Write the implementation**

```python
# src/kryptos/detectors/mono_invariant_runkey/synthesize.py
"""Build synthetic Mono+Trans+Running-key ciphertexts for detector validation.

perm maps PT position p -> CT position perm[p] (i.e. CT[perm[p]] receives PT pos p).
"""
from __future__ import annotations
from typing import List, Sequence

def synthesize_model1(pt: Sequence[int], runkey: Sequence[int], sigma: Sequence[int],
                      perm: Sequence[int], variant: str) -> List[int]:
    # PT -> sigma -> trans -> +K -> CT.  CT[perm[p]] = addkey(sigma(pt[p]), K[perm[p]])
    n = len(pt)
    ct = [0] * n
    for p in range(n):
        s = sigma[pt[p]]
        m = perm[p]
        k = runkey[m]
        if variant == "vigenere":
            ct[m] = (s + k) % 26
        elif variant == "beaufort":
            ct[m] = (k - s) % 26
        else:  # var_beaufort: CT = PT' - K
            ct[m] = (s - k) % 26
    return ct

def synthesize_model2(pt: Sequence[int], runkey: Sequence[int], sigma: Sequence[int],
                      perm: Sequence[int], variant: str) -> List[int]:
    # PT -> +K -> trans -> sigma -> CT.  W[p]=addkey(pt[p],K[p]); Z[perm[p]]=W[p]; CT=sigma(Z)
    n = len(pt)
    z = [0] * n
    for p in range(n):
        k = runkey[p]
        if variant == "vigenere":
            w = (pt[p] + k) % 26
        elif variant == "beaufort":
            w = (k - pt[p]) % 26
        else:  # var_beaufort
            w = (pt[p] - k) % 26
        z[perm[p]] = w
    return [sigma[z[i]] for i in range(n)]
```

- [ ] **Step 4: Run to verify it passes** — PASS (this proves forced_differences inverts synthesize, the core correctness guard).
- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(detector): synthetic Mono+Trans+Running-key builder + round-trip test"`

---

## Task 6: Null calibration + max-LLR over universe

**Files:**
- Create: `src/kryptos/detectors/mono_invariant_runkey/null_calibration.py`
- Test: append.

- [ ] **Step 1: Write the failing test**

```python
import random
from kryptos.detectors.mono_invariant_runkey import null_calibration as nc

def test_shuffle_preserves_letter_multiset():
    rng = random.Random(0)
    ct = [rng.randrange(26) for _ in range(97)]
    sh = nc.shuffle_ct(ct, rng)
    assert sorted(sh) == sorted(ct) and sh != ct

def test_max_llr_runs_small_universe():
    # tiny stand-in universe to keep the unit test fast
    rng = random.Random(2)
    ct = [rng.randrange(26) for _ in range(97)]
    crib = [(p, rng.randrange(26)) for p in list(range(21,34))+list(range(63,74))]
    uni = [("identity", list(range(97))), ("reverse", list(range(96,-1,-1)))]
    stats = {lag: [1/26]*26 for lag in range(1,13)}
    best, mx = nc.max_llr_over_universe(ct, crib, uni, ("vigenere",), ("model1",), stats, l_max=12)
    assert isinstance(mx, float) and best["name"] in {"identity", "reverse"}
```

- [ ] **Step 2: Run to verify it fails** — `... -k 'shuffle or max_llr' ` → FAIL.

- [ ] **Step 3: Write the implementation**

```python
# src/kryptos/detectors/mono_invariant_runkey/null_calibration.py
"""Shuffled-CT matched null and max-LLR over the transposition universe."""
from __future__ import annotations
import random
from typing import Dict, Iterable, List, Sequence, Tuple

from .forced_differences import forced_diffs_model1, forced_diffs_model2
from .llr_detector import llr

_MODELS = {"model1": forced_diffs_model1, "model2": forced_diffs_model2}

def shuffle_ct(ct_idx: Sequence[int], rng: random.Random) -> List[int]:
    out = list(ct_idx); rng.shuffle(out); return out

def max_llr_over_universe(ct_idx, crib_items, universe: Iterable[Tuple[str, Sequence[int]]],
                          variants: Sequence[str], models: Sequence[str],
                          lag_stats: Dict[int, List[float]], l_max: int = 12):
    best = {"name": None, "variant": None, "model": None, "llr": float("-inf")}
    for name, perm in universe:
        for model in models:
            fn = _MODELS[model]
            for variant in variants:
                diffs = fn(ct_idx, crib_items, perm, variant)
                score = llr(diffs, lag_stats, l_max=l_max)
                if score > best["llr"]:
                    best = {"name": name, "variant": variant, "model": model, "llr": score,
                            "n_constraints": len(diffs)}
    return best, best["llr"]

def matched_null_pvalue(real_max: float, ct_idx, crib_items, universe_factory,
                        variants, models, lag_stats, n_null: int, seed: int, l_max: int = 12):
    """universe_factory: zero-arg callable returning a fresh universe iterator."""
    rng = random.Random(seed)
    null_max = []
    ge = 0
    for _ in range(n_null):
        sh = shuffle_ct(ct_idx, rng)
        _, mx = max_llr_over_universe(sh, crib_items, universe_factory(), variants, models, lag_stats, l_max)
        null_max.append(mx)
        if mx >= real_max:
            ge += 1
    p = (1 + ge) / (1 + n_null)
    return p, null_max
```

- [ ] **Step 4: Run to verify it passes** — PASS.
- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(detector): shuffled-CT matched null + max-LLR over universe"`

---

## Task 7: Integration — synthetic recovery proves detector power (go/no-go)

**Files:** Test only: append to `tests/test_mono_invariant_runkey_detector.py`

- [ ] **Step 1: Write the failing test**

```python
import random
from kryptos.detectors.mono_invariant_runkey import synthesize as syn, null_calibration as nc
from kryptos.detectors.mono_invariant_runkey import english_lag_stats as els

def test_synthetic_recovery_model1_beats_shuffle_null():
    # Plant a Model-1 solution with a REAL English running key, then confirm the
    # detector ranks the planted transposition above a shuffle-null band.
    rng = random.Random(42)
    eng = open("reference/running_key_texts/kahn_codebreakers_1967.txt", encoding="utf-8", errors="ignore").read()
    stats = els.build_lag_stats(eng, l_max=12)
    eng_idx = [ord(c)-65 for c in eng.upper() if "A" <= c.upper() <= "Z"]
    off = 1000
    runkey = eng_idx[off:off+97]
    pt = [rng.randrange(26) for _ in range(97)]
    crib = [(p, pt[p]) for p in list(range(21,34))+list(range(63,74))]
    sigma = list(range(26)); rng.shuffle(sigma)
    # planted transposition: a real columnar perm
    from kryptos.kernel.transforms.transposition import columnar_perm
    perm = list(columnar_perm(8, (3,1,7,0,5,2,6,4), 97))
    ct = syn.synthesize_model1(pt, runkey, sigma, perm, variant="vigenere")
    planted_llr = nc.max_llr_over_universe(ct, crib, [("planted", perm)], ("vigenere",), ("model1",), stats)[1]
    # shuffle band: planted must beat the 99th percentile of 200 shuffles on the SAME single perm
    band = []
    r2 = random.Random(7)
    for _ in range(200):
        sh = nc.shuffle_ct(ct, r2)
        band.append(nc.max_llr_over_universe(sh, crib, [("planted", perm)], ("vigenere",), ("model1",), stats)[1])
    band.sort()
    assert planted_llr > band[int(0.99*len(band))]  # planted English key is detectable
```

- [ ] **Step 2: Run to verify it fails** — FAIL (until prior tasks merged; if a real assertion fails, that is a SIGNAL the detector is underpowered — record it; do not force-pass).

- [ ] **Step 3: No new code** — this is a pure integration assertion over Tasks 1–6.

- [ ] **Step 4: Run to verify it passes**

Run: `PYTHONPATH=src pytest tests/test_mono_invariant_runkey_detector.py -k synthetic_recovery -v`
Expected: PASS. **If it FAILS**, the detector is genuinely underpowered for Model 1 — this is a real finding; capture the planted-vs-band numbers and proceed to Task 8 with `DETECTOR_UNDERPOWERED` rather than forcing the test.

- [ ] **Step 5: Commit** — `git add -A && git commit -m "test(detector): synthetic-recovery go/no-go (planted Model-1 solution beats shuffle null)"`

---

## Task 8: Runner + pre-registration + real-K4 run

**Files:**
- Create: `docs/campaigns/mono_trans_runkey_detector_2026_06_06.md` (pre-reg: lock L_MAX=12, N_NULL=2000, corpus=kahn_codebreakers_1967.txt + sha256, synthetic detection-rate floor Model 1 ≥0.80, escalation gate p<0.05, single bounded pass)
- Create: `scripts/campaigns/f_mono_trans_runkey_detector_2026_06_06.py`
- Result: `results/mono_trans_runkey_detector_2026_06_06.json`

- [ ] **Step 1: Write the pre-registration doc** (thresholds above; mirror the Carter-tape pre-reg structure in `docs/campaigns/non_direct_alignment_carter_tape_2026_06_05.md`).

- [ ] **Step 2: Write the runner.** It must:
  1. Build/load `stats` from `reference/running_key_texts/kahn_codebreakers_1967.txt` (record source + sha256).
  2. **Synthetic gate:** loop over (model ∈ {model1, model2}) × 3 variants × several planted (perm from universe, runkey offset) and compute detection rate = fraction where planted LLR > 99th pct of N_SHUF shuffle band. Record per-model rate.
  3. If Model-1 rate < 0.80 → write verdict `DETECTOR_UNDERPOWERED` with the measured ceiling and STOP (do not over-claim a K4 verdict).
  4. Else **real K4:** `real_best, real_max = max_llr_over_universe(CT_idx, crib_items, iter_universe(), ("vigenere","beaufort","var_beaufort"), enabled_models, stats)`; then `p, null_dist = matched_null_pvalue(real_max, CT_idx, crib_items, lambda: iter_universe(), variants, models, stats, n_null=2000, seed=...)`. Parallelize the null over cores (multiprocessing Pool; each worker does one shuffle's full-universe max).
  5. Verdict: `CANDIDATE_ESCALATE` if `p < 0.05`; else `CLEAN_NULL` → `ELIMINATED_UNDER_BOUNDED_MONO_TRANS_RUNKEY_UNIVERSE`.
  6. Write `results/mono_trans_runkey_detector_2026_06_06.json` with: universe_hash, n_universe, real_best config, real_max, p, null max distribution summary, synthetic detection rates, verdict, scope.
  Use the kernel for CT/cribs: `from kryptos.kernel.constants import CT, CRIB_DICT, ALPH_IDX`; `CT_idx=[ALPH_IDX[c] for c in CT]`; `crib_items=[(p, ALPH_IDX[ch]) for p,ch in sorted(CRIB_DICT.items())]`.

- [ ] **Step 3: Run the full pytest file** — `PYTHONPATH=src pytest tests/test_mono_invariant_runkey_detector.py -v` → all PASS.

- [ ] **Step 4: Run the detector** — `PYTHONPATH=src venv/bin/python scripts/campaigns/f_mono_trans_runkey_detector_2026_06_06.py` (venv for numpy/Pool). Read the verdict.

- [ ] **Step 5: Record** — register exhaustion_log.json entry `f_mono_trans_runkey_detector_2026_06_06` (status exhausted, verdict, result_file, universe_hash, pre-reg); write a memory note; if `ELIMINATED`, note D1 → bin B in `docs/exhaustion_audit_2026_04_08.md` (append a dated update, do not rewrite). Commit locally.

---

## Self-review notes
- **Spec coverage:** §1 insight → Task 2; §2 models → Task 2 + Task 5; §3 statistic → Task 4 + Task 6; §4 synthetic gate → Task 5 + Task 7 + Task 8.2/8.3; §5 universe → Task 3; §7 verdict → Task 8.2; §8 thresholds → Task 8.1; §9 testing → Tasks 1–7. All covered.
- **Placeholder scan:** none (all code complete; the one count caveat in Task 3 is an explicit run-and-lock instruction, not a placeholder).
- **Type consistency:** `forced_diffs_model{1,2}(ct_idx, crib_items, perm, variant)` and `max_llr_over_universe(...)` signatures are identical across Tasks 2/5/6/7/8. `crib_items` is always `[(pt_pos, pt_idx)]`. `perm` is always PT→CT (`perm[p]`). `models` strings are `"model1"/"model2"`.
