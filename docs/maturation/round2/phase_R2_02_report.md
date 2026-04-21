# Phase R2-2 — KA alphabet in dispatcher

**Date:** 2026-04-21
**Round:** Maturation Round 2
**Author:** Claude Code Opus 4.7
**Status:** complete — KA + keyword_mixed supported on all three additive substitution kinds

## Summary

| Metric | Before R2-2 | After R2-2 |
|---|---|---|
| Dispatcher alphabets supported | AZ only | **AZ, KA, keyword_mixed** |
| Vigenère/Beaufort/Var-Beaufort variants supported | all 3, AZ only | **all 3 × all 3 alphabets** |
| K1 expressible in DSL | no (KA rejected at Phase 4) | **yes — Vigenère on KA with keyword PALIMPSEST** |
| K2 expressible in DSL | no | **yes — same pattern, keyword ABSCISSA** |
| Test count (kryptosbot) | 583 | **603** (+20 R2-2 tests, 1 obsolete Phase-4 test updated) |
| Test count (core) | 1525 | 1525 (unchanged — kernel change is backward-compat) |

**K3 discovery status: YES** (§0.5 policy — R2-2 is positional-substitution work; K3 is pure transposition, no effect. Verified: cycle 9345 unchanged.)

## 1. Brief §3.2 deviation — kernel change was required

**Brief claim:** "The kernel already supports all three. `kryptos.kernel.alphabet.keyword_mixed_alphabet()` is the canonical construction. The work is in the dispatcher, not the kernel."

**Reality:** The kernel has the alphabet **construction** primitives (`Alphabet`, `keyword_mixed_alphabet`, the `KA` singleton), but the execution pipeline through `build_pipeline` → `decrypt_text` hardcoded AZ via `ord(c) - 65`. `TransformType.CUSTOM` explicitly forbids serializable custom transforms — so a "pre-remap / AZ-Vigenère / post-remap" pipeline built purely in the dispatcher would need an unavailable custom step.

**Resolution — minimal kernel extension:** `decrypt_text` and `encrypt_text` in `src/kryptos/kernel/transforms/vigenere.py` gained an optional `alphabet: Optional[Alphabet] = None` parameter. When None (default), the AZ fast path is used — **all existing callers unchanged**. When provided, both CT index lookup and PT emission route through the `Alphabet.index_table` and `Alphabet.sequence`. `kryptos.kernel.transforms.compose.build_transform` propagates an optional `alphabet_sequence` / `alphabet_label` in the VIGENERE / BEAUFORT / VAR_BEAUFORT params; when absent, it falls through to the AZ fast path.

This is strictly additive and passes the full 1525-test core suite with zero regressions.

## 2. Dispatcher changes

`kryptosbot/job_dispatcher.py` gains:

- **`_resolve_alphabet_sequence(alphabet, binding)`** — new function. Returns None for `"AZ"`; the KRYPTOS 26-char string for `"KA"`; `keyword_mixed_alphabet(binding["alphabet_keyword"])` for `"keyword_mixed"`; raises `DispatcherError` for unknown alphabet names or missing `alphabet_keyword`.

- **`_keyword_to_key_ints(keyword, alphabet, alphabet_sequence=None)`** — now accepts an explicit `alphabet_sequence` for KA / keyword_mixed paths. Key indices are computed in the ALPHABET'S OWN ORDERING, not AZ. E.g., `'K'` in KA has index 0 (K is first in KRYPTOSABCD...), not 10.

- **`_translate_layer`** — for `kind in {vigenere, beaufort, variant_beaufort}`:
  1. Resolve alphabet sequence via `_resolve_alphabet_sequence`.
  2. Convert keyword to indices in that alphabet.
  3. Emit a transform step whose params include `alphabet_sequence` + `alphabet_label` when non-AZ. For AZ the params are unchanged from Phase 4 (no `alphabet_sequence` leak).

## 3. Quagmire III reduction (brief §3.4 integration)

Kryptos K1 uses Quagmire III with keyword `PALIMPSEST`, indicator `K`, plaintext alphabet = ciphertext alphabet = KRYPTOS-mixed (= KA). Under the Quagmire III construction this reduces to:

> **Vigenère-on-KA** with key = `[KA.char_to_idx(c) for c in 'PALIMPSEST'] = [3, 7, 17, 15, 18, 3, 6, 11, 6, 4]`.

The reduction works because:
- Quagmire III's PA row is the standard A-Z position within the mixed PA alphabet.
- Quagmire III's CA rows are shifted by the keyword letter's position within the mixed CT alphabet.
- When PA = CA, both shifts operate in the same index space — identical to Vigenère arithmetic on the shared alphabet.
- Indicator `K` (which aligns the tableau's first CT row to the keyword's first letter) becomes a zero offset when `K` is index 0 in KA — which it is. So the indicator just confirms the alignment; no extra arithmetic.

Locked by `kryptosbot/tests/test_r2_2_ka_alphabet.py::TestK1QuagmireReduction::test_k1_reduces_to_vigenere_on_ka`, which:
1. Builds a single-layer Vigenère-on-KA spec via the DSL.
2. Validates the spec.
3. Under a `CT_LEN = 63` override, calls `_build_pipeline_config` → `build_pipeline`.
4. Applies the resulting transform to the K1 CT.
5. Asserts output equals the published K1 plaintext verbatim (63 chars).

This is the precondition for R2-5: the dispatcher can now execute the correct K1 decryption when given the right DSL spec.

## 4. Deferred items (per brief §3.2)

- **Polybius-family kinds (polybius, quagmire)**: declared in the DSL, no dispatcher translation. Brief explicitly deferred these — "Leave deferred. Polybius in particular requires a 25-letter alphabet (I/J merge) which is a separate design decision." R2-2 touched neither.

## 5. Test delta

New file: `kryptosbot/tests/test_r2_2_ka_alphabet.py` — 20 tests in 5 classes.

| Class | Tests | Guards |
|---|---|---|
| `TestKernelDecryptTextAcceptsAlphabet` | 4 | AZ default unchanged; KA roundtrip for each of Vig/Beau/VarBeau |
| `TestResolveAlphabetSequence` | 7 | AZ=None, KA constant, keyword_mixed construction, missing/empty/non-alpha keyword rejection, unknown alphabet rejection |
| `TestKAAlphabetAllThreeVariants` | 6 (3+3 parametrized) | Happy-path KA and keyword_mixed translation for each of vigenere/beaufort/variant_beaufort |
| `TestAdversarial` | 2 | AZ path doesn't leak alphabet params; keyword_mixed without alphabet_keyword fails at translate time |
| `TestK1QuagmireReduction` | 1 | **Integration: K1 decrypts via DSL dispatcher as Vigenère-on-KA** |

One existing Phase-4 test (`test_vigenere_ka_alphabet_not_supported_phase4` in `test_job_dispatcher.py`) was updated — its guard (KA raises DispatcherError) is exactly what R2-2 inverts. Renamed to `test_vigenere_ka_alphabet_translates_after_r2_2` and now asserts the positive path: KA produces `[3, 7, 17, ...]` key indices and the correct `alphabet_sequence` / `alphabet_label` params.

**Full test counts:**
```
tests/ (core):     1525 passed (unchanged)
kryptosbot/tests/: 603 passed (was 583 after R2-1, +20 new R2-2 tests)
Total:             2128 passed, 6 deprecation warnings (pre-existing), 0 failures
```

## 6. Self-test at phase exit

K1 cycle 15; K2 cycle 17; K3 cycle 9345. No drift from R2-1. Artifact: `results/self_test/r2_2_final.json`.

## 7. Brief acceptance criteria (§3.4) — self-audit

| Criterion | Status |
|---|---|
| Three alphabets supported for vigenere/beaufort/variant_beaufort | ✅ AZ + KA + keyword_mixed |
| K1 cipher expressible via DSL through dispatcher | ✅ Vigenère-on-KA with keyword PALIMPSEST (single layer, one binding) — test locked |
| K3 self-test still passes (no regression on R2-1) | ✅ cycle 9345 unchanged |
| ≥ 6 new tests | ✅ 20 tests (3 alphabets × 3 layer kinds × happy path = 9 happy-path tests; 7 resolver tests; 2 adversarial; 1 round-trip; 1 integration) |
| Report documents Quagmire-III-to-Vigenère-on-KA reduction | ✅ §3 |

## 8. Deviation from brief — one-paragraph summary

The brief said "dispatcher only, kernel is already fit." A pure-dispatcher implementation was not possible because `TransformType.CUSTOM` forbids serializable custom transforms, and the built-in VIGENERE transform hardcoded AZ indexing. R2-2 made a **strictly additive** kernel change: `decrypt_text` / `encrypt_text` accept an optional `alphabet: Alphabet = None` parameter; when absent the AZ fast path is unchanged (backward compatible, zero core-suite regressions). Compose.py propagates `alphabet_sequence` as a pipeline param. This enables the dispatcher-only surface area the brief intended without carving a new TransformType. Documented rather than hidden because Round 2's discipline requires deviations be legible.
