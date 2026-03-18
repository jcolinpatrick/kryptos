# K1-K3 Running Key Exhaustive Transformation Search

**Date:** 2026-03-17
**Status:** Approved
**Motivation:** Sanborn: "I have left instructions in the earlier text that refer to later text." K1-K3 PT tested as direct running key (max 7/24 = noise). Transformation space never explored.

---

## Architecture

```
Phase 1: K1-K3 Source Preparation (~60 derived texts)
  |
Phase 2: Crib-Drag Search (each text x offsets x 6 variants x 2 models)
  |
Phase 2b: Extended Transposition Search (+500K configs)
  |
Phase 3: Signal Classification + Bean Filtering
  |
Phase 4: [If no signal] Approach B -- Large Gutenberg Scan (background, 2-6 hours)
```

## Phase 1: K1-K3 Derived Running-Key Texts

### Source texts (4)
- K1 PT (63 chars), K2 PT (66 chars), K3 PT (166 chars), K1K2K3 combined (295 chars)

### Transformations (applied to each source)
1. **Identity** -- raw text (baseline)
2. **Reversed** -- read backwards
3. **Columnar transposition** -- width W in {7,8,9,10,14,24,31}, column orderings: ascending, KRYPTOS, PALIMPSEST, ABSCISSA, DEFECTOR, BERLINCLOCK
4. **Decimation** -- read every 2nd, 3rd, 5th, 7th, 13th letter
5. **Rail fence** -- 2, 3, 4, 5 rails
6. **K-section interleaving** -- K1[0]K2[0]K3[0]... in 3 orders (K1K2K3, K1K3K2, K2K1K3)
7. **All 6 concatenation orders** -- K1K2K3, K1K3K2, K2K1K3, K2K3K1, K3K1K2, K3K2K1

### Cross-section encryption (12 additional)
8. **Beaufort(Kx PT, key=Ky PT)** -- all 6 ordered pairs x 2 cipher variants (Beaufort, Vigenere)

### Total: ~60 derived texts

## Phase 2: Core Crib-Drag Search

For each derived text, slide a window across the text. At each offset, derive required running-key character at each crib position and count matches.

### Cipher variants (6)
- Beaufort AZ (A=0), Vigenere AZ, Variant Beaufort AZ
- Beaufort KA, Vigenere KA, Variant Beaufort KA

### Models (2)
- **Model B**: crib-drag on raw CT97 (cribs at 21-33 and 63-73)
- **Model A**: extract CT73 via consensus null mask (cribs at 13-25 and 47-57)

### W=7 exhaustive
All 5040 permutations x 4 source texts x 6 variants x 2 models = 241,920 configs

### Other widths
6 widths x 6 orderings x 4 sources x 6 variants x 2 models = 1,728 configs

### Non-transposed
60 texts x 6 variants x 2 models = 720 configs (each with sliding window)

### Total Phase 2: ~244K configs

## Phase 2b: Extended Transposition Search

- All widths 2-31 for K1K2K3 combined (295 chars)
- Double transposition: width-W then width-V (W,V in {7,8,9,10,14})
- K3 double-rotation applied to K1-K3 PT before crib-drag
- Grid reading orders on 28x31 master grid (column, diagonal, spiral, boustrophedon)

### Total Phase 2b: ~500K configs

## Phase 3: Signal Classification

| Score | Action |
|-------|--------|
| >= 18/24 | SIGNAL -- report immediately, Bean 242 inequality check, manual investigation |
| >= 12/24 | INTERESTING -- log with full provenance, Bean EQ check, quadgram score |
| <= 11/24 | Noise -- K1-K3 running key ELIMINATED under tested transformations |

Expected noise floor: ~0 hits at 12/24 across 750K configs (binomial p ~ 10^-6 per config).

## Phase 4: Approach B -- Gutenberg Scan (Background)

Triggered only if Phase 1-3 produces no signal >= 12/24.

### Sources (500 texts by category)
1. Cold War history / espionage (50)
2. Cryptography / codes (30)
3. CIA/NSA history (20)
4. Berlin Wall / Iron Curtain (30)
5. Egyptian archaeology (50 beyond current 18)
6. Howard Carter / Tutankhamun (10 additional)
7. Spy fiction -- le Carre, Fleming, Deighton, Ludlum (50)
8. Philosophy / classical (30)
9. Photography / art criticism (20)
10. Top-downloaded Gutenberg grab-bag (190)

### Methodology
Same crib-drag as Phase 2 on raw source text. Model B Beaufort primary + 5 variants.

### Scale
~500 texts x ~200K chars avg x 6 variants x 2 models = ~1.2B evaluations

## Runtime Estimates

| Phase | Configs | Time | Cores |
|-------|---------|------|-------|
| Phase 1 | 60 texts | < 1s | 1 |
| Phase 2 | 244K | ~30s | 28 |
| Phase 2b | 500K | ~60s | 28 |
| Phase 3 | ~100 hits | < 1s | 1 |
| **Total A** | **~750K** | **~2 min** | **28** |
| Phase 4 | ~1.2B | 2-6 hours | 28 |

## Output Artifacts

```
results/k123_running_key_exhaustive/
  +-- summary.json
  +-- phase1_texts.json
  +-- phase2_results.json
  +-- phase2b_results.json
  +-- phase3_signals.json
  +-- phase4_gutenberg/
      +-- download_manifest.json
      +-- scan_results.json
```

## Success Criteria

- **24/24 + Bean PASS**: K4 SOLVED
- **18-23/24 + Bean PASS**: Near-solution, manual investigation
- **12-17/24**: Genuine signal, investigate transformation
- **<= 11/24**: Noise, hypothesis eliminated, proceed to Phase 4

## Dependencies

- `kryptos.kernel.constants` (CT, cribs, Bean constraints)
- `data/english_quadgrams.json` (for Phase 3 scoring)
- K1-K3 plaintext (from constants or hardcoded)
- Gutenberg API access (Phase 4 only)
- 28 CPU cores available

## Key Constraints

- Import constants from `kryptos.kernel.constants` -- never hardcode
- Use `python3 -u` for unbuffered output
- Write results to `results/k123_running_key_exhaustive/`
- Register in exhaustion_log.json after completion
