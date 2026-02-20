# QA Verification: Structural Claims for Width-9 Hypothesis

**Date:** 2026-02-19
**Agent:** qa
**Task:** verify_width9_structural_claims
**Tests:** 49 new tests in `tests/test_qa_structural_claims.py`
**Repro:** `PYTHONPATH=src pytest tests/test_qa_structural_claims.py -v`

## Purpose

Independently verify the structural claims that TRANS and FRAC agents rely on
for the width-9 hypothesis — the project's top-priority untested lead.

## Results Summary

All 49 tests PASS. All major claims CONFIRMED.

### 1. DFT Peak at k=9 — CONFIRMED (strongest peak)

| Metric | Value |
|--------|-------|
| k=9 magnitude | 162.22 |
| Rayleigh sigma | 52.23 |
| Ratio | 3.11× sigma |
| Rank | **#1 absolute peak** (not just "top 10") |
| Period | 97/9 = 10.78 (≈ "10.8 rows") |
| Monte Carlo p-value | < 0.05 (5000 trials, random shuffles of CT) |

Top 5 DFT peaks:
1. k=9  (period=10.8): mag=162.22
2. k=18 (period=5.4): mag=134.25 ← harmonic of k=9
3. k=3  (period=32.3): mag=120.99
4. k=47 (period=2.1): mag=118.09
5. k=21 (period=4.6): mag=115.10

**Note:** k=18 is the 2nd harmonic of k=9 (18 = 2×9), which strengthens the
width-9 signal. Two of the top 5 peaks are at k=9 and its harmonic.

### 2. Lag-7 Autocorrelation — CONFIRMED

| Metric | Value |
|--------|-------|
| Observed matches | 9 (at lag 7) |
| Expected (random) | 3.46 |
| z-score | 3.036 |
| Monte Carlo p-value | < 0.01 (5000 trials) |
| Rank | **#1 strongest autocorrelation** among all lags 1–96 |

### 3. Width-9 Grid Geometry — CONFIRMED

- 97 / 9 = 10.778, matching Sanborn's "10.8 rows" annotation
- Grid structure: 7 columns of 11 rows + 2 columns of 10 rows = 97
- 9! = 362,880 column orderings to test

### 4. Bimodal Pre-filter — VERIFIED CORRECT

The AGENT_PROMPT.md bimodal_check() function:
- Correctly REJECTS the identity permutation (positions 64-74 too identity-ish)
- Correctly PASSES permutations preserving 22-30 but scrambling 64-74
- Boundary at displacement=5 (pass) vs 6 (fail) works correctly
- Boundary at identity_count=4 (pass) vs 5 (fail) works correctly
- Random permutation pass rate: < 1% (very selective filter)

### 5. Underdetermination Noise Floors — CONFIRMED

Majority-voting period consistency scores (identity permutation, Vigenère):

| Period | Observed | CLAUDE.md Claim | Status |
|--------|----------|-----------------|--------|
| 3 | 6/24 | (not stated) | Low — good discriminator |
| 5 | 8/24 | (not stated) | Low — good discriminator |
| 7 | 8/24 | ~8.2/24 | CONFIRMED |
| 10 | 11/24 | (not stated) | Moderate |
| 13 | 14/24 | (not stated) | Elevated |
| 17 | 17/24 | ~17.3/24 | CONFIRMED |
| 24 | 19/24 | ~19.2/24 | CONFIRMED |

Random-permutation average noise floors:
- Period 7: ~8.1 (5000 trials) — score >=18 is extremely rare (p < 0.001)
- Period 24: ~19.2 (2000 trials) — score >=18 is very common (>10% of random perms)

**Conclusion:** Periods <=7 are meaningful discriminators. Periods >=17 are
underdetermined. Any agent result at period >=17 MUST be accompanied by a
Monte Carlo null-hypothesis test.

### 6. Keystream Values — ALL VERIFIED

- Vigenère ENE (13 values) and BC (11 values): independently re-derived, match constants.py
- Beaufort ENE (13 values) and BC (11 values): independently re-derived, match constants.py
- Bean equality k[27]=k[65]: holds for Vigenère, Beaufort, AND Variant Beaufort
- Keystream aperiodicity: CONFIRMED (no period 1-26 gives full consistency)

### 7. IC and Crib Position Verification — ALL CONFIRMED

- IC = 0.0361, below random (0.0385) — unusual, constraining
- 24 crib positions correct (13 ENE + 11 BC)
- Self-encrypting: CT[32]=S=PT[32], CT[73]=K=PT[73]
- All 26 letters present in CT (eliminates 25-letter ciphers)

## Key Finding for Other Agents

The DFT result is **stronger than previously reported**. k=9 is not just
"among the top 10" — it is the **absolute maximum** DFT peak, and its 2nd
harmonic k=18 is the 2nd-highest peak. This makes width-9 the single most
statistically supported transposition width hypothesis.

## Test Coverage

| Test Class | Tests | Status |
|------------|-------|--------|
| TestDFTAnalysis | 6 | PASS |
| TestLag7Autocorrelation | 4 | PASS |
| TestWidth9Geometry | 6 | PASS |
| TestBimodalPreFilter | 6 | PASS |
| TestUnderdeterminationNoiseFloors | 9 | PASS |
| TestKeystreamValues | 7 | PASS |
| TestICVerification | 2 | PASS |
| TestCribPositions | 6 | PASS |
| TestPeriodConsistencyScoring | 3 | PASS |
| **Total** | **49** | **ALL PASS** |
