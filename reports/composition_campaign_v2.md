# K4 Composition Campaign Report — v2

**Date:** 2026-04-06
**Framework:** `src/kryptos/composition/` v2 (added Vigenere/Beaufort/VarBeaufort, Bean inequality pruning, variable-length CT)
**Ledger:** `db/composition_ledger.sqlite`
**Campaign script:** `scripts/campaigns/f_composition_k4_v2.py`

## Executive Summary

Tested **100,057 total compositions** (v1 + v2) across 28 campaigns.
**Maximum score achieved: 6/24** (7 branches, no Bean pass).
Expected score >=6 by random chance with 45,052 v2 trials: ~10.8.
Observed: 7. **No signal — all results consistent with noise.**

v2 additions: Vigenere/Beaufort inner cipher layers, 80-char null-extracted CT,
and Bean inequality pruning (242 constraints). The two-system hypothesis
(transposition + cipher) is now tested systematically for the first time
through the composition framework.

---

## v2 Framework Extensions

### 1. Vigenere / Beaufort / Variant Beaufort layer families
- Added to `LayerFamily` enum and registry
- Full roundtrip correctness verified (4 new tests)
- Beaufort correctly marked as involution (reciprocal)
- Parameter generators accept keyword lists like additive masks

### 2. Bean inequality pruning (242 constraints)
- For single periodic cipher + identity compositions, checks all 242 Bean
  inequality pairs against the keyword's residue pattern
- Any keyword where `keyword[a%L] == keyword[b%L]` for any Bean inequality
  pair (a,b) is exactly pruned
- Result: **no periodic keyword of any reasonable length survives** for
  direct single-layer application to 97-char K4 CT (independently confirms
  Tier 1 elimination of periodic substitution)
- Correctly disabled for multi-layer compositions (effective keystream is
  the combination of both layers)
- Correctly disabled for non-standard CT lengths (Bean positions don't apply)

### 3. Variable-length CT support
- `CampaignPolicy.ciphertext` field accepts any text
- Transposition layers automatically get `length` parameter injected
- Bean pruning disabled when CT length != 97
- Scoring uses `score_candidate_free` when positions are disrupted

---

## v2 Campaign Details

### Campaign D: Transposition outer x Vig/Beaufort inner (97-char)

The two-system hypothesis: K4 = transposition(cipher(plaintext)).

| Sub-campaign | Outer | Inner | Stacks | Tested | Best |
|-------------|-------|-------|--------|--------|------|
| col/vig | columnar (8 kw) | vigenere (28 kw) | 448 | 448 | 5 |
| col/beau | columnar (8 kw) | beaufort (28 kw) | 448 | 448 | 5 |
| rail/vig | rail fence (2-12) | vigenere (28 kw) | 616 | 616 | 5 |
| rail/beau | rail fence (2-12) | beaufort (28 kw) | 616 | 616 | **6** |
| block/vig | block (720 perms) | vigenere (28 kw) | 20,160 | 20,160 | **6** |
| block/beau | block (720 perms) | beaufort (28 kw) | 20,160 | 20,160 | **6** |
| **Total** | | | **42,448** | **42,448** | **6** |

Both peel orders tested for all combinations.

### Campaign E: Transposition outer x Vig/Beaufort inner (80-char extracted)

Same structure as D but on null-extracted 80-char text.

| Sub-campaign | Stacks | Tested | Best |
|-------------|--------|--------|------|
| col/vig/80c | 224 | 224 | 4 |
| col/beau/80c | 224 | 224 | 5 |
| rail/vig/80c | 308 | 308 | 4 |
| rail/beau/80c | 308 | 308 | 4 |
| **Total** | **1,064** | **1,064** | **5** |

### Campaign F: Additive outer x Vig/Beaufort inner (97-char)

Additive masking + periodic cipher: tests whether a shift mask over a
Vigenere/Beaufort cipher produces signal.

| Sub-campaign | Stacks | Tested | Best |
|-------------|--------|--------|------|
| add/vig (26 shifts x 28 kw) | 728 | 728 | 5 |
| add/beau (26 shifts x 28 kw) | 728 | 728 | 5 |
| **Total** | **1,456** | **1,456** | **5** |

### Campaign G: Single Vig/Beaufort on 80-char extracted text

Control: does the 80-char null-extracted text respond to simple periodic
substitution with thematic keywords?

| Sub-campaign | Stacks | Tested | Best |
|-------------|--------|--------|------|
| vig/80c | 28 | 28 | 4 |
| beau/80c | 28 | 28 | 3 |
| var_beau/80c | 28 | 28 | 4 |
| **Total** | **84** | **84** | **4** |

---

## Score-6 Results (All 7 Branches)

| Outer layer | Inner cipher | Peel | IC | Campaign |
|------------|-------------|------|-----|----------|
| rail_fence(d=7) | beaufort(KRYPTOS) | outer_first | 0.0417 | D-transp-beau |
| block(identity_reflected/r9) | vigenere(INVISIBLE) | inner_first | 0.0339 | D-block-vige |
| block(all_fwd_reflected/r9) | vigenere(INVISIBLE) | inner_first | 0.0339 | D-block-vige |
| block(identity_reflected/r20) | beaufort(IQLUSION) | outer_first | 0.0335 | D-block-beau |
| block(all_fwd_reflected/r20) | beaufort(IQLUSION) | outer_first | 0.0335 | D-block-beau |
| block(all_rev_reflected/r10) | beaufort(IQLUSION) | inner_first | 0.0391 | D-block-beau |
| block(reverse_bands/r10) | beaufort(IQLUSION) | inner_first | 0.0391 | D-block-beau |

**Analysis:** These 7 branches reduce to only 3 distinct plaintexts
(pairs of equivalent block routes). Keywords IQLUSION, INVISIBLE, and
KRYPTOS are K1/K3 vocabulary — high thematic prior but no English fragments
in the plaintext output. All below the NOISE threshold of 6 (border case),
no Bean pass, and below the random expectation of ~10.8 for this trial count.

---

## Grand Score Distribution (v1 + v2 combined, 100,057 tested)

| Score | v1 Count | v2 Count | Total | Expected (100K random) |
|-------|----------|----------|-------|----------------------|
| 0 | 21,028 | 17,358 | 38,386 | 39,012 |
| 1 | 20,518 | 16,749 | 37,267 | 37,452 |
| 2 | 9,592 | 7,877 | 17,469 | 17,226 |
| 3 | 3,182 | 2,455 | 5,637 | 5,055 |
| 4 | 619 | 530 | 1,149 | 1,061 |
| 5 | 66 | 76 | 142 | 170 |
| 6 | 0 | 7 | 7 | 24 |
| >=7 | 0 | 0 | 0 | 2.4 |

The entire distribution is consistent with random at binomial(24, 1/26).

---

## What Changed Project Belief

### Confirmed eliminations (v2 new)

1. **Two-system: transposition + periodic cipher on 97-char CT** — No
   combination of {columnar, rail fence, block transposition} x {Vigenere,
   Beaufort} with thematic keywords produces signal. Score ceiling: 6/24,
   below random expectation. 42,448 combinations tested.

2. **Two-system on 80-char null-extracted CT** — Same negative result on
   the cipher-layer text after stego removal. 1,064 combinations tested.

3. **Additive mask + periodic cipher** — No combination of 26 shift masks
   x 28 keyword Vigenere/Beaufort produces signal. 1,456 tested.

4. **Single periodic cipher on 80-char text** — Thematic keywords in
   Vigenere/Beaufort/VarBeaufort produce no signal on null-extracted text.
   84 combinations tested.

5. **Bean inequality independently confirms Tier 1** — No periodic keyword
   satisfies all 242 Bean inequalities for direct single-layer application
   to K4 CT. This is a new independent derivation within the composition
   framework.

### What this does NOT eliminate

- Non-thematic keywords (arbitrary strings, running-key text)
- Mixed-alphabet ciphers (Quagmire, keyed Vigenere with non-standard tableaux)
- Three-or-more-layer compositions
- Non-periodic substitution (autokey — separately proven impossible)
- Position-dependent masks (sawtooth, Wilson prime, etc.)
- Compositions where both layers use the same keyword
- Larger transposition parameter spaces (non-standard block sizes, routes)

---

## Recommendations for v3

1. **Same-keyword compositions** — Test where both layers share a keyword
   (KRYPTOS outer + KRYPTOS inner, etc.). Currently layers use independent keywords.

2. **Expand to Quagmire/keyed-alphabet ciphers** — Add keyed Vigenere
   (keyword-mixed CT alphabet) as an inner layer family.

3. **Running-key inner layer** — Test transposition outer + running-key
   inner (from corpus). This is a distinct attack surface from periodic keys.

4. **Position-dependent mask families** — Sawtooth masks, modular arithmetic
   masks, Wilson prime streams as proposed by community analysts.

5. **Three-layer compositions** — The framework supports arbitrary depth.
   Test trans(add(cipher(PT))) and similar.

---

## Artifacts

- **Ledger DB:** `db/composition_ledger.sqlite` (28 campaigns, 100,447 branches)
- **v2 summary:** `reports/composition_v2_summary.json`
- **v1 report:** `reports/composition_campaign_v1.md`
- **v1 leaderboard:** `reports/composition_leaderboard_v1.json`
- **Campaign scripts:** `scripts/campaigns/f_composition_k4_v1.py`, `f_composition_k4_v2.py`
- **Tests:** `tests/test_composition.py` (72 tests, all passing)
