# W-Anchored Permutation + Single-Keyword Additive Substitution: Bounded Negative Result

**Date:** 2026-04-30
**Status:** Bounded negative within tested scope. NOT a global W-delimiter elimination.
**Run type:** Verification rerun reproduces original result deterministically.
**Author:** Colin Patrick + Claude (research-record formalization).

---

## BLUF

A bounded sweep of W-anchored CT-side permutations followed by single-keyword additive substitution against a 719-keyword thematic list produced **zero hits at the STORE threshold**. Best crib_score 6/24 is at the noise floor (`NOISE_FLOOR = 6` per `kryptos.kernel.constants`). The result eliminates one specific cipher-class hypothesis and does NOT generalize to a global W-delimiter elimination, source-constrained long-key models, non-additive systems, multi-layer constructions, or untested W-anchored geometries.

---

## Run scope (exact)

| Field | Value |
|---|---|
| Carved CT | `OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR` (97 chars, from `kryptos.kernel.constants.CT`) |
| W positions | {20, 36, 48, 58, 74} (0-indexed) |
| Crib positions | EAST 21–24, NORTHEAST 25–33, BERLIN 63–68, CLOCK 69–73 (from `kryptos.kernel.constants.CRIB_DICT`, 24 positions, fixed) |
| Permutation forms tested | 5 (`NONE`, `SEG_ORDER_IMAGE`, `SEG_ORDER_W_LED`, `FULL_REV`, `REFL_W58`) |
| Cipher variants | 3 (Vigenère, Beaufort, Variant Beaufort) |
| Alphabets | 2 (standard `AZ`, KRYPTOS-mixed `KA`) |
| Keyword corpus | `wordlists/thematic_keywords_v2.txt` — 719 unique keywords (3–30 letter A–Z normalised) |
| Cartesian total | 5 × 3 × 2 × 719 = **21,570** configurations |
| Thresholds | NOISE=6, STORE=10, SIGNAL=18, BREAKTHROUGH=24 |
| Runtime | ~5 s on 26 worker processes |
| Script | `scratch/w_swap_seg_order_thematic_sweep.py` |
| Spot-check predecessor | `scratch/w_anchored_swap_spot_check.py` (cheap implied-keystream filter) |
| Persistent artifact | `results/w_anchor_reversal_v1/sweep_results.json` |

### Permutation form definitions

All permutations operate on the carved CT string. Decryption is then applied to the permuted string at the standard fixed crib positions.

- **`NONE`** — identity (baseline; same as standard K4 attack).
- **`SEG_ORDER_IMAGE`** — split CT on W's (W's removed), reverse the list of content segments, rejoin with W as separator. Matches the user's spreadsheet image SWAP 2. Central W at position 48 is preserved as a fixed point.
- **`SEG_ORDER_W_LED`** — split CT into W-led segments (each segment includes its leading W; the first segment has none), reverse the list, concatenate. Differs from `SEG_ORDER_IMAGE` by a 1-position shift; central W lands at position 49, not 48.
- **`FULL_REV`** — `CT[::-1]`. Equivalent to reflection around position 48. Central W is the only fixed point.
- **`REFL_W58`** — reflection `i ↔ 2·58 − i` for positions where the image is in `[0, 96]`; positions whose reflected image falls outside the string are left in place. Selected for follow-up because the spot-check showed two distinct-region keyword fragments (PTO ⊂ KRYPTOS, ISI ⊂ INVISIBLE) at the implied keystream under VARBEAU.

### Cipher convention

For each (permuted CT, keyword, alphabet, variant) combination the sweep computes `decrypt_text(permuted_CT, key_ints, variant, alphabet=alpha)` from `kryptos.kernel.transforms.vigenere` and scores the result with `score_candidate()` from `kryptos.kernel.scoring.aggregate`. Sign conventions: Vigenère `K = CT − PT`, Beaufort `K = CT + PT`, Variant Beaufort `K = PT − CT`, all mod 26 over the indicated alphabet.

---

## Result

**No configuration crossed the STORE threshold.** Distribution by best score:

- BREAKTHROUGH (24): 0
- SIGNAL (≥18): 0
- STORE (≥10): 0
- Above NOISE_FLOOR (≥6): 2 (FACADE/VIG/AZ on `SEG_ORDER_W_LED`; AETHER/BEAU/KA on `FULL_REV`)
- All others ≤ 5

### Best per (variant × cipher × alphabet) cell

| Permutation | Cipher | Alphabet | Crib | Best keyword |
|---|---|---|---|---|
| NONE | VIG | AZ | 4 | BRUMLEY |
| NONE | VIG | KA | 5 | BRUMLEY |
| NONE | BEAU | AZ | 4 | KARLSHORST |
| NONE | BEAU | KA | 4 | REFRACTION |
| NONE | VARBEAU | AZ | 4 | TOPOGRAPHY |
| NONE | VARBEAU | KA | 5 | BERLINCLOCK |
| SEG_ORDER_IMAGE | VIG | AZ | 4 | BEAUFORT |
| SEG_ORDER_IMAGE | VIG | KA | 4 | VERSCHLUESSELN |
| SEG_ORDER_IMAGE | BEAU | AZ | 5 | LIBERTAS |
| SEG_ORDER_IMAGE | BEAU | KA | 4 | TRANSMITTED |
| SEG_ORDER_IMAGE | VARBEAU | AZ | 5 | VERSCHLUESSELN |
| SEG_ORDER_IMAGE | VARBEAU | KA | 4 | BERLINWALL |
| SEG_ORDER_W_LED | VIG | AZ | **6** | FACADE |
| SEG_ORDER_W_LED | VIG | KA | 4 | ASTROLABE |
| SEG_ORDER_W_LED | BEAU | AZ | 5 | MUMMY |
| SEG_ORDER_W_LED | BEAU | KA | 4 | BIRDWATCHER |
| SEG_ORDER_W_LED | VARBEAU | AZ | 3 | VIRTUALLYINVISIBLE |
| SEG_ORDER_W_LED | VARBEAU | KA | 5 | BERLINWALL |
| FULL_REV | VIG | AZ | 5 | BETWEEN |
| FULL_REV | VIG | KA | 4 | GUTENBERG |
| FULL_REV | BEAU | AZ | 4 | BLITZKRIEG |
| FULL_REV | BEAU | KA | **6** | AETHER |
| FULL_REV | VARBEAU | AZ | 4 | DESPERATELY |
| FULL_REV | VARBEAU | KA | 5 | KOMPASS |
| REFL_W58 | VIG | AZ | 5 | ABYDOS |
| REFL_W58 | VIG | KA | 4 | BUCHSTABE |
| REFL_W58 | BEAU | AZ | 5 | NECROPOLIS |
| REFL_W58 | BEAU | KA | 5 | FOSSILIZED |
| REFL_W58 | VARBEAU | AZ | 5 | SARCOPHAGUS |
| REFL_W58 | VARBEAU | KA | 4 | MASQUERADE |

**Best overall:** `SEG_ORDER_W_LED + FACADE + Vigenère + AZ` → crib_score 6/24, classification = noise.

---

## Null interpretation

Under a random-plaintext null where each crib position matches its expected letter independently with probability 1/26, the per-trial score `X ~ Binomial(24, 1/26)` has mean ≈ 0.92 and `P(X ≥ 6) ≈ 5.4 × 10⁻⁵`. Across 21,570 trials the **expected number of random configurations scoring ≥ 6 is ≈ 1.16**. Observed: 2. This is consistent with sampling noise — not signal — and lies precisely at the kernel's `NOISE_FLOOR = 6`.

By the same null, `P(X ≥ 10)` (STORE) and `P(X ≥ 18)` (SIGNAL) are ~10⁻⁹ and ~10⁻²¹ respectively, so the STORE threshold remains the appropriate practical gate. The `STORE = 0` outcome is therefore not just "no hits" — it is "no hits in a regime where even one hit would have been compelling."

---

## Falsified claim (precisely scoped)

> *"Within the tested scope of five W-anchored swap/reversal transforms* — `NONE`, `SEG_ORDER_IMAGE`, `SEG_ORDER_W_LED`, `FULL_REV`, `REFL_W58` — *three additive cipher variants* (Vigenère, Beaufort, Variant Beaufort), *two alphabets* (standard A–Z, KRYPTOS-mixed KA), *and 719 thematic keywords drawn from* `wordlists/thematic_keywords_v2.txt`, *the construction "W-anchored permutation followed by single-keyword additive substitution" produced no STORE/SIGNAL/BREAKTHROUGH result on the carved 97-char K4 ciphertext under direct positional crib mapping. Best crib_score was 6/24, consistent with multiple-testing noise."*

This claim is appropriate as: a **summary**, **prompt context**, **duplicate-avoidance / ranking-down feature**, and **bounded elimination basis only within the tested family**. It is **NOT** appropriate as: a hard global constraint, a tier-1 elimination, or a basis to deprioritize the W-as-structural-anchor hypothesis at large.

---

## What this does NOT falsify

The bounded scope above is narrow on purpose. The following remain open:

1. **Source-constrained long-key / running-key second layers.** A multi-letter key drawn from a Sanborn/Kryptos-motivated source text is not in the tested space. Single-keyword substitution is a small slice of the additive-cipher family.
2. **Non-additive substitution systems** — Quagmire variants, polybius/fractionation, ADFGVX-class systems, slide-rule / strip-cipher mechanics, autokey (separately eliminated for K4 by structural argument; see `MEMORY.md`).
3. **Multi-layer constructions** — two-transposition stacks, transposition-then-transposition-then-substitution, or layered substitutions with a transposition between them. The composition framework (`reports/composition_campaign_v{1,2,3}.md`) covers many of these for direct positional alignment but not under a W-anchored outer permutation.
4. **Other W-anchored geometries** not among the five forms tested: sliding windows around each W, asymmetric block exchanges, partial reflections that drop fixed points, non-uniform segment manipulations, etc.
5. **Physical / installation use of W's** as anchors for sculpture-side decoding (`reference/ed_scheidt_dossier.md`, anomaly registry). This run is not designed to address that hypothesis class.
6. **Prior W-anchor work covered by `memory/project_w_anchor_hypothesis_eliminated_2026_04_29.md`** is complementary but distinct: that work eliminated W-as-cipher-event mechanisms (key resets, tape advances, schedule offsets) under additive periodic substitution preserving crib letter+order. The present run tests W-as-CT-permutation-anchor with simple keyword substitution, a different mechanism family.

---

## Recommendation: do NOT escalate to broader keyword-list expansion

Mechanically extending this sweep to `wordlists/english.txt` (~1M words) is **not recommended**. Rationale:

- Adding ~1400× the keyword count multiplies the multiple-testing burden by the same factor. Under the random-plaintext null, the expected number of trials scoring ≥ 6 grows from ~1 to ~1600; expected ≥ 10 grows from ~0.0002 to ~0.3. Any STORE-class hit would no longer be statistically distinguishable from selection noise without an additional independent confirmation channel.
- The 719-keyword thematic list is the project's **provenance-motivated** corpus (Kryptos vocabulary, K1–K3 keys, NSA / CIA / Berlin / cipher-history terms). Extending past that to arbitrary English imports words with no archival or stylistic justification.
- The cheap spot-check upstream (`scratch/w_anchored_swap_spot_check.py`) showed only weak fragmentary hints — no sustained English-keystream signal — so the prior probability of a real keyword hit in a longer list is correspondingly low.

**Do-not-revive policy:** Until new provenance-grade evidence motivates a specific source corpus, the following actions should be treated as already-decided no-go:

- Arbitrary W-anchored single-keyword additive sweeps (varying only the keyword list).
- Broader keyword-list enlargement (e.g., english.txt) without source provenance.

These belong on the duplicate-avoidance / ranking-down list per `feedback_red_team_before_swings.md`.

---

## Suggested next test (only if independently motivated)

The single residual extension that would be worth running is **source-constrained**:

> *Source-constrained long-key / running-key after `SEG_ORDER_IMAGE` (or other W-anchored transform), where the key/source corpus is independently motivated by Sanborn or Kryptos archival provenance.*

Concretely: if there is an archival document, Sanborn statement, or Scheidt-attested source that names a specific text or phrase corpus (e.g. a particular passage from the Smithsonian disclosures, a sculpture-engraved phrase, an NSA reference document, or a documented Sanborn personal text), then a running-key sweep over that source on `SEG_ORDER_IMAGE(CT)` is admissible. Without that provenance link, this thread should remain dormant — see `feedback_k4_keywords_must_fit_public_art_context.md` and `feedback_red_team_before_swings.md`.

---

## Reproduction

```bash
# Clean reproduction, ~5 seconds on 26 cores
PYTHONPATH=src python3 -u scratch/w_swap_seg_order_thematic_sweep.py

# Cheap upstream spot-check (implied-keystream filter)
PYTHONPATH=src python3 -u scratch/w_anchored_swap_spot_check.py
```

Artifact: `results/w_anchor_reversal_v1/sweep_results.json`.

The sweep is deterministic — keyword corpus, kernel constants, and decryption are pure functions. Re-runs produce identical scores per configuration. The verification rerun on 2026-04-30 reproduced the originally reported numbers exactly:

- 21,570 configurations, 0 STORE, best 6/24 (`SEG_ORDER_W_LED + FACADE + VIG + AZ`).
- All 30 per-cell best entries identical to the first-run summary.

---

## Cross-references

- `MEMORY.md` — live control document.
- `memory/project_w_anchor_hypothesis_eliminated_2026_04_29.md` — prior W-anchor work (substitution-with-event family, complementary scope).
- `memory/project_w_emphasis_rotated_out_2026_04_20.md` — prior W-emphasis controller posture rotation.
- `docs/claims_registry.json` — scoped claim recorded as `C-WANCHOR-SWAP-01`.
- `docs/elimination_tiers.md` — **NOT** updated. This is a bounded scope-limited negative, not a tier-1 / tier-2 elimination.
- `feedback_red_team_before_swings.md`, `feedback_k4_keywords_must_fit_public_art_context.md`, `feedback_preregister_thresholds.md` — relevant policy guidance.
