# Pre-registration: Masked Quagmire III probe (arbitrary_null_mask)

- **Date:** 2026-05-25
- **Tier:** secondary_exploratory
- **Operator:** attack-operator
- **Alignment model:** `arbitrary_null_mask` (NOT CLOSED per session briefing)
- **Mechanism:** Quagmire III (the cipher family K1-K3 actually use)
- **Status of slice before this run:** OPEN

## Why this is novel and open

[DERIVED FACT] Every prior masked K4 probe used Vigenere / Beaufort / additive-tape
mechanisms. K1-K3 were solved with **Quagmire III** (keyword-mixed alphabet, CT
alphabet = KRYPTOS, periodic keyword indicator). Masked Quagmire III has never
been tested.

[DERIVED FACT] The project closure "ALL periodic polyalphabetic substitution
periods 1-26 eliminated via the 242-Bean set" is tagged `align: direct_ct_pt` —
it assumes each carved char decrypts in place at length 97. The null-mask variant
proof is tagged `align: ct73_null_extracted` and applies only to `|mask| == 24`
(length-73 extraction). Under a null mask with `|mask| != 24`, the extracted CT'
has length != 73, Bean is **re-derived per-mask** on CT', and neither proof
transfers. So masked Quagmire III is genuinely open.

**Off-limits (already closed):** `|mask| == 24` producing length-73 extraction +
periodic substitution (the CT73 algebraic-proof slice). **All masks here keep
`|mask| != 24`** — verified programmatically (`any |mask|==24 == False`).

## Mask universe (generative rules)

All masks: `|mask| != 24`; none intersect crib positions 21-33 / 63-73 (validated
by `validate_mask` default invariant).

- **R1 residue masks:** positions `p` with `p mod m == r`, crib positions removed,
  for `m in {2,3,4,5,6,7}`, `r in 0..m-1`. Any mask with `|mask| == 24` dropped.
- **R2 contiguous-block masks:** blocks `[start, start+L-1]` of length `L in 1..20`
  fully inside a single non-crib gap (`[0,20]`, `[34,62]`, `[74,96]`). Any mask
  touching a crib or with `|mask| == 24` dropped.

**Exact mask count:** 915 (deduplicated by content). Mask-length range: 1..38.

## Key universe (generative rules)

- **CT alphabet:** fixed `KRYPTOS` (the panel tableau, canonical K1-K3).
- **Indicator:** `K` (K1-K3 convention).
- **PT-alphabet keyword:** swept over a bounded K4-context pool (18 keywords).
- **period_keyword:** each pool keyword, truncated/cycled to period `p in {3..12}`.

**Keyword pool (18):** KRYPTOS, PALIMPSEST, ABSCISSA, ORDINATE, LATITUDE,
LONGITUDE, BERLIN, CLOCK, EAST, NORTH, SHADOW, IQLUSION, UNDERGRUUND, DESPARATLY,
WESTIDARW, LANGLEY, SANBORN, WELCOME.

**Exact key count:** 18 (PT kw) x 18 (period src kw) x 10 (periods) = 3240 key tuples.

## Total config count

915 masks x 3240 keys = **2,964,600 configs**.

**Universe SHA-256 (masks + keys):** `dc8acf12b5e3ac1e...` (full hash recorded in
results JSON `universe.universe_sha256`).

## Decryption + Bean re-derivation (explicit-CT contract)

For each `(mask, pt_kw, period_keyword)`:
1. `ct' = extract_ct(CT, mask)`; `cribs2 = remap_crib_dict(CRIB_DICT, mask)`.
2. `pt = quagmire_decrypt(ct', period_keyword, ct_alphabet_keyword="KRYPTOS",
   pt_alphabet_keyword=pt_kw, indicator="K")`.
3. Bean **re-derived** on `ct'` against `cribs2` in the KRYPTOS-mixed index space
   (`derive_bean_constraints(ct', cribs2, alphabet=KRYPTOS_MIXED)`); keystream
   `k[i] = (KA_idx(ct'[i]) - KA_idx(pt[i])) mod 26`; `check_bean(k, eq, ineq, linear)`.
4. `score_candidate(pt, crib_dict=cribs2)` -> crib_score (0..24), ngram.

No global mutation of `kernel.constants`. Bean re-derived for **each** mask.

## Scoring thresholds (pre-registered)

NOISE=6, STORE=10, SIGNAL=18, BREAKTHROUGH=24.

## Analytic max-of-N crib expectation (computed BEFORE running)

Per-position crib match prob ~1/26; crib_score ~ Binomial(24, 1/26):
- per-config E[crib_score] = 24/26 = **0.923**, sd = **0.943**.
- Gumbel max-of-N (N = 2,964,600): E[max] ~ mu + sigma*sqrt(2 ln N) ~ **5.81/24**.

So under the null, the best-of-universe crib_score is expected ~5-6/24. A real
signal must clear this **AND** the empirical shuffled-CT null max **AND** Bean PASS
**AND** ngram support.

## Null calibration

B = 20 shuffled-CT runs (Fisher-Yates, fixed seeds 1000..1019). Each shuffle
re-runs the FULL universe to produce the mask-universe-aware max-of-N crib
distribution. Empirical p-value = (#{null max >= real best} + 1) / (B + 1), for
both unconditional crib max and Bean-pass-conditioned crib max.

## Stop rule

Exhaustive over the enumerated universe (no budget cut). Null B = 20 fixed.

## Promotion / disproof rule

- Any `crib_score >= 18` is a **candidate for DISPROOF**, not a solution. If
  observed, STOP and flag: check vs null max-of-N AND Bean PASS AND ngram.
- A clean null (no Bean-pass config clears SIGNAL and the empirical null max) is
  the intended deliverable: a scope-explicit, hash-documented closure of the
  masked-Quagmire-III slice under this bounded universe.

## Scope statement

- **Eliminated (if clean null):** Quagmire III (CT=KRYPTOS, indicator K, PT keyword
  in the 18-word pool, period 3-12) under the 915-mask residue+block universe with
  `|mask| != 24`, arbitrary_null_mask alignment.
- **NOT eliminated:** other Quagmire keyword pools / periods; masks outside the
  residue+block rules; `|mask| == 24` (separately closed); multi-layer compositions;
  non-KRYPTOS CT alphabets; other indicators.

## Reproduction

```
PYTHONPATH=src python3 -u scripts/campaigns/masked_quagmire_iii_probe_2026_05_25.py
```
