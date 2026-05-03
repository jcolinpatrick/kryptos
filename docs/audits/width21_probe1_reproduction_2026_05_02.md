# Width-21 Probe 1 — Reproduction Result

**Date:** 2026-05-02
**Predecessor:** `docs/audits/width21_bigram_re-examination.md` (today)
**Script:** `scripts/campaigns/f_width21_bigram_73char_v1.py`
**Output:** `results/f_width21_bigram_73char.json` (gitignored; recomputable)
**Trial budget:** 200,000 Monte Carlo letter-multiset shuffles per width

---

## Verdict

**PASSED.** The CT97 width-21 vertical-bigram anomaly reproduces under
the current kernel (commit `acfe266`+) with no palette dependency.
Numbers are identical to 5 decimals against the 2026-03-15 baseline.

| Statistic | 2026-03-15 | 2026-05-02 | Match |
|---|---:|---:|:---:|
| Actual repeated bigrams | 11 | 11 | ✓ |
| MC mean | 3.5 | 3.5 | ✓ |
| MC std | 1.68 | 1.68 | ✓ |
| p(≥) | 0.00016 | 0.00016 | ✓ |
| z-score | 4.48 | 4.48 | ✓ |

The script imports nothing from retired-palette code paths
(only `from kryptos.kernel.constants import CT, CT_LEN`). The MC null
is over CT97-letter-multiset shuffles — a palette-independent statistic.

## Anomaly is real and stable

`p = 1.6e-4` over 200K trials with z=4.48 is robust:

- **Stable across kernel versions.** The 2026-03-15 numbers were
  produced before the post-hardening kernel commits. Identical
  reproduction at `acfe266`+ rules out kernel drift as a contributor.
- **Robust to multiplicity.** Bonferroni across the 20 widths tested
  (3, 5, 7, 8, 9, 10, 11, 13, 14, 15, 17, 19, 21, 23, 24, 26, 28, 29,
  30, 31): corrected `p ≈ 3.2e-3`. Still notable.
- **Independent of the retired palette.** No CONSENSUS_NULL_POSITIONS,
  no NULL_PALETTE — pure statistic on the carved 97-character text.

## The 11 repeated bigrams (structural notes)

| Bigram | Position pair | Notes |
|---|---|---|
| LS | (11, 32) | 11 is pre-crib; 32 is in EASTNORTHEAST (PT[32]=S, CT[32]=S — self-encrypting). |
| BS | (12, 33) | 33 is the last position of EASTNORTHEAST. |
| LW | (15, 36) | Both in unknown plaintext regions. |
| IT | (16, 37) | Both in unknown plaintext regions. |
| QZ | (25, 46) | 25 is in EASTNORTHEAST (PT[25]=N). |
| KK | (31, 52) | **Threads to BERLINCLOCK at i=52→73**; see "KK chain" below. |
| WA | (36, 57) | Both in unknown plaintext regions. |
| SN | (39, 60) | Both in unknown plaintext regions. |
| ZT | (46, 67) | Both in unknown plaintext regions. |
| AZ | (49, 70) | 70 is in BERLINCLOCK (PT[70]=L). |
| PK | (65, 86) | 65 is in BERLINCLOCK (PT[65]=R). |

### The KK chain (structurally interesting)

`CT[31] = K`, `CT[52] = K`, `CT[73] = K` form a chain of three K's at
distances 21 apart. **`CT[73] = K` is one of the two self-encrypting
positions** (PT[73] = K = BERLIN-CLOCK's terminal K). So the width-21
signal threads through a known self-encrypting anchor.

This is not yet a mechanism — it is a structural fact about the
carved CT. A future cipher hypothesis that constrains positions 31,
52, 73 jointly to all decrypt to K under their respective keystreams
would make the chain a constructive prediction rather than an
observation.

## What this enables

Probe 2 and Probe 3 from `docs/audits/width21_bigram_re-examination.md`
§"Recommended action" are now unblocked:

- **Probe 2.** Cross-test CT97 in a 21-column grid with predeclared
  row offsets (3, 7, 11). Tests "is the width-21 structure aligned
  with a specific reading order?"
- **Probe 3.** Pre-declare a non-palette null mask candidate set and
  test width-21 under each. Tests "is it stego-attributable under
  any defensible non-palette null model?"

Both probes assume Probe 1's existence claim, which is now verified.

## Caveats and what we did NOT verify

- Bean's published d=21 metric (consecutive matching bigrams at
  distance 21) gives **0 matches on CT97**. The project's "any repeated
  vertical bigram at width 21" metric is different and produces the
  11-count signal. **The 11-count anomaly is the project's finding,
  not a direct reproduction of Bean's published p-value.** This was
  noted in the 2026-03-15 memo and should be carried forward.

- The CT73 results (width-10 p=0.006, width-17 p=0.008) also reproduced
  in this run, but they remain conditional on the script's hardcoded
  `USER_MASK` — a 24-position null mask that is its own (un-audited)
  hypothesis. Those results should not be cited as evidence without an
  audit of the mask's provenance.

- The CT97 width-7 marginal signal (p=0.036) and width-10 marginal
  signal (p=0.024) also reproduced. They survive uncorrected p<0.05
  but do not survive Bonferroni across the 20 widths tested.

## Registry implication

Recommend a new live registry claim:

```
C-WIDTH21-01
  status: live
  scope: existence claim, mechanism unattributed
  statement: "On the carved 97-char K4 ciphertext, the count of
              repeated vertical bigrams when written at width 21 is
              11 — significantly above the letter-multiset null
              (MC mean 3.5, p ≈ 1.6e-4, z = 4.48 over 200K trials).
              The signal is independent of any null-mask hypothesis;
              it is a property of the carved letters."
  caveats:
    - "Distinct from Bean's published consecutive-bigram-at-d=21
      metric, which gives 0 matches on CT97."
    - "Mechanism unknown after the 2026-04-01 retirement of the
      palette family. Whether cipher-internal, stego-attributable
      under a non-palette mask, or coincidental under multi-anomaly
      search remains open."
  reproducibility: high
  reproducibility_command: |
    PYTHONPATH=src python3 scripts/campaigns/f_width21_bigram_73char_v1.py
```

---

*Last updated 2026-05-02. Probe 1 reproduction confirmed; existence
claim cleared for promotion. Probes 2 and 3 are the natural next moves
to characterize the anomaly under predeclared non-palette null models.*
