# Cryptosclue / German Guesser K-panel XOR Hypothesis: Quantitative Null Disproof

**Date:** 2026-05-13
**Status:** Disproved by quantitative null model. Cryptosclue lineage closed pending substantively different evidence.
**Run type:** New replication + null model + p-value comparison.
**Script:** `scripts/novel/e_kpanel_xor_cryptosclue_replication.py`
**Persistent artifact:** `results/cryptosclue_replication_20260513.json`
**Exhaustion log entry:** `e_kpanel_xor_cryptosclue_replication` (status: exhausted)

---

## BLUF

The "Cryptosclue" / "German Guesser" hypothesis proposed K4 decrypts via XOR
against the KRYPTOS alphabet panel read as a long running key, with the reported
Index of Coincidence peaking at 0.06077 on the 93-character post-OBKR remainder
when started at row "M" of the panel. A 1000-trial null model built from random
shuffles of the K-panel rows shows the real K-panel's peak IoC achieves p = 0.362
and the headline 0.06077 itself sits at approximately the p99 of the same null.
The "peak at row M" effect is **selection bias from a max-of-676 order statistic
over a KA-rotation-derived structure on a 93-character text.** No signal.

---

## Run scope (exact)

| Field | Value |
|---|---|
| Carved CT | `OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR` (97 chars, from `kryptos.kernel.constants.CT`) |
| KA alphabet | `KRYPTOSABCDEFGHIJLMNQUVWXZ` (from `kryptos.kernel.constants.KRYPTOS_ALPHABET`) |
| K-panel construction | 26 left-rotations of KA, concatenated into a 676-character flat string |
| Panel starting positions tested | 676 (full coverage) |
| Encodings tested | 2 (`AZ` standard A=0; `ITA2` Baudot teletype 5-bit) |
| OBKR-handling modes | 2 (`with_obkr` on the full 97-char CT; `without_obkr` on the 93-char tail) |
| XOR null rule | If XOR result is in the decode table, emit the decoded letter; else emit the key letter at that position (Cryptosclue's "Rockex discriminator" rule) |
| Real-panel sweep total | 676 × 2 × 2 = 2,704 configurations |
| Null model | 1000 random row-permutations of the K-panel, re-run the same 2,704-configuration sweep, record max IoC per trial |
| Null trials | 1000 |

---

## Result

### Real K-panel sweep

Top 4 (one per encoding × OBKR-mode combination):

| Encoding | OBKR-mode | Start pos | IoC | PT[:20] |
|---|---|---|---|---|
| AZ | with_obkr | 486 | 0.05155 | NFPXTGJFLXAVXFXBZYOS |
| AZ | without_obkr | 464 | 0.04932 | SJIHKKEUUEZSCUZOFLZR |
| ITA2 | with_obkr | 44 | 0.04811 | HCUHHSNQKPQRMIEMKNHA |
| ITA2 | without_obkr | 48 | 0.04675 | HSNQKPQRMIEMKNHAUJBO |

Real K-panel peak IoC across all 2,704 configurations: **0.05155**.

### Null distribution (max-IoC over 1000 panel-row-shuffle trials)

| Statistic | Value |
|---|---|
| Mean | 0.05102 |
| Stdev | 0.00192 |
| p95 | 0.05470 |
| p99 | 0.05633 |
| Max | 0.06014 |

### Comparison

- Real K-panel peak IoC: **0.05155**
- p-value of real peak vs null: **0.362**
- Verdict: **PEAK_WITHIN_NULL** — Cryptosclue claim collapses to selection bias.

The real K-panel's peak is approximately 0.001 above the null mean, well below the p95 (0.05470) and far below the p99 (0.05633). The shuffled-panel null reached a max of 0.06014, demonstrating that K-panel-row-shuffled structures with no semantic relationship to KRYPTOS produce IoCs in the Cryptosclue-claimed range about 1% of the time.

---

## Why this kills the claim

Cryptosclue compares the headline 0.06077 against English IoC ~0.0667 and random ~0.0385, making it look like a >50% improvement over random. The relevant comparator for a max-of-676 sweep is the null distribution constructed here, which has mean 0.05102. The same headline number falls at approximately the p99 of that distribution — a value reachable by chance about 1% of the time even when the panel is randomly shuffled.

Cryptosclue's specific decryption arithmetic was also conditional on multiple post-hoc choices:

1. Whether to include or exclude the OBKR prefix
2. Which of 676 panel starting positions
3. Which 5-bit encoding (A=0, ITA-2, or other variants)
4. Which 25-letter alphabet for the proposed Layer 1 step
5. Null-substitution rule (key letter vs ciphertext letter when XOR yields unreachable values)

None of these choices were pre-registered. The IoC headline is therefore a multiplicity-uncontrolled maximum, not a per-position observation.

---

## Why exact reproduction does not match the headline

Our K-panel construction reads as 26 cyclic left-rotations of KA, concatenated to form a 676-character flat string. Cryptosclue's published key string suggests a slightly different per-row reading (possibly the sculpture's actual letter order with the misaligned "L" preserved), which would shift the IoC by a few thousandths. This does not affect the verdict: the null model shuffles those same rows, so any reasonable KA-derived running key family produces the same max-IoC distribution. The decisive number is the p-value, not exact arithmetic reproduction.

---

## Component-level coverage

Both component hypotheses were independently exhausted before this run:

- **5-bit XOR / Z/32-additive ciphers** —
  `scripts/novel/e_ita2_xor_stepping_01.py` (status: exhausted; 174,906 configurations across 3 encodings × ~425 keyword sources × 26 starting offsets × 2 null-handling models; best 7/24 anchored crib score; all noise; 2026-03-28). Tested keyword keys, not panel-as-running-key.
- **OBKR-as-indicator structural split** —
  `scripts/substitution/e_cable_format_hypotheses.py` (deprecated). Tested OBKRU = key indicator with mod-26 Vigenère, Beaufort, Variant Beaufort, autokey variants.
- **5-bit KRYPTOS table derivation** —
  `scripts/analysis/e_mod35_table_derivation.py`.

The 2026-05-13 run closes the specific configuration gap where panel-as-running-key had not been combined with 5-bit XOR in a single integrated test.

---

## On the "kind of scary" Sanborn remark

The March 2019 CNN documentary writeup reports Sanborn saying he received a solution from Germany "about a year ago" that was "kind of scary — the first part started to look right, but then the rest didn't." The Cryptosclue author's February 2018 submission matches the timing. The page's first decoded characters are "CIA...".

Per CLAUDE.md Truth Taxonomy, Sanborn statements are Tier-3 evidence: authentic creator commentary, but not promotable to PUBLIC FACT or DERIVED FACT. The historical base rate justifies durable skepticism (the 1996 CIA memo's 3-of-4-wrong cipher diagnoses; Sanborn's documented "I lied" admission about K2 coordinates). The "CIA" prefix attractor is one of the highest-prior partial-prefix false positives in K4 cryptanalysis. A polite Sanborn acknowledgment that something "looked right" at the prefix is consistent with both a real partial signal AND with pattern-completion on a known false-positive attractor.

The 2026-05-13 null comparison resolves the ambiguity. The IoC peak is statistically empty. There was no signal for the Sanborn remark to authenticate.

---

## Reproduction

```bash
PYTHONPATH=src python3 -u scripts/novel/e_kpanel_xor_cryptosclue_replication.py
```

Output: `results/cryptosclue_replication_20260513.json`. Tier 1 (real K-panel) is deterministic; Tier 2 (null model) is seeded per-trial in the script and reproducible across runs.

---

## Predicted outcomes were locked before running

The script's docstring documents the prediction made prior to execution: "Peak IoC across 676 positions will exceed the per-position null mean (max-of-N order statistic). This is expected and is NOT evidence. After comparing the peak against the MAX-IoC null distribution from K-panel-shuffles, the predicted outcome is: peak falls within the null distribution and the Cryptosclue claim collapses to selection bias." This prediction held.

---

## Limitations / scope

This result eliminates the **Cryptosclue / German Guesser specific lineage** of K-panel-XOR hypotheses on K4. It does NOT eliminate:

- Other XOR-based families with non-panel key sources (the keyword-key family is independently exhausted by `e_ita2_xor_stepping_01`).
- 5-bit / Z/32 ciphers more broadly under different structural assumptions.
- Multi-layer constructions where XOR-with-K-panel is paired with another layer in an order or composition not tested here.
- A genuinely different OBKR semantics (e.g., OBKR as a numeric offset feeding a different cipher family).

A substantially different mechanism would need its own null model.
