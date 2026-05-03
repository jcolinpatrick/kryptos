# Width-21 W-Removal Hypothesis — Disproof

**Date:** 2026-05-02
**Predecessor:** `docs/audits/width21_probe1_reproduction_2026_05_02.md`
**Trigger:** Operator observation: "the bigram anomaly DISAPPEARS when you
eliminate all W's in the ciphertext."

---

## Verdict

**The W observation is empirically correct but the natural reading
("W is the cipher signature") is false.** The width-21 anomaly is a
property of CT97's *positional structure*, not its W content. Length-
preserving W-substitution (W → any other letter) leaves the 11-count
anomaly **completely intact**. Only length perturbation destroys it.

This places the W observation in the same epistemic category as the
retired palette: a surface manifestation of a length-fragility pattern,
not a cipher-mechanism signature.

---

## Evidence

### W-removal kills the anomaly (operator's claim — confirmed)

| Operation | Length | Repeated bigrams at width 21 | p(≥) | z |
|---|---:|---:|---:|---:|
| Baseline CT97 | 97 | 11 | 1.6e-4 | +4.48 |
| Remove all 5 W's | 92 | **0** | 1.000 | -2.04 |

### W-replacement preserves the anomaly (the disproof)

Length kept at 97 by replacing each W with a single substitute letter:

| Substitute | Repeated bigrams | p(≥) | z |
|---|---:|---:|---:|
| W → A | **11** | 8e-4 | +3.80 |
| W → X | **11** | 4e-4 | +4.09 |
| W → Q | **11** | 7e-4 | +3.81 |
| W → `_` (out-of-alphabet) | **11** | 2e-4 | +4.48 |

The actual count of repeated bigrams is **invariant** under W
replacement. Only the MC null distribution changes (because the letter
multiset shifts), driving the p-value modestly. Significance still
strongly survives.

### Other length-preserving letter replacements

Control: replace each of K, N, P, J (which also kill the anomaly under
*removal*) with X (length stays 97):

| Substitute | Repeated bigrams | p(≥) | z |
|---|---:|---:|---:|
| K → X | 11 | 6e-4 | +3.96 |
| N → X | 11 | 4e-4 | +4.21 |
| P → X | 11 | 3e-4 | +4.21 |
| J → X | **12** | 0 | +4.79 |

J → X actually *adds* one repeated bigram. Replacement either preserves
or strengthens the anomaly across all tested letters.

### Removing only "structural" W's vs "non-structural" W's

- Remove only W at {36, 74} (the W's involved in the LW and WA repeated
  bigrams): length 95, **actual=4**, p=0.43, z=+0.43.
- Remove only W at {20, 48, 58} (the W's NOT involved in any repeated
  bigram): length 94, **actual=5**, p=0.21, z=+1.07.

Both partial removals destroy the anomaly. The destruction is
indistinguishable from "any 2-3 character removal" — it is **length
fragility, not W positional importance**.

---

## What this means structurally

The 11-count of repeated vertical bigrams at width 21 on CT97 is a
property of the **integer pair structure** of CT positions, not of the
letters that occupy those positions. Specifically:

> Among the 76 vertical position pairs `(i, i+21)` for i ∈ [0, 76], the
> distribution of letter-pairs is more concentrated than a letter-
> multiset shuffle predicts. This concentration is invariant under any
> bijective relabeling of letters that preserves position assignments.

In cipher terms, this is the signature of a **structural / positional
mechanism** at width 21 — most plausibly a transposition or route layer
with period or width 21. It is NOT the signature of a substitution
acting on a particular letter.

A substitution-only cipher acting position-by-position would not
produce this pattern (because each position's output is independent of
its width-21 partner). A transposition/route at width 21 would tend to
preserve such position-pair regularity through the mapping.

## What this means for the palette retirement

The 2026-04-01 palette retirement (`{B, G, I, K, O, W, Z}`) was based
on:

1. The palette claim was post-hoc (positions selected to fit a
   pre-chosen letter set), and
2. SA produces 11 different palettes on K4 with similar properties,
   indicating no specific signal.

The W-removal effect is **consistent with finding 2**: the property is
fragile to perturbation in a way that admits many surface
"explanations" because the underlying signal is structural, not letter-
specific. The palette never explained anything beyond surface
correlation.

Re-attribution: the palette family was symptomatic of a **width-21
positional structure**, not of any 7-letter letter-set preference.

## What this means for next moves

Probe 2 (predeclared row offsets in a 21-column grid) is the right
next test, because it directly probes whether the width-21 structure
aligns with a specific reading order. A positive result on Probe 2
would point at a transposition/route-at-21 hypothesis. A null result
would say the structure is offset-symmetric (which would still be
consistent with substitution-after-transposition, but tighten the
mechanism class).

Probe 3 (predeclared non-palette null masks) is now **lower priority**:
the W-replacement disproof shows the anomaly is content-invariant, so
testing it under various null-mask extractions will mostly tell us the
length-shift effect we already have.

## Registry implication

`C-WIDTH21-01` claim text should be sharpened:

> "On the carved 97-char K4 ciphertext, the count of repeated vertical
> bigrams when written at width 21 is 11 — significantly above the
> letter-multiset null (MC mean 3.5, p ≈ 1.6e-4, z = 4.48 over 200K
> trials). The signal is **structural / positional**: it is invariant
> under length-preserving letter substitution but destroyed by length
> perturbation. This makes it a candidate signature of a width-21
> transposition / route layer rather than of any letter-content
> property."

Caveat: Bean's published consecutive-bigram-at-d=21 metric remains a
distinct (and null) statistic, unchanged by this analysis.

---

*Last updated 2026-05-02. The W-removal observation is verified but
the natural reading is disproved. The structural-positional reading
that survives is a stronger and more actionable hypothesis. Probe 2 is
now the highest-value follow-up.*
