# E-CKM-02: Constructive Key Management Exhaustive Sweep

**Date:** 2026-03-22
**Status:** Design approved
**Family:** two_system
**Hypothesis:** K4's cipher key is CONSTRUCTED by combining two keyword sources through a simple mod-26 operation, producing a non-periodic key from periodic components.

## Motivation

Ed Scheidt co-founded TecSec Inc. in 1990 and holds 36 patents in "Constructive Key Management" (CKM) — keys assembled from independent splits. Gillogly stated K4 uses "an invention by Ed Scheidt that has never appeared in cryptographic literature." The key DERIVATION (combining sources) may be the novel invention, not the cipher primitive.

Prior test E-SPLIT-00 (51K configs, best 6/24) used only 23 handpicked keywords and tested on CT97 only. This experiment fills critical gaps:
- SEVEN not tested as keyword (generates stego layer via KRYPTOS×SEVEN)
- CT73 not tested (periods >23 not covered by Bean proof on CT73)
- Phase offsets not tested
- Much larger keyword space needed

## Model

```
key[i] = f(WORD_A[i % L_A], WORD_B[(i + d) % L_B]) mod 26
```

Where:
- WORD_A, WORD_B are keywords (possibly the same)
- L_A, L_B are their lengths
- d is a phase offset (0 to L_B-1)
- f is a simple two-input function

The combined key has period lcm(L_A, L_B). On CT97, periodic keys are already
conditionally eliminated under direct positional crib mapping. On CT73, only
periods 1-23 are eliminated in the tested harness scope; periods ≥24 remain
open. This experiment primarily targets CT73 at periods ≥24.

## Combination Functions (6)

| Name | Formula | Physical interpretation |
|------|---------|----------------------|
| add | (A + B) mod 26 | "Add two numbers from two keyword lists" |
| sub_AB | (A - B) mod 26 | "Subtract B from A" |
| sub_BA | (B - A) mod 26 | "Subtract A from B" |
| mul | (A × B) mod 26 | "Multiply" (only 12 coprime values, but test anyway) |
| min | min(A, B) | "Take the smaller value" |
| max | max(A, B) | "Take the larger value" |

## Keyword Sources

### Tier 1 — Priority targets (35 words)
KRYPTOS, SEVEN, PALIMPSEST, ABSCISSA, DEFECTOR, BERLIN, CLOCK, KOMPASS, SHADOW, LANGLEY, SCHEIDT, SANBORN, CARTER, LAYERTWO, IDBYROWS, IQLUSION, CIPHER, SECRET, BURIED, NORTH, EAST, WEST, POINT, COMPASS, DEGREES, MINUTES, SECONDS, INVISIBLE, MAGNETIC, FIELD, LODGE, TOWER, CHART, FILTER, MEDUSA

### Tier 2 — Thematic (~200 words)
From `wordlists/thematic_keywords.txt`

### Tier 3 — English frequency (~1000 words)
Top words from `wordlists/english.txt` by frequency, lengths 3-13, prioritizing lengths coprime with 7.

## Test Matrix

| Dimension | Values | Count |
|-----------|--------|-------|
| Word A | Tier 1+2 | ~235 |
| Word B | Tier 1+2+3 | ~1,235 |
| Phase offset d | 0 to min(L_B-1, 7) | ~4 avg |
| Combination function | 6 | 6 |
| Cipher variant | Vig, Beau, VBeau | 3 |
| Alphabet | AZ, KA | 2 |
| Ciphertext | CT97, CT73 × 3 mask layouts | 4 |

**Estimated total:** ~167M configs
**Estimated runtime:** ~5 minutes on 28 cores (24 mod ops + 24 comparisons per config)

## Scoring

Blind crib scoring at 24 known positions. No keystream property filtering.

| Score | Classification | Action |
|-------|---------------|--------|
| 0-9 | noise | Skip |
| 10-17 | interesting | Log details |
| 18-23 | signal | HALT AND INVESTIGATE |
| 24 | breakthrough | HALT — potential solution |

## Null Mask Strategy

From the Gutenberg sweep optimization: 55 candidate null masks collapse to 3 distinct crib-scoring layouts (no varying null falls within/between crib groups). Test all 3 layouts plus raw CT97.

## Output

- `results/e_ckm_exhaustive_02.json` — standard format
- Score distribution histogram
- All configs scoring ≥10 with full details
- Runtime and throughput metrics

## What This Eliminates (if max ≤ 9)

Two-keyword mod-26 key construction for this keyword space × combination rules × cipher variants is ELIMINATED. Extends E-SPLIT-00's 51K configs to ~167M configs.

## Dependencies

- `kryptos.kernel.constants` — CT, cribs, Bean constraints
- `kryptos.kernel.transforms.vigenere` — decrypt functions
- `kryptos.kernel.alphabet` — AZ, KA
- `wordlists/thematic_keywords.txt`
- `wordlists/english.txt`
