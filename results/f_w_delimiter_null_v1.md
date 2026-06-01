# W-Delimiter Null Elimination v1

**Timestamp:** 2026-05-23T00:54:00.312493+00:00
**Runtime:** 6.76s  
**Variants:** vig, beau, vbeau  
**Seed:** 42  

## Hypothesis under test

Under the assumption that W in K4 CT is a delimiter (or null), K4 splits into 6 runs at W positions. Two of those runs contain free-fill slots adjacent to the known cribs: slot A (2 chars after EASTNORTHEAST) and slot B (4 chars before BERLINCLOCK). The question: across the full constrained English-plausible fill space, does any candidate produce a multi-feature tail event distinguishable from constrained combinatorics? This test covers slots A and B only. The unconstrained segments (0, 2, 3, 5) are NOT tested.

## Slot model

W positions: `[20, 36, 48, 58, 74]`  

| Slot | Positions | Len | CT | Context before | Context after | Role |
|---|---|---|---|---|---|---|
| A | [34, 35] | 2 | `OT` | EASTNORTHEAST | - | follows direction phrase, precedes W delimiter |
| B | [59, 60, 61, 62] | 4 | `INFB` | - | BERLINCLOCK | follows W delimiter, precedes location name |

Unconstrained segments (NOT tested): [0, 19], [37, 47], [49, 57], [75, 96]

### Assumptions
- H1: carved 97-char CT is the cipher input
- H2: W in CT is a delimiter or null, not a payload letter
- H3: cribs at canonical 0-indexed positions
- H4: only slots A (34-35) and B (59-62) are testable under cribs; segments 0/2/3/5 are unconstrained

## Populations

| Population | Size | Rule |
|---|---|---|
| random | 50000 | uniform A-Z x A-Z (seed 42) |
| dictionary | 100000 | ASCII 2-letter x 4-letter English words, cap 100000 |
| grammatical | 1035 | rule-based POS-curated lists (slot A: prep/pronoun/copula; slot B: spatial/temporal/structural/verbal) |
| curated | 24 | tightest: slot A in {TO,AT,IS,BY}, slot B in {NEAR,ATOP,UPON,INTO,PAST,FROM} |

## Feature set

Seven independently reported channels: `new_zero_count` (capped), `new_equality_with_27_or_65`, `common_bigram_count`, `common_trigram_count`, `contains_known_keyword`, `semantic_coherence_score`, `fill_complexity` (penalty). Composite = sum of per-channel clipped contributions under the default weights.

## Grammatical-population distributions
### variant = vig

| Feature | n | mean | std | p50 | p90 | p99 | p99.9 |
|---|---|---|---|---|---|---|---|
| new_zero_count | 1035 | 0.306 | 0.544 | 0.00 | 1.00 | 2.00 | 3.00 |
| new_equality_with_27_or_65 | 1035 | 0.111 | 0.314 | 0.00 | 1.00 | 1.00 | 1.00 |
| common_bigram_count | 1035 | 1.346 | 0.640 | 1.00 | 2.00 | 3.00 | 4.00 |
| common_trigram_count | 1035 | 0.000 | 0.000 | 0.00 | 0.00 | 0.00 | 0.00 |
| semantic_coherence_score | 1035 | 0.539 | 0.134 | 0.50 | 0.50 | 1.00 | 1.00 |

### variant = beau

| Feature | n | mean | std | p50 | p90 | p99 | p99.9 |
|---|---|---|---|---|---|---|---|
| new_zero_count | 1035 | 0.243 | 0.459 | 0.00 | 1.00 | 2.00 | 2.00 |
| new_equality_with_27_or_65 | 1035 | 0.196 | 0.407 | 0.00 | 1.00 | 1.00 | 2.00 |
| common_bigram_count | 1035 | 1.598 | 0.759 | 1.00 | 3.00 | 4.00 | 4.00 |
| common_trigram_count | 1035 | 0.006 | 0.076 | 0.00 | 0.00 | 0.00 | 1.00 |
| semantic_coherence_score | 1035 | 0.539 | 0.134 | 0.50 | 0.50 | 1.00 | 1.00 |

### variant = vbeau

| Feature | n | mean | std | p50 | p90 | p99 | p99.9 |
|---|---|---|---|---|---|---|---|
| new_zero_count | 1035 | 0.306 | 0.544 | 0.00 | 1.00 | 2.00 | 3.00 |
| new_equality_with_27_or_65 | 1035 | 0.111 | 0.314 | 0.00 | 1.00 | 1.00 | 1.00 |
| common_bigram_count | 1035 | 0.509 | 0.752 | 0.00 | 2.00 | 3.00 | 3.00 |
| common_trigram_count | 1035 | 0.007 | 0.082 | 0.00 | 0.00 | 0.00 | 1.00 |
| semantic_coherence_score | 1035 | 0.539 | 0.134 | 0.50 | 0.50 | 1.00 | 1.00 |

## Top 20 candidates by composite (per population)
### random

| Rank | A | B | variant | composite | nz | neq | bg | tg | kw | sem | joint_tail |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | OV | KBFD | vig | 9.30 | 2 | 3 | 2 | 0 | - | 0.00 | False |
| 2 | OV | KBFD | vbeau | 9.30 | 2 | 3 | 2 | 0 | - | 0.00 | False |
| 3 | OA | KPUD | vig | 8.30 | 1 | 3 | 2 | 0 | - | 0.00 | False |
| 4 | AV | KNYD | vbeau | 8.30 | 1 | 3 | 2 | 0 | - | 0.00 | False |
| 5 | UN | YMBZ | beau | 8.30 | 1 | 3 | 2 | 0 | - | 0.00 | False |
| 6 | QA | KNGD | vbeau | 8.30 | 1 | 3 | 2 | 0 | - | 0.00 | False |
| 7 | QV | VRWD | vbeau | 7.80 | 0 | 3 | 3 | 0 | - | 0.00 | False |
| 8 | LN | YNBK | beau | 7.80 | 1 | 3 | 1 | 0 | - | 0.00 | False |
| 9 | SH | OTBF | beau | 7.80 | 1 | 4 | 1 | 0 | - | 0.00 | False |
| 10 | QV | YNID | vig | 7.80 | 1 | 3 | 1 | 0 | - | 0.00 | False |
| 11 | QV | YNID | vbeau | 7.80 | 1 | 3 | 1 | 0 | - | 0.00 | False |
| 12 | OA | KPUD | vbeau | 7.80 | 1 | 3 | 1 | 0 | - | 0.00 | False |
| 13 | SN | WTNH | beau | 7.80 | 0 | 3 | 3 | 0 | - | 0.00 | False |
| 14 | IE | YNBF | beau | 7.80 | 1 | 3 | 1 | 0 | - | 0.00 | False |
| 15 | AV | KNYD | vig | 7.80 | 1 | 3 | 1 | 0 | - | 0.00 | False |
| 16 | SJ | YMBZ | beau | 7.80 | 1 | 3 | 1 | 0 | - | 0.00 | False |
| 17 | QA | KNGD | vig | 7.80 | 1 | 3 | 1 | 0 | - | 0.00 | False |
| 18 | FY | YTBZ | beau | 7.80 | 1 | 3 | 1 | 0 | - | 0.00 | False |
| 19 | CU | YTBS | beau | 7.80 | 0 | 3 | 3 | 0 | - | 0.00 | False |
| 20 | QV | KMFE | vig | 7.80 | 1 | 3 | 1 | 0 | - | 0.00 | False |

### dictionary

| Rank | A | B | variant | composite | nz | neq | bg | tg | kw | sem | joint_tail |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | ON | STEF | beau | 8.49 | 1 | 3 | 1 | 0 | - | 0.25 | False |
| 2 | SO | ATBS | beau | 8.49 | 0 | 3 | 3 | 0 | - | 0.25 | False |
| 3 | QV | EPOB | vig | 8.30 | 1 | 3 | 2 | 0 | - | 0.00 | False |
| 4 | QV | IGHS | vbeau | 8.30 | 1 | 3 | 2 | 0 | - | 0.00 | False |
| 5 | SH | YABO | beau | 8.30 | 1 | 3 | 2 | 0 | - | 0.00 | False |
| 6 | SO | YOBS | beau | 7.99 | 0 | 3 | 2 | 0 | - | 0.25 | False |
| 7 | BV | IPAD | vig | 7.80 | 1 | 3 | 1 | 0 | - | 0.00 | False |
| 8 | BV | IPAD | vbeau | 7.80 | 1 | 3 | 1 | 0 | - | 0.00 | False |
| 9 | KN | STUF | beau | 7.80 | 1 | 3 | 1 | 0 | - | 0.00 | False |
| 10 | QV | IGHS | vig | 7.80 | 1 | 3 | 1 | 0 | - | 0.00 | False |
| 11 | QV | KNIK | vig | 7.80 | 1 | 3 | 1 | 0 | - | 0.00 | False |
| 12 | QV | NPFX | vig | 7.80 | 1 | 3 | 1 | 0 | - | 0.00 | False |
| 13 | SH | YFBD | beau | 7.80 | 1 | 3 | 1 | 0 | - | 0.00 | False |
| 14 | SI | STEF | beau | 7.80 | 1 | 3 | 1 | 0 | - | 0.00 | False |
| 15 | SN | CNCF | beau | 7.80 | 1 | 3 | 1 | 0 | - | 0.00 | False |
| 16 | SN | STIG | beau | 7.80 | 1 | 3 | 1 | 0 | - | 0.00 | False |
| 17 | SS | STUF | beau | 7.80 | 1 | 3 | 1 | 0 | - | 0.00 | False |
| 18 | VV | KEND | vbeau | 7.80 | 0 | 3 | 3 | 0 | - | 0.00 | False |
| 19 | IN | BTBI | beau | 7.49 | 0 | 3 | 1 | 0 | - | 0.25 | False |
| 20 | US | KPOD | vig | 7.31 | 0 | 3 | 1 | 0 | - | 0.25 | False |

### grammatical

| Rank | A | B | variant | composite | nz | neq | bg | tg | kw | sem | joint_tail |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | IN | ATOP | beau | 5.50 | 0 | 2 | 1 | 0 | - | 1.00 | False |
| 2 | ON | ATOP | beau | 5.50 | 0 | 2 | 1 | 0 | - | 1.00 | False |
| 3 | SO | ATOP | beau | 5.50 | 0 | 2 | 2 | 0 | - | 0.50 | False |
| 4 | AN | ATOP | beau | 5.00 | 0 | 2 | 1 | 0 | - | 0.50 | False |
| 5 | AT | UPON | vig | 4.68 | 1 | 1 | 3 | 0 | - | 1.00 | False |
| 6 | ON | UPON | vig | 4.68 | 1 | 1 | 3 | 0 | - | 1.00 | False |
| 7 | OF | UPON | vig | 4.68 | 1 | 1 | 3 | 0 | - | 1.00 | False |
| 8 | OR | UPON | vig | 4.68 | 1 | 1 | 4 | 0 | - | 0.50 | False |
| 9 | SO | WEST | beau | 4.50 | 0 | 1 | 3 | 1 | - | 0.50 | False |
| 10 | AT | FIND | vbeau | 4.18 | 1 | 1 | 3 | 0 | - | 0.50 | False |
| 11 | IT | UPON | vig | 4.18 | 1 | 1 | 3 | 0 | - | 0.50 | False |
| 12 | SO | SEEK | beau | 4.00 | 1 | 1 | 3 | 0 | - | 0.50 | False |
| 13 | MY | ATOP | beau | 4.00 | 1 | 1 | 3 | 0 | - | 0.50 | False |
| 14 | TO | UPON | vig | 3.68 | 0 | 1 | 3 | 0 | - | 1.00 | False |
| 15 | AT | UPON | vbeau | 3.68 | 1 | 1 | 1 | 0 | - | 1.00 | False |
| 16 | IN | UPON | vig | 3.68 | 0 | 1 | 3 | 0 | - | 1.00 | False |
| 17 | IN | INTO | beau | 3.68 | 1 | 1 | 1 | 0 | - | 1.00 | False |
| 18 | ON | INTO | beau | 3.68 | 1 | 1 | 1 | 0 | - | 1.00 | False |
| 19 | ON | FIND | vbeau | 3.68 | 1 | 1 | 2 | 0 | - | 0.50 | False |
| 20 | OF | FIND | vbeau | 3.68 | 1 | 1 | 2 | 0 | - | 0.50 | False |

### curated

| Rank | A | B | variant | composite | nz | neq | bg | tg | kw | sem | joint_tail |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | AT | UPON | vig | 4.68 | 1 | 1 | 3 | 0 | - | 1.00 | False |
| 2 | TO | UPON | vig | 3.68 | 0 | 1 | 3 | 0 | - | 1.00 | False |
| 3 | AT | UPON | vbeau | 3.68 | 1 | 1 | 1 | 0 | - | 1.00 | False |
| 4 | IS | UPON | vig | 3.68 | 0 | 1 | 3 | 0 | - | 1.00 | False |
| 5 | BY | UPON | vig | 3.68 | 0 | 1 | 3 | 0 | - | 1.00 | False |
| 6 | AT | INTO | vbeau | 3.18 | 3 | 0 | 2 | 0 | - | 1.00 | False |
| 7 | TO | ATOP | beau | 3.00 | 0 | 1 | 2 | 0 | - | 1.00 | False |
| 8 | AT | ATOP | beau | 3.00 | 0 | 1 | 2 | 0 | - | 1.00 | False |
| 9 | IS | ATOP | beau | 3.00 | 0 | 1 | 2 | 0 | - | 1.00 | False |
| 10 | BY | ATOP | beau | 3.00 | 0 | 1 | 2 | 0 | - | 1.00 | False |
| 11 | AT | INTO | vig | 2.68 | 3 | 0 | 1 | 0 | - | 1.00 | False |
| 12 | TO | UPON | vbeau | 2.18 | 0 | 1 | 0 | 0 | - | 1.00 | False |
| 13 | IS | UPON | vbeau | 2.18 | 0 | 1 | 0 | 0 | - | 1.00 | False |
| 14 | BY | UPON | vbeau | 2.18 | 0 | 1 | 0 | 0 | - | 1.00 | False |
| 15 | TO | INTO | vig | 1.68 | 2 | 0 | 1 | 0 | - | 1.00 | False |
| 16 | TO | INTO | vbeau | 1.68 | 2 | 0 | 1 | 0 | - | 1.00 | False |
| 17 | IS | INTO | vig | 1.68 | 2 | 0 | 1 | 0 | - | 1.00 | False |
| 18 | IS | INTO | vbeau | 1.68 | 2 | 0 | 1 | 0 | - | 1.00 | False |
| 19 | BY | INTO | vig | 1.68 | 2 | 0 | 1 | 0 | - | 1.00 | False |
| 20 | BY | INTO | vbeau | 1.68 | 2 | 0 | 1 | 0 | - | 1.00 | False |

## AT+NEAR specific ranks

| Population | Variant | Rank | Of | Composite | new_zero | joint_tail |
|---|---|---|---|---|---|---|
| grammatical | vig | 168 | 1035 | 0.68 | 1 | False |
| grammatical | beau | 351 | 1035 | 0.18 | 0 | False |
| grammatical | vbeau | 157 | 1035 | 0.68 | 1 | False |
| curated | vig | 11 | 24 | 0.68 | 1 | False |
| curated | beau | 13 | 24 | 0.18 | 0 | False |
| curated | vbeau | 10 | 24 | 0.68 | 1 | False |

## Joint-tail candidates

Total joint-tail candidates across all populations and variants: **633**

## Multiplicity correction

Total candidates evaluated across all populations: 453177. Any single-channel tail at percentile p needs p < 1/453177 (log10 = 5.66) to be genuinely rare. The joint-tail criterion requires multi-channel tail events in the grammatical population, which is a stricter bar than single-channel multiplicity.

## Verdict: **NARROW_RESIDUAL**

Candidates that cleared joint-tail but NOT curated+multiplicity:
  - A='SV' B='ZGND' src=random variant=vbeau composite=5.30
  - A='SL' B='BBJP' src=random variant=vbeau composite=0.80
  - A='BF' B='SYGH' src=random variant=beau composite=2.30
  - A='QX' B='BRNS' src=random variant=beau composite=1.30
  - A='XL' B='GNUQ' src=random variant=vig composite=2.30
  - A='SG' B='BRIR' src=random variant=vbeau composite=1.30
  - A='FT' B='VQIF' src=random variant=vbeau composite=1.80
  - A='QB' B='KRSE' src=random variant=vbeau composite=5.30
  - A='XV' B='SYGQ' src=random variant=beau composite=2.30
  - A='JX' B='VGNF' src=random variant=vbeau composite=0.80
  - A='NU' B='VUBK' src=random variant=vig composite=0.80
  - A='AG' B='GJFH' src=random variant=vig composite=1.80
  - A='LP' B='MNMX' src=random variant=vig composite=1.80
  - A='ZX' B='KVOH' src=random variant=beau composite=1.30
  - A='LO' B='UWDN' src=random variant=vig composite=0.80
  - A='UU' B='YLFH' src=random variant=beau composite=4.30
  - A='SK' B='BRWH' src=random variant=vbeau composite=0.80
  - A='NP' B='FUZQ' src=random variant=beau composite=1.30
  - A='AT' B='BRZD' src=random variant=vbeau composite=5.49
  - A='KG' B='PXMX' src=random variant=vig composite=0.80

### Publication wording

> A narrow residual tail survives the multi-channel joint-tail criterion but does not clear multiplicity-corrected curated-population bar. The W-delimiter hypothesis is not eliminated within these narrow surviving cells; each listed candidate requires an independent follow-up test before any further claim. Scope caveats apply.

### Scope caveats
- This null does NOT cover segments 0, 2, 3, 5 (unconstrained under the cribs).
- This null only tests additive cipher variants (Vigenere, Beaufort, Variant Beaufort).
- This null assumes direct positional alignment CT[i] -> PT[i].
- This null does not rule out physical-overlay or procedural mechanisms outside the feature set.
- The W-delimiter hypothesis itself (H2) is treated as a working assumption, not as proven.
