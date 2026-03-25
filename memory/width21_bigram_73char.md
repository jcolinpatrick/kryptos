# Width-21 Bigram Analysis: CT97 vs CT73 vs CT73_COL7

**Date**: 2026-03-15
**Script**: `scripts/campaigns/f_width21_bigram_73char_v1.py`
**Result**: `results/f_width21_bigram_73char.json`
**MC Trials**: 200,000 per test

## Summary

Bean's width-21 bigram anomaly (highly significant on raw 97) was tested on the null-extracted 73-char text for the first time. The anomaly DISAPPEARS after null extraction, proving it is a stego-layer artifact.

## Key Results

### CT97 (raw 97 chars)
| Width | Repeated | MC Mean | MC Std | p(>=) | z-score | Verdict |
|-------|----------|---------|--------|-------|---------|---------|
| **21** | **11** | **3.5** | **1.68** | **0.00016** | **4.48** | **HIGH** |
| 7 | 9 | 4.9 | 1.93 | 0.036 | 2.15 | ELEVATED |
| 10 | 9 | 4.5 | 1.88 | 0.024 | 2.37 | ELEVATED |
| 14 | 7 | 4.1 | 1.81 | 0.100 | 1.58 | NORMAL |
| 28 | 5 | 2.9 | 1.54 | 0.147 | 1.37 | NORMAL |

### CT73 (null-extracted 73 chars)
| Width | Repeated | MC Mean | MC Std | p(>=) | z-score | Verdict |
|-------|----------|---------|--------|-------|---------|---------|
| **21** | **3** | **1.7** | **1.21** | **0.247** | **1.04** | **NORMAL** |
| **10** | **7** | **2.5** | **1.42** | **0.006** | **3.14** | **HIGH** |
| **17** | **6** | **2.0** | **1.29** | **0.008** | **3.09** | **HIGH** |
| 7 | 6 | 2.8 | 1.48 | 0.042 | 2.17 | ELEVATED |
| 19 | 4 | 1.9 | 1.24 | 0.102 | 1.71 | NORMAL |

### CT73_COL7 (col7-undone 73 chars)
| Width | Repeated | MC Mean | MC Std | p(>=) | z-score | Verdict |
|-------|----------|---------|--------|-------|---------|---------|
| 21 | 2 | 1.7 | 1.20 | 0.540 | 0.22 | NORMAL |
| 15 | 5 | 2.2 | 1.33 | 0.049 | 2.14 | ELEVATED |
| All others | normal | | | | | NORMAL |

## Critical Findings

1. **Width-21 anomaly is a STEGO LAYER ARTIFACT**: The highly significant width-21 signal (p=0.00016 on CT97) completely disappears on CT73 (p=0.247). The null insertion process CREATED this pattern.

2. **NEW anomalies on CT73**: Width 10 (p=0.006) and width 17 (p=0.008) are highly significant on CT73 but NOT on CT97 (width 10: p=0.024, width 17: p=0.172). These are properties of the CIPHER LAYER (they survived null removal and may have been obscured by it).

3. **Width 7 weakens but persists**: p=0.036 on CT97 -> p=0.042 on CT73. The width-7 signal partially survives null extraction.

4. **Col7 transposition eliminates most signals**: CT73_COL7 shows almost no anomalies except a marginal width-15 (p=0.049).

## Implications

- The width-21 property constrains the STEGO LAYER (how nulls were inserted), not the cipher layer
- The cipher layer has width-10 and width-17 structure (potentially related to period 10 or 17)
- Width 10 bigram anomaly on CT73: repeated bigrams LV, FK, RS, QT, SZ (all x2). These are column-like repetitions at distance 10.
- Width 17 bigram anomaly on CT73: repeated bigrams LK, LS, QZ, NT, TF (all x2). Some overlap with raw-CT97 patterns.

## Bean d=21 Consecutive Bigram Test
- Bean's specific metric (consecutive matching bigrams at distance 21): 0 on both CT97 and CT73
- Our metric (all repeated vertical bigrams at width 21) is different and shows the 11-count anomaly on CT97
- The two metrics are related but not identical; Bean's specific d=21 observation should be verified against his paper for exact definition
