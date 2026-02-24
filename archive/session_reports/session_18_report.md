# Session 18 Report — Constrained Transposition Families + Constraint Quantification

**Date**: 2026-02-18
**Focus**: Keyword columnar sweep, pre-ENE analysis, grid route ciphers, affine polyalphabetic, period-7 constraint enumeration.

## Key Meta-Result: Exact Underdetermination Quantification

The E-S-57/57b experiment provides the first exact count of feasible (key, σ-at-cribs) combinations for period-7 Vigenère + arbitrary transposition:

| Constraint | Feasible combos | Notes |
|-----------|----------------|-------|
| None (26^7 keys × arbitrary σ) | ~3.0×10²³ | Upper bound (ignores cross-residue injectivity) |
| Bean equality (k[6]=k[2]) | ~1.35×10²² | 22× reduction — only constraint from cribs |
| Period-7 + structured transposition | O(thousands) | From E-S-53/55 — all at noise floor |

**The gap between 10²² (arbitrary σ) and O(thousands) (structured σ) is ~10¹⁹.** This quantifies exactly WHY structured transposition sweeps find noise while SA with arbitrary σ finds artifacts.

### E-S-57a Bug: Bean Constraints Under Transposition

**[INTERNAL RESULT — BUG FIX]**
The original E-S-57 incorrectly applied Bean inequality (27,72) to the period-7 key tuple, yielding k[6]≠k[2] which contradicts Bean equality k[6]=k[2]. This appeared to prove period-7 impossible. **THE BUG**: Bean inequalities were derived under direct correspondence. With transposition σ, the inequality becomes CT[σ(27)]−R ≠ CT[σ(72)]−C, which is a constraint on σ, not the key. The corrected analysis (E-S-57b) confirms period-7 + transposition remains viable.

**Implication**: All Bean-constrained analyses in this repo (E-S-04 and later) that applied Bean inequalities to the key tuple are ONLY valid for the direct-correspondence model. With transposition, Bean constraints become σ-dependent.

## Experiment Results

### E-S-53: Keyword Columnar + Polyalphabetic — ELIMINATED

**Method**: 127 thematic keywords → columnar transpositions at all widths (3-26) + Myszkowski variants. Both transposition directions × Vig/Beau/VarBeau × periods 2-14. Total: 15,756 configs.

**Result**: Best 18/24 at period 13 (SCHEIDT keyword) — underdetermined regime. **Zero results at period ≤7 in top 20.** All high scores at periods 10-14.

- Artifact: `results/e_s_53_keyword_columnar.json`
- Repro: `PYTHONPATH=src python3 -u scripts/e_s_53_keyword_columnar_sweep.py`

### E-S-54: Pre-ENE Segment Analysis — MARGINAL ARTIFACT

**Method**: Deep analysis of positions 0-20 (OBKRUOXOGHULBSOLIFBBW). IC=0.0667 matches English.

| Metric | Pre-ENE | Verdict |
|--------|---------|---------|
| IC | 0.0667 | p=0.04 — borderline significant |
| Chi² vs English | 99.0 | REJECTS English (critical: 37.65) |
| Distinct letters | 13/26 | Low diversity |
| Repeated letters | O×4, B×4 | Drive 85% of IC |
| Best Caesar | shift=3, chi²=54.0 | Not English |
| Best affine | a=21,b=14, chi²=19.1 | Passes chi² but text incoherent |
| Key indicator (Vig) | 3/24 | Noise |
| Key indicator (Beau) | 4/24 | Noise |
| Last segment (84-96) IC | 0.0641 | Also elevated — boundary effect? |

**Verdict**: IC=0.0667 is a marginal statistical artifact (p=0.04, driven by O×4 and B×4). Chi² strongly rejects English. NOT evidence of a structurally different cipher at positions 0-20.

- Artifact: `results/e_s_54_pre_ene.json`
- Repro: `PYTHONPATH=src python3 -u scripts/e_s_54_pre_ene_analysis.py`

### E-S-55: Grid Route Ciphers — ELIMINATED

**Method**: 13 grid dimensions (excluding 7×14 already tested) × 8 reading orders × inverse × 2 dirs × 3 variants × periods 2-14. Total: 16,224 configs.

| Grid dimensions tested | Pad | Best at p≤7 |
|----------------------|-----|-------------|
| 3×33, 33×3, 3×34, 34×3 | 2-5 | 11/24 at p=6 |
| 9×11, 11×9 | 2 | 10/24 at p=7 |
| 4×25, 25×4, 5×20, 20×5 | 3 | 10/24 |
| 10×10 | 3 | 10/24 |
| 6×17, 17×6 | 5 | 10/24 |

All top scores at periods 13-14 (underdetermined). Period ≤7: only 16 hits, all ≤11/24 with most failing Bean.

- Artifact: `results/e_s_55_grid_route.json`
- Repro: `PYTHONPATH=src python3 -u scripts/e_s_55_grid_route_sweep.py`

### E-S-56: Affine Polyalphabetic — NO SIGNAL

**Method**: Generalized cipher CT[i] = a[i%p]*PT[i] + b[i%p] mod 26. Tests all 12 valid `a` values (coprime to 26) per residue class, including Vigenère (a=1) and Variant Beaufort (a=25).

| Period | Vigenère | Best Affine | Gain |
|--------|---------|-------------|------|
| 5 | 7/24 | 9/24 | +2 |
| 7 | 7/24 | 13/24 | +6 |
| 10 | 11/24 | 17/24 | +6 |
| 13 | 14/24 | 20/24 | +6 |

**The affine improvement is ENTIRELY due to extra DOF** (12 choices of `a` per residue). Expected random for affine at period 7 with 4 positions/residue is ~12-13/24. The observed 13/24 is at the expected level.

**Verdict**: Affine generalization provides no signal beyond what extra parameters explain. K4 is not distinguished as affine vs additive.

- Artifact: `results/e_s_56_affine_polyalphabetic.json`
- Repro: `PYTHONPATH=src python3 -u scripts/e_s_56_affine_polyalphabetic.py`

### E-S-57/57b: Period-7 Constraint Enumeration — UNDERDETERMINED

**Method**: For each of 26^7 period-7 keys, count injective σ-mappings at 24 crib positions satisfying CT[σ(p)] = PT[p] + k[p%7] mod 26. Per-residue independence yields exact counts.

**Key result**: ALL 26 key values are feasible for ALL 7 residue classes. No key is eliminated by the crib constraints alone.

| Residue | Crib positions | σ-sum (over 26 keys) | Min σ | Max σ |
|---------|---------------|---------------------|-------|-------|
| 0 | 4 | 4,636 | 24 | 576 |
| 1 | 4 | 4,538 | 8 | 576 |
| 2 | 4 | 4,528 | 20 | 720 |
| 3 | 4 | 5,133 | 12 | 768 |
| 4 | 3 | 1,340 | 4 | 144 |
| 5 | 3 | 1,304 | 6 | 144 |
| 6 | 2 | 350 | 2 | 32 |

- Artifact: `results/e_s_57b_period7_constraint.json`
- Repro: `PYTHONPATH=src python3 -u scripts/e_s_57b_period7_constraint_correct.py`

## Background Tasks (from prior sessions)

| Task | Status | Progress |
|------|--------|----------|
| E-S-11 (running key + columnar) | Running | Width 8, ~5hrs elapsed |
| E-S-17 (wider double columnar SA) | Running | Width 13, ~25min elapsed |
| E-S-31 (Carter running key) | Running | Width 9 |

All expected to produce noise based on underdetermination findings.

## Updated Elimination Summary

### Newly eliminated/confirmed this session
| Family | Method | Verdict |
|--------|--------|---------|
| Keyword columnar (127 keywords, all widths) | Exhaustive | ELIMINATED (noise at p≤7) |
| Grid route ciphers (13 dimensions, 8 orders) | Exhaustive | ELIMINATED (noise at p≤7) |
| Affine polyalphabetic | Algebraic | NO SIGNAL (extra DOF explains scores) |
| Pre-ENE different cipher (RQ-7) | Statistical | ARTIFACT (p=0.04, driven by O×4, B×4) |

### Confirmed findings
| Finding | Method | Significance |
|---------|--------|-------------|
| Period-7 + arbitrary σ is massively underdetermined | Exact counting | 3×10²³ feasible combos |
| Bean constraints don't apply to key tuple under transposition | Algebraic | Bug fix: prior analyses overconstraining |

## Strategic Assessment

The constraint enumeration (E-S-57b) provides the clearest picture yet of K4's difficulty:

1. **At the crib positions alone, period-7 Vigenère + arbitrary σ has ~10²² solutions** (even with Bean equality). The cribs are necessary but far from sufficient.

2. **Structured transpositions (columnar, route, etc.) constrain σ to O(thousands)** of possibilities, which is why they show noise — the specific transposition + period-7 key combo is so constrained that no classical family matches.

3. **The gap (10¹⁹) between arbitrary and structured σ** explains the underdetermination wall: SA can explore arbitrary σ and always find artifacts, while structured sweeps are too constrained to hit the solution.

### What this means for the path forward

The K4 solution likely requires:
- **The SPECIFIC transposition method** (not trying all families, but knowing which one Sanborn used)
- **OR the SPECIFIC key source** (not trying all texts, but knowing the actual document/procedure)
- **OR external information** (the sealed Smithsonian plaintext, the auctioned coding charts)
- **OR a non-standard model** entirely (not Vigenère + transposition at all)

### Recommended next directions
1. **Deeper investigation of Sanborn's statements** — "What's the point?" and "delivering a message" may directly describe the method
2. **K3 method analysis** — What specific K3→K4 changes are consistent with our data?
3. **LLM-assisted coherence scoring** — Use AI to check if partially-decrypted text is thematically coherent (Egypt trip, Berlin Wall)
4. **Physical sculpture reverse-engineering** — Determine the exact physical layout from photographs

---
*Session 18 — 2026-02-18 — 5 experiments (E-S-53 through E-S-57b)*
