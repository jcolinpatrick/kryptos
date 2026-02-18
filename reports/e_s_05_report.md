# E-S-05: Algebraic Fractionation & Hill Cipher Sweep — Report

**Elapsed:** 0.01s  
**Deterministic:** yes (no randomness)  

## Part A: Hill Cipher n=2,3,4 (mod 26)

- Configs tested: 9
- Eliminated: 9
- Solutions: 0
- Underdetermined: 0

| n | offset | status | detail |
|---|--------|--------|--------|
| 2 | 0 | eliminated | {'reason': 'best matrix still has 9/11 mismatches', 'blocks' |
| 2 | 1 | eliminated | {'reason': 'best matrix still has 9/11 mismatches', 'blocks' |
| 3 | 0 | eliminated | {'reason': 'best matrix still has 4/7 mismatches', 'blocks': |
| 3 | 1 | eliminated | {'reason': 'best matrix still has 4/7 mismatches', 'blocks': |
| 3 | 2 | eliminated | {'reason': 'best matrix still has 3/6 mismatches', 'blocks': |
| 4 | 0 | eliminated | {'reason': 'no invertible PT submatrix among all block combo |
| 4 | 1 | eliminated | {'reason': 'best matrix still has 1/5 mismatches', 'blocks': |
| 4 | 2 | eliminated | {'reason': 'best matrix still has 1/5 mismatches', 'blocks': |
| 4 | 3 | eliminated | {'reason': 'no invertible PT submatrix among all block combo |

## Part B: Trifid 3x3x3 (periods 2-49)

- Eliminated: 7 periods
- Not eliminated (with crib data): 2 periods
- No fully-known groups: 39 periods

**Eliminated periods:** [2, 3, 4, 5, 6, 7, 8]

**Feasible periods (need deeper analysis):** [9, 11]

**No-data periods:** [10, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49]

## Part C: Bifid 5x5

- **ELIMINATED**
- K4 CT contains 26 unique letters (A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,Z). A 5x5 Polybius grid holds at most 25 (one letter pair merged). Since all 26 appear, no 5x5 Bifid variant can produce this CT.

## Part D: Bifid 6x6 (periods 2-49)

- Eliminated: 8 periods
- Not eliminated (with crib data): 1 periods
- No fully-known groups: 39 periods

**Eliminated periods:** [2, 3, 4, 5, 6, 7, 8, 11]

**Feasible periods (need deeper analysis):** [9]

## Summary of New Eliminations

- Hill cipher n=2,3,4 (all offsets, mod 26): **9 configs ELIMINATED**
- Bifid 5x5 (all variants): **ELIMINATED** (26 unique CT letters)
- Trifid 3x3x3: **7 periods ELIMINATED** out of 48
- Bifid 6x6: **8 periods ELIMINATED** out of 48

## Repro Command

```bash
PYTHONPATH=src python3 -u scripts/e_s_05_algebraic_fractionation.py
```

Artifacts: `artifacts/e_s_05_results.json`
