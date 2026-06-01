# f_two_layer_stego_cipher_v1 — Results

- Started: 2026-05-23T00:48:49.391845+00:00
- Completed: 2026-05-23T00:48:51.206841+00:00
- Sampling mode: exploratory_stride (seed=0)
- Total profiles tested: 2000
- Workers: 16
- Outer families: 552
- Inner families: 374

## Summary

EXPLORATORY null over 2000 stride-sampled profiles. Coverage is approximate; this is not a definitive negative result.

## Coverage report
- Distinct outer instances: 551/552
- Distinct inner instances: 374/374
- Cross (outer_fam, inner_fam) pairs: 16/16
- Outers seeing ALL inner family classes: 48
- Median inner families per outer: 3.0
- Complexity histogram: low=170 medium=361 high=1469
- Qualifies family-cover complete: False
- Qualifies low-complexity emphasized: False
- Qualifies full-cartesian complete: False

## Coverage guarantees
- Exploratory only; stride sampling across row-major cartesian product.
- No guarantee of per-outer family coverage.

## Scope warnings
- Bean compatibility is None for all mask/projection outers (H1 disabled).
- Stehle metrics are advisory; never used as hard elimination gate.
- crib_compatibility at anchored positions is H1_CONDITIONAL.

## Joint anomaly successes
None.

## Top candidates (soft ranking — NOT selection)
- `p00000486` seg_K4_21_48_73_same_key + caesar_6: crib=2 z21=4.36 stehle=0 flags=[]
- `p00000497` seg_K4_21_33_63_same_key + caesar_17: crib=1 z21=5.12 stehle=0 flags=[]
- `p00000431` project_w14_row_identity + near_id_swap2_EF_ST: crib=3 z21=4.64 stehle=0 flags=[]
- `p00000482` seg_K3_33_63_increment_offset + near_id_swap2_IJ_ST: crib=2 z21=5.00 stehle=0 flags=[]
- `p00000420` project_w10_row_identity + near_id_swap2_CD_QR: crib=2 z21=4.98 stehle=0 flags=[]
- `p00000496` seg_K4_21_33_63_same_key + near_id_swap_ST: crib=2 z21=4.93 stehle=0 flags=[]
- `p00000478` seg_K3_33_63_k1k2k3_keywords + near_id_swap2_AB_ST: crib=2 z21=4.79 stehle=0 flags=[]
- `p00000471` seg_K2_48_increment_offset + near_id_swap2_GH_MN: crib=2 z21=4.79 stehle=0 flags=[]
- `p00000493` seg_K4_21_48_73_increment_offset + near_id_swap2_MN_OP: crib=2 z21=4.74 stehle=0 flags=[]
- `p00000485` seg_K4_21_48_73_same_key + near_id_swap_HI: crib=2 z21=4.64 stehle=0 flags=[]

## Family baselines
- OUTER-MASK-EVERYNTH: n=77 mean_crib=0.13 mean_z21=0.04 max_crib=2
- OUTER-MASK-PERIODIC: n=1830 mean_crib=0.48 mean_z21=0.04 max_crib=4
- OUTER-PROJECT: n=54 mean_crib=1.28 mean_z21=0.81 max_crib=4
- OUTER-SEG: n=39 mean_crib=1.21 mean_z21=2.78 max_crib=3
