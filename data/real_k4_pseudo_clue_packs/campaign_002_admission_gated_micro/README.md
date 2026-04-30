# Real-K4 Bridge Campaign 002 — Admission-Gated Micro

> **STATUS: CLOSED (null_level, side-effect predictions unfired,
> 2026-04-30).** See [`CLOSURE.md`](CLOSURE.md) for the closure note.

The first campaign run AFTER the admission standard at
[`docs/REAL_K4_PSEUDO_CLUE_PACK_ADMISSION.md`](../../../docs/REAL_K4_PSEUDO_CLUE_PACK_ADMISSION.md)
was created. Three packs only, each `tightened` from a campaign-001
family, each carrying a predicted side-effect and predeclared success
criterion.

| pack | tightens | mechanism | n_specs |
|---|---|---|---:|
| `01_stehle_lesson019_tightened.json` | F3-31 | LESSON-019 (caesar+columnar+route_boustrophedon), single keyword (BERLIN), single shift (5), single width (4) | 12 |
| `02_width21_route_boustrophedon_tightened.json` | F5-51 | route_boustrophedon + vigenere only, single keyword (BERLIN), width=21 | 12 |
| `03_bcl_variant_beaufort_kryptos_tightened.json` | F4-43 | columnar + variant_beaufort, single keyword (KRYPTOS) | 6 |

All 3 passed `scripts/_infra/validate_pseudo_clue_pack_admission.py`
mechanical checks before dispatch. Audit produced 30 candidates with
max_crib=1/24, well below the null expected_max of 3.24. Side-effect
predictions activate at crib_score ≥ 12; no candidate reached that
threshold, so all three predictions are **unfired** (neither
corroborated nor falsified).

This README is a brief landing page; the authoritative disposition
lives in [`CLOSURE.md`](CLOSURE.md).
