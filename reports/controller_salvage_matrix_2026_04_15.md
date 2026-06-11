# Controller Salvage Matrix

Generated: `2026-04-15T14:00:54.828739+00:00`

## Scope

- Tested theories analyzed: **269**
- Keep: **11**
- Revalidate: **128**
- Quarantine: **130**

## Standards

- Kernel verification cutover: `2026-04-13T22:13:31+00:00`
- Null-retirement reference: `2026-04-14T00:00:00+00:00`
- `Keep` means post-hardening, non-retired-assumption, bounded-method controller history.
- `Revalidate` means potentially useful but not safe to trust as an active elimination without rerun.
- `Quarantine` means do not use for active prompting, family exhaustion, or anomaly weighting.
- Important: **no controller experiment in this ledger preserves a structured `script_id`**. Even kept rows still have a reproducibility gap relative to deterministic harness-grade evidence.

## Summary By Disposition

### Keep

- Count: **11**
- Contamination buckets: `{'other': 11}`
- Theory statuses: `{'eliminated': 11}`

- `a2d882aae635` [eliminated] Coordinate delta key: false-vs-true coordinate difference as Gronsfeld keystream (k2_coords, other)
- `1e7d16753a83` [eliminated] Systematic transcription-phase perturbation as a deliberate additional cipher layer (archive_evidence, other)
- `d32b533d4d8a` [eliminated] True coordinate digits as Beaufort key (pre-falsification values from 'He lied' notebook) (k2_coords, other)
- `d38c9de74196` [eliminated] Sequential four-width columnar transposition from '4, 8, 10, 26 = Col' (archive_evidence, other)
- `7cb543d6946b` [eliminated] Compass Grid-Walk Cipher on KA-Keyed 5x5+1 Board (geometry, other)
- `91f8496b4fab` [eliminated] Four-Interleaved Compass-Bearing Keystreams Explaining Stehle Delta-5 (encoding, other)
- `b767faec6315` [eliminated] Coordinate-Lie Delta Digits as Beaufort Keystream (k2_coords, other)
- `846379a97774` [eliminated] Systematic Single-Character CT Perturbation Sweep (crib_analysis, other)
- `cce6656dadfa` [eliminated] CKM Precursor: Dual-Source Key-Split Additive Cipher (key_tape, other)
- `68a3a0886c22` [eliminated] Compass Cipher: Bearing-Indexed Diagonal Tableau Read (archive_evidence, other)
- `bfee52a4f94c` [eliminated] Medieval Code Circle: Fixed Tableau Ring with Keyword-Indexed Starting Position (encoding, other)

### Revalidate

- Count: **128**
- Contamination buckets: `{'other': 59, 'stego_or_selection': 69}`
- Theory statuses: `{'eliminated': 108, 'completed': 20}`

- `c92a9ba65bfe` [eliminated] Bifid fractionation as IC-suppression mechanism (fractionation, other)
- `3e972818003f` [eliminated] W-delimited segmented encoding with per-segment keying (encoding, other)
- `e4fa0f7b4af4` [eliminated] Antipodal period-38 involution from Bean equality (antipodes, other)
- `5c74d202893e` [eliminated] Double columnar transposition with crib-anchored key recovery via pre-ENE segment (crib_analysis, other)
- `030acb9cac14` [eliminated] Finite key tape with 624-constrained modular keystream (key_tape, other)
- `3c7b16b384c2` [completed] K2-coordinate-keyed columnar transposition with variable block widths (double_columnar, other)
- `99a25e23eb36` [eliminated] Pre-ENE high-IC segment as independent Vigenère layer over archive-evidenced base cipher (archive_evidence, stego_or_selection)
- `53f79b033676` [eliminated] Geodetic Mercator projection encoding with crib-anchored latitude/longitude interleave (geodetic, stego_or_selection)
- `7866c9fd271f` [eliminated] Stehle delta-5 as Beaufort running-key phase boundary (crib_analysis, other)
- `12d46d9c6a53` [eliminated] Double columnar transposition with W-positions as column-break markers and coordinate-digit column widths (double_columnar, other)
- `007267a5b9a4` [eliminated] Geodetic-bearing running key with linear Stehle segment (geodetic, other)
- `86d689f84034` [eliminated] W-delimited variable-length Polybius encoding with dual-alphabet fractionation (encoding, other)

### Quarantine

- Count: **130**
- Contamination buckets: `{'direct_null': 130}`
- Theory statuses: `{'eliminated': 99, 'completed': 31}`

- `cff11dfda2a3` [eliminated] Cardan grille with null-cipher fixed points at positions 32 and 73 (grille, direct_null)
- `d31718a75c93` [eliminated] Nonlinear geometric path through Polybius square with IC-suppressing read-off (geometry, direct_null)
- `27c6e25db98e` [eliminated] Null-palette 7-letter restriction as Cardan grille padding signature (grille, direct_null)
- `6954e8061f7d` [eliminated] Antipodal coordinate digit key with W-delimited Vigenère segments (antipodes, direct_null)
- `dec6346357cb` [eliminated] Non-periodic multi-alphabet masking with bigram compression explaining sub-random IC (encoding, direct_null)
- `2c01274951ac` [eliminated] BCL Beaufort palette enrichment as ADFGX-style fractionation artifact (fractionation, direct_null)
- `cfa84547de5f` [eliminated] Sanborn's 'matrix' as a keyed 26×26 tabula recta with K2 coordinate-digit row selection producing null-palette restriction (archive_evidence, direct_null)
- `184e6e7c404b` [eliminated] Grille-masked polyalphabetic cipher where grille holes select a Vigenère layer and mask positions carry an independent substitution, explaining pre-ENE IC elevation (grille, direct_null)
- `636347ba7711` [eliminated] Coordinate-digit-seeded LFSR key tape with restricted null palette (key_tape, direct_null)
- `862488589878` [eliminated] Antipodal Beaufort switching on keyed-alphabet parity (antipodes, direct_null)
- `58a4d9359d09` [eliminated] Period-38 nonlinear key tape from Bean equality distance (key_tape, direct_null)
- `0c475af3e92a` [eliminated] K2 coordinate digits as columnar transposition key over masked Beaufort (k2_coords, direct_null)

## Kernel And Harness Backing

- Current verification slice run during this audit: `199 passed` across `tests/test_h_624_73_nullmask_harness.py`, `tests/test_h_624_nonword_key_schedule_harness.py`, `tests/test_h_pretransposition_layer_harness.py`, and `tests/test_qa_kernel_verify.py`.
- This supports the current kernel/harness layer, but it does **not** retroactively validate the old controller experiments because those experiments lack structured script linkage in the ledger.

## Files

- JSON matrix: `/home/cpatrick/kryptos/reports/controller_salvage_matrix_2026_04_15.json`
