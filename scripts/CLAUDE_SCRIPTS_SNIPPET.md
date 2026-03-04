## Scripts Directory Structure

### How to navigate
- Read `MANIFEST.tsv` before exploring individual scripts
- Check `EXHAUSTION.json` before running any attack to avoid duplicating work
- Each subdirectory has a specific cipher family focus

### Directory layout
- `_uncategorized/` (95 scripts) — Uncategorized — needs manual review
- `grille/` (58 scripts) — Grille, turning grille, and Cardan aperture attacks
- `fractionation/` (55 scripts) — Fractionation & bean-period analysis
- `transposition/columnar/` (37 scripts) — Columnar transposition attacks
- `blitz/` (30 scripts) — Blitz campaign — fast brute-force sweeps
- `substitution/` (28 scripts) — Monoalphabetic, affine, Hill, bifid, trifid
- `exploration/` (27 scripts) — Exploratory analysis, bespoke methods, chart series
- `transposition/other/` (26 scripts) — Non-columnar transposition attacks
- `campaigns/` (26 scripts) — Multi-vector campaign scripts and novel attack ideas
- `polyalphabetic/` (24 scripts) — Vigenère, Beaufort, autokey, and polyalphabetic
- `yar/` (23 scripts) — YAR family — grille reconstruction and variants
- `tableau/` (22 scripts) — Tableau, KA alphabet, and keyword analysis
- `running_key/` (19 scripts) — Running key and book cipher attacks
- `crib_analysis/` (18 scripts) — Crib dragging, plaintext reconstruction, constraint solving
- `_infra/` (14 scripts) — Infrastructure, harnesses, validators, corpus tools
- `team/` (13 scripts) — Team-sourced attack ideas and collaborative scripts
- `k3_continuity/` (12 scripts) — K1-K3 method applied to K4, cross-section analysis
- `thematic/berlin_clock/` (11 scripts) — Berlin clock, Weltzeituhr, and DDR-era keys
- `thematic/sculpture_physical/` (10 scripts) — Physical sculpture, installation, and coordinate keys
- `cfm/` (8 scripts) — Cipher family modeling and constraint-based elimination
- `statistical/` (7 scripts) — Statistical analysis, frequency, IC, entropy
- `encoding/` (7 scripts) — Morse code, encoding transforms, extraction patterns
- `antipodes/` (4 scripts) — Antipodes series — paired/complementary attacks

### Script contract
Every attack script should return `list[tuple[float, str, str]]`:
- float: fitness score (quadgram default)
- str: candidate plaintext
- str: method description

### Before adding a new script
1. Check MANIFEST.tsv for existing coverage of the cipher family
2. Check EXHAUSTION.json for parameter ranges already tested
3. Place in the correct subdirectory by family
4. Add a docstring header with: Cipher, Family, Status, Keyspace
