#!/usr/bin/env python3
"""
Cipher: mono_trans_runkey
Family: archive_evidence
Status: active
Keyspace: ~5000 configs × 10 alphabet modes × ~1.6M offsets
Last run:
Best score:
"""
"""E-AAA-RUNKEY-BIJECTION-08: Running-key bijection discriminator on keyword-mixed tableaux.

SOURCE: Archives of American Art + prior campaign E-AAA-TABLEAU-STRUCT-06.
  - Periodic models on mixed tableaux: ELIMINATED (E-AAA-TABLEAU-STRUCT-06)
  - This tests the NON-PERIODIC variant: running-key Beaufort/Vigenère with
    keyword-mixed tableaux, discriminated by mono bijection (not score optimization)

MODEL: CT73 = Mono(Trans(Sub_S(PT73, Source[offset:])))
  Where Sub_S uses keyword-mixed alphabet S for indexing, not standard AZ.

STRUCTURAL VARIABLES:
  - Tableau alphabet S: AZ, KA, ABSCISSA(AZ), ABSCISSA(KA), PALIMPSEST(AZ)
  - Orientation: standard vs bottom-chart (reversed row indexing)
  - Cipher variant: Beaufort, Vigenère
  - Transposition: widths 1-10 with keyword orderings + identity
  - Source texts: Carter, CIA charter, JFK/Reagan Berlin, K2/K3 plaintext, etc.

DISCRIMINATOR (deterministic):
  For each (alphabet, orientation, source, offset, config):
  1. Compute intermediate X[i] using S_idx arithmetic
  2. Injectivity: same CT letter at cribs → same X value (10+ constraints, ~10^-14 joint)
  3. Consistency: same X → same CT letter
  4. Survivors have a valid partial mono map

WHY THIS IS NEW:
  - Prior bijection script (e_mono_sourcetext_bijection_01) used ONLY AZ indexing
  - S_idx is a permutation of 0..25, so X values change with alphabet
  - Configs rejected under AZ may survive under ABSCISSA-mixed, and vice versa
  - This is the final untested variant of the archive-supported non-periodic chart hypothesis
"""

import sys
import os
import re
import time
import json
from pathlib import Path
from collections import defaultdict
from itertools import permutations as iterperms

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, 'src')):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CONSENSUS_NULL_POSITIONS, NULL_PALETTE,
    CRIB_DICT, CRIB_POSITIONS,
    KRYPTOS_ALPHABET,
)
from kryptos.kernel.alphabet import keyword_mixed_alphabet
from kryptos.kernel.transforms.transposition import columnar_perm, keyword_to_order

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False
    print("WARNING: numpy not available, using pure Python (much slower)")

# ═══════════════════════════════════════════════════════════════════════════
# TABLEAU ALPHABET MODES
# ═══════════════════════════════════════════════════════════════════════════

TABLEAU_MODES = {}

def add_mode(name, alpha_seq, bottom=False):
    idx = {ch: i for i, ch in enumerate(alpha_seq)}
    TABLEAU_MODES[name] = {
        'seq': alpha_seq,
        'idx': idx,
        'bottom': bottom,
    }

# Standard orientations
add_mode('AZ_std', ALPH, bottom=False)
add_mode('KA_std', KRYPTOS_ALPHABET, bottom=False)
add_mode('ABSCISSA_AZ_std', keyword_mixed_alphabet('ABSCISSA', ALPH), bottom=False)
add_mode('ABSCISSA_KA_std', keyword_mixed_alphabet('ABSCISSA', KRYPTOS_ALPHABET), bottom=False)
add_mode('PALIMPSEST_AZ_std', keyword_mixed_alphabet('PALIMPSEST', ALPH), bottom=False)

# Bottom-chart orientations (archive: "Bottom chart reading")
add_mode('AZ_bot', ALPH, bottom=True)
add_mode('KA_bot', KRYPTOS_ALPHABET, bottom=True)
add_mode('ABSCISSA_AZ_bot', keyword_mixed_alphabet('ABSCISSA', ALPH), bottom=True)
add_mode('ABSCISSA_KA_bot', keyword_mixed_alphabet('ABSCISSA', KRYPTOS_ALPHABET), bottom=True)
add_mode('PALIMPSEST_AZ_bot', keyword_mixed_alphabet('PALIMPSEST', ALPH), bottom=True)

print(f"Tableau modes: {len(TABLEAU_MODES)}")
for name, mode in TABLEAU_MODES.items():
    print(f"  {name:25s}: {mode['seq'][:20]}...  bottom={mode['bottom']}")

# ═══════════════════════════════════════════════════════════════════════════
# CRIB DATA
# ═══════════════════════════════════════════════════════════════════════════

ORIG_CRIB_POS = list(range(21, 34)) + list(range(63, 74))
CRIB_PT_LETTERS = [CRIB_DICT[p] for p in ORIG_CRIB_POS]
CRIB_CT_LETTERS = [CT[p] for p in ORIG_CRIB_POS]

# Precompute same-CT-letter pairs (injectivity constraints)
SAME_CT_PAIRS = []
for i in range(24):
    for j in range(i + 1, 24):
        if CRIB_CT_LETTERS[i] == CRIB_CT_LETTERS[j]:
            SAME_CT_PAIRS.append((i, j))

# Different-CT pairs (consistency constraints)
DIFF_CT_PAIRS = []
for i in range(24):
    for j in range(i + 1, 24):
        if CRIB_CT_LETTERS[i] != CRIB_CT_LETTERS[j]:
            DIFF_CT_PAIRS.append((i, j))

CRIB_CT_NUMS = [ALPH_IDX[c] for c in CRIB_CT_LETTERS]

print(f"Injectivity constraint pairs: {len(SAME_CT_PAIRS)}")
print(f"Consistency constraint pairs: {len(DIFF_CT_PAIRS)}")

# ═══════════════════════════════════════════════════════════════════════════
# (a1, a2, a3) TRIPLES — null mask allocation
# ═══════════════════════════════════════════════════════════════════════════

SEG1_CONSENSUS = len([p for p in CONSENSUS_NULL_POSITIONS if p < 21])
SEG2_CONSENSUS = len([p for p in CONSENSUS_NULL_POSITIONS if 34 <= p <= 62])
EXTRA_CANDIDATES = sorted(set(
    i for i, c in enumerate(CT) if c in NULL_PALETTE
) - CRIB_POSITIONS - CONSENSUS_NULL_POSITIONS)
SEG1_EXTRA_AVAIL = len([p for p in EXTRA_CANDIDATES if p < 21])
SEG2_EXTRA_AVAIL = len([p for p in EXTRA_CANDIDATES if 34 <= p <= 62])
SEG3_EXTRA_AVAIL = len([p for p in EXTRA_CANDIDATES if p >= 74])

def generate_triples():
    triples = []
    for a1 in range(min(7, SEG1_EXTRA_AVAIL) + 1):
        for a2 in range(min(7 - a1, SEG2_EXTRA_AVAIL) + 1):
            a3 = 7 - a1 - a2
            if 0 <= a3 <= SEG3_EXTRA_AVAIL:
                triples.append((a1, a2, a3))
    return triples

def shifted_cribs_for_triple(a1, a2, a3):
    nulls_before_ene = SEG1_CONSENSUS + a1
    ene_start = 21 - nulls_before_ene
    nulls_before_bcl = SEG1_CONSENSUS + a1 + SEG2_CONSENSUS + a2
    bcl_start = 63 - nulls_before_bcl
    return list(range(ene_start, ene_start + 13)) + list(range(bcl_start, bcl_start + 11))

# ═══════════════════════════════════════════════════════════════════════════
# CONFIG GENERATION
# ═══════════════════════════════════════════════════════════════════════════

def build_unique_configs(triples):
    """Build structural configs (transposition variants), dedup on key-positions."""
    seen_kp = set()
    configs = []
    dup_count = 0

    KEYWORD_ORDERINGS = {}
    for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "DEFECTOR",
               "KOMPASS", "HOROLOGE", "EQUINOX", "BERLIN", "CLOCK"]:
        for w in range(2, 11):
            order = keyword_to_order(kw, w)
            if order:
                KEYWORD_ORDERINGS.setdefault(w, set()).add(order)

    for a1, a2, a3 in triples:
        shifted = shifted_cribs_for_triple(a1, a2, a3)

        for w in range(1, 11):
            if w == 1:
                orderings = [tuple(range(1))]
            elif w <= 4:
                orderings = list(iterperms(range(w)))
            else:
                orderings = [tuple(range(w))]
                orderings.extend(KEYWORD_ORDERINGS.get(w, []))

            for ordering in orderings:
                if w == 1:
                    key_positions = tuple(shifted)
                else:
                    perm = columnar_perm(w, ordering, length=73)
                    key_positions = tuple(perm[s] for s in shifted)

                if key_positions in seen_kp:
                    dup_count += 1
                    continue
                seen_kp.add(key_positions)
                configs.append({
                    'triple': (a1, a2, a3),
                    'width': w,
                    'key_positions': key_positions,
                })

    return configs, dup_count

# ═══════════════════════════════════════════════════════════════════════════
# VECTORIZED BIJECTION CHECK (alphabet-aware)
# ═══════════════════════════════════════════════════════════════════════════

def check_offsets_numpy(source_nums_S, pt_nums_S, key_positions, variant, bottom,
                        max_offset):
    """Check all offsets using numpy. Returns list of (offset, mono_map) survivors."""
    kp = list(key_positions)
    max_kp = max(kp)
    actual_max = min(max_offset, len(source_nums_S) - max_kp)
    if actual_max <= 0:
        return []

    offsets = np.arange(actual_max, dtype=np.int32)
    indices = offsets[:, None] + np.array(kp, dtype=np.int32)[None, :]
    src_vals = source_nums_S[indices]  # (N, 24) — alphabet-indexed source values

    if bottom:
        src_vals = (25 - src_vals) % MOD

    pt_arr = np.array(pt_nums_S, dtype=np.int32)

    if variant == 'beau':
        X = (src_vals - pt_arr) % MOD
    else:  # vig
        X = (pt_arr + src_vals) % MOD

    # Injectivity: same-CT pairs must have same X
    mask = np.ones(actual_max, dtype=bool)
    for pi, pj in SAME_CT_PAIRS:
        mask &= (X[:, pi] == X[:, pj])
        if not mask.any():
            return []

    surviving_offsets = offsets[mask]
    if len(surviving_offsets) == 0:
        return []

    # Consistency: diff-CT pairs must have diff X (if same X but different CT → contradiction)
    X_surv = X[mask]
    mask2 = np.ones(len(surviving_offsets), dtype=bool)
    for pi, pj in DIFF_CT_PAIRS:
        mask2 &= (X_surv[:, pi] != X_surv[:, pj])
        if not mask2.any():
            return []

    final_offsets = surviving_offsets[mask2]
    X_final = X_surv[mask2]
    ct_arr = np.array(CRIB_CT_NUMS, dtype=np.int32)

    results = []
    for idx in range(len(final_offsets)):
        x_vals = X_final[idx]
        mono = {}
        valid = True
        for c in range(24):
            x, y = int(x_vals[c]), int(ct_arr[c])
            if x in mono:
                if mono[x] != y:
                    valid = False
                    break
            else:
                mono[x] = y
        if valid:
            results.append((int(final_offsets[idx]), mono))

    return results

# ═══════════════════════════════════════════════════════════════════════════
# SOURCE TEXTS
# ═══════════════════════════════════════════════════════════════════════════

def sanitize(text):
    return re.sub(r'[^A-Z]', '', text.upper())

def load_source_texts():
    ref_dir = Path(_ROOT) / "reference"
    texts = {}
    for name, path in [
        ("carter_gutenberg", ref_dir / "carter_gutenberg.txt"),
        ("carter_vol1", ref_dir / "carter_vol1.txt"),
        ("carter_tomb", ref_dir / "Carter_Tomb.txt"),
        ("cia_charter", ref_dir / "running_key_texts" / "cia_charter.txt"),
        ("jfk_berlin", ref_dir / "running_key_texts" / "jfk_berlin.txt"),
        ("nsa_act_1947", ref_dir / "running_key_texts" / "nsa_act_1947.txt"),
        ("reagan_berlin", ref_dir / "running_key_texts" / "reagan_berlin.txt"),
        ("udhr", ref_dir / "running_key_texts" / "udhr.txt"),
    ]:
        if path.exists():
            clean = sanitize(path.read_text(errors='replace'))
            if len(clean) >= 73:
                texts[name] = clean

    # K1-K3 plaintext as potential running keys
    k2_pt = sanitize("IT WAS TOTALLY INVISIBLE HOWS THAT POSSIBLE THEY USED THE EARTHS MAGNETIC FIELD X THE INFORMATION WAS GATHERED AND TRANSMITTED UNDERGRUUND TO AN UNKNOWN LOCATION X DOES LANGLEY KNOW ABOUT THIS THEY SHOULD ITS BURIED OUT THERE SOMEWHERE X WHO KNOWS THE EXACT LOCATION ONLY WW THIS WAS HIS LAST MESSAGE X THIRTY EIGHT DEGREES FIFTY SEVEN MINUTES SIX POINT FIVE SECONDS NORTH SEVENTY SEVEN DEGREES EIGHT MINUTES FORTY FOUR SECONDS WEST ID BY ROWS")
    k3_pt = sanitize("SLOWLY DESPARATLY SLOWLY THE REMAINS OF PASSAGE DEBRIS THAT ENCUMBERED THE LOWER PART OF THE DOORWAY WAS REMOVED WITH TREMBLING HANDS I MADE A TINY BREACH IN THE UPPER LEFT HAND CORNER AND THEN WIDENING THE HOLE A LITTLE I INSERTED THE CANDLE AND PEERED IN THE HOT AIR ESCAPING FROM THE CHAMBER CAUSED THE FLAME TO FLICKER BUT PRESENTLY DETAILS OF THE ROOM WITHIN EMERGED FROM THE MIST X CAN YOU SEE ANYTHING Q")
    if len(k2_pt) >= 73:
        texts["k2_plaintext"] = k2_pt
    if len(k3_pt) >= 73:
        texts["k3_plaintext"] = k3_pt

    # Smithsonian archive manuscript text as potential running key (archive-supported)
    archive_path = ref_dir / "smithsonian_archive.md"
    if archive_path.exists():
        clean = sanitize(archive_path.read_text(errors='replace'))
        if len(clean) >= 73:
            texts["sanborn_manuscript"] = clean

    return texts

# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    print("\n" + "=" * 80)
    print("E-AAA-RUNKEY-BIJECTION-08")
    print("Running-key bijection discriminator on keyword-mixed tableaux")
    print("=" * 80)

    triples = generate_triples()
    print(f"\nValid (a1,a2,a3) triples: {len(triples)}")

    # We deduplicate configs independent of variant (variant doesn't affect key_positions)
    configs, n_dups = build_unique_configs(triples)
    print(f"Unique structural configs (trans widths 1-10): {len(configs)} (deduped {n_dups})")

    texts = load_source_texts()
    print(f"\nSource texts:")
    total_chars = 0
    for name in sorted(texts):
        total_chars += len(texts[name])
        print(f"  {name}: {len(texts[name]):,} chars")
    print(f"  Total: {total_chars:,} chars")

    if not HAS_NUMPY:
        print("ERROR: numpy required for tractable runtime. Install via: pip install numpy")
        return

    # ── MAIN SWEEP ──
    t0 = time.time()
    grand_total_checks = 0
    all_survivors = []

    # Precompute PT nums for each alphabet
    PT_NUMS_BY_ALPHA = {}
    for mode_name, mode in TABLEAU_MODES.items():
        PT_NUMS_BY_ALPHA[mode_name] = np.array(
            [mode['idx'][ch] for ch in CRIB_PT_LETTERS], dtype=np.int32)

    for mode_name, mode in TABLEAU_MODES.items():
        mode_t0 = time.time()
        mode_survivors = 0
        mode_checks = 0
        S_idx = mode['idx']
        bottom = mode['bottom']
        pt_nums_S = PT_NUMS_BY_ALPHA[mode_name]

        for text_name in sorted(texts):
            text = texts[text_name]
            # Convert source text to alphabet-indexed nums
            source_nums_S = np.array([S_idx[c] for c in text], dtype=np.int32)

            for direction in ['fwd', 'rev']:
                src_np = source_nums_S if direction == 'fwd' else source_nums_S[::-1].copy()
                n_offsets = max(0, len(src_np) - 72)

                for variant in ['beau', 'vig']:
                    for cfg in configs:
                        kp = cfg['key_positions']
                        max_kp = max(kp)

                        results = check_offsets_numpy(
                            src_np, pt_nums_S, kp, variant, bottom, n_offsets)

                        mode_checks += min(n_offsets, len(src_np) - max_kp)

                        for offset, mono in results:
                            mode_survivors += 1
                            mono_readable = {ALPH[k]: ALPH[v] for k, v in mono.items()}
                            all_survivors.append({
                                'mode': mode_name,
                                'text': text_name,
                                'direction': direction,
                                'offset': offset,
                                'variant': variant,
                                'triple': cfg['triple'],
                                'width': cfg['width'],
                                'n_determined': len(mono),
                                'mono_map': mono_readable,
                            })

        mode_elapsed = time.time() - mode_t0
        grand_total_checks += mode_checks
        print(f"\n  Mode {mode_name:25s}: {mode_survivors} survivors, "
              f"{mode_checks:,} checks, {mode_elapsed:.1f}s")

    elapsed = time.time() - t0

    # ── RESULTS ──
    print("\n" + "=" * 80)
    print("RESULTS")
    print("=" * 80)
    print(f"\nTotal offset checks: {grand_total_checks:,}")
    print(f"Elapsed: {elapsed:.1f}s")
    print(f"Total survivors: {len(all_survivors)}")

    # Per-mode summary
    print(f"\n--- Per-mode survivor counts ---")
    mode_counts = defaultdict(int)
    for s in all_survivors:
        mode_counts[s['mode']] += 1
    for mode_name in TABLEAU_MODES:
        print(f"  {mode_name:25s}: {mode_counts.get(mode_name, 0)}")

    if all_survivors:
        print(f"\nSURVIVORS:")
        print(f"{'Mode':<25s} {'Text':<18s} {'Dir':>4} {'Off':>7} {'Var':>5} "
              f"{'W':>3} {'#M':>4} {'Mono (partial)'}")
        print("-" * 100)
        for s in all_survivors[:50]:
            mono_str = " ".join(f"{k}→{v}" for k, v in sorted(s['mono_map'].items()))
            if len(mono_str) > 25:
                mono_str = mono_str[:22] + "..."
            print(f"{s['mode']:<25s} {s['text']:<18s} {s['direction']:>4} "
                  f"{s['offset']:>7} {s['variant']:>5} {s['width']:>3} "
                  f"{s['n_determined']:>4} {mono_str}")

        # Show key segments for first survivors
        print(f"\n--- Source context for first survivors ---")
        for s in all_survivors[:5]:
            text = texts[s['text']]
            if s['direction'] == 'rev':
                text = text[::-1]
            start = s['offset']
            key73 = text[start:start+73] if start + 73 <= len(text) else text[start:]
            print(f"\n  {s['mode']} | {s['text']} ({s['direction']}) offset={s['offset']} "
                  f"variant={s['variant']} w={s['width']}")
            print(f"  Key 73: {key73}")
            print(f"  Mono: {s['mono_map']}")
    else:
        print("\nZERO SURVIVORS across all modes.")

    # ── VERDICT ──
    print("\n" + "=" * 80)
    print("VERDICT")
    print("=" * 80)

    n_modes = len(TABLEAU_MODES)
    n_texts = len(texts)
    n_configs = len(configs)

    if len(all_survivors) == 0:
        print(f"\nZERO candidates survive mono-bijection across:")
        print(f"  - {n_modes} tableau alphabet modes (5 alphabets × 2 orientations)")
        print(f"  - {n_texts} source texts (fwd + rev = {n_texts*2} orientations)")
        print(f"  - {n_configs} unique structural configs (widths 1-10)")
        print(f"  - Beaufort + Vigenère variants")
        print(f"  - {grand_total_checks:,} total offset checks")
        print(f"\nELIMINATED: Mono + columnar(w1-10) + running-key Beaufort/Vigenère")
        print(f"on keyword-mixed tableaux (AZ, KA, ABSCISSA-mixed, PALIMPSEST-mixed)")
        print(f"with standard AND bottom-chart orientations,")
        print(f"from all tested source texts.")
        print(f"\nThe {len(SAME_CT_PAIRS)} injectivity constraints rejected ALL candidates")
        print(f"under ALL {n_modes} alphabet modes.")
        print(f"\nNOT eliminated: running-key from UNKNOWN sources, or with alphabets")
        print(f"not in {{AZ, KA, ABSCISSA-mixed, PALIMPSEST-mixed}}.")
    else:
        print(f"\n*** {len(all_survivors)} SURVIVORS — INVESTIGATE ***")
        # Check if any mode has survivors that AZ_std doesn't
        az_std_survivors = {(s['text'], s['direction'], s['offset'], s['variant'], s['width'])
                           for s in all_survivors if s['mode'] == 'AZ_std'}
        for mode_name in TABLEAU_MODES:
            if mode_name == 'AZ_std':
                continue
            mode_set = {(s['text'], s['direction'], s['offset'], s['variant'], s['width'])
                        for s in all_survivors if s['mode'] == mode_name}
            novel = mode_set - az_std_survivors
            if novel:
                print(f"\n  {mode_name}: {len(novel)} survivors NOT in AZ_std — NOVEL")

    # Save
    result_path = os.path.join(_ROOT, "results", "e_aaa_runkey_bijection_08.json")
    save_data = {
        'experiment': 'e_aaa_runkey_bijection_08',
        'total_offset_checks': grand_total_checks,
        'elapsed_s': round(elapsed, 2),
        'n_modes': n_modes,
        'n_configs': n_configs,
        'n_texts': n_texts,
        'n_survivors': len(all_survivors),
        'per_mode_survivors': dict(mode_counts),
        'survivors': all_survivors[:200],
    }
    with open(result_path, 'w') as f:
        json.dump(save_data, f, indent=2, default=str)
    print(f"\nResults saved to {result_path}")


if __name__ == "__main__":
    main()
