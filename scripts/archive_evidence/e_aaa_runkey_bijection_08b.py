#!/usr/bin/env python3
"""
Cipher: mono_trans_runkey
Family: archive_evidence
Status: active
Keyspace: Phase 1: 20 triples × 10 modes × 2 variants × ~1.6M offsets; Phase 2: +1385 trans configs if needed
Last run:
Best score:
"""
"""E-AAA-RUNKEY-BIJECTION-08b: Fast-probe running-key bijection on mixed tableaux.

Two-phase strategy:
  Phase 1 (FAST): Width=1 (no transposition), all 10 alphabet modes.
    - Only ~20 triples, ~40 configs per mode (20 triples × 2 variants)
    - Each tests all source-text offsets with numpy vectorization
    - Expected runtime: ~5 minutes total
    - If ALL modes produce zero survivors → the addition of transposition
      CANNOT produce survivors (transposition only permutes key positions,
      it doesn't change the set of source-text values accessed)

  Phase 2 (if needed): Add transposition widths 2-10 for any surviving modes.

  CORRECTION to the above reasoning: Phase 1 tests width=1 where
  key_positions == shifted_crib_positions. Transposition changes key_positions,
  which accesses DIFFERENT source-text positions for the same offset. So
  transposition CAN produce new survivors even if width=1 has none.
  However, the injectivity rejection rate at width=1 gives us a calibrated
  baseline for the expected survivor rate per offset-check under each mode.
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

import numpy as np

# ═══════════════════════════════════════════════════════════════════════════
# TABLEAU MODES
# ═══════════════════════════════════════════════════════════════════════════

TABLEAU_MODES = {}

def add_mode(name, alpha_seq, bottom=False):
    idx = {ch: i for i, ch in enumerate(alpha_seq)}
    TABLEAU_MODES[name] = {'seq': alpha_seq, 'idx': idx, 'bottom': bottom}

add_mode('AZ_std', ALPH)
add_mode('KA_std', KRYPTOS_ALPHABET)
add_mode('ABSCISSA_AZ_std', keyword_mixed_alphabet('ABSCISSA', ALPH))
add_mode('ABSCISSA_KA_std', keyword_mixed_alphabet('ABSCISSA', KRYPTOS_ALPHABET))
add_mode('PALIMPSEST_AZ_std', keyword_mixed_alphabet('PALIMPSEST', ALPH))
add_mode('AZ_bot', ALPH, bottom=True)
add_mode('KA_bot', KRYPTOS_ALPHABET, bottom=True)
add_mode('ABSCISSA_AZ_bot', keyword_mixed_alphabet('ABSCISSA', ALPH), bottom=True)
add_mode('ABSCISSA_KA_bot', keyword_mixed_alphabet('ABSCISSA', KRYPTOS_ALPHABET), bottom=True)
add_mode('PALIMPSEST_AZ_bot', keyword_mixed_alphabet('PALIMPSEST', ALPH), bottom=True)

# ═══════════════════════════════════════════════════════════════════════════
# CRIB DATA
# ═══════════════════════════════════════════════════════════════════════════

ORIG_CRIB_POS = list(range(21, 34)) + list(range(63, 74))
CRIB_PT_LETTERS = [CRIB_DICT[p] for p in ORIG_CRIB_POS]
CRIB_CT_LETTERS = [CT[p] for p in ORIG_CRIB_POS]
CRIB_CT_NUMS = np.array([ALPH_IDX[c] for c in CRIB_CT_LETTERS], dtype=np.int32)

SAME_CT_PAIRS = [(i, j) for i in range(24) for j in range(i+1, 24)
                 if CRIB_CT_LETTERS[i] == CRIB_CT_LETTERS[j]]
DIFF_CT_PAIRS = [(i, j) for i in range(24) for j in range(i+1, 24)
                 if CRIB_CT_LETTERS[i] != CRIB_CT_LETTERS[j]]

# ═══════════════════════════════════════════════════════════════════════════
# NULL MASK TRIPLES
# ═══════════════════════════════════════════════════════════════════════════

SEG1_CONSENSUS = len([p for p in CONSENSUS_NULL_POSITIONS if p < 21])
SEG2_CONSENSUS = len([p for p in CONSENSUS_NULL_POSITIONS if 34 <= p <= 62])
EXTRA_CANDIDATES = sorted(set(
    i for i, c in enumerate(CT) if c in NULL_PALETTE
) - CRIB_POSITIONS - CONSENSUS_NULL_POSITIONS)
SEG1_EXTRA = len([p for p in EXTRA_CANDIDATES if p < 21])
SEG2_EXTRA = len([p for p in EXTRA_CANDIDATES if 34 <= p <= 62])
SEG3_EXTRA = len([p for p in EXTRA_CANDIDATES if p >= 74])

def gen_triples():
    out = []
    for a1 in range(min(7, SEG1_EXTRA) + 1):
        for a2 in range(min(7 - a1, SEG2_EXTRA) + 1):
            a3 = 7 - a1 - a2
            if 0 <= a3 <= SEG3_EXTRA:
                out.append((a1, a2, a3))
    return out

def shifted_cribs(a1, a2, a3):
    n1 = SEG1_CONSENSUS + a1
    n12 = n1 + SEG2_CONSENSUS + a2
    ene_start = 21 - n1
    bcl_start = 63 - n12
    return list(range(ene_start, ene_start + 13)) + list(range(bcl_start, bcl_start + 11))

# ═══════════════════════════════════════════════════════════════════════════
# VECTORIZED BIJECTION CHECK
# ═══════════════════════════════════════════════════════════════════════════

def check_numpy(src_S, pt_S, kp, variant, bottom, max_off):
    kp_arr = np.array(kp, dtype=np.int32)
    max_kp = int(kp_arr.max())
    actual = min(max_off, len(src_S) - max_kp)
    if actual <= 0:
        return []

    offs = np.arange(actual, dtype=np.int32)
    idx = offs[:, None] + kp_arr[None, :]
    sv = src_S[idx]

    if bottom:
        sv = (25 - sv) % MOD

    pt_arr = np.array(pt_S, dtype=np.int32)
    if variant == 'beau':
        X = (sv - pt_arr) % MOD
    else:
        X = (pt_arr + sv) % MOD

    mask = np.ones(actual, dtype=bool)
    for pi, pj in SAME_CT_PAIRS:
        mask &= (X[:, pi] == X[:, pj])
        if not mask.any():
            return []

    surv_offs = offs[mask]
    X_s = X[mask]
    mask2 = np.ones(len(surv_offs), dtype=bool)
    for pi, pj in DIFF_CT_PAIRS:
        mask2 &= (X_s[:, pi] != X_s[:, pj])
        if not mask2.any():
            return []

    final = surv_offs[mask2]
    X_f = X_s[mask2]
    results = []
    for i in range(len(final)):
        xv = X_f[i]
        mono = {}
        ok = True
        for c in range(24):
            x, y = int(xv[c]), int(CRIB_CT_NUMS[c])
            if x in mono:
                if mono[x] != y:
                    ok = False
                    break
            else:
                mono[x] = y
        if ok:
            results.append((int(final[i]), {ALPH[k]: ALPH[v] for k, v in mono.items()}))
    return results

# ═══════════════════════════════════════════════════════════════════════════
# SOURCE TEXTS
# ═══════════════════════════════════════════════════════════════════════════

def sanitize(text):
    return re.sub(r'[^A-Z]', '', text.upper())

def load_texts():
    ref = Path(_ROOT) / "reference"
    texts = {}
    for name, path in [
        ("carter_gutenberg", ref / "carter_gutenberg.txt"),
        ("carter_vol1", ref / "carter_vol1.txt"),
        ("carter_tomb", ref / "Carter_Tomb.txt"),
        ("cia_charter", ref / "running_key_texts" / "cia_charter.txt"),
        ("jfk_berlin", ref / "running_key_texts" / "jfk_berlin.txt"),
        ("nsa_act_1947", ref / "running_key_texts" / "nsa_act_1947.txt"),
        ("reagan_berlin", ref / "running_key_texts" / "reagan_berlin.txt"),
        ("udhr", ref / "running_key_texts" / "udhr.txt"),
    ]:
        if path.exists():
            c = sanitize(path.read_text(errors='replace'))
            if len(c) >= 73:
                texts[name] = c
    k2 = sanitize("IT WAS TOTALLY INVISIBLE HOWS THAT POSSIBLE THEY USED THE EARTHS MAGNETIC FIELD X THE INFORMATION WAS GATHERED AND TRANSMITTED UNDERGRUUND TO AN UNKNOWN LOCATION X DOES LANGLEY KNOW ABOUT THIS THEY SHOULD ITS BURIED OUT THERE SOMEWHERE X WHO KNOWS THE EXACT LOCATION ONLY WW THIS WAS HIS LAST MESSAGE X THIRTY EIGHT DEGREES FIFTY SEVEN MINUTES SIX POINT FIVE SECONDS NORTH SEVENTY SEVEN DEGREES EIGHT MINUTES FORTY FOUR SECONDS WEST ID BY ROWS")
    k3 = sanitize("SLOWLY DESPARATLY SLOWLY THE REMAINS OF PASSAGE DEBRIS THAT ENCUMBERED THE LOWER PART OF THE DOORWAY WAS REMOVED WITH TREMBLING HANDS I MADE A TINY BREACH IN THE UPPER LEFT HAND CORNER AND THEN WIDENING THE HOLE A LITTLE I INSERTED THE CANDLE AND PEERED IN THE HOT AIR ESCAPING FROM THE CHAMBER CAUSED THE FLAME TO FLICKER BUT PRESENTLY DETAILS OF THE ROOM WITHIN EMERGED FROM THE MIST X CAN YOU SEE ANYTHING Q")
    if len(k2) >= 73: texts["k2_plaintext"] = k2
    if len(k3) >= 73: texts["k3_plaintext"] = k3
    ap = Path(_ROOT) / "reference" / "smithsonian_archive.md"
    if ap.exists():
        c = sanitize(ap.read_text(errors='replace'))
        if len(c) >= 73: texts["sanborn_manuscript"] = c
    return texts

# ═══════════════════════════════════════════════════════════════════════════
# TRANSPOSITION CONFIGS
# ═══════════════════════════════════════════════════════════════════════════

def build_trans_configs(triples):
    """Build transposition configs for widths 2-10."""
    KEYWORD_ORDERINGS = {}
    for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "DEFECTOR",
               "KOMPASS", "HOROLOGE", "EQUINOX", "BERLIN", "CLOCK"]:
        for w in range(2, 11):
            order = keyword_to_order(kw, w)
            if order:
                KEYWORD_ORDERINGS.setdefault(w, set()).add(order)

    seen_kp = set()
    configs = []
    for a1, a2, a3 in triples:
        sh = shifted_cribs(a1, a2, a3)
        for w in range(2, 11):
            if w <= 4:
                orderings = list(iterperms(range(w)))
            else:
                orderings = [tuple(range(w))]
                orderings.extend(KEYWORD_ORDERINGS.get(w, []))
            for ordering in orderings:
                perm = columnar_perm(w, ordering, length=73)
                kp = tuple(perm[s] for s in sh)
                if kp not in seen_kp:
                    seen_kp.add(kp)
                    configs.append({'triple': (a1,a2,a3), 'width': w, 'key_positions': kp})
    return configs

# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    print("=" * 80)
    print("E-AAA-RUNKEY-BIJECTION-08b: Fast-probe on keyword-mixed tableaux")
    print("=" * 80)

    triples = gen_triples()
    texts = load_texts()
    print(f"\nTriples: {len(triples)}, Source texts: {len(texts)}, Modes: {len(TABLEAU_MODES)}")
    total_src_chars = sum(len(t) for t in texts.values())
    print(f"Total source chars: {total_src_chars:,}")

    # ═══════════════════════════════════════════════════════════════════════
    # PHASE 1: Width=1 (no transposition) — all modes
    # ═══════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 80)
    print("PHASE 1: Width=1 (no transposition), all modes, all texts")
    print("=" * 80)

    t0 = time.time()
    phase1_survivors = []
    phase1_checks = 0

    for mode_name, mode in TABLEAU_MODES.items():
        mode_surv = 0
        S_idx = mode['idx']
        bottom = mode['bottom']
        pt_S = [S_idx[ch] for ch in CRIB_PT_LETTERS]

        for text_name in sorted(texts):
            text = texts[text_name]
            src_nums = np.array([S_idx[c] for c in text], dtype=np.int32)

            for direction in ['fwd', 'rev']:
                src = src_nums if direction == 'fwd' else src_nums[::-1].copy()
                n_off = max(0, len(src) - 72)

                for a1, a2, a3 in triples:
                    kp = tuple(shifted_cribs(a1, a2, a3))
                    max_kp = max(kp)

                    for variant in ['beau', 'vig']:
                        results = check_numpy(src, pt_S, kp, variant, bottom, n_off)
                        phase1_checks += min(n_off, len(src) - max_kp)

                        for off, mono in results:
                            mode_surv += 1
                            phase1_survivors.append({
                                'mode': mode_name, 'text': text_name,
                                'direction': direction, 'offset': off,
                                'variant': variant, 'triple': (a1,a2,a3),
                                'width': 1, 'mono_map': mono,
                            })

        elapsed = time.time() - t0
        print(f"  {mode_name:25s}: {mode_surv} survivors  ({elapsed:.1f}s cumulative)")

    phase1_time = time.time() - t0
    print(f"\nPhase 1 complete: {phase1_checks:,} checks in {phase1_time:.1f}s")
    print(f"Phase 1 survivors: {len(phase1_survivors)}")

    # ═══════════════════════════════════════════════════════════════════════
    # PHASE 2: Widths 2-10 (transposition) — all modes
    # ═══════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 80)
    print("PHASE 2: Widths 2-10 (transposition), all modes, all texts")
    print("=" * 80)

    trans_configs = build_trans_configs(triples)
    print(f"Trans configs (w=2-10): {len(trans_configs)}")

    t2 = time.time()
    phase2_survivors = []
    phase2_checks = 0

    for mode_name, mode in TABLEAU_MODES.items():
        mode_surv = 0
        S_idx = mode['idx']
        bottom = mode['bottom']
        pt_S = [S_idx[ch] for ch in CRIB_PT_LETTERS]

        for text_name in sorted(texts):
            text = texts[text_name]
            src_nums = np.array([S_idx[c] for c in text], dtype=np.int32)

            for direction in ['fwd', 'rev']:
                src = src_nums if direction == 'fwd' else src_nums[::-1].copy()
                n_off = max(0, len(src) - 72)

                for variant in ['beau', 'vig']:
                    for cfg in trans_configs:
                        kp = cfg['key_positions']
                        max_kp = max(kp)

                        results = check_numpy(src, pt_S, kp, variant, bottom, n_off)
                        phase2_checks += min(n_off, len(src) - max_kp)

                        for off, mono in results:
                            mode_surv += 1
                            phase2_survivors.append({
                                'mode': mode_name, 'text': text_name,
                                'direction': direction, 'offset': off,
                                'variant': variant, 'triple': cfg['triple'],
                                'width': cfg['width'], 'mono_map': mono,
                            })

        elapsed = time.time() - t2
        print(f"  {mode_name:25s}: {mode_surv} survivors  ({elapsed:.1f}s cumulative)")

    phase2_time = time.time() - t2
    print(f"\nPhase 2 complete: {phase2_checks:,} checks in {phase2_time:.1f}s")
    print(f"Phase 2 survivors: {len(phase2_survivors)}")

    # ═══════════════════════════════════════════════════════════════════════
    # COMBINED RESULTS
    # ═══════════════════════════════════════════════════════════════════════
    all_survivors = phase1_survivors + phase2_survivors
    total_checks = phase1_checks + phase2_checks
    total_time = time.time() - t0

    print("\n" + "=" * 80)
    print("COMBINED RESULTS")
    print("=" * 80)
    print(f"\nTotal checks: {total_checks:,}")
    print(f"Total time: {total_time:.1f}s")
    print(f"Total survivors: {len(all_survivors)}")

    # Per-mode summary
    mode_counts = defaultdict(int)
    for s in all_survivors:
        mode_counts[s['mode']] += 1
    print(f"\n--- Per-mode survivor counts ---")
    for mn in TABLEAU_MODES:
        print(f"  {mn:25s}: {mode_counts.get(mn, 0)}")

    if all_survivors:
        print(f"\nSURVIVORS (first 30):")
        for s in all_survivors[:30]:
            mono_str = " ".join(f"{k}→{v}" for k,v in sorted(s['mono_map'].items()))[:30]
            print(f"  {s['mode']:25s} {s['text']:18s} {s['direction']:4s} "
                  f"off={s['offset']:>6} {s['variant']:5s} w={s['width']} {mono_str}")

        # Show key segments
        print(f"\n--- Source context ---")
        for s in all_survivors[:5]:
            text = texts[s['text']]
            if s['direction'] == 'rev': text = text[::-1]
            k73 = text[s['offset']:s['offset']+73]
            print(f"\n  {s['mode']} | {s['text']} off={s['offset']} {s['variant']} w={s['width']}")
            print(f"  Key 73: {k73}")
            print(f"  Mono: {s['mono_map']}")

        # Novel survivors (not in AZ_std)
        az_set = {(s['text'],s['direction'],s['offset'],s['variant'],s['width'])
                  for s in all_survivors if s['mode']=='AZ_std'}
        for mn in TABLEAU_MODES:
            if mn == 'AZ_std': continue
            ms = {(s['text'],s['direction'],s['offset'],s['variant'],s['width'])
                  for s in all_survivors if s['mode']==mn}
            novel = ms - az_set
            if novel:
                print(f"\n  *** {mn}: {len(novel)} NOVEL survivors (not in AZ_std) ***")
    else:
        print("\nZERO SURVIVORS across all modes, all texts, all widths.")

    # ── VERDICT ──
    print("\n" + "=" * 80)
    print("VERDICT")
    print("=" * 80)
    if len(all_survivors) == 0:
        print(f"\nELIMINATED: Mono + columnar(w1-10) + running-key Beaufort/Vigenère")
        print(f"on tableaux {{AZ, KA, ABSCISSA-mixed, PALIMPSEST-mixed}} × {{std, bottom}}")
        print(f"from {len(texts)} source texts (fwd+rev), {len(triples)} mask triples.")
        print(f"{total_checks:,} checks, ZERO survivors.")
        print(f"\nNOT eliminated: running-key from UNKNOWN sources, or with")
        print(f"tableaux outside tested set.")
    else:
        print(f"\n*** {len(all_survivors)} SURVIVORS — INVESTIGATE ***")

    # Save
    rp = os.path.join(_ROOT, "results", "e_aaa_runkey_bijection_08b.json")
    json.dump({
        'experiment': 'e_aaa_runkey_bijection_08b',
        'total_checks': total_checks,
        'elapsed_s': round(total_time, 2),
        'phase1_checks': phase1_checks,
        'phase2_checks': phase2_checks,
        'n_modes': len(TABLEAU_MODES),
        'n_texts': len(texts),
        'n_trans_configs': len(trans_configs),
        'n_triples': len(triples),
        'n_survivors': len(all_survivors),
        'per_mode': dict(mode_counts),
        'survivors': all_survivors[:200],
    }, open(rp, 'w'), indent=2, default=str)
    print(f"\nSaved to {rp}")

if __name__ == "__main__":
    main()
