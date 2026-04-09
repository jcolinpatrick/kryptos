#!/usr/bin/env python3
"""
Cipher: mono_trans_runkey
Family: archive_evidence
Status: exhausted
Keyspace: 1385 configs × 10 modes × 2 variants × 11 texts × 2 dirs
Last run:
Best score:
"""
"""E-AAA-RUNKEY-BIJECTION-08c: Batched running-key bijection on mixed tableaux.

Same hypothesis as 08b but with batched numpy operations for tractable runtime.

Key optimization: for each (text, direction, mode, variant), we check ALL
transposition configs simultaneously by building a 3D index array:
  indices[config_c, offset_o, crib_i] = offset_o + key_positions[config_c][crib_i]
Then compute X in one shot and apply vectorized injectivity checks.

This reduces 1,385 × numpy-calls to 1 × big-numpy-call per text-direction-mode-variant.
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
# SETUP (same as 08b)
# ═══════════════════════════════════════════════════════════════════════════

TABLEAU_MODES = {}
def add_mode(name, alpha_seq, bottom=False):
    TABLEAU_MODES[name] = {
        'seq': alpha_seq,
        'idx': {ch: i for i, ch in enumerate(alpha_seq)},
        'bottom': bottom,
    }

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

ORIG_CRIB_POS = list(range(21, 34)) + list(range(63, 74))
CRIB_PT_LETTERS = [CRIB_DICT[p] for p in ORIG_CRIB_POS]
CRIB_CT_LETTERS = [CT[p] for p in ORIG_CRIB_POS]
CRIB_CT_NUMS = np.array([ALPH_IDX[c] for c in CRIB_CT_LETTERS], dtype=np.int32)

SAME_CT_PAIRS = [(i, j) for i in range(24) for j in range(i+1, 24)
                 if CRIB_CT_LETTERS[i] == CRIB_CT_LETTERS[j]]
DIFF_CT_PAIRS = [(i, j) for i in range(24) for j in range(i+1, 24)
                 if CRIB_CT_LETTERS[i] != CRIB_CT_LETTERS[j]]

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
    return list(range(21 - n1, 21 - n1 + 13)) + list(range(63 - n12, 63 - n12 + 11))

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
            if len(c) >= 73: texts[name] = c
    k2 = sanitize("IT WAS TOTALLY INVISIBLE HOWS THAT POSSIBLE THEY USED THE EARTHS MAGNETIC FIELD X THE INFORMATION WAS GATHERED AND TRANSMITTED UNDERGRUUND TO AN UNKNOWN LOCATION X DOES LANGLEY KNOW ABOUT THIS THEY SHOULD ITS BURIED OUT THERE SOMEWHERE X WHO KNOWS THE EXACT LOCATION ONLY WW THIS WAS HIS LAST MESSAGE X THIRTY EIGHT DEGREES FIFTY SEVEN MINUTES SIX POINT FIVE SECONDS NORTH SEVENTY SEVEN DEGREES EIGHT MINUTES FORTY FOUR SECONDS WEST ID BY ROWS")
    k3 = sanitize("SLOWLY DESPARATLY SLOWLY THE REMAINS OF PASSAGE DEBRIS THAT ENCUMBERED THE LOWER PART OF THE DOORWAY WAS REMOVED WITH TREMBLING HANDS I MADE A TINY BREACH IN THE UPPER LEFT HAND CORNER AND THEN WIDENING THE HOLE A LITTLE I INSERTED THE CANDLE AND PEERED IN THE HOT AIR ESCAPING FROM THE CHAMBER CAUSED THE FLAME TO FLICKER BUT PRESENTLY DETAILS OF THE ROOM WITHIN EMERGED FROM THE MIST X CAN YOU SEE ANYTHING Q")
    if len(k2) >= 73: texts["k2_plaintext"] = k2
    if len(k3) >= 73: texts["k3_plaintext"] = k3
    ap = ref / "smithsonian_archive.md"
    if ap.exists():
        c = sanitize(ap.read_text(errors='replace'))
        if len(c) >= 73: texts["sanborn_manuscript"] = c
    return texts

# ═══════════════════════════════════════════════════════════════════════════
# BUILD ALL KEY-POSITION SETS
# ═══════════════════════════════════════════════════════════════════════════

def build_all_configs(triples):
    """Build all unique key-position tuples (width 1-10)."""
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
                    kp = tuple(sh)
                else:
                    perm = columnar_perm(w, ordering, length=73)
                    kp = tuple(perm[s] for s in sh)
                if kp not in seen_kp:
                    seen_kp.add(kp)
                    configs.append({'triple': (a1,a2,a3), 'width': w, 'kp': kp})
    return configs

# ═══════════════════════════════════════════════════════════════════════════
# BATCHED BIJECTION CHECK
# ═══════════════════════════════════════════════════════════════════════════

def batched_check(src_S, pt_S, all_kp, variant, bottom, chunk_size=200):
    """Check ALL configs × ALL offsets for one (source, mode, variant).

    Process configs in chunks to manage memory.
    Returns list of (config_idx, offset, mono_map) survivors.
    """
    n_src = len(src_S)
    survivors = []

    for chunk_start in range(0, len(all_kp), chunk_size):
        chunk_kp = all_kp[chunk_start:chunk_start + chunk_size]
        n_configs = len(chunk_kp)

        pt_arr = np.array(pt_S, dtype=np.int32)

        for ci, kp in enumerate(chunk_kp):
            max_kp_this = max(kp)
            actual_n = n_src - max_kp_this
            if actual_n <= 0:
                continue

            kp_arr = np.array(kp, dtype=np.int32)
            offs = np.arange(actual_n, dtype=np.int32)
            idx = offs[:, None] + kp_arr[None, :]  # (actual_n, 24)
            sv = src_S[idx]  # (actual_n, 24)

            if bottom:
                sv = (25 - sv) % MOD

            if variant == 'beau':
                X = (sv - pt_arr) % MOD
            else:
                X = (pt_arr + sv) % MOD

            # Injectivity cascade
            mask = np.ones(actual_n, dtype=bool)
            for pi, pj in SAME_CT_PAIRS:
                mask &= (X[:, pi] == X[:, pj])
                if not mask.any():
                    break

            if not mask.any():
                continue

            surv_offs = offs[mask]
            X_s = X[mask]

            # Consistency cascade
            mask2 = np.ones(len(surv_offs), dtype=bool)
            for pi, pj in DIFF_CT_PAIRS:
                mask2 &= (X_s[:, pi] != X_s[:, pj])
                if not mask2.any():
                    break

            if not mask2.any():
                continue

            final = surv_offs[mask2]
            X_f = X_s[mask2]

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
                    real_ci = chunk_start + ci
                    survivors.append((real_ci, int(final[i]),
                                     {ALPH[k]: ALPH[v] for k, v in mono.items()}))

    return survivors

# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    print("=" * 80)
    print("E-AAA-RUNKEY-BIJECTION-08c: Batched bijection on mixed tableaux")
    print("=" * 80)

    triples = gen_triples()
    texts = load_texts()
    configs = build_all_configs(triples)
    all_kp = [cfg['kp'] for cfg in configs]

    print(f"\nTriples: {len(triples)}, Configs: {len(configs)}, "
          f"Texts: {len(texts)}, Modes: {len(TABLEAU_MODES)}")
    print(f"Total source chars: {sum(len(t) for t in texts.values()):,}")
    print(f"Estimated total checks: ~{len(configs) * sum(len(t) for t in texts.values()) * 2 * 2 * len(TABLEAU_MODES):,}")

    t0 = time.time()
    all_survivors = []
    total_checks = 0

    for mode_name, mode in TABLEAU_MODES.items():
        mode_t0 = time.time()
        mode_surv = 0
        S_idx = mode['idx']
        bottom = mode['bottom']
        pt_S = [S_idx[ch] for ch in CRIB_PT_LETTERS]

        for text_name in sorted(texts):
            text = texts[text_name]
            src_nums = np.array([S_idx[c] for c in text], dtype=np.int32)

            for direction in ['fwd', 'rev']:
                src = src_nums if direction == 'fwd' else src_nums[::-1].copy()

                for variant in ['beau', 'vig']:
                    results = batched_check(src, pt_S, all_kp, variant, bottom)

                    # Count checks (approximate)
                    for kp in all_kp:
                        mx = max(kp)
                        if len(src) > mx:
                            total_checks += len(src) - mx

                    for ci, off, mono in results:
                        mode_surv += 1
                        cfg = configs[ci]
                        all_survivors.append({
                            'mode': mode_name, 'text': text_name,
                            'direction': direction, 'offset': off,
                            'variant': variant, 'triple': cfg['triple'],
                            'width': cfg['width'], 'mono_map': mono,
                        })

        elapsed = time.time() - mode_t0
        cum = time.time() - t0
        print(f"  {mode_name:25s}: {mode_surv} survivors  "
              f"({elapsed:.0f}s mode, {cum:.0f}s cumulative)")

    total_time = time.time() - t0

    # ── RESULTS ──
    print("\n" + "=" * 80)
    print("RESULTS")
    print("=" * 80)
    print(f"\nTotal time: {total_time:.1f}s ({total_time/3600:.1f}h)")
    print(f"Total survivors: {len(all_survivors)}")

    mode_counts = defaultdict(int)
    for s in all_survivors:
        mode_counts[s['mode']] += 1
    print(f"\n--- Per-mode ---")
    for mn in TABLEAU_MODES:
        print(f"  {mn:25s}: {mode_counts.get(mn, 0)}")

    if all_survivors:
        print(f"\nSURVIVORS:")
        for s in all_survivors[:30]:
            mono_str = " ".join(f"{k}→{v}" for k,v in sorted(s['mono_map'].items()))[:30]
            print(f"  {s['mode']:25s} {s['text']:18s} {s['direction']:4s} "
                  f"off={s['offset']:>6} {s['variant']:5s} w={s['width']} {mono_str}")

        # Novel analysis
        az_set = {(s['text'],s['direction'],s['offset'],s['variant'],s['width'])
                  for s in all_survivors if s['mode']=='AZ_std'}
        for mn in TABLEAU_MODES:
            if mn == 'AZ_std': continue
            ms = {(s['text'],s['direction'],s['offset'],s['variant'],s['width'])
                  for s in all_survivors if s['mode']==mn}
            novel = ms - az_set
            if novel:
                print(f"\n  *** {mn}: {len(novel)} NOVEL survivors ***")
    else:
        print("\nZERO SURVIVORS across all modes.")

    # ── VERDICT ──
    print("\n" + "=" * 80)
    print("VERDICT")
    print("=" * 80)
    if len(all_survivors) == 0:
        print(f"\nELIMINATED: Mono + columnar(w1-10) + running-key Beaufort/Vigenère")
        print(f"on tableaux {{AZ, KA, ABSCISSA-mixed, PALIMPSEST-mixed}} × {{std, bottom}}")
        print(f"from {len(texts)} source texts × 2 directions.")
        print(f"{len(configs)} structural configs × {len(TABLEAU_MODES)} modes tested.")
        print(f"\nNOT eliminated: unknown source texts, untested tableau alphabets.")
    else:
        print(f"\n*** {len(all_survivors)} SURVIVORS — INVESTIGATE ***")

    rp = os.path.join(_ROOT, "results", "e_aaa_runkey_bijection_08c.json")
    json.dump({
        'experiment': 'e_aaa_runkey_bijection_08c',
        'total_time_s': round(total_time, 2),
        'n_modes': len(TABLEAU_MODES),
        'n_configs': len(configs),
        'n_texts': len(texts),
        'n_survivors': len(all_survivors),
        'per_mode': dict(mode_counts),
        'survivors': all_survivors[:200],
    }, open(rp, 'w'), indent=2, default=str)
    print(f"\nSaved to {rp}")

if __name__ == "__main__":
    main()
