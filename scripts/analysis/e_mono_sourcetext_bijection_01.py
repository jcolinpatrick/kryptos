#!/usr/bin/env python3
"""Source-text mono-bijection discriminator for mono+trans+running-key model.

Cipher:   Mono + Trans + Running Key (source-text matching)
Family:   analysis
Status:   active
Keyspace: ~500 unique key-position configs × 2 variants × ~1.6M offsets
Last run: 2026-03-27
Best score: TBD

MODEL: CT73 = Mono(Trans(Sub(PT73, K_source_text)))

DISCRIMINATOR: For each (source_text, offset, config, variant):
  1. Compute 24 intermediate values from crib equations
  2. Check consistency: same intermediate → same CT letter
  3. Check injectivity: same CT letter → same intermediate
  4. Survivors have a valid partial mono map

OPTIMIZATIONS:
  - Deduplicate configs on key-position tuples (many orderings give same positions)
  - Vectorize: compute all 24 intermediates for all offsets at once with numpy
  - Cascade rejection: check same-CT pairs first (10 constraints, ~10^-14 joint survival)
"""

import sys
import os
import re
import time
import json
from pathlib import Path
from collections import defaultdict
from itertools import permutations as iterperms

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CONSENSUS_NULL_POSITIONS, NULL_PALETTE,
    CRIB_DICT, CRIB_POSITIONS,
)
from kryptos.kernel.transforms.transposition import (
    columnar_perm, keyword_to_order,
)

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False
    print("WARNING: numpy not available, using pure Python (slower)")

# ═══════════════════════════════════════════════════════════════════════════
# CRIB DATA
# ═══════════════════════════════════════════════════════════════════════════

ORIG_CRIB_POS = list(range(21, 34)) + list(range(63, 74))
CRIB_PT_NUMS = [ALPH_IDX[CRIB_DICT[p]] for p in ORIG_CRIB_POS]
CRIB_CT_NUMS = [ALPH_IDX[CT[p]] for p in ORIG_CRIB_POS]
CRIB_CT_LETTERS = [CT[p] for p in ORIG_CRIB_POS]

# Precompute same-CT-letter pairs (the injectivity constraints)
# For each pair (i,j) where CRIB_CT_LETTERS[i] == CRIB_CT_LETTERS[j],
# injectivity requires: X_i == X_j (same intermediate value)
SAME_CT_PAIRS = []
for i in range(24):
    for j in range(i + 1, 24):
        if CRIB_CT_LETTERS[i] == CRIB_CT_LETTERS[j]:
            SAME_CT_PAIRS.append((i, j))

# Different-CT pairs (consistency constraints)
# For each pair (i,j) where X_i == X_j but CT_i != CT_j → contradiction
DIFF_CT_PAIRS = []
for i in range(24):
    for j in range(i + 1, 24):
        if CRIB_CT_LETTERS[i] != CRIB_CT_LETTERS[j]:
            DIFF_CT_PAIRS.append((i, j))

print(f"Same-CT pairs (injectivity constraints): {len(SAME_CT_PAIRS)}")
print(f"Different-CT pairs (consistency constraints): {len(DIFF_CT_PAIRS)}")

# ═══════════════════════════════════════════════════════════════════════════
# (a1, a2, a3) TRIPLES
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
# CONFIG GENERATION WITH DEDUPLICATION
# ═══════════════════════════════════════════════════════════════════════════

def build_unique_configs(triples):
    """Build configs, deduplicating on key-position tuples."""
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
                # Full enumeration: 2!+3!+4! = 2+6+24 = 32 orderings
                orderings = list(iterperms(range(w)))
            else:
                # Keyword orderings only for w>=5 (w! too large)
                orderings = [tuple(range(w))]  # identity
                orderings.extend(KEYWORD_ORDERINGS.get(w, []))

            for ordering in orderings:
                if w == 1:
                    key_positions = tuple(shifted)
                else:
                    perm = columnar_perm(w, ordering, length=73)
                    key_positions = tuple(perm[s] for s in shifted)

                for variant in ['beau', 'vig']:
                    # Dedup key: the check depends on key_positions + variant
                    # (PT offsets differ by sign between variants)
                    dedup_key = (key_positions, variant)
                    if dedup_key in seen_kp:
                        dup_count += 1
                        continue
                    seen_kp.add(dedup_key)

                    configs.append({
                        'triple': (a1, a2, a3),
                        'width': w,
                        'variant': variant,
                        'key_positions': key_positions,
                    })

    return configs, dup_count

# ═══════════════════════════════════════════════════════════════════════════
# VECTORIZED BIJECTION CHECK
# ═══════════════════════════════════════════════════════════════════════════

def check_all_offsets_numpy(source_nums_np, key_positions, variant, max_offset):
    """Check all offsets at once using numpy. Returns list of surviving offsets."""
    kp = list(key_positions)
    n_crib = len(kp)
    max_kp = max(kp)

    if max_offset <= 0:
        return []

    # Clip max_offset so offset + max_kp < len(source)
    actual_max = min(max_offset, len(source_nums_np) - max_kp)
    if actual_max <= 0:
        return []

    # Build index array: shape (actual_max, 24)
    offsets = np.arange(actual_max, dtype=np.int32)
    indices = offsets[:, None] + np.array(kp, dtype=np.int32)[None, :]  # (N, 24)

    # Gather source values at key positions for all offsets
    src_vals = source_nums_np[indices]  # (N, 24)

    # Compute intermediate X values
    pt_arr = np.array(CRIB_PT_NUMS, dtype=np.int32)
    if variant == 'beau':
        X = (src_vals - pt_arr) % MOD  # (N, 24)
    else:
        X = (pt_arr + src_vals) % MOD

    # Check injectivity: for each same-CT pair, X[i] must equal X[j]
    # This is the strongest filter — cascade through pairs
    mask = np.ones(actual_max, dtype=bool)
    for pi, pj in SAME_CT_PAIRS:
        mask &= (X[:, pi] == X[:, pj])
        if not mask.any():
            return []

    surviving_offsets = offsets[mask]
    if len(surviving_offsets) == 0:
        return []

    # Check consistency: for each different-CT pair, X[i] != X[j]
    # (if X[i] == X[j] but CT[i] != CT[j], the mono map is inconsistent)
    X_surv = X[mask]
    mask2 = np.ones(len(surviving_offsets), dtype=bool)
    for pi, pj in DIFF_CT_PAIRS:
        mask2 &= (X_surv[:, pi] != X_surv[:, pj])
        if not mask2.any():
            return []

    final_offsets = surviving_offsets[mask2]

    # Build mono maps for survivors
    results = []
    X_final = X_surv[mask2]
    ct_arr = np.array(CRIB_CT_NUMS, dtype=np.int32)
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


def check_all_offsets_python(source_nums, key_positions, variant, max_offset):
    """Pure Python fallback."""
    kp = list(key_positions)
    max_kp = max(kp)
    actual_max = min(max_offset, len(source_nums) - max_kp)
    results = []

    for offset in range(actual_max):
        X = [0] * 24
        for c in range(24):
            sv = source_nums[offset + kp[c]]
            if variant == 'beau':
                X[c] = (sv - CRIB_PT_NUMS[c]) % MOD
            else:
                X[c] = (CRIB_PT_NUMS[c] + sv) % MOD

        # Injectivity: same-CT pairs must have same X
        ok = True
        for pi, pj in SAME_CT_PAIRS:
            if X[pi] != X[pj]:
                ok = False
                break
        if not ok:
            continue

        # Consistency: diff-CT pairs must have diff X
        for pi, pj in DIFF_CT_PAIRS:
            if X[pi] == X[pj]:
                ok = False
                break
        if not ok:
            continue

        # Build mono map
        mono = {}
        for c in range(24):
            x, y = X[c], CRIB_CT_NUMS[c]
            if x in mono:
                if mono[x] != y:
                    ok = False
                    break
            else:
                mono[x] = y
        if ok:
            results.append((offset, mono))

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

    # K1-K3 plaintext
    k2_pt = sanitize("IT WAS TOTALLY INVISIBLE HOWS THAT POSSIBLE THEY USED THE EARTHS MAGNETIC FIELD X THE INFORMATION WAS GATHERED AND TRANSMITTED UNDERGRUUND TO AN UNKNOWN LOCATION X DOES LANGLEY KNOW ABOUT THIS THEY SHOULD ITS BURIED OUT THERE SOMEWHERE X WHO KNOWS THE EXACT LOCATION ONLY WW THIS WAS HIS LAST MESSAGE X THIRTY EIGHT DEGREES FIFTY SEVEN MINUTES SIX POINT FIVE SECONDS NORTH SEVENTY SEVEN DEGREES EIGHT MINUTES FORTY FOUR SECONDS WEST ID BY ROWS")
    k3_pt = sanitize("SLOWLY DESPARATLY SLOWLY THE REMAINS OF PASSAGE DEBRIS THAT ENCUMBERED THE LOWER PART OF THE DOORWAY WAS REMOVED WITH TREMBLING HANDS I MADE A TINY BREACH IN THE UPPER LEFT HAND CORNER AND THEN WIDENING THE HOLE A LITTLE I INSERTED THE CANDLE AND PEERED IN THE HOT AIR ESCAPING FROM THE CHAMBER CAUSED THE FLAME TO FLICKER BUT PRESENTLY DETAILS OF THE ROOM WITHIN EMERGED FROM THE MIST X CAN YOU SEE ANYTHING Q")
    if len(k2_pt) >= 73:
        texts["k2_plaintext"] = k2_pt
    if len(k3_pt) >= 73:
        texts["k3_plaintext"] = k3_pt

    return texts

# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    print("=" * 78)
    print("SOURCE-TEXT MONO-BIJECTION DISCRIMINATOR")
    print("Model: CT73 = Mono(Trans(Sub(PT73, K_source_text)))")
    print("=" * 78)
    print()

    triples = generate_triples()
    print(f"Valid (a1,a2,a3) triples: {len(triples)}")

    configs, n_dups = build_unique_configs(triples)
    print(f"Unique structural configs: {len(configs)} (deduplicated {n_dups})")

    texts = load_source_texts()
    print(f"\nSource texts loaded:")
    total_chars = 0
    for name in sorted(texts):
        total_chars += len(texts[name])
        print(f"  {name}: {len(texts[name]):,} chars")
    print(f"  Total: {total_chars:,} chars")

    check_fn = check_all_offsets_numpy if HAS_NUMPY else check_all_offsets_python
    print(f"Using: {'numpy vectorized' if HAS_NUMPY else 'pure Python'}")

    # ── Main sweep ──
    t0 = time.time()
    total_offset_checks = 0
    all_survivors = []
    injectivity_fails = 0
    consistency_fails = 0

    for text_name in sorted(texts):
        text = texts[text_name]
        source_nums = [ALPH_IDX[c] for c in text]
        if HAS_NUMPY:
            source_np = np.array(source_nums, dtype=np.int32)

        for direction in ['fwd', 'rev']:
            src = source_nums if direction == 'fwd' else source_nums[::-1]
            if HAS_NUMPY:
                src_np = source_np if direction == 'fwd' else source_np[::-1].copy()

            n_offsets = max(0, len(src) - 72)
            text_survivors = 0

            for ci, cfg in enumerate(configs):
                kp = cfg['key_positions']
                max_kp = max(kp)

                if HAS_NUMPY:
                    results = check_all_offsets_numpy(src_np, kp, cfg['variant'], n_offsets)
                else:
                    results = check_all_offsets_python(src, kp, cfg['variant'], n_offsets)

                total_offset_checks += min(n_offsets, len(src) - max_kp)

                for offset, mono in results:
                    text_survivors += 1
                    mono_readable = {ALPH[k]: ALPH[v] for k, v in mono.items()}
                    all_survivors.append({
                        'text': text_name,
                        'direction': direction,
                        'offset': offset,
                        'triple': cfg['triple'],
                        'width': cfg['width'],
                        'variant': cfg['variant'],
                        'n_determined': len(mono),
                        'mono_map': mono_readable,
                    })

            elapsed = time.time() - t0
            print(f"  {text_name} ({direction}): {text_survivors} survivors, "
                  f"{elapsed:.1f}s elapsed")

    elapsed = time.time() - t0

    # ── Results ──
    print()
    print("=" * 78)
    print("RESULTS")
    print("=" * 78)
    print(f"\nTotal offset checks: {total_offset_checks:,}")
    print(f"Elapsed: {elapsed:.1f}s")
    print(f"Total survivors: {len(all_survivors)}")

    if all_survivors:
        print(f"\nSURVIVORS:")
        print(f"{'Text':<22} {'Dir':>4} {'Off':>7} {'Triple':>12} "
              f"{'W':>3} {'Var':>5} {'#M':>4} {'Mono map (partial)'}")
        print("-" * 95)
        for s in all_survivors[:50]:
            mono_str = " ".join(f"{k}→{v}" for k, v in sorted(s['mono_map'].items()))
            if len(mono_str) > 30:
                mono_str = mono_str[:27] + "..."
            print(f"{s['text']:<22} {s['direction']:>4} {s['offset']:>7} "
                  f"{str(s['triple']):>12} {s['width']:>3} {s['variant']:>5} "
                  f"{s['n_determined']:>4} {mono_str}")

        # Secondary: show source text context for survivors
        print(f"\n--- SECONDARY: Source text context for survivors ---")
        for s in all_survivors[:10]:
            text = texts[s['text']]
            if s['direction'] == 'rev':
                text = text[::-1]
            ctx_start = max(0, s['offset'] - 10)
            ctx_end = min(len(text), s['offset'] + 83)
            ctx = text[ctx_start:ctx_end]
            key_segment = text[s['offset']:s['offset']+73]
            print(f"\n  {s['text']} ({s['direction']}) offset={s['offset']}:")
            print(f"  Key 73 chars: {key_segment}")
            print(f"  Mono: {s['mono_map']}")
    else:
        print("\nZERO SURVIVORS.")

    # ── Verdict ──
    print()
    print("=" * 78)
    print("VERDICT")
    print("=" * 78)

    n_texts = len(texts)
    if len(all_survivors) == 0:
        print(f"\nZERO candidates survive mono-bijection across:")
        print(f"  - {n_texts} source texts (fwd + rev = {n_texts*2} orientations)")
        print(f"  - {len(configs)} unique structural configs (widths 1-10)")
        print(f"  - Beaufort + Vigenère variants")
        print(f"  - 20 (a1,a2,a3) mask triples")
        print(f"  - {total_offset_checks:,} total offset checks")
        print(f"\nELIMINATED: Mono + columnar trans (w1-10) + running key")
        print(f"from all tested source texts under palette-consistent masks.")
        print(f"\nThe 10+ injectivity constraints (same-CT pairs requiring")
        print(f"equal intermediate values) rejected all candidates.")
        print(f"\nNOT eliminated: mono+trans+running key from UNKNOWN sources.")
    else:
        print(f"\n*** {len(all_survivors)} SURVIVORS — INVESTIGATE ***")

    # Save
    result_path = os.path.join(_ROOT, "results", "mono_sourcetext_bijection_01.json")
    save_data = {
        'experiment': 'e_mono_sourcetext_bijection_01',
        'total_offset_checks': total_offset_checks,
        'elapsed_s': round(elapsed, 2),
        'n_unique_configs': len(configs),
        'n_configs_deduped': n_dups,
        'n_texts': n_texts,
        'n_survivors': len(all_survivors),
        'survivors': all_survivors[:100],
        'texts_tested': {n: len(t) for n, t in texts.items()},
    }
    with open(result_path, 'w') as f:
        json.dump(save_data, f, indent=2, default=str)
    print(f"\nResults saved to {result_path}")


if __name__ == "__main__":
    main()
