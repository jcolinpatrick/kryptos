#!/usr/bin/env python3
"""Running-key cipher attack on 73-char null-extracted K4 text.

Cipher: Running key (Beaufort + Vigenere)
Family: campaigns
Status: active
Keyspace: ~50M (sources x offsets x variants x alphabets x trans)
Last run: never
Best score: N/A

THREE attack modes:
1. Exhaustive crib-drag: For each (source, offset, variant, alphabet, trans),
   derive the required key at shifted crib positions and check if any contiguous
   passage in the source matches enough positions.
2. Griffin-style beam search: Position-by-position beam decoder using quadgram
   scores to find the best running-key passage (not limited to known sources).
3. Full-source sweep: Try every possible offset for each source text.

Uses 73-char null-extracted text with USER_MASK (consensus 17 + best 7).
Also tests with col7 transposition applied first.

Running key: CT[i] = f(PT[i], KEY[i]) where KEY is a passage from a known text.
Beaufort: PT[i] = (KEY[i] - CT[i]) mod 26
Vigenere: PT[i] = (CT[i] - KEY[i]) mod 26
VarBeau:  PT[i] = (KEY[i] + CT[i]) mod 26  (actually: P = K-C for Beau, P = C-K for Vig)
"""
import sys, os, re, time, json, math
from pathlib import Path
from multiprocessing import Pool, cpu_count
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))
from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, ALPH, MOD, ALPH_IDX, KRYPTOS_ALPHABET

# === CONSTANTS ===
CT97 = CT
N = 97; N_NULLS = 24; N_PT = 73
ENE_WORD = "EASTNORTHEAST"; BCL_WORD = "BERLINCLOCK"
ENE_START_97 = 21; BCL_START_97 = 63

# Consensus mask (17 fixed + 7 best from exhaustive search)
USER_MASK = sorted([0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96])
assert len(USER_MASK) == N_NULLS

MASK_SET = frozenset(USER_MASK)
KEPT = [i for i in range(N) if i not in MASK_SET]
CT73 = ''.join(CT97[i] for i in KEPT)
CT73_NUMS = [ord(c) - 65 for c in CT73]
assert len(CT73) == N_PT

# Shifted crib positions in 73-char space
def compute_shifted_pos(pos97):
    """Convert a position in 97-char to position in 73-char after null removal."""
    return pos97 - sum(1 for m in USER_MASK if m < pos97)

ENE_S = compute_shifted_pos(ENE_START_97)  # Should be ~13
BCL_S = compute_shifted_pos(BCL_START_97)  # Should be ~47
print(f"Shifted crib positions: ENE starts at {ENE_S}, BCL starts at {BCL_S}")
print(f"CT73 = {CT73}")

# Col7 transposition (undo)
def col7_undo(text):
    """Undo columnar transposition width 7 (read columns top-to-bottom, write rows left-to-right)."""
    n = len(text)
    ncols = 7
    nrows_full = n // ncols
    extra = n % ncols
    # Build column lengths
    col_lens = [nrows_full + (1 if c < extra else 0) for c in range(ncols)]
    # Read by columns
    result = [''] * n
    idx = 0
    cols = []
    for c in range(ncols):
        cols.append(text[idx:idx+col_lens[c]])
        idx += col_lens[c]
    # Write by rows
    out = []
    for r in range(nrows_full + (1 if extra > 0 else 0)):
        for c in range(ncols):
            if r < col_lens[c]:
                out.append(cols[c][r])
    return ''.join(out)

def col7_apply(text):
    """Apply columnar transposition width 7 (read rows, write columns)."""
    n = len(text)
    ncols = 7
    nrows = (n + ncols - 1) // ncols
    # Read by rows, write by columns
    out = []
    for c in range(ncols):
        for r in range(nrows):
            idx = r * ncols + c
            if idx < n:
                out.append(text[idx])
    return ''.join(out)

# Two text variants
CT73_COL7 = col7_undo(CT73)  # After undoing col7
CT73_COL7_NUMS = [ord(c) - 65 for c in CT73_COL7]

# For col7-undone text, crib positions shift differently
# Actually: if cipher was col7(sub(PT)) = CT73, then sub(PT) = col7_undo(CT73)
# The cribs should be in the sub output, which maps to the CT73_COL7 intermediate
# But crib positions in the intermediate depend on the transposition
# For simplicity: we score both CT73 and CT73_COL7 against shifted cribs

# === ALPHABETS ===
KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}

# === SCORING ===
def count_crib_hits(pt_nums, ene_start, bcl_start, n_pt=73):
    """Count how many crib characters match at shifted positions."""
    e = 0
    for j, c in enumerate(ENE_WORD):
        pos = ene_start + j
        if 0 <= pos < n_pt and pt_nums[pos] == (ord(c) - 65):
            e += 1
    b = 0
    for j, c in enumerate(BCL_WORD):
        pos = bcl_start + j
        if 0 <= pos < n_pt and pt_nums[pos] == (ord(c) - 65):
            b += 1
    return e + b, e, b

def decrypt_running_key(ct_nums, key_nums, variant, alpha='AZ'):
    """Decrypt using running key cipher.
    variant: 'vig' -> P = C - K, 'beau' -> P = K - C, 'vbeau' -> P = K + C (all mod 26)
    alpha: 'AZ' or 'KA' for alphabet ordering
    """
    if alpha == 'KA':
        # Convert through KA indexing
        ka_ct = [KA_IDX[ALPH[c]] for c in ct_nums]
        ka_key = [KA_IDX[ALPH[k]] for k in key_nums]
        if variant == 'vig':
            ka_pt = [(c - k) % 26 for c, k in zip(ka_ct, ka_key)]
        elif variant == 'beau':
            ka_pt = [(k - c) % 26 for c, k in zip(ka_ct, ka_key)]
        else:  # vbeau
            ka_pt = [(k + c) % 26 for c, k in zip(ka_ct, ka_key)]
        # Convert back to AZ
        return [ALPH_IDX[KA[p]] for p in ka_pt]
    else:
        if variant == 'vig':
            return [(c - k) % 26 for c, k in zip(ct_nums, key_nums)]
        elif variant == 'beau':
            return [(k - c) % 26 for c, k in zip(ct_nums, key_nums)]
        else:  # vbeau
            return [(k + c) % 26 for c, k in zip(ct_nums, key_nums)]

# === LOAD QUADGRAMS ===
QG_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "english_quadgrams.json"
with open(QG_PATH) as f:
    QG_RAW = json.load(f)
QG = {}
for k, v in QG_RAW.items():
    if len(k) == 4 and k.isalpha():
        idx = tuple(ord(c) - 65 for c in k.upper())
        QG[idx] = v
QG_FLOOR = min(QG.values()) - 1.0  # Floor for missing quadgrams

def qg_score(pt_nums):
    """Quadgram log-probability score."""
    s = 0.0
    for i in range(len(pt_nums) - 3):
        key = (pt_nums[i], pt_nums[i+1], pt_nums[i+2], pt_nums[i+3])
        s += QG.get(key, QG_FLOOR)
    return s

# === LOAD SOURCE TEXTS ===
def sanitize(text):
    return re.sub(r'[^A-Z]', '', text.upper())

def load_file(path):
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            return sanitize(f.read())
    except:
        return ''

BASE = Path(__file__).resolve().parent.parent.parent

# K1-K3 plaintexts
K1_PT = sanitize("BETWEEN SUBTLE SHADING AND THE ABSENCE OF LIGHT LIES THE NUANCE OF IQLUSION")
K2_PT = sanitize("IT WAS TOTALLY INVISIBLE HOWS THAT POSSIBLE THEY USED THE EARTHS MAGNETIC FIELD X THE INFORMATION WAS GATHERED AND TRANSMITTED UNDERGRUUND TO AN UNKNOWN LOCATION X DOES LANGLEY KNOW ABOUT THIS THEY SHOULD ITS BURIED OUT THERE SOMEWHERE X WHO KNOWS THE EXACT LOCATION ONLY WW X THIRTY EIGHT DEGREES FIFTY SEVEN MINUTES SIX POINT FIVE SECONDS NORTH SEVENTY SEVEN DEGREES EIGHT MINUTES FORTY FOUR SECONDS WEST X LAYER TWO")
K3_PT = sanitize("SLOWLY DESPARATLY SLOWLY THE REMAINS OF PASSAGE DEBRIS THAT ENCUMBERED THE LOWER PART OF THE DOORWAY WAS REMOVED WITH TREMBLING HANDS I MADE A TINY BREACH IN THE UPPER LEFT HAND CORNER AND THEN WIDENING THE HOLE A LITTLE I INSERTED THE CANDLE AND PEERED IN THE HOT AIR ESCAPING FROM THE CHAMBER CAUSED THE FLAME TO FLICKER BUT PRESENTLY DETAILS OF THE ROOM WITHIN EMERGED FROM THE MIST X CAN YOU SEE ANYTHING Q")

SOURCES = {}
SOURCES['K1'] = K1_PT
SOURCES['K2'] = K2_PT
SOURCES['K3'] = K3_PT
SOURCES['K1K2'] = K1_PT + K2_PT
SOURCES['K2K3'] = K2_PT + K3_PT
SOURCES['K1K2K3'] = K1_PT + K2_PT + K3_PT
SOURCES['K1_repeat'] = (K1_PT * 3)[:200]  # K1 repeated

# Reference texts
for fname in ['carter_gutenberg.txt', 'carter_vol1.txt']:
    p = BASE / 'reference' / fname
    t = load_file(p)
    if t:
        SOURCES[fname.replace('.txt','')] = t

for fname in os.listdir(BASE / 'reference' / 'running_key_texts'):
    p = BASE / 'reference' / 'running_key_texts' / fname
    t = load_file(p)
    if t:
        SOURCES[f'rkt_{fname.replace(".txt","")}'] = t

print(f"\n=== SOURCES LOADED ===")
for name, text in sorted(SOURCES.items()):
    print(f"  {name:30s}: {len(text):>7d} chars")
print()

# === PHASE 1: EXHAUSTIVE CRIB-DRAG ===
def crib_drag_worker(args):
    """Worker: for a given source+variant+alpha+text_variant, try all offsets."""
    src_name, src_text, variant, alpha, use_col7 = args
    src_nums = [ord(c) - 65 for c in src_text]
    ct_nums = CT73_COL7_NUMS if use_col7 else CT73_NUMS
    ene_s = ENE_S
    bcl_s = BCL_S
    n_pt = N_PT

    results = []
    max_offset = max(0, len(src_nums) - n_pt)

    for offset in range(max_offset + 1):
        key_slice = src_nums[offset:offset + n_pt]
        if len(key_slice) < n_pt:
            break
        pt_nums = decrypt_running_key(ct_nums, key_slice, variant, alpha)
        total, e, b = count_crib_hits(pt_nums, ene_s, bcl_s, n_pt)

        if total >= 8:
            pt_str = ''.join(chr(x + 65) for x in pt_nums)
            qg = qg_score(pt_nums) / max(1, len(pt_nums) - 3)
            results.append({
                'src': src_name, 'offset': offset, 'variant': variant,
                'alpha': alpha, 'col7': use_col7,
                'total': total, 'ene': e, 'bcl': b,
                'qg_per_char': round(qg, 4),
                'pt': pt_str
            })

    return results

# === PHASE 2: BEAM SEARCH ===
def beam_search_worker(args):
    """Beam search for running key on 73-char text.
    At each position, try all 26 key values, keep top-N by cumulative qg score.
    """
    use_col7, variant, alpha, beam_width = args
    ct_nums = CT73_COL7_NUMS if use_col7 else CT73_NUMS
    n = len(ct_nums)

    # Initialize beam: list of (cumulative_qg, key_so_far, pt_so_far)
    beam = [(0.0, [], [])]

    for pos in range(n):
        candidates = []
        for cum_qg, key_prefix, pt_prefix in beam:
            for k in range(26):
                if alpha == 'KA':
                    ka_c = KA_IDX[ALPH[ct_nums[pos]]]
                    ka_k = KA_IDX[ALPH[k]]
                    if variant == 'vig':
                        ka_p = (ka_c - ka_k) % 26
                    elif variant == 'beau':
                        ka_p = (ka_k - ka_c) % 26
                    else:
                        ka_p = (ka_k + ka_c) % 26
                    p = ALPH_IDX[KA[ka_p]]
                else:
                    if variant == 'vig':
                        p = (ct_nums[pos] - k) % 26
                    elif variant == 'beau':
                        p = (k - ct_nums[pos]) % 26
                    else:
                        p = (k + ct_nums[pos]) % 26

                new_pt = pt_prefix + [p]
                new_key = key_prefix + [k]

                # Quadgram score (only count when we have 4+ chars)
                new_qg = cum_qg
                if pos >= 3:
                    qkey = (new_pt[-4], new_pt[-3], new_pt[-2], new_pt[-1])
                    new_qg += QG.get(qkey, QG_FLOOR)

                candidates.append((new_qg, new_key, new_pt))

        # Keep top beam_width
        candidates.sort(key=lambda x: x[0], reverse=True)
        beam = candidates[:beam_width]

    # Score final candidates against cribs
    results = []
    for cum_qg, key_seq, pt_seq in beam[:10]:  # Top 10 from beam
        total, e, b = count_crib_hits(pt_seq, ENE_S, BCL_S, n)
        pt_str = ''.join(chr(x + 65) for x in pt_seq)
        key_str = ''.join(chr(x + 65) for x in key_seq)
        qg_per = cum_qg / max(1, len(pt_seq) - 3)
        results.append({
            'variant': variant, 'alpha': alpha, 'col7': use_col7,
            'beam_width': beam_width,
            'total': total, 'ene': e, 'bcl': b,
            'qg_per_char': round(qg_per, 4),
            'pt': pt_str,
            'key': key_str[:40] + '...'
        })

    return results

# === MAIN ===
if __name__ == '__main__':
    t0 = time.time()
    NWORKERS = min(28, cpu_count())
    all_results = []

    print("=" * 70)
    print("RUNNING KEY CIPHER ON 73-CHAR NULL-EXTRACTED K4")
    print(f"Workers: {NWORKERS}, CT73: {CT73}")
    print(f"CT73_COL7: {CT73_COL7}")
    print("=" * 70)

    # === PHASE 1: CRIB DRAG ===
    print("\n--- PHASE 1: Exhaustive crib-drag across all sources ---")
    phase1_args = []
    for src_name, src_text in SOURCES.items():
        if len(src_text) < N_PT:
            continue
        for variant in ['vig', 'beau', 'vbeau']:
            for alpha in ['AZ', 'KA']:
                for use_col7 in [False, True]:
                    phase1_args.append((src_name, src_text, variant, alpha, use_col7))

    print(f"  Total configs: {len(phase1_args)} (source x variant x alpha x trans)")
    total_offsets = sum(max(0, len(SOURCES[a[0]]) - N_PT + 1) for a in phase1_args)
    print(f"  Total offsets to test: ~{total_offsets:,}")

    p1_results = []
    with Pool(NWORKERS) as pool:
        for batch_results in pool.imap_unordered(crib_drag_worker, phase1_args, chunksize=1):
            p1_results.extend(batch_results)
            for r in batch_results:
                print(f"  HIT {r['total']}/24 src={r['src']} off={r['offset']} "
                      f"{r['variant']}:{r['alpha']} col7={r['col7']} "
                      f"ene={r['ene']}/13 bcl={r['bcl']}/11 qg={r['qg_per_char']}")

    p1_results.sort(key=lambda x: (-x['total'], x['qg_per_char']))
    print(f"\nPhase 1 complete: {len(p1_results)} hits >= 8/24 in {time.time()-t0:.1f}s")
    all_results.extend(p1_results)

    # === PHASE 2: BEAM SEARCH ===
    print("\n--- PHASE 2: Griffin-style beam search ---")
    t2 = time.time()
    beam_args = []
    for variant in ['beau', 'vig']:  # Focus on most promising variants
        for alpha in ['AZ', 'KA']:
            for use_col7 in [False, True]:
                beam_args.append((use_col7, variant, alpha, 500))  # Beam width 500

    print(f"  Beam configs: {len(beam_args)}")
    p2_results = []
    with Pool(min(NWORKERS, 8)) as pool:
        for batch_results in pool.imap_unordered(beam_search_worker, beam_args, chunksize=1):
            p2_results.extend(batch_results)
            for r in batch_results:
                if r['total'] >= 6 or r['qg_per_char'] > -5.0:
                    print(f"  BEAM {r['total']}/24 {r['variant']}:{r['alpha']} "
                          f"col7={r['col7']} qg={r['qg_per_char']} "
                          f"ene={r['ene']}/13 bcl={r['bcl']}/11")
                    print(f"       PT={r['pt'][:60]}...")

    p2_results.sort(key=lambda x: (-x['total'], -x['qg_per_char']))
    print(f"\nPhase 2 complete: {len(p2_results)} candidates in {time.time()-t2:.1f}s")
    all_results.extend(p2_results)

    # === SUMMARY ===
    elapsed = time.time() - t0
    print("\n" + "=" * 70)
    print(f"TOTAL TIME: {elapsed:.1f}s")
    print(f"TOTAL RESULTS >= 8/24 (crib-drag): {len(p1_results)}")
    print(f"BEAM SEARCH RESULTS: {len(p2_results)}")

    if p1_results:
        print("\n--- TOP 20 CRIB-DRAG HITS ---")
        for r in p1_results[:20]:
            print(f"  {r['total']}/24 src={r['src']} off={r['offset']} "
                  f"{r['variant']}:{r['alpha']} col7={r['col7']} "
                  f"ene={r['ene']}/13 bcl={r['bcl']}/11 qg={r['qg_per_char']}")
            print(f"    PT: {r['pt'][:70]}")

    if p2_results:
        print("\n--- TOP 10 BEAM RESULTS ---")
        for r in p2_results[:10]:
            print(f"  {r['total']}/24 {r['variant']}:{r['alpha']} col7={r['col7']} "
                  f"bw={r['beam_width']} qg={r['qg_per_char']}")
            print(f"    PT: {r['pt'][:70]}")

    # Save results
    out_path = BASE / 'results' / 'f_running_key_73char_overnight.json'
    with open(out_path, 'w') as f:
        json.dump({
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
            'elapsed_s': round(elapsed, 1),
            'mask': USER_MASK,
            'ct73': CT73,
            'ct73_col7': CT73_COL7,
            'ene_shifted': ENE_S,
            'bcl_shifted': BCL_S,
            'n_sources': len(SOURCES),
            'phase1_configs': len(phase1_args),
            'phase1_hits': len(p1_results),
            'phase2_beam_configs': len(beam_args),
            'phase2_results': len(p2_results),
            'top_crib_drag': p1_results[:50],
            'top_beam': p2_results[:20],
            'all_results_count': len(all_results),
        }, f, indent=2)
    print(f"\nResults saved to {out_path}")
