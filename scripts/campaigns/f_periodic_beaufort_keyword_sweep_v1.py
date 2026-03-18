#!/usr/bin/env python3
"""Exhaustive periodic Beaufort/Vigenere keyword sweep on 73-char null-extracted K4.

Cipher: Periodic Beaufort/Vigenere
Family: campaigns
Status: active
Keyspace: ~1M+ words x 4 variants x 2 trans = ~8M+
Last run: never
Best score: N/A

Autokey is dead. Periodic sub on RAW 97 is proven impossible (all 26 periods).
BUT: on the 73-char null-extracted text where the stego layer is removed, periodic
sub has NOT been exhaustively tested with the full 1M+ wordlist.

Prior null-mask + periodic sub proof (2026-03-11) showed impossibility for ANY mask
at periods 1-23 on raw 97 -- but that assumes the null mask and periodic cipher
operate INDEPENDENTLY. With a FIXED mask (consensus + best 7), the 73-char text
is determined, and periodic sub on that 73-char text is a DIFFERENT problem.

For each word in english.txt:
- Use as periodic Beaufort key on CT73 (with and without col7 undo)
- Use as periodic Vigenere key
- Score against shifted cribs (24 positions)
- Report anything >= 10/24
- Also try KA alphabet

Each eval = 73 mod operations + 24 comparisons = trivial.
1M words x 4 variants x 2 trans = ~8M evals. Should complete in minutes.
"""
import sys, time, json
from pathlib import Path
from multiprocessing import Pool, cpu_count

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))
from kryptos.kernel.constants import CT, KRYPTOS_ALPHABET, ALPH_IDX

BASE = Path(__file__).resolve().parent.parent.parent

# === CONSTANTS ===
CT97 = CT
USER_MASK = sorted([0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96])
MASK_SET = frozenset(USER_MASK)
KEPT = [i for i in range(97) if i not in MASK_SET]
CT73 = ''.join(CT97[i] for i in KEPT)
CT73_NUMS = [ord(c) - 65 for c in CT73]
N_PT = 73

KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}

# Col7 undo
def col7_undo(text):
    n = len(text)
    ncols = 7
    nrows_full = n // ncols
    extra = n % ncols
    col_lens = [nrows_full + (1 if c < extra else 0) for c in range(ncols)]
    idx = 0; cols = []
    for c in range(ncols):
        cols.append(text[idx:idx+col_lens[c]])
        idx += col_lens[c]
    out = []
    for r in range(nrows_full + (1 if extra > 0 else 0)):
        for c in range(ncols):
            if r < col_lens[c]:
                out.append(cols[c][r])
    return ''.join(out)

CT73_COL7 = col7_undo(CT73)
CT73_COL7_NUMS = [ord(c) - 65 for c in CT73_COL7]

# Shifted crib positions
def compute_shifted_pos(pos97):
    return pos97 - sum(1 for m in USER_MASK if m < pos97)

ENE_S = compute_shifted_pos(21)
BCL_S = compute_shifted_pos(63)
ENE_WORD = "EASTNORTHEAST"
BCL_WORD = "BERLINCLOCK"
ENE_TARGETS = [(ENE_S + j, ord(c) - 65) for j, c in enumerate(ENE_WORD)]
BCL_TARGETS = [(BCL_S + j, ord(c) - 65) for j, c in enumerate(BCL_WORD)]

print(f"CT73 = {CT73}")
print(f"CT73_COL7 = {CT73_COL7}")
print(f"ENE_S={ENE_S}, BCL_S={BCL_S}")

# === LOAD WORDLIST ===
wordlist_path = BASE / 'wordlists' / 'english.txt'
print(f"Loading wordlist from {wordlist_path}...")
with open(wordlist_path) as f:
    WORDS_RAW = [line.strip().upper() for line in f if line.strip()]
# Filter to alpha-only words of length 1-30
WORDS = [w for w in WORDS_RAW if w.isascii() and w.isalpha() and 1 <= len(w) <= 30]
print(f"Loaded {len(WORDS)} words (alpha only, len 1-30)")

# Deduplicate
WORDS = list(set(WORDS))
WORDS.sort()
print(f"After dedup: {len(WORDS)} unique words")

# Pre-convert words to number arrays
WORD_NUMS = [(w, [ord(c) - 65 for c in w]) for w in WORDS]

# === SCORING FUNCTION ===
def score_periodic(ct_nums, key_nums, variant):
    """Decrypt with periodic key and score against cribs.
    Returns (total, ene, bcl).
    variant: 0=AZ_vig, 1=AZ_beau, 2=KA_vig, 3=KA_beau
    """
    klen = len(key_nums)
    n = len(ct_nums)

    # Decrypt
    if variant < 2:  # AZ
        if variant == 0:  # vig: P = C - K
            pt = [(ct_nums[i] - key_nums[i % klen]) % 26 for i in range(n)]
        else:  # beau: P = K - C
            pt = [(key_nums[i % klen] - ct_nums[i]) % 26 for i in range(n)]
    else:  # KA
        if variant == 2:  # KA vig
            pt_ka = [(KA_IDX[chr(ct_nums[i]+65)] - KA_IDX[chr(key_nums[i%klen]+65)]) % 26 for i in range(n)]
            pt = [ord(KA[p]) - 65 for p in pt_ka]
        else:  # KA beau
            pt_ka = [(KA_IDX[chr(key_nums[i%klen]+65)] - KA_IDX[chr(ct_nums[i]+65)]) % 26 for i in range(n)]
            pt = [ord(KA[p]) - 65 for p in pt_ka]

    # Score
    e = sum(1 for pos, target in ENE_TARGETS if 0 <= pos < n and pt[pos] == target)
    b = sum(1 for pos, target in BCL_TARGETS if 0 <= pos < n and pt[pos] == target)
    return e + b, e, b

# Pre-compute KA lookup tables for speed
_KA_IDX_ARRAY = [KA_IDX[chr(i+65)] for i in range(26)]
_KA_CHAR_ARRAY = [ord(KA[i]) - 65 for i in range(26)]

def score_periodic_fast(ct_nums, key_nums, variant):
    """Optimized version with pre-computed lookups."""
    klen = len(key_nums)
    n = len(ct_nums)

    if variant == 0:  # AZ vig
        pt = [(ct_nums[i] - key_nums[i % klen]) % 26 for i in range(n)]
    elif variant == 1:  # AZ beau
        pt = [(key_nums[i % klen] - ct_nums[i]) % 26 for i in range(n)]
    elif variant == 2:  # KA vig
        pt = [_KA_CHAR_ARRAY[(_KA_IDX_ARRAY[ct_nums[i]] - _KA_IDX_ARRAY[key_nums[i%klen]]) % 26] for i in range(n)]
    else:  # KA beau
        pt = [_KA_CHAR_ARRAY[(_KA_IDX_ARRAY[key_nums[i%klen]] - _KA_IDX_ARRAY[ct_nums[i]]) % 26] for i in range(n)]

    e = sum(1 for pos, target in ENE_TARGETS if 0 <= pos < n and pt[pos] == target)
    b = sum(1 for pos, target in BCL_TARGETS if 0 <= pos < n and pt[pos] == target)
    return e + b, e, b

# === WORKER ===
def sweep_worker(args):
    """Process a chunk of words across all variants and both text versions."""
    word_chunk, chunk_id = args
    threshold = 10
    hits = []
    count = 0

    for word, key_nums in word_chunk:
        for variant in range(4):  # AZ_vig, AZ_beau, KA_vig, KA_beau
            for use_col7 in (False, True):
                ct_nums = CT73_COL7_NUMS if use_col7 else CT73_NUMS
                total, e, b = score_periodic_fast(ct_nums, key_nums, variant)
                count += 1
                if total >= threshold:
                    variant_name = ['AZ_vig', 'AZ_beau', 'KA_vig', 'KA_beau'][variant]
                    # Compute full plaintext for reporting
                    klen = len(key_nums)
                    n = len(ct_nums)
                    if variant == 0:
                        pt = [(ct_nums[i] - key_nums[i % klen]) % 26 for i in range(n)]
                    elif variant == 1:
                        pt = [(key_nums[i % klen] - ct_nums[i]) % 26 for i in range(n)]
                    elif variant == 2:
                        pt = [_KA_CHAR_ARRAY[(_KA_IDX_ARRAY[ct_nums[i]] - _KA_IDX_ARRAY[key_nums[i%klen]]) % 26] for i in range(n)]
                    else:
                        pt = [_KA_CHAR_ARRAY[(_KA_IDX_ARRAY[key_nums[i%klen]] - _KA_IDX_ARRAY[ct_nums[i]]) % 26] for i in range(n)]
                    pt_str = ''.join(chr(x+65) for x in pt)

                    hits.append({
                        'word': word, 'variant': variant_name,
                        'col7': use_col7,
                        'total': total, 'ene': e, 'bcl': b,
                        'period': len(word),
                        'pt': pt_str
                    })

    return hits, count

# === MAIN ===
if __name__ == '__main__':
    t0 = time.time()
    NWORKERS = min(28, cpu_count())

    print("\n" + "=" * 70)
    print("EXHAUSTIVE PERIODIC BEAUFORT/VIGENERE KEYWORD SWEEP ON CT73")
    print(f"Words: {len(WORD_NUMS)}, Variants: 4, Trans: 2 = ~{len(WORD_NUMS)*8:,} evals")
    print(f"Workers: {NWORKERS}")
    print("=" * 70)

    # Split words into chunks
    chunk_size = max(1, len(WORD_NUMS) // (NWORKERS * 4))
    chunks = []
    for i in range(0, len(WORD_NUMS), chunk_size):
        chunks.append((WORD_NUMS[i:i+chunk_size], i // chunk_size))

    print(f"Split into {len(chunks)} chunks of ~{chunk_size} words each")

    all_hits = []
    total_evals = 0
    completed_chunks = 0

    with Pool(NWORKERS) as pool:
        for hits, count in pool.imap_unordered(sweep_worker, chunks, chunksize=1):
            all_hits.extend(hits)
            total_evals += count
            completed_chunks += 1
            if completed_chunks % 20 == 0:
                elapsed = time.time() - t0
                rate = total_evals / elapsed if elapsed > 0 else 0
                print(f"  [{completed_chunks}/{len(chunks)}] "
                      f"{total_evals:,} evals in {elapsed:.1f}s ({rate:,.0f}/s), "
                      f"{len(all_hits)} hits so far")

    elapsed = time.time() - t0
    all_hits.sort(key=lambda x: -x['total'])

    print(f"\n{'='*70}")
    print(f"COMPLETE: {total_evals:,} evals in {elapsed:.1f}s ({total_evals/elapsed:,.0f}/s)")
    print(f"Hits >= 10/24: {len(all_hits)}")

    if all_hits:
        print("\n--- TOP 30 HITS ---")
        for r in all_hits[:30]:
            print(f"  {r['total']}/24 word={r['word']} {r['variant']} "
                  f"col7={r['col7']} p={r['period']} "
                  f"ene={r['ene']}/13 bcl={r['bcl']}/11")
            print(f"    PT: {r['pt'][:70]}")

    # Also report distribution
    from collections import Counter
    score_dist = Counter(h['total'] for h in all_hits)
    print(f"\nScore distribution of hits: {dict(sorted(score_dist.items(), reverse=True))}")

    # Variant distribution
    var_dist = Counter(h['variant'] for h in all_hits)
    print(f"Variant distribution: {dict(var_dist)}")

    # Period distribution
    per_dist = Counter(h['period'] for h in all_hits)
    per_sorted = sorted(per_dist.items(), key=lambda x: -x[1])
    print(f"Period distribution (top 10): {per_sorted[:10]}")

    # Save
    out_path = BASE / 'results' / 'f_periodic_beaufort_keyword_sweep_73char.json'
    with open(out_path, 'w') as f:
        json.dump({
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
            'elapsed_s': round(elapsed, 1),
            'mask': USER_MASK,
            'ct73': CT73,
            'ct73_col7': CT73_COL7,
            'ene_shifted': ENE_S,
            'bcl_shifted': BCL_S,
            'total_words': len(WORD_NUMS),
            'total_evals': total_evals,
            'hits_ge10': len(all_hits),
            'score_distribution': dict(sorted(score_dist.items(), reverse=True)),
            'variant_distribution': dict(var_dist),
            'top_hits': all_hits[:100],
            'all_hits_count': len(all_hits),
        }, f, indent=2)
    print(f"\nResults saved to {out_path}")
