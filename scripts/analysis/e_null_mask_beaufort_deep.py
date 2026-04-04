#!/usr/bin/env python3 -u
"""
=================================================================
NULL-MASK + KEYWORD-BEAUFORT DEEP ATTACK
=================================================================
Cipher:     Null masking (stego) + Beaufort with keyword-mixed alphabet
Family:     analysis
Status:     active
Keyspace:   ~50M+ configs across 4 phases
Last run:   never
Best score: TBD

HYPOTHESIS
----------
K4 embeds a shorter plaintext within 97 carved characters. Some positions
are steganographic nulls. After removing nulls, the remaining ciphertext
decrypts via Beaufort cipher with a keyword-mixed alphabet.

Evidence:
  1. IMG_1236: "encrypted message within set of modern day font characters"
  2. Physical overlays in archive (IMG_1221/1237)
  3. Scheidt confirmed "a little bit of stego"
  4. Bean E0b: near-identity substitution at KRYPTOS positions (p~1/5520)
  5. Bean E0c: one-to-one encryption, no transposition (p~1/240)
  6. Width-21 structural significance

MATERIALLY NEW ASSUMPTION: Combines null masking with keyword-mixed Beaufort
using score_candidate_free (position-free crib search). Prior null-mask tests
used periodic substitution (eliminated) or fixed-position scoring.
=================================================================
"""

import sys
import os
import json
import time
import itertools
from multiprocessing import Pool, cpu_count
from collections import defaultdict

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, 'src')):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET,
    CONSENSUS_NULL_POSITIONS, CRIB_WORDS, N_CRIBS,
    NOISE_FLOOR, STORE_THRESHOLD, SIGNAL_THRESHOLD,
)
from kryptos.kernel.alphabet import keyword_mixed_alphabet
from kryptos.kernel.scoring.aggregate import score_candidate_free

# ── Configuration ─────────────────────────────────────────────────

WORKERS = max(1, cpu_count() - 2)
REPORT_INTERVAL = 100000

# Thematic keywords
THEMATIC_KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "FORCES",
    "UNDERGRUUND", "LUCID", "MEMORY", "DEFECTOR", "CIA",
    "BERLIN", "CLOCK", "EAST", "NORTH", "LANGLEY",
    "SANBORN", "SCHEIDT", "SCULPTURE", "CODE", "MORSE",
    "ENIGMA", "CIPHER", "SECRET", "LIGHT", "DARK",
    "INVISIBLE", "HIDDEN", "STEALTH", "MATRIX", "QUAGMIRE",
    "VENUS", "MERCURY", "NEPTUNE", "JUPITER", "SATURN",
    "PHARAOH", "EGYPT", "CARTER", "TOMB", "PYRAMID",
    "TUTANKHAMUN", "VALLEY", "KINGS", "NILE", "SPHINX",
    "VIRTUALLY", "PASSAGE", "RUINS", "ANCIENT", "SLOWLY",
    "DESPERATELY", "TOTALLY", "IQLUSION", "ILLUSION",
    "DYAHR", "NDYAHR", "OBKR", "SOS", "ATBASH",
    "DIGETAL", "INTERPRETATU", "THEILLUSION",
]

ENE = "EASTNORTHEAST"  # 13 chars
BCL = "BERLINCLOCK"    # 11 chars


def extract_ct(ct, null_positions):
    """Remove null positions from ciphertext."""
    return "".join(c for i, c in enumerate(ct) if i not in null_positions)


def fast_free_score(plaintext):
    """Fast substring check for both cribs. Returns 0, 11, 13, or 24."""
    s = 0
    if ENE in plaintext:
        s += 13
    if BCL in plaintext:
        s += 11
    return s


def beaufort_dec(ct_str, key_nums):
    """Standard Beaufort decrypt: P = (K - C) mod 26."""
    klen = len(key_nums)
    return "".join(
        ALPH[(key_nums[i % klen] - ALPH_IDX[c]) % MOD]
        for i, c in enumerate(ct_str)
    )


def vigenere_dec(ct_str, key_nums):
    """Vigenere decrypt: P = (C - K) mod 26."""
    klen = len(key_nums)
    return "".join(
        ALPH[(ALPH_IDX[c] - key_nums[i % klen]) % MOD]
        for i, c in enumerate(ct_str)
    )


def beaufort_mixed_dec(ct_str, key_nums, mixed_alph):
    """Beaufort with keyword-mixed alphabet: P = alph[(K - idx[C]) mod 26]."""
    idx = {c: i for i, c in enumerate(mixed_alph)}
    klen = len(key_nums)
    return "".join(
        mixed_alph[(key_nums[i % klen] - idx[c]) % MOD]
        for i, c in enumerate(ct_str)
    )


# ── Phase 1A: Consensus nulls + thematic keywords ─────────────────

def phase1a_worker(keyword):
    """Test one keyword against consensus null mask, 3 variants."""
    null_mask = CONSENSUS_NULL_POSITIONS
    ext_ct = extract_ct(CT, null_mask)
    key_nums = [ALPH_IDX[c] for c in keyword if c in ALPH_IDX]
    if not key_nums:
        return []

    results = []

    # Beaufort standard
    pt = beaufort_dec(ext_ct, key_nums)
    s = fast_free_score(pt)
    if s >= 11:
        results.append((s, keyword, "beaufort", pt))

    # Beaufort mixed
    try:
        mixed = keyword_mixed_alphabet(keyword)
        pt_m = beaufort_mixed_dec(ext_ct, key_nums, mixed)
        s_m = fast_free_score(pt_m)
        if s_m >= 11:
            results.append((s_m, keyword, "beau_mixed", pt_m))
    except Exception:
        pass

    # Vigenere
    pt_v = vigenere_dec(ext_ct, key_nums)
    s_v = fast_free_score(pt_v)
    if s_v >= 11:
        results.append((s_v, keyword, "vigenere", pt_v))

    return results


def phase1a():
    """Consensus null mask + thematic keywords."""
    print("=" * 70)
    print("PHASE 1A: Consensus nulls (17) + thematic keywords")
    print("=" * 70)

    ext_ct = extract_ct(CT, CONSENSUS_NULL_POSITIONS)
    print(f"  Extracted CT ({len(ext_ct)} chars): {ext_ct}")
    print(f"  Keywords: {len(THEMATIC_KEYWORDS)}")

    results = []
    for kw in THEMATIC_KEYWORDS:
        r = phase1a_worker(kw)
        results.extend(r)

    results.sort(key=lambda x: x[0], reverse=True)
    print(f"  Hits (score>=11): {len(results)}")
    for s, kw, var, pt in results[:10]:
        print(f"    score={s:2d} kw={kw:<20s} var={var}")
    print()
    return results


# ── Phase 1B: Consensus nulls + exhaustive short keywords ─────────

def phase1b_batch_worker(batch):
    """Process a batch of keywords against consensus null mask."""
    null_mask = CONSENSUS_NULL_POSITIONS
    ext_ct = extract_ct(CT, null_mask)
    results = []

    for keyword in batch:
        key_nums = [ALPH_IDX[c] for c in keyword]

        # Beaufort standard
        pt = beaufort_dec(ext_ct, key_nums)
        s = fast_free_score(pt)
        if s >= 11:
            results.append((s, keyword, "beaufort", pt))

        # Vigenere
        pt_v = vigenere_dec(ext_ct, key_nums)
        s_v = fast_free_score(pt_v)
        if s_v >= 11:
            results.append((s_v, keyword, "vigenere", pt_v))

    return results


def generate_keyword_batches(max_len=4, batch_size=2000):
    """Generate keywords in batches to keep memory low."""
    batch = []
    for length in range(1, max_len + 1):
        for combo in itertools.product(ALPH, repeat=length):
            batch.append("".join(combo))
            if len(batch) >= batch_size:
                yield batch
                batch = []
    if batch:
        yield batch


def phase1b():
    """Consensus null mask + exhaustive keywords len 1-4."""
    print("=" * 70)
    print("PHASE 1B: Consensus nulls + exhaustive keywords (len 1-4)")
    print("=" * 70)

    total_kws = sum(26**i for i in range(1, 5))  # 475,254
    print(f"  Total keywords: {total_kws:,} (x2 variants = {total_kws*2:,} configs)")
    print(f"  Workers: {WORKERS}")

    results = []
    tested = 0
    t0 = time.time()

    with Pool(WORKERS) as pool:
        for batch_results in pool.imap_unordered(
            phase1b_batch_worker,
            generate_keyword_batches(4, 2000),
            chunksize=4
        ):
            tested += 2000  # approximate
            results.extend(batch_results)
            if tested % REPORT_INTERVAL == 0:
                el = time.time() - t0
                print(f"  [{el:6.1f}s] ~{tested:>10,}/{total_kws:,} "
                      f"hits={len(results)}")

    el = time.time() - t0
    results.sort(key=lambda x: x[0], reverse=True)
    print(f"  Done: ~{total_kws:,} kws in {el:.1f}s, hits={len(results)}")
    for s, kw, var, pt in results[:10]:
        print(f"    score={s:2d} kw={kw:<10s} var={var}")
    print()
    return results


# ── Phase 2: Variable null masks + promising keywords ──────────────

def build_null_masks():
    """Build a diverse but manageable set of null masks."""
    masks = set()

    # Consensus and variants (+/- 1 position)
    consensus = frozenset(CONSENSUS_NULL_POSITIONS)
    masks.add(consensus)
    for p in range(CT_LEN):
        if p in consensus:
            masks.add(consensus - {p})
        else:
            masks.add(consensus | {p})

    # Width-based column masks
    for w in [7, 10, 11, 13, 14, 17, 19, 21]:
        n_rows = (CT_LEN + w - 1) // w
        for col in range(w):
            m = frozenset(row * w + col for row in range(n_rows)
                         if row * w + col < CT_LEN)
            if 3 <= len(m) <= 30:
                masks.add(m)
        # Two-column masks for smaller widths
        if w <= 14:
            for c1 in range(w):
                for c2 in range(c1+1, w):
                    m = frozenset(row*w+c for row in range(n_rows)
                                for c in (c1,c2) if row*w+c < CT_LEN)
                    if 5 <= len(m) <= 30:
                        masks.add(m)

    # Interleaved: every Nth position
    for step in range(2, 8):
        for offset in range(step):
            m = frozenset(range(offset, CT_LEN, step))
            if 10 <= len(m) <= 35:
                masks.add(m)

    return list(masks)


def phase2_worker(args):
    """Test one (mask, keyword) against 2 variants."""
    mask_tuple, keyword = args
    null_mask = frozenset(mask_tuple)
    ext_ct = extract_ct(CT, null_mask)
    if len(ext_ct) < 24:
        return []

    key_nums = [ALPH_IDX[c] for c in keyword if c in ALPH_IDX]
    if not key_nums:
        return []

    results = []

    pt = beaufort_dec(ext_ct, key_nums)
    s = fast_free_score(pt)
    if s >= 11:
        results.append((s, keyword, "beaufort", pt, len(null_mask), sorted(null_mask)))

    pt_v = vigenere_dec(ext_ct, key_nums)
    s_v = fast_free_score(pt_v)
    if s_v >= 11:
        results.append((s_v, keyword, "vigenere", pt_v, len(null_mask), sorted(null_mask)))

    return results


def phase2_task_gen(masks, keywords):
    """Generate (mask, keyword) pairs as a lazy iterator."""
    for mask in masks:
        mask_t = tuple(sorted(mask))
        for kw in keywords:
            yield (mask_t, kw)


def phase2():
    """Variable null masks + selected keywords."""
    print("=" * 70)
    print("PHASE 2: Variable null masks + keyword sweep")
    print("=" * 70)

    masks = build_null_masks()

    # Keywords: single letters + 2-letter + thematic
    keywords = (
        [chr(65+i) for i in range(26)] +
        [chr(65+i)+chr(65+j) for i in range(26) for j in range(26)] +
        THEMATIC_KEYWORDS
    )

    total = len(masks) * len(keywords)
    print(f"  Null masks: {len(masks):,}")
    print(f"  Keywords: {len(keywords):,}")
    print(f"  Total configs: {total:,} (x2 variants)")
    print(f"  Workers: {WORKERS}")

    results = []
    tested = 0
    t0 = time.time()

    with Pool(WORKERS) as pool:
        for r in pool.imap_unordered(
            phase2_worker,
            phase2_task_gen(masks, keywords),
            chunksize=500
        ):
            tested += 1
            results.extend(r)
            if tested % REPORT_INTERVAL == 0:
                el = time.time() - t0
                rate = tested / el if el > 0 else 0
                print(f"  [{el:7.1f}s] {tested:>10,}/{total:,} "
                      f"({100*tested/total:.1f}%) {rate:.0f}/s hits={len(results)}")

    el = time.time() - t0
    results.sort(key=lambda x: x[0], reverse=True)
    print(f"  Done: {tested:,} in {el:.1f}s, hits={len(results)}")
    for r in results[:10]:
        s, kw, var, pt, nn, npos = r
        print(f"    score={s:2d} kw={kw:<15s} var={var} nulls={nn}")
    print()
    return results


# ── Phase 3: Crib-anchored key recovery (reverse approach) ────────

def phase3():
    """For each null mask, try every position for ENE and BCL in extracted CT.
    Recover Beaufort key at crib positions. Check if key is periodic (keyword).
    """
    print("=" * 70)
    print("PHASE 3: Crib-anchored key recovery")
    print("=" * 70)

    masks_to_try = []
    # Consensus + width-21 column masks
    masks_to_try.append(("consensus_17", frozenset(CONSENSUS_NULL_POSITIONS)))

    for ncols in range(1, 4):
        for cols in itertools.combinations(range(21), ncols):
            n_rows = (CT_LEN + 20) // 21
            positions = frozenset(
                row * 21 + col
                for row in range(n_rows)
                for col in cols
                if row * 21 + col < CT_LEN
            )
            if 3 <= len(positions) <= 25:
                name = f"w21_c{'_'.join(str(c) for c in cols)}"
                masks_to_try.append((name, positions))

    # Also width-7 column masks
    for ncols in range(1, 4):
        for cols in itertools.combinations(range(7), ncols):
            n_rows = (CT_LEN + 6) // 7
            positions = frozenset(
                row * 7 + col for row in range(n_rows)
                for col in cols if row * 7 + col < CT_LEN
            )
            if 5 <= len(positions) <= 25:
                name = f"w7_c{'_'.join(str(c) for c in cols)}"
                masks_to_try.append((name, positions))

    print(f"  Null masks to test: {len(masks_to_try)}")

    results = []
    masks_done = 0

    for mask_name, null_mask in masks_to_try:
        ext_ct = extract_ct(CT, null_mask)
        ext_len = len(ext_ct)

        if ext_len < 24:
            continue

        # Try all placements of ENE
        for ene_start in range(ext_len - 12):
            # Recover key at ENE positions: K = (C + P) mod 26
            ene_keys = []
            for j in range(13):
                ct_ch = ext_ct[ene_start + j]
                pt_ch = ENE[j]
                k = (ALPH_IDX[ct_ch] + ALPH_IDX[pt_ch]) % MOD
                ene_keys.append(k)

            # Check keyword consistency for lengths 1..13
            for kw_len in range(1, 14):
                slots = [None] * kw_len
                ok = True
                for j in range(13):
                    s = (ene_start + j) % kw_len
                    if slots[s] is None:
                        slots[s] = ene_keys[j]
                    elif slots[s] != ene_keys[j]:
                        ok = False
                        break
                if not ok:
                    continue

                # Check BCL at every position
                for bc_start in range(ext_len - 10):
                    if bc_start + 10 <= ene_start or bc_start >= ene_start + 13:
                        pass  # no overlap is fine
                    elif bc_start >= ene_start and bc_start + 10 <= ene_start + 13:
                        pass  # fully inside (unusual but allowed)
                    else:
                        # Partial overlap - skip to avoid contradictions
                        continue

                    test_slots = list(slots)
                    bc_ok = True
                    for j in range(11):
                        ct_ch = ext_ct[bc_start + j]
                        pt_ch = BCL[j]
                        k = (ALPH_IDX[ct_ch] + ALPH_IDX[pt_ch]) % MOD
                        s = (bc_start + j) % kw_len
                        if test_slots[s] is None:
                            test_slots[s] = k
                        elif test_slots[s] != k:
                            bc_ok = False
                            break

                    if not bc_ok:
                        continue

                    # Both cribs consistent with repeating key!
                    kw_final = [v if v is not None else 0 for v in test_slots]
                    kw_str = "".join(ALPH[v] for v in kw_final)

                    # Decrypt
                    pt = beaufort_dec(ext_ct, kw_final)
                    sb = score_candidate_free(pt)

                    results.append({
                        "score": sb.crib_score,
                        "mask_name": mask_name,
                        "n_nulls": len(null_mask),
                        "kw_len": kw_len,
                        "keyword": kw_str,
                        "keyword_nums": kw_final,
                        "ene_pos": ene_start,
                        "bc_pos": bc_start,
                        "plaintext": pt,
                        "ene_found": sb.ene_found,
                        "bc_found": sb.bc_found,
                        "ic": sb.ic_value,
                    })

        masks_done += 1
        if masks_done % 20 == 0:
            print(f"  [{masks_done}/{len(masks_to_try)}] masks done, "
                  f"hits={len(results)}")

    results.sort(key=lambda x: x["score"], reverse=True)
    print(f"\n  Done: {masks_done} masks, hits={len(results)}")
    for r in results[:20]:
        print(f"    score={r['score']:2d} mask={r['mask_name']:<25s} "
              f"kwlen={r['kw_len']} kw={r['keyword']:<15s} "
              f"ENE@{r['ene_pos']} BC@{r['bc_pos']} IC={r['ic']:.4f}")
        if r['score'] >= 11:
            print(f"      PT: {r['plaintext'][:60]}...")
    print()
    return results


# ── Phase 4: Near-identity alphabet with single shifts ─────────────

def phase4_worker(swap_pair):
    """Test a single-swap near-identity alphabet with all 26 shifts."""
    null_mask = CONSENSUS_NULL_POSITIONS
    ext_ct = extract_ct(CT, null_mask)

    # Build permuted alphabet
    alph_list = list(ALPH)
    if swap_pair:
        i, j = swap_pair
        alph_list[i], alph_list[j] = alph_list[j], alph_list[i]
    perm_alph = "".join(alph_list)
    perm_idx = {c: i for i, c in enumerate(perm_alph)}

    results = []
    for shift in range(26):
        pt = "".join(
            perm_alph[(shift - perm_idx[c]) % MOD]
            for c in ext_ct
        )
        s = fast_free_score(pt)
        if s >= 11:
            results.append((s, perm_alph, shift, pt))

    return results


def phase4():
    """Near-identity alphabets (0-1 swaps) + single-shift Beaufort."""
    print("=" * 70)
    print("PHASE 4: Near-identity alphabet + Beaufort shifts")
    print("=" * 70)

    # Identity + all C(26,2) = 325 single swaps
    swaps = [None]  # identity
    for i in range(26):
        for j in range(i+1, 26):
            swaps.append((i, j))

    print(f"  Alphabets: {len(swaps)} (identity + {len(swaps)-1} single-swaps)")
    print(f"  x 26 shifts = {len(swaps)*26:,} configs")

    results = []
    with Pool(WORKERS) as pool:
        for r in pool.imap_unordered(phase4_worker, swaps, chunksize=10):
            results.extend(r)

    results.sort(key=lambda x: x[0], reverse=True)
    print(f"  Hits: {len(results)}")
    for s, alph, shift, pt in results[:10]:
        print(f"    score={s:2d} shift={shift:2d} alph={alph}")
    print()
    return results


# ── Phase 5: Keyword-mixed alphabet exhaustive ─────────────────────

def phase5_worker(kw_batch):
    """Test batch of keywords as mixed alphabets with all 26 shifts."""
    null_mask = CONSENSUS_NULL_POSITIONS
    ext_ct = extract_ct(CT, null_mask)
    results = []

    for keyword in kw_batch:
        try:
            mixed = keyword_mixed_alphabet(keyword)
        except Exception:
            continue
        mixed_idx = {c: i for i, c in enumerate(mixed)}

        for shift in range(26):
            pt = "".join(
                mixed[(shift - mixed_idx[c]) % MOD]
                for c in ext_ct
            )
            s = fast_free_score(pt)
            if s >= 11:
                results.append((s, keyword, mixed, shift, pt))

    return results


def phase5():
    """Keyword-mixed alphabets from wordlist + 26 shifts each."""
    print("=" * 70)
    print("PHASE 5: Keyword-mixed alphabets + monoalphabetic Beaufort")
    print("=" * 70)

    # Load wordlist for keywords
    wordlist_path = os.path.join(_ROOT, "wordlists", "english.txt")
    if os.path.exists(wordlist_path):
        with open(wordlist_path) as f:
            words = [w.strip().upper() for w in f if 3 <= len(w.strip()) <= 12]
        # Deduplicate by the mixed alphabet they produce
        seen_alphs = set()
        unique_words = []
        for w in words:
            try:
                ma = keyword_mixed_alphabet(w)
                if ma not in seen_alphs:
                    seen_alphs.add(ma)
                    unique_words.append(w)
            except Exception:
                pass
        words = unique_words
    else:
        words = THEMATIC_KEYWORDS

    # Also add all 2-letter keywords
    for a in ALPH:
        for b in ALPH:
            kw = a + b
            try:
                ma = keyword_mixed_alphabet(kw)
                if ma not in {keyword_mixed_alphabet(w) for w in words[:10]}:
                    words.append(kw)
            except Exception:
                pass

    print(f"  Unique keyword alphabets: {len(words):,}")
    print(f"  x 26 shifts = {len(words)*26:,} configs")

    # Batch into groups of 100
    batches = []
    batch = []
    for w in words:
        batch.append(w)
        if len(batch) >= 100:
            batches.append(batch)
            batch = []
    if batch:
        batches.append(batch)

    results = []
    tested = 0
    t0 = time.time()

    with Pool(WORKERS) as pool:
        for r in pool.imap_unordered(phase5_worker, batches, chunksize=4):
            tested += 1
            results.extend(r)
            if tested % 100 == 0:
                el = time.time() - t0
                print(f"  [{el:6.1f}s] {tested*100:,}/{len(words):,} kws, "
                      f"hits={len(results)}")

    el = time.time() - t0
    results.sort(key=lambda x: x[0], reverse=True)
    print(f"  Done: {len(words):,} kws in {el:.1f}s, hits={len(results)}")
    for s, kw, alph, shift, pt in results[:10]:
        print(f"    score={s:2d} kw={kw:<15s} shift={shift}")
    print()
    return results


# ── Main ───────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("NULL-MASK + KEYWORD-BEAUFORT DEEP ATTACK")
    print("=" * 70)
    print(f"CT ({CT_LEN} chars): {CT}")
    print(f"Consensus nulls ({len(CONSENSUS_NULL_POSITIONS)}): "
          f"{sorted(CONSENSUS_NULL_POSITIONS)}")
    print(f"Workers: {WORKERS}")
    print()

    t_start = time.time()
    all_hits = []

    # Phase 1A: Thematic keywords
    hits_1a = phase1a()
    for h in hits_1a:
        all_hits.append((h[0], "P1A", h))

    # Phase 1B: Exhaustive short keywords (len 1-4)
    hits_1b = phase1b()
    for h in hits_1b:
        all_hits.append((h[0], "P1B", h))

    # Phase 3: Crib-anchored reverse search (before Phase 2 to get fast results)
    hits_3 = phase3()
    for h in hits_3:
        all_hits.append((h["score"], "P3", h))

    # Phase 4: Near-identity alphabets
    hits_4 = phase4()
    for h in hits_4:
        all_hits.append((h[0], "P4", h))

    # Phase 5: Keyword-mixed alphabets from wordlist
    hits_5 = phase5()
    for h in hits_5:
        all_hits.append((h[0], "P5", h))

    # Phase 2: Variable null masks (most expensive, run last)
    hits_2 = phase2()
    for h in hits_2:
        all_hits.append((h[0], "P2", h))

    t_total = time.time() - t_start

    # ── Summary ──────────────────────────────────────────────────────
    print("=" * 70)
    print("FINAL SUMMARY")
    print("=" * 70)
    print(f"Total runtime: {t_total:.1f}s ({t_total/60:.1f} min)")
    print(f"Total hits across all phases: {len(all_hits)}")

    all_hits.sort(key=lambda x: x[0], reverse=True)
    best_score = all_hits[0][0] if all_hits else 0
    print(f"Best score: {best_score}")

    if best_score >= SIGNAL_THRESHOLD:
        print("*** SIGNAL DETECTED ***")
    elif best_score >= STORE_THRESHOLD:
        print("*** INTERESTING ***")
    else:
        print("All noise")

    print(f"\nTop 30 results:")
    for i, (score, phase, hit) in enumerate(all_hits[:30]):
        if isinstance(hit, dict):
            print(f"  #{i+1}: score={score:2d} phase={phase} "
                  f"kw={hit.get('keyword','?')}")
            if score >= 11:
                print(f"       PT: {hit.get('plaintext','?')[:60]}...")
        elif isinstance(hit, tuple):
            kw = hit[1] if len(hit) > 1 else "?"
            var = hit[2] if len(hit) > 2 else "?"
            print(f"  #{i+1}: score={score:2d} phase={phase} kw={kw} var={var}")
            pt = hit[3] if len(hit) > 3 else hit[4] if len(hit) > 4 else "?"
            if score >= 11 and isinstance(pt, str):
                print(f"       PT: {pt[:60]}...")

    # ── Save results ─────────────────────────────────────────────────
    ts = time.strftime('%Y%m%d_%H%M%S')
    result_file = os.path.join(_ROOT, "results",
                               f"null_mask_beaufort_deep_{ts}.json")

    serializable = []
    for score, phase, hit in all_hits[:200]:
        entry = {"score": score, "phase": phase}
        if isinstance(hit, dict):
            for k, v in hit.items():
                if isinstance(v, (str, int, float, bool, list)):
                    entry[k] = v
        elif isinstance(hit, tuple):
            entry["keyword"] = str(hit[1]) if len(hit) > 1 else "?"
            entry["variant"] = str(hit[2]) if len(hit) > 2 else "?"
            if len(hit) > 3 and isinstance(hit[3], str) and len(hit[3]) > 20:
                entry["plaintext"] = hit[3]
            elif len(hit) > 4 and isinstance(hit[4], str) and len(hit[4]) > 20:
                entry["plaintext"] = hit[4]
        serializable.append(entry)

    output = {
        "attack": "null_mask_beaufort_deep",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "ct": CT,
        "consensus_nulls": sorted(CONSENSUS_NULL_POSITIONS),
        "runtime_seconds": round(t_total, 1),
        "total_hits": len(all_hits),
        "best_score": best_score,
        "verdict": ("SIGNAL" if best_score >= SIGNAL_THRESHOLD
                    else "INTERESTING" if best_score >= STORE_THRESHOLD
                    else "NOISE"),
        "phases": {
            "P1A": {"hits": len(hits_1a), "desc": "thematic keywords"},
            "P1B": {"hits": len(hits_1b), "desc": "exhaustive 1-4 char keywords"},
            "P2": {"hits": len(hits_2), "desc": "variable null masks"},
            "P3": {"hits": len(hits_3), "desc": "crib-anchored reverse"},
            "P4": {"hits": len(hits_4), "desc": "near-identity alphabets"},
            "P5": {"hits": len(hits_5), "desc": "keyword-mixed from wordlist"},
        },
        "results": serializable,
    }

    os.makedirs(os.path.dirname(result_file), exist_ok=True)
    with open(result_file, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to: {result_file}")

    return best_score


if __name__ == "__main__":
    best = main()
    sys.exit(0 if best < SIGNAL_THRESHOLD else 1)
