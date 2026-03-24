"""
Cipher: Wheatstone clock
Family: novel
Status: active
Keyspace: ~425 keywords x 425 keywords x 27 x 26 x 2 alphabets x 3 modes = ~327M configs
Last run:
Best score:
"""
import sys, os, json, itertools, time
from datetime import datetime, timezone
from multiprocessing import Pool, cpu_count
from collections import defaultdict

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CRIB_DICT, ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET
from kryptos.kernel.scoring.aggregate import score_candidate, score_candidate_free
from kryptos.kernel.alphabet import keyword_mixed_alphabet

# ── Constants ────────────────────────────────────────────────────────────────

DELIMITER = '_'  # The 27th element on the PT ring (non-letter marker)

PRIORITY_KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "DEFECTOR",
    "SANBORN", "MEDUSA", "EAST", "BERLINCLOCK", "CLOCK",
    "WHEATSTONE", "CIPHER", "ENIGMA", "LANGLEY", "SCHEIDT",
]

def load_thematic_keywords(path, limit=500):
    """Load keywords from thematic_keywords.txt, skipping comments/blanks."""
    words = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or ' ' in line:
                    continue
                w = line.upper()
                if w.isalpha() and len(w) >= 2:
                    words.append(w)
                    if len(words) >= limit:
                        break
    except FileNotFoundError:
        pass
    return words


def build_keyword_list():
    """Build deduplicated keyword list with priority keywords first."""
    thematic_path = os.path.join(_ROOT, "wordlists", "thematic_keywords.txt")
    thematic = load_thematic_keywords(thematic_path, limit=500)

    seen = set()
    result = []
    for kw in PRIORITY_KEYWORDS + thematic:
        if kw not in seen:
            seen.add(kw)
            result.append(kw)
    return result


# ── Wheatstone Cipher Core ───────────────────────────────────────────────────

def make_ct_ring(keyword, base_alphabet=ALPH):
    """Build 26-char CT (inner) ring from keyword."""
    return keyword_mixed_alphabet(keyword, base_alphabet)


def make_pt_ring(keyword, base_alphabet=ALPH, delimiter_pos=0):
    """Build 27-char PT (outer) ring from keyword + delimiter.

    The delimiter is inserted at delimiter_pos (default: position 0, i.e., before
    the keyword-mixed alphabet). This matches the classic Wheatstone convention
    where the blank/space is at a specific position on the outer ring.
    """
    alpha = keyword_mixed_alphabet(keyword, base_alphabet)
    # Insert delimiter at the specified position
    ring = alpha[:delimiter_pos] + DELIMITER + alpha[delimiter_pos:]
    assert len(ring) == 27, f"PT ring length {len(ring)}"
    return ring


def wheatstone_decrypt_stepping(ct_text, ct_ring, pt_ring, ct_start=0, pt_start=0):
    """Classic Wheatstone decryption with fixed +1 stepping on both rings.

    Mechanism:
    - Two pointers track the current alignment of each ring.
    - For each CT character, find its position on the CT ring.
    - Compute the angular offset from the CT pointer.
    - Apply the same offset from the PT pointer on the PT ring.
    - Read the PT character at that position.
    - Advance both pointers by 1 (mod their respective ring sizes).

    Since CT ring has 26 positions and PT ring has 27, the relative offset
    shifts by 1 position per step, cycling with period lcm(26,27)=702.
    """
    ct_ptr = ct_start % 26
    pt_ptr = pt_start % 27
    plaintext = []

    for c in ct_text:
        if c not in ct_ring:
            plaintext.append('?')
            ct_ptr = (ct_ptr + 1) % 26
            pt_ptr = (pt_ptr + 1) % 27
            continue

        ct_pos = ct_ring.index(c)
        offset = (ct_pos - ct_ptr) % 26
        pt_pos = (pt_ptr + offset) % 27
        pt_char = pt_ring[pt_pos]

        if pt_char == DELIMITER:
            # Delimiter hit -- skip it, don't add to plaintext
            # In practice this means the message is shorter than CT
            plaintext.append('')
        else:
            plaintext.append(pt_char)

        # Fixed stepping
        ct_ptr = (ct_ptr + 1) % 26
        pt_ptr = (pt_ptr + 1) % 27

    return ''.join(plaintext)


def wheatstone_encrypt_stepping(pt_text, ct_ring, pt_ring, ct_start=0, pt_start=0):
    """Classic Wheatstone encryption with fixed +1 stepping."""
    ct_ptr = ct_start % 26
    pt_ptr = pt_start % 27
    ciphertext = []

    for p in pt_text:
        if p not in pt_ring:
            ciphertext.append('?')
            ct_ptr = (ct_ptr + 1) % 26
            pt_ptr = (pt_ptr + 1) % 27
            continue

        pt_pos = pt_ring.index(p)
        offset = (pt_pos - pt_ptr) % 27
        # Map the offset to the CT ring -- since CT ring is smaller,
        # we take offset mod 26
        ct_pos = (ct_ptr + offset) % 26
        ct_char = ct_ring[ct_pos]
        ciphertext.append(ct_char)

        ct_ptr = (ct_ptr + 1) % 26
        pt_ptr = (pt_ptr + 1) % 27

    return ''.join(ciphertext)


def wheatstone_decrypt_autokey(ct_text, ct_ring, pt_ring, ct_start=0, pt_start=0):
    """Wheatstone decryption with plaintext autokey stepping.

    After decrypting each letter, the PT ring pointer advances to the
    position of the just-decrypted PT letter (autokey), while the CT
    ring pointer advances by 1 (standard stepping).
    """
    ct_ptr = ct_start % 26
    pt_ptr = pt_start % 27
    plaintext = []

    for c in ct_text:
        if c not in ct_ring:
            plaintext.append('?')
            ct_ptr = (ct_ptr + 1) % 26
            continue

        ct_pos = ct_ring.index(c)
        offset = (ct_pos - ct_ptr) % 26
        pt_pos = (pt_ptr + offset) % 27
        pt_char = pt_ring[pt_pos]

        if pt_char == DELIMITER:
            plaintext.append('')
            # For delimiter, advance PT by 1 as fallback
            pt_ptr = (pt_ptr + 1) % 27
        else:
            plaintext.append(pt_char)
            # Autokey: advance PT pointer to the position of this PT letter
            pt_ptr = pt_pos

        # CT ring always advances by 1
        ct_ptr = (ct_ptr + 1) % 26

    return ''.join(plaintext)


def wheatstone_decrypt_ct_autokey(ct_text, ct_ring, pt_ring, ct_start=0, pt_start=0):
    """Wheatstone decryption with ciphertext autokey stepping.

    After decrypting each letter, the CT ring pointer advances to the
    position of the just-consumed CT letter, while the PT ring pointer
    advances by 1.
    """
    ct_ptr = ct_start % 26
    pt_ptr = pt_start % 27
    plaintext = []

    for c in ct_text:
        if c not in ct_ring:
            plaintext.append('?')
            pt_ptr = (pt_ptr + 1) % 27
            continue

        ct_pos = ct_ring.index(c)
        offset = (ct_pos - ct_ptr) % 26
        pt_pos = (pt_ptr + offset) % 27
        pt_char = pt_ring[pt_pos]

        if pt_char == DELIMITER:
            plaintext.append('')
        else:
            plaintext.append(pt_char)

        # CT autokey: advance CT pointer to the position of this CT letter
        ct_ptr = ct_pos
        # PT ring advances by 1
        pt_ptr = (pt_ptr + 1) % 27

    return ''.join(plaintext)


# ── Scoring helpers ──────────────────────────────────────────────────────────

def quick_crib_check(pt, threshold=3):
    """Fast pre-filter: count how many crib letters match at known positions.
    Returns count of matches. Full scoring only if >= threshold.
    """
    matches = 0
    for pos, expected in CRIB_DICT.items():
        if pos < len(pt) and pt[pos] == expected:
            matches += 1
    return matches


# ── Worker functions for multiprocessing (must be module-level) ──────────────

def _eval_keyword_pair(args):
    """Evaluate all start positions for a keyword pair + base + mode.

    Returns list of hits with score >= threshold.
    """
    ct_kw, pt_kw, base_label, mode = args

    base_alpha = ALPH if base_label == "AZ" else KRYPTOS_ALPHABET
    ct_ring = make_ct_ring(ct_kw, base_alpha)

    hits = []

    for delim_pos in [0, 13, 26]:
        pt_ring = make_pt_ring(pt_kw, base_alpha, delimiter_pos=delim_pos)

        for ct_start in range(26):
            for pt_start in range(27):
                if mode == "stepping":
                    pt = wheatstone_decrypt_stepping(CT, ct_ring, pt_ring, ct_start, pt_start)
                elif mode == "autokey":
                    pt = wheatstone_decrypt_autokey(CT, ct_ring, pt_ring, ct_start, pt_start)
                elif mode == "ct_autokey":
                    pt = wheatstone_decrypt_ct_autokey(CT, ct_ring, pt_ring, ct_start, pt_start)
                else:
                    continue

                if len(pt) < 97:
                    pt = pt + 'X' * (97 - len(pt))
                pt = pt[:97]

                matches = quick_crib_check(pt)
                if matches >= 3:
                    hits.append({
                        "ct_keyword": ct_kw,
                        "pt_keyword": pt_kw,
                        "base": base_label,
                        "ct_start": ct_start,
                        "pt_start": pt_start,
                        "mode": mode,
                        "delim_pos": delim_pos,
                        "plaintext": pt,
                        "crib_matches": matches,
                    })

    return hits


def _eval_single(args):
    """Evaluate a single configuration (module-level for pickling)."""
    ct_kw, pt_kw, base_label, mode, ct_s, pt_s, delim_pos = args
    base_alpha = ALPH if base_label == "AZ" else KRYPTOS_ALPHABET
    ct_ring = make_ct_ring(ct_kw, base_alpha)
    pt_ring = make_pt_ring(pt_kw, base_alpha, delimiter_pos=delim_pos)

    if mode == "stepping":
        pt = wheatstone_decrypt_stepping(CT, ct_ring, pt_ring, ct_s, pt_s)
    elif mode == "autokey":
        pt = wheatstone_decrypt_autokey(CT, ct_ring, pt_ring, ct_s, pt_s)
    elif mode == "ct_autokey":
        pt = wheatstone_decrypt_ct_autokey(CT, ct_ring, pt_ring, ct_s, pt_s)
    else:
        return None

    if len(pt) < 97:
        pt = pt + 'X' * (97 - len(pt))
    pt = pt[:97]

    matches = quick_crib_check(pt)
    if matches >= 3:
        return {
            "ct_keyword": ct_kw,
            "pt_keyword": pt_kw,
            "base": base_label,
            "ct_start": ct_s,
            "pt_start": pt_s,
            "mode": mode,
            "delim_pos": delim_pos,
            "plaintext": pt,
            "crib_matches": matches,
        }
    return None


# ── Sub-message variant ──────────────────────────────────────────────────────

def test_sub_messages(ct_ring, pt_ring, ct_start, pt_start, mode, splits=None):
    """Test K4 as 2 or 3 sub-messages with independent ring resets.

    splits: list of (start, end) tuples for sub-message boundaries.
    Default: [(0,33), (33,66), (66,97)] (the 33/33/31 hypothesis).
    """
    if splits is None:
        splits = [(0, 33), (33, 66), (66, 97)]

    full_pt = []
    for start, end in splits:
        sub_ct = CT[start:end]
        if mode == "stepping":
            sub_pt = wheatstone_decrypt_stepping(sub_ct, ct_ring, pt_ring, ct_start, pt_start)
        elif mode == "autokey":
            sub_pt = wheatstone_decrypt_autokey(sub_ct, ct_ring, pt_ring, ct_start, pt_start)
        elif mode == "ct_autokey":
            sub_pt = wheatstone_decrypt_ct_autokey(sub_ct, ct_ring, pt_ring, ct_start, pt_start)
        else:
            sub_pt = sub_ct
        full_pt.append(sub_pt)

    return ''.join(full_pt)


# ── Main search ──────────────────────────────────────────────────────────────

def main():
    print(f"=== Wheatstone Clock Cipher Attack on K4 ===", flush=True)
    print(f"CT: {CT}", flush=True)
    print(f"CT length: {len(CT)}", flush=True)
    print(f"Start: {datetime.now(timezone.utc).isoformat()}", flush=True)
    print(flush=True)

    keywords = build_keyword_list()
    print(f"Keywords loaded: {len(keywords)}", flush=True)

    modes = ["stepping", "autokey", "ct_autokey"]
    bases = ["AZ", "KA"]

    # Phase 1: Priority keywords -- full position sweep
    print(f"\n--- Phase 1: Priority keyword pairs (full position sweep) ---", flush=True)

    priority_tasks = []
    for ct_kw in PRIORITY_KEYWORDS:
        for pt_kw in PRIORITY_KEYWORDS:
            for base in bases:
                for mode in modes:
                    priority_tasks.append((ct_kw, pt_kw, base, mode))

    print(f"Priority tasks: {len(priority_tasks)} keyword-pair configs", flush=True)
    print(f"Each config tests 26 x 27 x 3 = {26*27*3} (start positions x delim positions)", flush=True)

    all_hits = []
    best_score = 0
    best_hit = None

    n_workers = min(cpu_count() - 1, 4)  # Leave cores for other work
    n_workers = max(n_workers, 1)
    print(f"Workers: {n_workers}", flush=True)

    t0 = time.time()
    configs_done = 0

    with Pool(n_workers) as pool:
        for i, hits in enumerate(pool.imap_unordered(_eval_keyword_pair, priority_tasks, chunksize=4)):
            configs_done += 1
            if hits:
                for h in hits:
                    all_hits.append(h)
                    if h["crib_matches"] > best_score:
                        best_score = h["crib_matches"]
                        best_hit = h
                        print(f"  NEW BEST: {best_score}/24 | "
                              f"ct_kw={h['ct_keyword']} pt_kw={h['pt_keyword']} "
                              f"base={h['base']} mode={h['mode']} "
                              f"ct_s={h['ct_start']} pt_s={h['pt_start']} "
                              f"delim={h['delim_pos']}", flush=True)
                        print(f"  PT: {h['plaintext'][:50]}...", flush=True)

            if configs_done % 100 == 0:
                elapsed = time.time() - t0
                rate = configs_done / elapsed if elapsed > 0 else 0
                print(f"  Phase 1: {configs_done}/{len(priority_tasks)} "
                      f"({rate:.1f} configs/s) best={best_score}/24 "
                      f"hits={len(all_hits)}", flush=True)

    elapsed_p1 = time.time() - t0
    print(f"\nPhase 1 complete: {elapsed_p1:.1f}s, {len(all_hits)} hits, "
          f"best={best_score}/24", flush=True)

    # Phase 2: Full keyword list -- sampled positions for speed
    print(f"\n--- Phase 2: Full keyword list (sampled positions) ---", flush=True)

    # For the full keyword list, test only a subset of start positions
    # to keep runtime reasonable. Focus on start=0 and a few others.
    sample_starts = [(0, 0), (0, 13), (13, 0), (13, 13), (25, 26)]

    phase2_tasks = []
    for ct_kw in keywords:
        for pt_kw in keywords[:50]:  # Limit PT keywords for cross-product
            for base in bases:
                for mode in modes:
                    for ct_s, pt_s in sample_starts:
                        for delim_pos in [0, 13, 26]:
                            phase2_tasks.append((ct_kw, pt_kw, base, mode, ct_s, pt_s, delim_pos))

    print(f"Phase 2 tasks: {len(phase2_tasks)} configs", flush=True)

    t1 = time.time()
    configs_done_p2 = 0

    with Pool(n_workers) as pool:
        for result in pool.imap_unordered(_eval_single, phase2_tasks, chunksize=200):
            configs_done_p2 += 1
            if result is not None:
                all_hits.append(result)
                if result["crib_matches"] > best_score:
                    best_score = result["crib_matches"]
                    best_hit = result
                    print(f"  NEW BEST: {best_score}/24 | "
                          f"ct_kw={result['ct_keyword']} pt_kw={result['pt_keyword']} "
                          f"base={result['base']} mode={result['mode']} "
                          f"ct_s={result['ct_start']} pt_s={result['pt_start']} "
                          f"delim={result['delim_pos']}", flush=True)
                    print(f"  PT: {result['plaintext'][:50]}...", flush=True)

            if configs_done_p2 % 50000 == 0:
                elapsed = time.time() - t1
                rate = configs_done_p2 / elapsed if elapsed > 0 else 0
                print(f"  Phase 2: {configs_done_p2}/{len(phase2_tasks)} "
                      f"({rate:.0f} configs/s) best={best_score}/24 "
                      f"hits={len(all_hits)}", flush=True)

    elapsed_p2 = time.time() - t1
    print(f"\nPhase 2 complete: {elapsed_p2:.1f}s, best={best_score}/24", flush=True)

    # Phase 3: Sub-message splits (33/33/31 and 48/49)
    print(f"\n--- Phase 3: Sub-message splits ---", flush=True)

    split_configs = [
        [(0, 33), (33, 66), (66, 97)],   # 33/33/31
        [(0, 48), (48, 97)],              # 48/49
        [(0, 49), (49, 97)],              # 49/48
        [(0, 32), (32, 65), (65, 97)],    # 32/33/32
    ]

    sub_hits = []
    for ct_kw in PRIORITY_KEYWORDS[:8]:
        for pt_kw in PRIORITY_KEYWORDS[:8]:
            for base in bases:
                base_alpha = ALPH if base == "AZ" else KRYPTOS_ALPHABET
                ct_ring = make_ct_ring(ct_kw, base_alpha)
                for mode in modes:
                    for splits in split_configs:
                        for delim_pos in [0, 13, 26]:
                            pt_ring = make_pt_ring(pt_kw, base_alpha, delimiter_pos=delim_pos)
                            for ct_s in range(0, 26, 5):
                                for pt_s in range(0, 27, 5):
                                    pt = test_sub_messages(ct_ring, pt_ring, ct_s, pt_s, mode, splits)
                                    if len(pt) < 97:
                                        pt = pt + 'X' * (97 - len(pt))
                                    pt = pt[:97]
                                    matches = quick_crib_check(pt)
                                    if matches >= 3:
                                        hit = {
                                            "ct_keyword": ct_kw,
                                            "pt_keyword": pt_kw,
                                            "base": base,
                                            "ct_start": ct_s,
                                            "pt_start": pt_s,
                                            "mode": mode,
                                            "delim_pos": delim_pos,
                                            "splits": splits,
                                            "plaintext": pt,
                                            "crib_matches": matches,
                                        }
                                        sub_hits.append(hit)
                                        if matches > best_score:
                                            best_score = matches
                                            best_hit = hit
                                            print(f"  NEW BEST (sub-msg): {best_score}/24 | "
                                                  f"{ct_kw}/{pt_kw}/{base}/{mode} "
                                                  f"splits={splits}", flush=True)

    all_hits.extend(sub_hits)
    print(f"Phase 3 complete: {len(sub_hits)} sub-message hits", flush=True)

    # ── Full scoring on top hits ─────────────────────────────────────────────
    print(f"\n--- Scoring top hits ---", flush=True)

    # Sort by crib matches, take top 50
    all_hits.sort(key=lambda h: h["crib_matches"], reverse=True)
    top_hits = all_hits[:50]

    scored_results = []
    for h in top_hits:
        pt = h["plaintext"]
        breakdown = score_candidate(pt)
        free_breakdown = score_candidate_free(pt)

        h["score_anchored"] = breakdown.to_dict()
        h["score_free"] = free_breakdown.to_dict() if hasattr(free_breakdown, 'to_dict') else str(free_breakdown)
        h["score_summary"] = breakdown.summary
        scored_results.append(h)

        if h["crib_matches"] >= 4:
            print(f"  {breakdown.summary} | {h['ct_keyword']}/{h['pt_keyword']}/{h['base']}/{h['mode']}", flush=True)
            print(f"    PT: {pt[:60]}...", flush=True)

    # ── Save results ─────────────────────────────────────────────────────────
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    results_path = os.path.join(_ROOT, "results", f"wheatstone_clock_{timestamp}.json")

    output = {
        "attack": "Wheatstone clock cipher",
        "family": "novel",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ciphertext": CT,
        "ct_length": len(CT),
        "keywords_tested": len(keywords),
        "modes": modes,
        "bases": bases,
        "total_hits_above_3": len(all_hits),
        "best_crib_score": best_score,
        "best_hit": best_hit,
        "top_50": scored_results,
        "phase1_time_s": round(elapsed_p1, 1),
        "phase2_time_s": round(elapsed_p2, 1),
        "conclusion": "PROMISING" if best_score >= 10 else
                      "INCONCLUSIVE" if best_score >= 6 else
                      "NOISE",
    }

    with open(results_path, 'w') as f:
        json.dump(output, f, indent=2, default=str)

    print(f"\n=== RESULTS ===", flush=True)
    print(f"Results saved to: {results_path}", flush=True)
    print(f"Total hits (>= 3 crib matches): {len(all_hits)}", flush=True)
    print(f"Best crib score: {best_score}/24", flush=True)
    print(f"Conclusion: {output['conclusion']}", flush=True)

    if best_hit:
        print(f"\nBest config:", flush=True)
        for k, v in best_hit.items():
            if k != "plaintext":
                print(f"  {k}: {v}", flush=True)
        print(f"  plaintext: {best_hit['plaintext']}", flush=True)

    total_time = time.time() - t0
    print(f"\nTotal runtime: {total_time:.1f}s", flush=True)

    return output


# ── Self-test ────────────────────────────────────────────────────────────────

def self_test():
    """Verify encrypt/decrypt roundtrip for all three modes."""
    print("Running self-tests...", flush=True)

    ct_ring = make_ct_ring("KRYPTOS")
    pt_ring = make_pt_ring("KRYPTOS")

    test_pt = "HELLOWORLD"

    # Test stepping mode roundtrip
    encrypted = wheatstone_encrypt_stepping(test_pt, ct_ring, pt_ring, 0, 0)
    decrypted = wheatstone_decrypt_stepping(encrypted, ct_ring, pt_ring, 0, 0)
    # Remove any delimiter artifacts
    decrypted_clean = decrypted.replace('', '')
    assert decrypted_clean == test_pt, \
        f"Stepping roundtrip failed: {test_pt} -> {encrypted} -> {decrypted_clean}"
    print(f"  Stepping roundtrip: PASS ({test_pt} -> {encrypted} -> {decrypted_clean})", flush=True)

    # Test that different start positions produce different output
    enc1 = wheatstone_encrypt_stepping(test_pt, ct_ring, pt_ring, 0, 0)
    enc2 = wheatstone_encrypt_stepping(test_pt, ct_ring, pt_ring, 5, 3)
    assert enc1 != enc2, "Different start positions should produce different ciphertext"
    print(f"  Different starts produce different CT: PASS", flush=True)

    # Test that different keywords produce different output
    ct_ring2 = make_ct_ring("SANBORN")
    enc3 = wheatstone_encrypt_stepping(test_pt, ct_ring2, pt_ring, 0, 0)
    assert enc1 != enc3, "Different CT keywords should produce different ciphertext"
    print(f"  Different keywords produce different CT: PASS", flush=True)

    # Test non-periodicity: encrypt a repeated character
    repeated = "AAAAAAAAAAAAAAAAAAAAAAAAAAAA"  # 28 A's (> lcm period)
    enc_rep = wheatstone_encrypt_stepping(repeated, ct_ring, pt_ring, 0, 0)
    # Check that the output is NOT periodic with any small period
    is_periodic = False
    for p in range(1, 14):
        chunk = enc_rep[:p]
        if all(enc_rep[i] == chunk[i % p] for i in range(len(enc_rep))):
            is_periodic = True
            break
    assert not is_periodic, f"Wheatstone should NOT be periodic for small periods"
    print(f"  Non-periodicity check: PASS (encrypted 'AAA...' has no small period)", flush=True)

    # Just verify that autokey produces different output from stepping
    dec_step = wheatstone_decrypt_stepping(CT[:20], ct_ring, pt_ring, 0, 0)
    dec_ak = wheatstone_decrypt_autokey(CT[:20], ct_ring, pt_ring, 0, 0)
    assert dec_step != dec_ak, "Autokey should differ from stepping"
    print(f"  Autokey differs from stepping: PASS", flush=True)

    # Test CT autokey also differs
    dec_ctak = wheatstone_decrypt_ct_autokey(CT[:20], ct_ring, pt_ring, 0, 0)
    assert dec_ctak != dec_step, "CT autokey should differ from stepping"
    assert dec_ctak != dec_ak, "CT autokey should differ from PT autokey"
    print(f"  CT autokey differs from others: PASS", flush=True)

    # Test PT ring has 27 elements
    assert len(pt_ring) == 27, f"PT ring should be 27 chars, got {len(pt_ring)}"
    assert DELIMITER in pt_ring, "PT ring should contain delimiter"
    print(f"  PT ring = 27 chars with delimiter: PASS", flush=True)

    # Test CT ring has 26 elements
    assert len(ct_ring) == 26, f"CT ring should be 26 chars, got {len(ct_ring)}"
    print(f"  CT ring = 26 chars: PASS", flush=True)

    print("All self-tests passed.\n", flush=True)


if __name__ == "__main__":
    self_test()
    main()
