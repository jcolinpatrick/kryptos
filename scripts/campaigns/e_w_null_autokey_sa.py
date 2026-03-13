#!/usr/bin/env python3
"""
Cipher:   W-as-Null + Autokey SA (Model A)
Family:   campaigns
Status:   active
Keyspace: 5 W-nulls fixed + 19 SA-searched × 340kw × 2modes × 3ciphers × 2alph = ~816M
Last run:
Best score:

W-AS-NULL + AUTOKEY SA
-----------------------
Hypothesis: The 5 W chars at positions [20,36,48,58,74] are the NULL DELIMITERS.
Fix these as 5 of 24 nulls. SA searches for the remaining 19 null positions.
W-as-null is structurally motivated: W brackets BOTH cribs (W[20] before ENE,
W[74] after BERLINCLOCK), matches telegram delimiter ('what's the point?').

KEY DIFFERENCE from e_two_sys_04_autokey_mask_sa.py:
  - That script does NOT fix W positions (random initial mask)
  - That script has never been run (no Last run date)
  - This script ANCHORS 5 of 24 nulls at W positions

Autokey hides English statistics (matches Scheidt 'masking technique').
Null mask + PERIODIC sub proven impossible (Bean). Autokey is non-periodic → OPEN.
"""

import math, os, random, sys, time
import multiprocessing as mp

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, KRYPTOS_ALPHABET,
    CRIB_DICT, CRIB_POSITIONS,
)

# ── Constants ──────────────────────────────────────────────────────────────

W_NULLS = frozenset([20, 36, 48, 58, 74])   # fixed null positions (W chars)
N_NULLS = 24                                  # total nulls
N_EXTRA = N_NULLS - len(W_NULLS)             # = 19 additional nulls needed

# Positions that CANNOT be nulls (crib positions)
FORBIDDEN = CRIB_POSITIONS   # frozenset(21..33 ∪ 63..73)

# Available positions for the 19 extra nulls
AVAILABLE = sorted(set(range(CT_LEN)) - W_NULLS - FORBIDDEN)
# len(AVAILABLE) = 97 - 5 - 24 = 68

CRIB_LIST = sorted(CRIB_DICT.items())

# SA parameters
SA_ITERATIONS = 50_000
SA_RESTARTS = 4
SA_T_INIT = 2.0
SA_T_MIN = 0.01
SA_COOLING = 0.99993

REPORT_THRESHOLD = 6
N_WORKERS = min(28, os.cpu_count() or 4)

ALPHABETS = {
    "AZ": (ALPH, {c: i for i, c in enumerate(ALPH)}),
    "KA": (KRYPTOS_ALPHABET, {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}),
}

def vig_dec(c, k): return (c - k) % 26
def beau_dec(c, k): return (k - c) % 26
def vbeau_dec(c, k): return (c + k) % 26
CIPHERS = {"Vig": vig_dec, "Beau": beau_dec, "VBeau": vbeau_dec}

PRIORITY_KEYWORDS = [
    "KRYPTOS", "KOMPASS", "DEFECTOR", "COLOPHON", "ABSCISSA",
    "SHADOW", "PARALLAX", "VERDIGRIS", "KRYPTA", "KOLOPHON",
    "CIPHER", "SECRET", "BERLIN", "CLOCK", "PALIMPSEST",
    "SANBORN", "SCHEIDT", "LANGLEY", "MAGNETIC", "LODESTONE",
    "COMPASS", "ENIGMA",
]

THEMATIC_KEYWORDS_FILE = os.path.join(
    os.path.dirname(__file__), '..', '..', 'wordlists', 'thematic_keywords.txt'
)

def load_keywords():
    kws = set(PRIORITY_KEYWORDS)
    if os.path.exists(THEMATIC_KEYWORDS_FILE):
        with open(THEMATIC_KEYWORDS_FILE) as f:
            for line in f:
                w = line.strip().upper()
                if w and not w.startswith('#') and 3 <= len(w) <= 20 and w.isalpha():
                    kws.add(w)
    return sorted(kws)

# ── Autokey decryption ─────────────────────────────────────────────────────

def decrypt_pt_autokey(ct_ords, kw_ords, dec_fn):
    L = len(kw_ords)
    key = list(kw_ords)
    pt = []
    for c in ct_ords:
        k = key[len(pt)] if len(pt) < L else pt[len(pt) - L]
        p = dec_fn(c, k)
        pt.append(p)
        key.append(p)
    return pt

def decrypt_ct_autokey(ct_ords, kw_ords, dec_fn):
    L = len(kw_ords)
    pt = []
    for i, c in enumerate(ct_ords):
        k = kw_ords[i] if i < L else ct_ords[i - L]
        pt.append(dec_fn(c, k))
    return pt

# ── Scoring ────────────────────────────────────────────────────────────────

def score_autokey_w_null(extra_nulls_set, ct_full, kw_ords, c2i, alph_str, dec_fn, mode):
    """Remove W+extra nulls, decrypt 73-char with autokey, score cribs."""
    full_nulls = W_NULLS | extra_nulls_set
    ct_ords = []
    orig_to_red = {}
    ridx = 0
    for i in range(CT_LEN):
        if i not in full_nulls:
            ct_ords.append(c2i[ct_full[i]])
            orig_to_red[i] = ridx
            ridx += 1

    if mode == "pt":
        pt = decrypt_pt_autokey(ct_ords, kw_ords, dec_fn)
    else:
        pt = decrypt_ct_autokey(ct_ords, kw_ords, dec_fn)

    # Mapped crib hits
    mapped = sum(
        1 for orig, ch in CRIB_LIST
        if orig in orig_to_red and orig_to_red[orig] < len(pt)
        and pt[orig_to_red[orig]] == ord(ch) - 65
    )
    # Free crib bonus
    pt_str = ''.join(alph_str[p] for p in pt)
    free = 13 if "EASTNORTHEAST" in pt_str else 0
    free += 11 if "BERLINCLOCK" in pt_str else 0
    return max(mapped, free), pt_str

# ── SA search ──────────────────────────────────────────────────────────────

def sa_search(args):
    keyword = args["keyword"]
    cipher_name = args["cipher_name"]
    alph_name = args["alph_name"]
    mode = args["mode"]
    seed = args["seed"]

    alph_str, c2i = ALPHABETS[alph_name]
    dec_fn = CIPHERS[cipher_name]
    try:
        kw_ords = [c2i[c] for c in keyword]
    except KeyError:
        return []

    rng = random.Random(seed)
    results = []
    best_overall = {"score": -1}

    for restart in range(SA_RESTARTS):
        extra = list(rng.sample(AVAILABLE, N_EXTRA))
        extra_set = set(extra)
        non_null = [p for p in AVAILABLE if p not in extra_set]

        cur_score, cur_pt = score_autokey_w_null(extra_set, CT, kw_ords, c2i, alph_str, dec_fn, mode)
        best_score = cur_score
        best_extra = list(extra)
        best_pt = cur_pt

        T = SA_T_INIT
        for _ in range(SA_ITERATIONS):
            ri = rng.randrange(N_EXTRA)
            ai = rng.randrange(len(non_null))
            extra[ri], non_null[ai] = non_null[ai], extra[ri]
            new_set = set(extra)

            new_score, new_pt = score_autokey_w_null(new_set, CT, kw_ords, c2i, alph_str, dec_fn, mode)
            delta = new_score - cur_score
            if delta >= 0 or (T > SA_T_MIN and rng.random() < math.exp(delta / T)):
                cur_score, cur_pt = new_score, new_pt
                if cur_score > best_score:
                    best_score = cur_score
                    best_extra = list(extra)
                    best_pt = cur_pt
            else:
                extra[ri], non_null[ai] = non_null[ai], extra[ri]
            T *= SA_COOLING

        if best_score >= REPORT_THRESHOLD:
            results.append({
                "keyword": keyword, "cipher": cipher_name,
                "alphabet": alph_name, "mode": mode,
                "null_extra": sorted(best_extra),
                "score": best_score, "plaintext": best_pt,
            })
        if best_score > best_overall["score"]:
            best_overall = {
                "keyword": keyword, "cipher": cipher_name,
                "alphabet": alph_name, "mode": mode,
                "null_extra": sorted(best_extra),
                "score": best_score, "plaintext": best_pt,
            }

    if best_overall not in results and best_overall["score"] >= 0:
        results.append(best_overall)
    return results

# ── Main ──────────────────────────────────────────────────────────────────

def main():
    t0 = time.time()
    keywords = load_keywords()

    print("=" * 78)
    print("E-W-NULL-AUTOKEY-SA: W positions fixed as 5 of 24 nulls + SA autokey")
    print("=" * 78)
    print(f"CT ({CT_LEN} chars): {CT}")
    print(f"Fixed W nulls: {sorted(W_NULLS)}")
    print(f"Available for extra nulls: {len(AVAILABLE)} positions")
    print(f"Keywords: {len(keywords)} | Autokey modes: pt, ct | Ciphers: Vig/Beau/VBeau")
    print(f"SA: {SA_ITERATIONS:,} iters × {SA_RESTARTS} restarts | Workers: {N_WORKERS}")

    tasks = []
    tid = 0
    for kw in keywords:
        for mode in ["pt", "ct"]:
            for cn in CIPHERS:
                for an in ALPHABETS:
                    tasks.append({
                        "keyword": kw, "cipher_name": cn,
                        "alph_name": an, "mode": mode,
                        "seed": 42 + tid,
                    })
                    tid += 1

    total_evals = len(tasks) * SA_RESTARTS * SA_ITERATIONS
    print(f"Total SA configs: {len(tasks):,} | Total evals: {total_evals:,}")
    print()
    sys.stdout.flush()

    all_results = []
    done = 0
    batch = N_WORKERS * 2

    with mp.Pool(N_WORKERS) as pool:
        for i in range(0, len(tasks), batch):
            b = tasks[i:i + batch]
            for res in pool.map(sa_search, b):
                all_results.extend(res)
            done += len(b)
            elapsed = time.time() - t0
            rate = done / elapsed if elapsed else 0
            hits = len([r for r in all_results if r["score"] >= REPORT_THRESHOLD])
            print(f"  [{done}/{len(tasks)}] {elapsed:.0f}s {rate:.1f}/s | hits≥{REPORT_THRESHOLD}: {hits}")
            sys.stdout.flush()

    elapsed = time.time() - t0
    print(f"\n{'=' * 78}")
    print(f"RESULTS | Elapsed: {elapsed:.1f}s")
    all_results.sort(key=lambda r: -r["score"])
    reportable = [r for r in all_results if r["score"] >= REPORT_THRESHOLD]
    print(f"Results with score >= {REPORT_THRESHOLD}: {len(reportable)}")

    for i, r in enumerate(all_results[:20]):
        print(f"  #{i+1}: score={r['score']} | {r['keyword']}/{r['cipher']}/{r['alphabet']}/{r['mode']}")
        print(f"       null_extra={r['null_extra'][:8]}...")
        print(f"       PT: {r['plaintext']}")

    best_score = all_results[0]["score"] if all_results else 0
    print(f"\nBest score: {best_score}/24")
    if best_score >= 18:
        print("*** SIGNAL — INVESTIGATE ***")
    elif best_score >= REPORT_THRESHOLD:
        print("Above noise floor")
    else:
        print("NOISE — W-null autokey: no signal")
    print("=" * 78)

if __name__ == "__main__":
    main()
