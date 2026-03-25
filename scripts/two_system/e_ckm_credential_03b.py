#!/usr/bin/env python3
"""
Cipher: constructive-key-management
Family: two_system
Status: active
Keyspace: ~1.92M
Last run:
Best score:

E-CKM-03b: CKM M1 with Top 1000 English Words

Follow-up to E-CKM-03 which tested 33 thematic keywords and got zero hits.
Now tests ~1000 English words (lengths 3-13) from wordlists/english.txt
using only Model M1 (the most general):

  key[i] = f(section[(i+offset) % Ls], keyword[i % Lk]) mod 26

Words are sampled evenly across the 896K-word alphabetical file to get
broad alphabet coverage rather than being stuck in AAA-ABE.

Parameters:
  - Sections: K1, K2, K3 plaintexts
  - Keywords: ~1000 English words (lengths 3-13), evenly sampled
  - Combiners: add, sub_AB, sub_BA, xor (4)
  - Cipher variants: vig, beau, vbeau (3)
  - Alphabets: AZ, KA (2)
  - Offsets: 0-19 (20)
  - CT variants: CT97 + 3 CT73 masks (4)
  - Threshold: >= 8
"""

import json
import os
import sys
import time
from multiprocessing import Pool, cpu_count

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, MOD, CRIB_DICT

# ── K1/K2/K3 Plaintext ("credentials") ──────────────────────────────────
K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
K2_PT = "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELD"
K3_PT = (
    "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBERED"
    "THELOWERPARTOFTHEDOORWAYWASREMOVEDWITHTREMBLINGHANDSIMADEA"
    "TINYBREACHINTHEUPPERLEFTHANDCORNERANDTHENWIDENINGTHEHOLE"
    "ALITTLEINSERTEDACANDLEANDPEEREDIN"
)

SECTION_SOURCES = [
    ("K1", K1_PT),
    ("K2", K2_PT),
    ("K3", K3_PT),
]

# ── Load ~1000 English words evenly sampled ──────────────────────────────
def load_english_words_sampled(path, target_count=1000):
    """Load all valid words, then sample evenly to get ~target_count."""
    all_valid = []
    with open(path, "r") as f:
        for line in f:
            w = line.strip()
            if 3 <= len(w) <= 13 and w.isalpha() and w.isascii():
                all_valid.append(w.upper())

    n = len(all_valid)
    if n <= target_count:
        return all_valid

    # Evenly sample target_count words across the full list
    step = n / target_count
    words = []
    for i in range(target_count):
        idx = int(i * step)
        words.append(all_valid[idx])

    # Deduplicate while preserving order
    seen = set()
    deduped = []
    for w in words:
        if w not in seen:
            seen.add(w)
            deduped.append(w)

    return deduped

WORDLIST_PATH = os.path.join(_ROOT, "wordlists", "english.txt")

# ── Ciphertext setup ─────────────────────────────────────────────────────
CT_NUM = [ALPH_IDX[c] for c in CT]

# Consensus null masks
CONSENSUS_NULLS = {0, 1, 2, 5, 8, 12, 14, 20, 36, 52, 58, 59, 74, 75, 78, 84, 85}
MASK_A = sorted(CONSENSUS_NULLS | {38, 39, 40, 55, 87, 93, 94})
MASK_B = sorted(CONSENSUS_NULLS | {38, 39, 40, 56, 88, 93, 94})
MASK_C = sorted(CONSENSUS_NULLS | {41, 42, 43, 55, 87, 95, 96})


def extract_ct(mask):
    """Remove null positions from CT, return (ct73_nums, crib_map, length)."""
    mask_set = set(mask)
    ct73 = []
    pos_map = {}
    j = 0
    for i in range(CT_LEN):
        if i not in mask_set:
            ct73.append(CT_NUM[i])
            pos_map[i] = j
            j += 1
    crib73 = {}
    for pos, ch in CRIB_DICT.items():
        if pos in pos_map:
            crib73[pos_map[pos]] = ALPH_IDX[ch]
    return ct73, crib73, len(ct73)


CT73_VARIANTS = {}
for name, mask in [("mask_a", MASK_A), ("mask_b", MASK_B), ("mask_c", MASK_C)]:
    CT73_VARIANTS[name] = extract_ct(mask)

CRIB97 = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}

# ── KA alphabet ──────────────────────────────────────────────────────────
KA_STR = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {c: i for i, c in enumerate(KA_STR)}


def to_nums(text, alpha):
    idx = ALPH_IDX if alpha == "AZ" else KA_IDX
    return [idx[c] for c in text if c in idx]


# ── Combination functions ────────────────────────────────────────────────
def combine_add(a, b):
    return (a + b) % MOD

def combine_sub_ab(a, b):
    return (a - b) % MOD

def combine_sub_ba(a, b):
    return (b - a) % MOD

def combine_xor_like(a, b):
    return (a ^ b) % MOD

COMBINERS = [
    ("add", combine_add),
    ("sub_AB", combine_sub_ab),
    ("sub_BA", combine_sub_ba),
    ("xor", combine_xor_like),
]


# ── Core scoring ─────────────────────────────────────────────────────────
def score_key(key_nums, ct_nums, crib_map, ct_len):
    best = 0
    best_var = ""
    key_len = len(key_nums)

    for var_name, sign_a, sign_b in [("vig", 1, -1), ("beau", -1, 1), ("vbeau", 1, 1)]:
        score = 0
        for pos, expected in crib_map.items():
            if pos < ct_len and pos < key_len:
                pt_val = (sign_a * ct_nums[pos] + sign_b * key_nums[pos]) % MOD
                if pt_val == expected:
                    score += 1
        if score > best:
            best = score
            best_var = var_name

    return best, best_var


# ── Model M1: key[i] = f(section[(i+offset) % Ls], keyword[i % Lk]) ────
def build_m1_key(section_nums, kw_nums, offset, comb_fn, length):
    Ls = len(section_nums)
    Lk = len(kw_nums)
    key = []
    for i in range(length):
        si = (i + offset) % Ls
        ki = i % Lk
        key.append(comb_fn(section_nums[si], kw_nums[ki]))
    return key


# ── Worker: process a batch of keywords for one (section, alpha) ─────────
def worker_batch(args):
    """Test M1 for a batch of keywords against one (section, alpha)."""
    section_name, section_text, kw_batch, alpha_name = args

    section_nums = to_nums(section_text, alpha_name)
    if not section_nums:
        return [], 0

    Ls = len(section_nums)
    hits = []
    tested = 0
    max_offset = min(Ls, 20)

    for kw_text in kw_batch:
        kw_nums = to_nums(kw_text, alpha_name)
        if not kw_nums:
            continue

        for comb_name, comb_fn in COMBINERS:
            for d in range(max_offset):
                # CT97
                key = build_m1_key(section_nums, kw_nums, d, comb_fn, CT_LEN)
                score, var = score_key(key, CT_NUM, CRIB97, CT_LEN)
                tested += 1
                if score >= 8:
                    hits.append((score, var, f"M1_{section_name}+{kw_text}",
                                 comb_name, d, alpha_name, "ct97"))

                # CT73 variants
                for ct_name, (ct73, crib73, ct73_len) in CT73_VARIANTS.items():
                    key73 = build_m1_key(section_nums, kw_nums, d, comb_fn, ct73_len)
                    score, var = score_key(key73, ct73, crib73, ct73_len)
                    tested += 1
                    if score >= 8:
                        hits.append((score, var, f"M1_{section_name}+{kw_text}",
                                     comb_name, d, alpha_name, ct_name))

    return hits, tested


# ── Main ─────────────────────────────────────────────────────────────────
def main():
    t0 = time.time()
    print("=" * 72)
    print("E-CKM-03b: CKM M1 with Top 1000 English Words")
    print("=" * 72)

    # Load words (evenly sampled across the alphabetical file)
    words = load_english_words_sampled(WORDLIST_PATH, target_count=1000)
    print(f"Loaded {len(words)} English words (lengths 3-13, evenly sampled)")
    print(f"  First 5: {words[:5]}")
    print(f"  Mid:     {words[len(words)//2 : len(words)//2 + 5]}")
    print(f"  Last 5:  {words[-5:]}")

    n_workers = min(cpu_count(), 28)
    print(f"Workers: {n_workers}")

    BATCH_SIZE = 50  # keywords per work item

    work_items = []
    for sname, stext in SECTION_SOURCES:
        for alpha in ["AZ", "KA"]:
            for i in range(0, len(words), BATCH_SIZE):
                batch = words[i:i + BATCH_SIZE]
                work_items.append((sname, stext, batch, alpha))

    print(f"Work items: {len(work_items)} (batches of {BATCH_SIZE} keywords)")
    est_configs = len(words) * 3 * 2 * 4 * 20 * 4
    print(f"Estimated configs: ~{est_configs:,}")

    all_hits = []
    total_tested = 0

    with Pool(n_workers) as pool:
        results = pool.map(worker_batch, work_items)

    for hits, tested in results:
        total_tested += tested
        all_hits.extend(hits)

    elapsed = time.time() - t0
    all_hits.sort(key=lambda x: -x[0])

    print()
    print("=" * 72)
    print(f"COMPLETE: {total_tested:,} configs in {elapsed:.1f}s "
          f"({total_tested / max(elapsed, 0.01):,.0f} configs/sec)")
    print(f"Hits >= 8: {len(all_hits)}")

    if all_hits:
        print(f"BEST SCORE: {all_hits[0][0]}/24")
        print()
        print("TOP 20 RESULTS:")
        print("-" * 72)
        for h in all_hits[:20]:
            score, var, model_label, comb, d, alpha, ct_name = h
            print(f"  {score:2d}/24 | {var:6s} | {alpha:2s} | {ct_name:6s} | "
                  f"d={d:2d} {comb:6s} | {model_label}")
    else:
        print("ZERO hits >= 8. CKM M1 English wordlist = NOISE.")

    print("=" * 72)

    # Score distribution
    score_dist = {}
    for h in all_hits:
        s = h[0]
        score_dist[s] = score_dist.get(s, 0) + 1
    print(f"\nScore distribution (>=8): {dict(sorted(score_dist.items()))}")

    # Save results
    output = {
        "experiment": "E-CKM-03b",
        "description": "CKM M1 with ~1000 English Words (evenly sampled from wordlists/english.txt)",
        "hypothesis": "K4 key = f(K-section PT, English keyword) mod 26 (M1 model)",
        "total_configs": total_tested,
        "elapsed_seconds": round(elapsed, 1),
        "configs_per_second": round(total_tested / max(elapsed, 0.01)),
        "model": "M1: key[i] = f(section[(i+offset) % Ls], keyword[i % Lk]) mod 26",
        "sections": ["K1", "K2", "K3"],
        "n_keywords": len(words),
        "keyword_source": "wordlists/english.txt (~1000 evenly sampled, lengths 3-13)",
        "sample_words": words[:10] + ["..."] + words[-10:],
        "combiners": ["add", "sub_AB", "sub_BA", "xor"],
        "cipher_variants": ["vig", "beau", "vbeau"],
        "alphabets": ["AZ", "KA"],
        "offsets": "0-19",
        "ct_variants": ["ct97", "mask_a", "mask_b", "mask_c"],
        "threshold": 8,
        "best_score": all_hits[0][0] if all_hits else 0,
        "hits_above_8": len(all_hits),
        "score_distribution": score_dist,
        "top_20": [
            {
                "score": h[0], "variant": h[1], "model": h[2],
                "combiner": h[3], "offset": h[4], "alphabet": h[5],
                "ct_name": h[6],
            }
            for h in all_hits[:20]
        ],
    }

    out_path = os.path.join(_ROOT, "results", "e_ckm_credential_03b.json")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {out_path}")


if __name__ == "__main__":
    main()
