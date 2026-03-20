#!/usr/bin/env python3 -u
"""
Cipher:     Stego-aware cipher key brute force
Family:     polyalphabetic
Status:     active
Keyspace:   55 masks × ~850K keywords × ~20 cycling rules × 4 modes + SA
Last run:   never
Best score: --

Three-phase attack exploiting the chi-square-favored null mask core:
  Phase 1: Keyword × cycling rule sweep (fast, exhaustive crib check)
  Phase 2: SA mask discriminator (which of 55 masks produces best English?)
  Phase 3: Deep SA on top masks with keyword seeds
"""

import sys, os, time, math, random, json
from pathlib import Path
from itertools import combinations
from collections import Counter, defaultdict
from multiprocessing import Pool, cpu_count

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, CRIB_POSITIONS, ALPH, ALPH_IDX, MOD,
    KRYPTOS_ALPHABET, BEAN_EQ, BEAN_INEQ,
)
from kryptos.kernel.alphabet import keyword_mixed_alphabet

# ── Quadgrams ────────────────────────────────────────────────────────────

QG_PATH = _ROOT / "data" / "english_quadgrams.json"
with open(QG_PATH) as f:
    _qg_raw = json.load(f)
QG_FLOOR = min(_qg_raw.values()) - 1.0
QG = [QG_FLOOR] * (26 ** 4)
for gram, logp in _qg_raw.items():
    if len(gram) == 4:
        a, b, c, d = [ord(ch) - 65 for ch in gram]
        QG[a * 17576 + b * 676 + c * 26 + d] = logp
del _qg_raw


def qg_score(arr):
    n = len(arr)
    if n < 4:
        return QG_FLOOR
    total = 0.0
    for i in range(n - 3):
        total += QG[arr[i] * 17576 + arr[i + 1] * 676 + arr[i + 2] * 26 + arr[i + 3]]
    return total / (n - 3)


# ── Mask setup ───────────────────────────────────────────────────────────

CONSENSUS_NULLS = {0, 1, 2, 5, 8, 12, 14, 20, 36, 52, 58, 59, 74, 75, 78, 84, 85}
CORE_5 = {38, 39, 45, 87, 93}
REMAINING_11 = [40, 41, 42, 43, 44, 55, 56, 88, 94, 95, 96]
CRIB_POS = sorted(CRIB_DICT.keys())


def build_55_masks():
    masks = []
    for extra in combinations(REMAINING_11, 2):
        full = CONSENSUS_NULLS | CORE_5 | set(extra)
        masks.append(sorted(full))
    return masks


def extract_text(ct, null_positions):
    """Remove null positions, return (extracted_text, position_map)."""
    null_set = set(null_positions)
    extracted = []
    pos_map = {}  # ct73_pos -> ct97_pos
    for i, ch in enumerate(ct):
        if i not in null_set:
            pos_map[len(extracted)] = i
            extracted.append(ch)
    return "".join(extracted), pos_map


def map_cribs_to_ct73(null_positions):
    """Map crib positions from CT97 to CT73 space."""
    null_set = set(null_positions)
    ct97_to_ct73 = {}
    ct73_pos = 0
    for i in range(CT_LEN):
        if i not in null_set:
            ct97_to_ct73[i] = ct73_pos
            ct73_pos += 1
    crib73 = {}
    for pos, ch in CRIB_DICT.items():
        if pos in ct97_to_ct73:
            crib73[ct97_to_ct73[pos]] = ch
    return crib73, ct97_to_ct73


# ── Thematic keywords ────────────────────────────────────────────────────

THEMATIC_KEYWORDS = [
    "ROSETTA", "PHARAOH", "PASSAGE", "PYRAMID", "OBELISK", "CARTER",
    "HOWARD", "TUTANKHAMUN", "THEBES", "LUXOR", "KARNAK", "VALLEY",
    "TOMB", "CRYPT", "MUMMY", "ANKH", "SCARAB", "PAPYRUS", "CANOPIC",
    "DISCOVERY", "EXCAVATE", "TREASURE", "SARCOPHAGUS", "WONDERFUL",
    "ANTECHAMBER", "HIEROGLYPH", "SPHINX", "QUEENS", "CARTOUCHE",
    # K1-K3 thematic
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "INVISIBLE",
    "ILLUSION", "NUANCE", "LAYERS", "MAGNETIC", "POSITION",
    # Survivor keywords
    "KOMPASS", "DEFECTOR", "COLOPHON", "SEVEN",
    # Berlin/espionage
    "BERLIN", "CLOCK", "ENIGMA", "COMPASS", "URANIA", "WELTZEITUHR",
    "HOROLOGE", "TELEGRAPH",
    # Additional Egypt
    "ROSETTASTONE", "AMENHOTEP", "AKHENATEN", "NEFERTITI", "RAMESSES",
    "CLEOPATRA", "PTOLEMY", "THEBAN", "MEMPHIS", "GIZA", "CHEOPS",
    "IMHOTEP", "ANUBIS", "OSIRIS", "HORUS", "THOTH", "HATHOR",
    "TEMPLE", "OBELISKS", "COLUMNS", "MASONRY", "CHAMBER",
    # Meta-decipherment (like PALIMPSEST/ABSCISSA)
    "ROSETTA", "CIPHER", "DECODE", "DECIPHER", "ENCRYPT", "SECRET",
    "HIDDEN", "CONCEAL", "OBSCURE", "CRYPTIC", "ENIGMATIC",
    # Numbers as words
    "SEVEN", "FIVE", "THREE", "EIGHT", "THIRTEEN", "ELEVEN",
    "TWENTYFOUR", "THIRTYFIVE", "NINETYSEVEN",
]


def load_all_keywords():
    """Load thematic + wordlist keywords, 3-12 letters."""
    words = set(w.upper() for w in THEMATIC_KEYWORDS)
    wl_path = _ROOT / "wordlists" / "english.txt"
    if wl_path.exists():
        with open(wl_path) as f:
            for line in f:
                w = line.strip().upper()
                if 3 <= len(w) <= 12 and w.isalpha():
                    words.add(w)
    return sorted(words)


# ── Phase 1: Keyword × cycling rule sweep ────────────────────────────────

def compute_required_keys(ct73, crib73, alph_idx, mode='beau'):
    """Compute required key values at crib positions in CT73 space."""
    required = {}
    for pos73, pt_ch in crib73.items():
        if pos73 >= len(ct73):
            continue
        ct_idx = alph_idx[ct73[pos73]]
        pt_idx = alph_idx[pt_ch]
        if mode == 'beau':
            required[pos73] = (ct_idx + pt_idx) % 26
        else:  # vig
            required[pos73] = (ct_idx - pt_idx) % 26
    return required


def check_keyword_cycling(keyword_indices, p, crib_positions_73, required_keys,
                          null_positions_73=None, se_positions_73=None):
    """Check multiple cycling rules for a keyword against crib constraints.

    Returns list of (rule_name, matches) for any rule achieving >=18/24.
    """
    hits = []
    crib_list = sorted(required_keys.keys())
    n_cribs = len(crib_list)

    # Rule 1: Standard periodic at multiple offsets
    for offset in range(p):
        matches = sum(1 for pos in crib_list
                      if keyword_indices[(pos + offset) % p] == required_keys[pos])
        if matches >= 18:
            hits.append((f"periodic_off{offset}", matches))
        if matches == n_cribs:
            hits.append((f"BREAKTHROUGH_periodic_off{offset}", matches))

    # Rule 2: Reversed keyword
    rev_kw = keyword_indices[::-1]
    for offset in range(p):
        matches = sum(1 for pos in crib_list
                      if rev_kw[(pos + offset) % p] == required_keys[pos])
        if matches >= 18:
            hits.append((f"reversed_off{offset}", matches))

    # Rule 3: Null-skip cycling (keyword advances only at non-null CT73 positions)
    # In CT73 space, ALL positions are non-null by definition, so this IS standard periodic.
    # But if we skip SELF-ENCRYPTING positions:
    if se_positions_73:
        se_set = set(se_positions_73)
        eff_pos = {}
        eff = 0
        max_pos = max(crib_list) if crib_list else 0
        for i in range(max_pos + 1):
            if i in se_set:
                eff_pos[i] = None
            else:
                eff_pos[i] = eff
                eff += 1
        for offset in range(p):
            matches = 0
            for pos in crib_list:
                ep = eff_pos.get(pos)
                if ep is not None and keyword_indices[(ep + offset) % p] == required_keys[pos]:
                    matches += 1
                elif ep is None:
                    # Self-encrypting: key doesn't matter (CT=PT)
                    matches += 1
            if matches >= 18:
                hits.append((f"se_skip_off{offset}", matches))

    # Rule 4: Boustrophedon (forward/backward alternating per keyword cycle)
    for offset in range(p):
        matches = 0
        for pos in crib_list:
            adj = (pos + offset)
            cycle = adj // p
            within = adj % p
            if cycle % 2 == 0:
                idx = within
            else:
                idx = p - 1 - within
            if keyword_indices[idx] == required_keys[pos]:
                matches += 1
        if matches >= 18:
            hits.append((f"boustro_off{offset}", matches))

    # Rule 5: Progressive shift (keyword + cycle_number)
    for offset in range(p):
        matches = 0
        for pos in crib_list:
            adj = pos + offset
            cycle = adj // p
            kw_val = (keyword_indices[adj % p] + cycle) % 26
            if kw_val == required_keys[pos]:
                matches += 1
        if matches >= 18:
            hits.append((f"prog_shift_off{offset}", matches))

    # Rule 6: Accumulating shift (keyword + sum of previous keyword letters in cycle)
    cum = [0] * p
    s = 0
    for j in range(p):
        cum[j] = s
        s = (s + keyword_indices[j]) % 26
    for offset in range(p):
        matches = 0
        for pos in crib_list:
            adj = pos + offset
            cycle = adj // p
            kw_val = (keyword_indices[adj % p] + cum[adj % p] + cycle * s) % 26
            if kw_val == required_keys[pos]:
                matches += 1
        if matches >= 18:
            hits.append((f"accum_off{offset}", matches))

    return hits


def phase1_worker(args):
    """Worker: test one mask × one keyword across cycling rules and modes."""
    mask, keyword, alph_name, alph_idx = args
    ct73, pos_map = extract_text(CT, mask)
    crib73, ct97_to_ct73 = map_cribs_to_ct73(mask)

    # Self-encrypting positions in CT73
    se_73 = []
    for pos97 in [32, 73]:
        if pos97 in ct97_to_ct73:
            se_73.append(ct97_to_ct73[pos97])

    p = len(keyword)
    try:
        K = [alph_idx[ch] for ch in keyword]
    except KeyError:
        return []  # non-A-Z character in keyword

    all_hits = []
    for mode in ['beau', 'vig']:
        required = compute_required_keys(ct73, crib73, alph_idx, mode)
        hits = check_keyword_cycling(K, p, sorted(required.keys()), required,
                                     se_positions_73=se_73)
        for rule, matches in hits:
            all_hits.append({
                "keyword": keyword,
                "mask_id": mask[:5],  # first 5 null positions as ID
                "alph": alph_name,
                "mode": mode,
                "rule": rule,
                "matches": matches,
            })
    return all_hits


KA_IDX = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}


def phase1(n_workers=28):
    """Phase 1: Keyword × cycling rule × mask sweep."""
    print("=" * 65)
    print("PHASE 1: Keyword × Cycling Rule Sweep (55 masks)")
    print("=" * 65)

    masks = build_55_masks()
    all_keywords = load_all_keywords()

    # Strategy: test ALL keywords on the best chi-square mask (index 0),
    # test THEMATIC keywords on all 55 masks
    thematic_set = set(w.upper() for w in THEMATIC_KEYWORDS if w.upper().isalpha())
    print(f"  Masks: {len(masks)}")
    print(f"  Total keywords: {len(all_keywords)}")
    print(f"  Thematic keywords: {len(thematic_set)}")

    tasks = []
    # All keywords × best mask × 2 alphabets
    for kw in all_keywords:
        tasks.append((masks[0], kw, "AZ", ALPH_IDX))
        tasks.append((masks[0], kw, "KA", KA_IDX))

    # Thematic keywords × all 55 masks × 2 alphabets
    for mask in masks:
        for kw in sorted(thematic_set):
            tasks.append((mask, kw, "AZ", ALPH_IDX))
            tasks.append((mask, kw, "KA", KA_IDX))

    print(f"  Tasks: {len(tasks):,}")
    print(f"  Cycling rules per task: ~12 (6 rules × 2 modes)")
    print(f"  Total configs: ~{len(tasks) * 12:,}")

    all_hits = []
    t0 = time.time()
    batch_size = 1000

    with Pool(min(n_workers, cpu_count())) as pool:
        for i, result in enumerate(pool.imap_unordered(phase1_worker, tasks, chunksize=50)):
            all_hits.extend(result)
            if (i + 1) % 10000 == 0:
                elapsed = time.time() - t0
                pct = (i + 1) / len(tasks) * 100
                best = max((h["matches"] for h in all_hits), default=0)
                print(f"  [{i+1:>8,}/{len(tasks):,}] {pct:.1f}% "
                      f"elapsed={elapsed:.0f}s hits={len(all_hits)} best={best}/24",
                      flush=True)

    elapsed = time.time() - t0
    all_hits.sort(key=lambda x: -x["matches"])
    print(f"\n  Phase 1 complete: {elapsed:.0f}s")
    print(f"  Total hits ≥18/24: {len(all_hits)}")
    if all_hits:
        print(f"  Best: {all_hits[0]['matches']}/24 keyword={all_hits[0]['keyword']} "
              f"rule={all_hits[0]['rule']} mode={all_hits[0]['mode']}")
    else:
        print("  ZERO hits ≥18/24")
    return all_hits, masks


# ── Phase 2: SA mask discriminator ───────────────────────────────────────

def sa_ct73_worker(args):
    """SA on extracted CT73 with Beaufort. Returns best score."""
    mask_idx, mask, seed, n_steps = args
    ct73, pos_map = extract_text(CT, mask)
    crib73, ct97_to_ct73 = map_cribs_to_ct73(mask)
    n = len(ct73)

    rng = random.Random(seed)
    ct_arr = [ALPH_IDX[ch] for ch in ct73]

    # Pin key at crib positions
    pinned = {}
    for pos73, pt_ch in crib73.items():
        pinned[pos73] = (ct_arr[pos73] + ALPH_IDX[pt_ch]) % 26  # Beaufort

    free_pos = [i for i in range(n) if i not in pinned]
    key = [0] * n
    for pos, val in pinned.items():
        key[pos] = val
    for pos in free_pos:
        key[pos] = rng.randint(0, 25)

    # Decrypt and score
    pt = [(key[i] - ct_arr[i]) % 26 for i in range(n)]
    cur_score = qg_score(pt)
    best_score = cur_score
    best_pt = pt[:]

    T_start = 2.0
    T_end = 0.005
    log_ratio = math.log(T_end / T_start)
    n_free = len(free_pos)

    for step in range(n_steps):
        T = T_start * math.exp(log_ratio * step / n_steps)
        pos = free_pos[rng.randint(0, n_free - 1)]
        old_val = key[pos]
        key[pos] = rng.randint(0, 25)
        if key[pos] == old_val:
            key[pos] = (old_val + rng.randint(1, 25)) % 26

        old_pt = pt[pos]
        pt[pos] = (key[pos] - ct_arr[pos]) % 26
        new_score = qg_score(pt)

        delta = new_score - cur_score
        if delta > 0 or (T > 0.001 and rng.random() < math.exp(delta / T)):
            cur_score = new_score
            if new_score > best_score:
                best_score = new_score
                best_pt = pt[:]
        else:
            key[pos] = old_val
            pt[pos] = old_pt

    pt_str = "".join(ALPH[v] for v in best_pt)
    return {
        "mask_idx": mask_idx,
        "score": best_score,
        "pt": pt_str,
        "seed": seed,
    }


def phase2(masks, n_workers=28, n_restarts_per_mask=100, n_steps=100_000):
    """Phase 2: SA discriminator — which mask produces best English?"""
    print("\n" + "=" * 65)
    print("PHASE 2: SA Mask Discriminator (55 masks × SA)")
    print("=" * 65)
    print(f"  Restarts per mask: {n_restarts_per_mask}")
    print(f"  Steps per restart: {n_steps:,}")

    tasks = []
    for idx, mask in enumerate(masks):
        for r in range(n_restarts_per_mask):
            seed = hash(f"mask{idx}_r{r}") % (2 ** 31)
            tasks.append((idx, mask, seed, n_steps))

    print(f"  Total SA restarts: {len(tasks):,}")

    results_by_mask = defaultdict(list)
    t0 = time.time()

    with Pool(min(n_workers, cpu_count())) as pool:
        for i, r in enumerate(pool.imap_unordered(sa_ct73_worker, tasks, chunksize=2)):
            results_by_mask[r["mask_idx"]].append(r)
            if (i + 1) % 200 == 0:
                elapsed = time.time() - t0
                print(f"  [{i+1:>5}/{len(tasks)}] {elapsed:.0f}s", flush=True)

    elapsed = time.time() - t0

    # Rank masks by best SA score
    mask_scores = []
    for idx in range(len(masks)):
        results = results_by_mask[idx]
        best = max(results, key=lambda x: x["score"])
        avg = sum(r["score"] for r in results) / len(results)
        mask_scores.append({
            "mask_idx": idx,
            "mask_varying": sorted(set(masks[idx]) - CONSENSUS_NULLS),
            "best_score": best["score"],
            "avg_score": avg,
            "best_pt": best["pt"],
        })

    mask_scores.sort(key=lambda x: -x["best_score"])
    print(f"\n  Phase 2 complete: {elapsed:.0f}s")
    print(f"  Top 10 masks by best SA score:")
    for ms in mask_scores[:10]:
        print(f"    varying={ms['mask_varying']} best={ms['best_score']:.4f} "
              f"avg={ms['avg_score']:.4f}")
        print(f"      PT: {ms['best_pt'][:60]}...")

    return mask_scores


# ── Phase 3: Deep SA on top masks with keyword seeds ─────────────────────

def sa_seeded_worker(args):
    """SA starting from a keyword-derived key."""
    mask_idx, mask, keyword, seed, n_steps = args
    ct73, pos_map = extract_text(CT, mask)
    crib73, ct97_to_ct73 = map_cribs_to_ct73(mask)
    n = len(ct73)

    rng = random.Random(seed)
    ct_arr = [ALPH_IDX[ch] for ch in ct73]
    kw_indices = [ALPH_IDX[ch] for ch in keyword]
    p = len(keyword)

    # Pin key at crib positions
    pinned = {}
    for pos73, pt_ch in crib73.items():
        pinned[pos73] = (ct_arr[pos73] + ALPH_IDX[pt_ch]) % 26

    free_pos = [i for i in range(n) if i not in pinned]

    # Initialize key from keyword (periodic seed)
    key = [kw_indices[i % p] for i in range(n)]
    for pos, val in pinned.items():
        key[pos] = val

    pt = [(key[i] - ct_arr[i]) % 26 for i in range(n)]
    cur_score = qg_score(pt)
    best_score = cur_score
    best_pt = pt[:]

    T_start = 2.0
    T_end = 0.005
    log_ratio = math.log(T_end / T_start)
    n_free = len(free_pos)

    for step in range(n_steps):
        T = T_start * math.exp(log_ratio * step / n_steps)
        pos = free_pos[rng.randint(0, n_free - 1)]
        old_val = key[pos]
        key[pos] = rng.randint(0, 25)
        if key[pos] == old_val:
            key[pos] = (old_val + rng.randint(1, 25)) % 26

        old_pt = pt[pos]
        pt[pos] = (key[pos] - ct_arr[pos]) % 26
        new_score = qg_score(pt)

        delta = new_score - cur_score
        if delta > 0 or (T > 0.001 and rng.random() < math.exp(delta / T)):
            cur_score = new_score
            if new_score > best_score:
                best_score = new_score
                best_pt = pt[:]
        else:
            key[pos] = old_val
            pt[pos] = old_pt

    pt_str = "".join(ALPH[v] for v in best_pt)
    return {
        "mask_idx": mask_idx,
        "keyword": keyword,
        "score": best_score,
        "pt": pt_str,
    }


def phase3(masks, top_mask_indices, n_workers=28, n_steps=200_000):
    """Phase 3: Deep SA on top masks with keyword seeds."""
    print("\n" + "=" * 65)
    print("PHASE 3: Deep SA with Keyword Seeds (top masks)")
    print("=" * 65)

    seed_keywords = [
        "ROSETTA", "PHARAOH", "PASSAGE", "PYRAMID", "OBELISK", "CARTER",
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "KOMPASS",
        "SEVEN", "SHADOW", "INVISIBLE", "DISCOVERY", "HIEROGLYPH",
        "SPHINX", "TREASURE", "CARTOUCHE", "TUTANKHAMUN",
    ]

    tasks = []
    for idx in top_mask_indices:
        mask = masks[idx]
        for kw in seed_keywords:
            for r in range(25):  # 25 restarts per keyword per mask
                seed = hash(f"deep_{idx}_{kw}_{r}") % (2 ** 31)
                tasks.append((idx, mask, kw, seed, n_steps))
        # Also 200 random-seed restarts
        for r in range(200):
            seed = hash(f"deep_rand_{idx}_{r}") % (2 ** 31)
            tasks.append((idx, mask, "RANDOM", seed, n_steps))

    print(f"  Top masks: {top_mask_indices}")
    print(f"  Seed keywords: {len(seed_keywords)}")
    print(f"  Total restarts: {len(tasks):,}")
    print(f"  Steps per restart: {n_steps:,}")

    results_by_mask = defaultdict(list)
    t0 = time.time()

    with Pool(min(n_workers, cpu_count())) as pool:
        for i, r in enumerate(pool.imap_unordered(sa_seeded_worker, tasks, chunksize=2)):
            results_by_mask[r["mask_idx"]].append(r)
            if (i + 1) % 200 == 0:
                elapsed = time.time() - t0
                best_all = max(
                    (r for rs in results_by_mask.values() for r in rs),
                    key=lambda x: x["score"], default={"score": -99}
                )
                print(f"  [{i+1:>5}/{len(tasks)}] {elapsed:.0f}s "
                      f"best={best_all['score']:.4f} kw={best_all.get('keyword','')}",
                      flush=True)

    elapsed = time.time() - t0
    print(f"\n  Phase 3 complete: {elapsed:.0f}s")

    # Report per-mask results
    all_results = []
    for idx in top_mask_indices:
        results = results_by_mask[idx]
        best = max(results, key=lambda x: x["score"])
        all_results.append(best)
        varying = sorted(set(masks[idx]) - CONSENSUS_NULLS)
        print(f"  Mask {idx} (varying={varying}):")
        print(f"    Best: score={best['score']:.4f} kw={best['keyword']}")
        print(f"    PT: {best['pt'][:60]}...")

    return all_results


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    print("Stego-Aware Cipher Key Brute Force")
    print(f"CT: {CT[:40]}... ({CT_LEN} chars)")
    print(f"Workers: {min(28, cpu_count())}")
    print()

    t0 = time.time()

    # Phase 1: Keyword × cycling rule sweep
    phase1_hits, masks = phase1()

    # Phase 2: SA mask discriminator
    mask_scores = phase2(masks, n_restarts_per_mask=100, n_steps=100_000)

    # Phase 3: Deep SA on top 5 masks
    top_indices = [ms["mask_idx"] for ms in mask_scores[:5]]
    phase3_results = phase3(masks, top_indices, n_steps=200_000)

    elapsed = time.time() - t0

    # Save results
    output = {
        "experiment": "e_stego_cipher_brute",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "elapsed_s": round(elapsed, 1),
        "phase1": {
            "n_masks": len(masks),
            "n_keywords": len(load_all_keywords()),
            "hits_18plus": phase1_hits[:20],
            "verdict": "BREAKTHROUGH" if any(h["matches"] == 24 for h in phase1_hits)
                       else f"{len(phase1_hits)}_hits" if phase1_hits else "noise",
        },
        "phase2": {
            "top_10_masks": [{
                "mask_varying": ms["mask_varying"],
                "best_score": ms["best_score"],
                "avg_score": ms["avg_score"],
            } for ms in mask_scores[:10]],
        },
        "phase3": {
            "top_results": [{
                "mask_idx": r["mask_idx"],
                "keyword": r["keyword"],
                "score": r["score"],
                "pt": r["pt"],
            } for r in sorted(phase3_results, key=lambda x: -x["score"])[:10]],
        },
    }

    out_path = _ROOT / "results" / "e_stego_cipher_brute.json"
    out_path.parent.mkdir(exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\nResults saved to {out_path}")
    print(f"Total elapsed: {elapsed:.0f}s ({elapsed / 3600:.1f}h)")


if __name__ == "__main__":
    main()
