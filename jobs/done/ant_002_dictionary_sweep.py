#!/usr/bin/env python3
"""ANT-002: Dictionary Keyword Sweep on Antipodes Segments

Heavy-compute experiment: tries every word in english.txt (370K) and
thematic_keywords.txt (~340) as a Vigenère/Beaufort/VarBeau keyword on
multiple Antipodes segments, in both KA-space and AZ-space.

Targets:
  - K4 alone (97 chars) — the unsolved section
  - Stream Alpha: merged K3+K4 (433 chars) — if K3+K4 are one block
  - K2 alone (370 chars) — with UNDERGROUND correction, recheck

For K4: dual-hypothesis scoring (same message via cribs, OR different
English message via IC + quadgrams).

For Stream Alpha: no cribs available at K3 positions, so pure statistical
scoring (IC + quadgrams + word detection).

Scoring pipeline:
  1. Decrypt with keyword
  2. Fast IC check (flag if > 0.050)
  3. If flagged: full quadgram scoring
  4. For K4: also check cribs (flag if > NOISE_FLOOR)
  5. For all: check for common English words in output

Search space: ~370K words × 3 variants × 2 alphabets × 3 targets = ~6.7M configs
Expected runtime: ~30-60 min with 28 workers

Usage:
    PYTHONPATH=src python3 -u jobs/pending/ant_002_dictionary_sweep.py --workers 28
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter
from multiprocessing import Pool
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, MOD,
    CRIB_DICT, N_CRIBS,
    KRYPTOS_ALPHABET,
    NOISE_FLOOR, STORE_THRESHOLD,
)
from kryptos.kernel.scoring.ic import ic
from kryptos.kernel.scoring.ngram import NgramScorer
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, DECRYPT_FN, KEY_RECOVERY,
)

# ── Paths ────────────────────────────────────────────────────────────────────

ROOT = Path(__file__).resolve().parent.parent.parent
RESULTS_DIR = ROOT / "results" / "ant_002"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
SUMMARY_FILE = ROOT / "reports" / "ant_002_dictionary_sweep.summary.json"
QUADGRAM_FILE = ROOT / "data" / "english_quadgrams.json"
WORDLIST_FILE = ROOT / "wordlists" / "english.txt"
THEMATIC_FILE = ROOT / "wordlists" / "thematic_keywords.txt"

# ── Alphabets ────────────────────────────────────────────────────────────────

KA = KRYPTOS_ALPHABET
KA_IDX: Dict[str, int] = {c: i for i, c in enumerate(KA)}
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
AZ_IDX: Dict[str, int] = {c: i for i, c in enumerate(AZ)}

# ── Antipodes Grid ───────────────────────────────────────────────────────────

ANTIPODES_ROWS = [
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACH",
    "TNREYULDSLLSLLNOHSNOSMRWXMNETPRNG",
    "ATIHNRARPESLNNELEBLPIIACAEWMTWNDITE",
    "ENRAHCTENEUDRETNHAEOETFOLSEDTIWENH",
    "AEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWE",
    "NATAMATEGYEERLBTEEFOASFIOTUETUAEOT",
    "OARMAEERTNRTIBSEDDNIAAHTTMSTEWPIER",
    "OAGRIEWFEBAECTDDHILCEIHSITEGOEAOSDD",
    "RYDLORITRKLMLEHAGTDHARDPNEOHMGFMF",
    "EUHEECDMRIPFEIMEHNLSSTTRTVDOHWOBK",
    "RUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTW",
    "TQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZF",
    "PKWGDKZXTJCDIGKUHUAUEKCAREMUFPHZL",
    "RFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQV",
    "YUVLLTREVJYQTMKYRDMFDVFPJUDEEHZWE",
    "TZYVGWHKKQETGFQJNCEGGWHKKDQMCPFQ",
    "ZDQMMIAGPFXHQRLGTIMVMZJANQLVKQEDA",
    "GDVFRPJUNGEUNAQZGZLECGYUXUEENJTBJL",
    "BQCETBJDFHRRYIZETKZEMVDUFKSJHKFWHK",
    "UWQLSZFTIHHDDDUVHDWKBFUFPWNTDFIYC",
    "UQZEREEVLDKFEZMOQQJLTTUGSYQPFEUNLA",
    "VIDXFLGGTEZFKZBSFDQVGOGIPUFXHHDRKF",
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQELZ",
    "ZVRRGKFFVOEEXBDMVPNFQXEZLGREDNQFM",
    "PNZGLFLPMRJQYALMGNUVPDXVKPDQUMEBE",
    "DMHDAFMJGZNUPLGEWJLLAETGENDYAHROH",
    "NLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSL",
    "LSLLNOHSNOSMRWXMNETPRNGATIHNRARPE",
    "SLNNELEBLPIIACAEWMTWNDITEENRAHCTEN",
    "EUDRETNHAEOETFOLSEDTIWENHAEIOYTEYQ",
    "HEENCTAYCREIFTBRSPAMHHEWENATAMATEG",
    "YEERLBTEEFOASFIOTUETUAEOTOARMAEERT",
    "NRTIBSEDDNIAAHTTMSTEWPIEROAGRIEWFEB",
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORITRKL",
    "MLEHAGTDHARDPNEOHMGFMFEUHEECDMRIP",
    "FEIMEHNLSSTTRTVDOHWOBKRUOXOGHULBS",
    "OLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZ",
    "WATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJ",
    "CDIGKUHUAUEKCAREMUFPHZLRFAXYUSDJKZ",
    "LDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJY",
    "QTMKYRDMFDVFPJUDEEHZWETZYVGWHKKQ",
    "ETGFQJNCEGGWHKKDQMCPFQZDQMMIAGPF",
    "XHQRLGTIMVMZJANQLVKQEDAGDVFRPJUNG",
    "EUNAQZGZLECGYUXUEENJTBJLBQCETBJDFH",
    "RRYIZETKZEMVDUFKSJHKFWHKUWQLSZFTIH",
    "HDDDUVHDWKBFUFPWNTDFIYCUQZEREEVLD",
    "KFEZMOQQJLTTUGSYQPFEUNLAVIDXFLGGTEZ",
]

FLAT = "".join(ANTIPODES_ROWS)

# ── Section boundaries ───────────────────────────────────────────────────────

K4_P1 = FLAT.find(CT)
assert K4_P1 >= 0

K3_CT_STR = (
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLLNOHSNOSMRWXMNE"
    "TPRNGATIHNRARPESLNNELEBLPIIACAEWMTWNDITEENRAHCTENEUDRETNHAEOE"
    "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWENATAMATEGYEERLB"
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTIBSEDDNIAAHTTMSTEWPIEROAGRIEWFEB"
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORITRKLMLEHAGTDHARDPNEOHMGFMFEUHE"
    "ECDMRIPFEIMEHNLSSTTRTVDOHW"
)

K1_CT_STR = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"

# Full K2 CT (Kryptos version — 370 chars, with R at pos 114)
K2_CT_KRYPTOS = (
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKKDQMCPFQZDQMMIAGPFXHQRLG"
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNAQZGZLECGYUXUEENJTBJLBQCRTBJDFHRR"
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTIHHDDDUVHDWKBFUFPWNTDFIYCUQZERE"
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDXFLGGTEZFKZBSFDQVGOGIPUFXHHDRKF"
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE"
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKPDQUMEBEDMHDAFMJGZNUPLGEWJLLAETG"
)

# Sections
STREAM_ALPHA = FLAT[:K4_P1 + CT_LEN]  # K3+K4 = 433 chars
K1_START = K4_P1 + CT_LEN
K2_START = K1_START + len(K1_CT_STR)

# Antipodes K2 (370 chars with E at pos 114)
AP_K2 = FLAT[K2_START:K2_START + len(K2_CT_KRYPTOS)]

# ── Crib expectations for K4 ────────────────────────────────────────────────

CRIB_SORTED = sorted(CRIB_DICT.items())
CPOS = [p for p, _ in CRIB_SORTED]

# Precompute EXPECTED keys for each variant × alphabet
def _precompute_expected():
    """For K4 cribs, precompute expected key values."""
    results = {}
    ct_ints_ka = [KA_IDX[CT[p]] for p in CPOS]
    ct_ints_az = [ord(CT[p]) - 65 for p in CPOS]
    pt_chars = [c for _, c in CRIB_SORTED]
    pt_ints_ka = [KA_IDX[c] for c in pt_chars]
    pt_ints_az = [ord(c) - 65 for c in pt_chars]

    for var in (CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT):
        kr = KEY_RECOVERY[var]
        for alph_name, ct_ints, pt_ints in [
            ("ka", ct_ints_ka, pt_ints_ka),
            ("az", ct_ints_az, pt_ints_az),
        ]:
            expected = [kr(ct_ints[i], pt_ints[i]) % MOD for i in range(len(CPOS))]
            results[(var, alph_name)] = expected
    return results

EXPECTED = _precompute_expected()

# ── Common English words for word detection ─────────────────────────────────

COMMON_WORDS = {
    "THE", "AND", "THAT", "HAVE", "WITH", "THIS", "WILL", "YOUR",
    "FROM", "THEY", "BEEN", "SAID", "EACH", "WHICH", "THEIR", "TIME",
    "ABOUT", "WOULD", "THERE", "COULD", "OTHER", "AFTER", "THESE",
    "FIRST", "ALSO", "PEOPLE", "INTO", "JUST", "OVER", "SUCH",
    "MAKE", "LIKE", "THAN", "THEM", "SOME", "WHAT", "ONLY", "COME",
    "MADE", "FIND", "HERE", "THING", "MANY", "WELL", "BETWEEN",
    "NORTH", "EAST", "SOUTH", "WEST", "BERLIN", "CLOCK", "LIGHT",
    "SHADOW", "BURIED", "SECRET", "HIDDEN", "TUNNEL", "WALL",
    "CHAMBER", "PASSAGE", "SLOWLY", "INVISIBLE", "MAGNETIC",
    "FIELD", "LOCATION", "MESSAGE", "POSITION", "UNKNOWN",
}

def count_words(text: str) -> int:
    """Count how many common English words appear in text."""
    count = 0
    for w in COMMON_WORDS:
        if w in text:
            count += 1
    return count


# ── Decryption functions ────────────────────────────────────────────────────

def decrypt(ct: str, key_ints: List[int], variant: CipherVariant,
            alph: str, alph_idx: Dict[str, int]) -> str:
    """Decrypt ciphertext with integer key array."""
    fn = DECRYPT_FN[variant]
    return "".join(
        alph[fn(alph_idx[ct[i]], key_ints[i % len(key_ints)]) % MOD]
        for i in range(len(ct))
    )


def keyword_to_key(keyword: str, alph_idx: Dict[str, int]) -> List[int]:
    """Convert keyword string to integer key array."""
    return [alph_idx[c] for c in keyword]


# ── Worker function ─────────────────────────────────────────────────────────

# Globals set by pool initializer
_ngram_scorer = None
_ic_threshold = 0.050
_quadgram_threshold = -5.5


def _init_worker():
    """Initialize per-worker globals (ngram scorer)."""
    global _ngram_scorer
    _ngram_scorer = NgramScorer.from_file(str(QUADGRAM_FILE))


def _worker(work_item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Process a single keyword × variant × alphabet × target config."""
    keyword = work_item["keyword"]
    variant = work_item["variant"]
    alph_name = work_item["alph"]
    target = work_item["target"]
    target_ct = work_item["target_ct"]

    alph = KA if alph_name == "ka" else AZ
    alph_idx = KA_IDX if alph_name == "ka" else AZ_IDX

    # Check keyword is valid in this alphabet
    for c in keyword:
        if c not in alph_idx:
            return None

    key_ints = keyword_to_key(keyword, alph_idx)
    pt = decrypt(target_ct, key_ints, variant, alph, alph_idx)

    # ── Fast scoring ──
    result = {
        "keyword": keyword,
        "variant": variant.name,
        "alph": alph_name,
        "target": target,
    }

    # IC check
    pt_ic = ic(pt)
    result["ic"] = round(pt_ic, 5)

    # Crib check (K4 only)
    crib_score = 0
    if target == "k4":
        expected = EXPECTED[(variant, alph_name)]
        key_len = len(key_ints)
        for i, pos in enumerate(CPOS):
            if key_ints[pos % key_len] == expected[i]:
                crib_score += 1
        result["crib_score"] = crib_score

    # Word detection
    word_count = count_words(pt)
    result["word_count"] = word_count

    # Flag thresholds
    ic_flagged = pt_ic > _ic_threshold
    crib_flagged = crib_score > NOISE_FLOOR
    word_flagged = word_count >= 5

    if not (ic_flagged or crib_flagged or word_flagged):
        return None  # Below all thresholds

    # Full quadgram scoring for flagged configs
    if _ngram_scorer and len(pt) >= 4:
        qscore = _ngram_scorer.score(pt) / len(pt)
        result["quadgram_per_char"] = round(qscore, 4)
    else:
        result["quadgram_per_char"] = -999.0

    result["pt_preview"] = pt[:60]
    result["flagged_by"] = []
    if ic_flagged:
        result["flagged_by"].append("ic")
    if crib_flagged:
        result["flagged_by"].append("crib")
    if word_flagged:
        result["flagged_by"].append("words")

    return result


# ── Main ─────────────────────────────────────────────────────────────────────

def load_wordlist() -> List[str]:
    """Load and prepare wordlist."""
    words = set()

    # English dictionary
    with open(WORDLIST_FILE) as f:
        for line in f:
            w = line.strip().upper()
            if w and all(c in AZ for c in w) and 3 <= len(w) <= 30:
                words.add(w)

    # Thematic keywords
    with open(THEMATIC_FILE) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            w = line.upper()
            if all(c in AZ for c in w):
                words.add(w)

    return sorted(words)


def generate_work_items(words: List[str]) -> List[Dict[str, Any]]:
    """Generate all work items (keyword × variant × alph × target)."""
    variants = [
        CipherVariant.VIGENERE,
        CipherVariant.BEAUFORT,
        CipherVariant.VAR_BEAUFORT,
    ]
    targets = [
        ("k4", CT),
        ("stream_alpha", STREAM_ALPHA),
    ]
    alphs = ["ka", "az"]

    items = []
    for keyword in words:
        for variant in variants:
            for alph_name in alphs:
                for target_name, target_ct in targets:
                    items.append({
                        "keyword": keyword,
                        "variant": variant,
                        "alph": alph_name,
                        "target": target_name,
                        "target_ct": target_ct,
                    })
    return items


def main():
    parser = argparse.ArgumentParser(description="ANT-002: Dictionary sweep on Antipodes segments")
    parser.add_argument("--workers", type=int, default=28, help="Number of parallel workers")
    args = parser.parse_args()

    print("=" * 70)
    print("ANT-002: Dictionary Keyword Sweep on Antipodes Segments")
    print("=" * 70)
    print(f"Workers: {args.workers}")
    print(f"Targets: K4 ({CT_LEN} chars), Stream Alpha ({len(STREAM_ALPHA)} chars)")
    print()

    # Load wordlist
    t0 = time.time()
    words = load_wordlist()
    print(f"Loaded {len(words)} keywords in {time.time()-t0:.1f}s")

    # Generate work items
    work_items = generate_work_items(words)
    total = len(work_items)
    print(f"Total configs: {total:,}")
    print()

    # Process with worker pool
    hits: List[Dict[str, Any]] = []
    best_ic = {"k4": 0.0, "stream_alpha": 0.0}
    best_crib = 0
    best_words = {"k4": 0, "stream_alpha": 0}
    processed = 0
    t_start = time.time()

    results_file = RESULTS_DIR / "hits.jsonl"

    with open(results_file, "w") as fout:
        with Pool(processes=args.workers, initializer=_init_worker) as pool:
            # Process in chunks for better progress reporting
            chunk_size = max(1, total // (args.workers * 100))
            for result in pool.imap_unordered(_worker, work_items, chunksize=chunk_size):
                processed += 1
                if processed % 500_000 == 0:
                    elapsed = time.time() - t_start
                    rate = processed / elapsed
                    eta = (total - processed) / rate if rate > 0 else 0
                    print(f"  [{processed:,}/{total:,}] {processed/total*100:.1f}% "
                          f"| {rate:.0f}/s | ETA {eta:.0f}s "
                          f"| hits={len(hits)} | best_ic_k4={best_ic['k4']:.4f} "
                          f"| best_crib={best_crib}")
                    sys.stdout.flush()

                if result is None:
                    continue

                hits.append(result)
                fout.write(json.dumps(result) + "\n")

                target = result["target"]
                r_ic = result["ic"]
                if r_ic > best_ic[target]:
                    best_ic[target] = r_ic
                if target == "k4" and result.get("crib_score", 0) > best_crib:
                    best_crib = result["crib_score"]
                if result.get("word_count", 0) > best_words[target]:
                    best_words[target] = result["word_count"]

                # Breakthrough detection
                if result.get("crib_score", 0) >= 18:
                    print(f"\n  *** SIGNAL: crib={result['crib_score']} "
                          f"kw={result['keyword']} var={result['variant']} "
                          f"alph={result['alph']} ***")
                    print(f"      PT: {result.get('pt_preview', '')}")
                    sys.stdout.flush()
                if r_ic > 0.060:
                    print(f"\n  *** HIGH IC: {r_ic:.4f} "
                          f"kw={result['keyword']} var={result['variant']} "
                          f"target={target} ***")
                    print(f"      PT: {result.get('pt_preview', '')}")
                    sys.stdout.flush()

    elapsed = time.time() - t_start

    # ── Summary ──────────────────────────────────────────────────────────────

    print()
    print("=" * 70)
    print("ANT-002 RESULTS")
    print("=" * 70)
    print(f"Total configs:  {total:,}")
    print(f"Processed:      {processed:,}")
    print(f"Hits (flagged): {len(hits)}")
    print(f"Elapsed:        {elapsed:.1f}s ({elapsed/60:.1f}min)")
    print(f"Rate:           {processed/elapsed:.0f} configs/s")
    print()
    print(f"Best IC (K4):           {best_ic['k4']:.5f}")
    print(f"Best IC (Stream Alpha): {best_ic['stream_alpha']:.5f}")
    print(f"Best crib (K4):         {best_crib}")
    print(f"Best words (K4):        {best_words['k4']}")
    print(f"Best words (Alpha):     {best_words['stream_alpha']}")

    # Top hits by quadgram
    if hits:
        top_by_quad = sorted(hits, key=lambda h: h.get("quadgram_per_char", -999), reverse=True)[:20]
        print("\n  Top 20 by quadgram/char:")
        for h in top_by_quad:
            print(f"    qg={h.get('quadgram_per_char', -999):.3f} "
                  f"ic={h['ic']:.4f} "
                  f"crib={h.get('crib_score', '-')} "
                  f"words={h.get('word_count', 0)} "
                  f"kw={h['keyword']} var={h['variant']} "
                  f"alph={h['alph']} target={h['target']}")
            print(f"         {h.get('pt_preview', '')}")

    # Save summary
    summary = {
        "experiment": "ant_002_dictionary_sweep",
        "total_configs": total,
        "hits": len(hits),
        "best_ic_k4": best_ic["k4"],
        "best_ic_alpha": best_ic["stream_alpha"],
        "best_crib": best_crib,
        "best_words_k4": best_words["k4"],
        "best_words_alpha": best_words["stream_alpha"],
        "elapsed_s": round(elapsed, 1),
        "workers": args.workers,
        "keywords_tested": len(words),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    SUMMARY_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(SUMMARY_FILE, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nRESULT: hits={len(hits)} best_crib={best_crib} best_ic_k4={best_ic['k4']:.5f} "
          f"best_ic_alpha={best_ic['stream_alpha']:.5f} elapsed={elapsed:.1f}s")
    print(f"Summary: {SUMMARY_FILE}")


if __name__ == "__main__":
    main()
