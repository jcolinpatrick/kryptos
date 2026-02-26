#!/usr/bin/env python3
"""Antipodes Key Engine — Running Key + Keyword Decryption through KA Tableau.

The Antipodes has a functional 32x33 KA Vigenere tableau — perfect cyclic
shifts, zero anomalies, no header/footer, no row labels. Tableau and
ciphertext on the SAME SIDE. This is a self-contained decryption device.

Hypothesis: K4 CT decrypted through the KA tableau with a new key produces
either (a) the known message (crib matches) or (b) a different English
plaintext (IC + quadgrams).

Families:
  A: Antipodes-adjacent CT running key (text surrounding K4 on cylinder)
  B: Known-plaintext running key (K1/K2/K3 PT)
  C: Keyword-only (EQUAL, misspelling-derived, thematic)
  D: Keyword + running key (two-layer combination)
  E: Row-adjacent key (physical adjacency on cylinder grid)

What's novel vs prior work:
  1. All prior running-key tests (e_antipodes_04, e_frac_49/50) used AZ space.
     The Antipodes tableau IS KA — we test KA-space decryption.
  2. Misspelling-derived keywords (EQUAL etc) never tested.
  3. Dual-hypothesis scoring: same plaintext (cribs) AND different plaintext (IC).
  4. Keyword + running key two-layer combination untested.

Usage:
    PYTHONPATH=src python3 -u bin/antipodes_key_engine.py
"""
from __future__ import annotations

import json
import os
import sys
import time
from itertools import permutations
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, MOD,
    CRIB_DICT, N_CRIBS,
    KRYPTOS_ALPHABET,
    NOISE_FLOOR, STORE_THRESHOLD,
)
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.scoring.ic import ic
from kryptos.kernel.scoring.ngram import NgramScorer
from kryptos.kernel.constraints.bean import verify_bean
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, DECRYPT_FN, KEY_RECOVERY,
)

# ── Paths ────────────────────────────────────────────────────────────────────

ROOT = Path(__file__).resolve().parent.parent
RESULTS_FILE = ROOT / "results" / "antipodes_key.jsonl"
SUMMARY_FILE = ROOT / "reports" / "antipodes_key.summary.json"
QUADGRAM_FILE = ROOT / "data" / "english_quadgrams.json"

# ── Antipodes Grid (47 rows, letters only) ───────────────────────────────────
# Source: human-verified 2026-02-25

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

KA = KRYPTOS_ALPHABET
KA_IDX: Dict[str, int] = {c: i for i, c in enumerate(KA)}

# ── Flat text + K4 boundaries ────────────────────────────────────────────────

FLAT = "".join(ANTIPODES_ROWS)

# Cumulative row lengths for flat-to-grid conversion
CUM_LENS = [0]
for _row in ANTIPODES_ROWS:
    CUM_LENS.append(CUM_LENS[-1] + len(_row))


def flat_to_grid(idx: int) -> Tuple[int, int]:
    """Convert flat text index to (row, col)."""
    for r in range(len(ANTIPODES_ROWS)):
        if idx < CUM_LENS[r + 1]:
            return r, idx - CUM_LENS[r]
    raise ValueError(f"Index {idx} out of range")


def grid_char(row: int, col: int) -> Optional[str]:
    """Get character at (row, col), or None if out of bounds."""
    if 0 <= row < len(ANTIPODES_ROWS) and 0 <= col < len(ANTIPODES_ROWS[row]):
        return ANTIPODES_ROWS[row][col]
    return None


# Find K4 in flat text (both passes)
K4_P1 = FLAT.find(CT)
assert K4_P1 >= 0, "K4 pass 1 not found in Antipodes flat text"
K4_P2 = FLAT.find(CT, K4_P1 + 1)
assert K4_P2 >= 0, "K4 pass 2 not found in Antipodes flat text"

# Surrounding text for running key sources
BEFORE_P1 = FLAT[:K4_P1]
AFTER_P1 = FLAT[K4_P1 + CT_LEN:]
BEFORE_P2 = FLAT[:K4_P2]
AFTER_P2 = FLAT[K4_P2 + CT_LEN:]

# ── Sculpture plaintexts ────────────────────────────────────────────────────

K1_CT = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"
K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"

K2_PT = (
    "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELD"
    "XTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATION"
    "XDOESLANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIEDOUTTHERESOMEWHEREXWHOKNOWS"
    "THEEXACTLOCATIONONLYWWTHISISHISTLASTMESSAGEXTHIRTYEIGHTDEGREESFIFTY"
    "SEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVENDEGREESEIGHTMINUTES"
    "FORTYFOURSECONDSWESTXLAYERTWO"
)

K3_PT = (
    "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFJPASSAGEDEBABORETURNST"
    "OTHEEARLIESTTASKWASENTALANTSANDHOWTESIDWALLSITTWASFORCED"
    "HEWALLSLOWLYWERECAVINGINTHEYWEREONLYABLETONOTREADITVERYC"
    "LEARLYWASTHEREACHAROOMBEYONDTHECHAMBERQCANYOUSEEANYTHINGQ"
)

# ── Crib expectations (precomputed for fast path) ───────────────────────────

CRIB_SORTED = sorted(CRIB_DICT.items())
CPOS = [p for p, _ in CRIB_SORTED]
NC = len(CRIB_SORTED)

EXPECTED: Dict[Tuple[str, str], List[int]] = {}
for _v in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
    _rec = KEY_RECOVERY[_v]
    EXPECTED[(_v.value, "az")] = [
        _rec(ord(CT[p]) - 65, ord(c) - 65) for p, c in CRIB_SORTED
    ]
    EXPECTED[(_v.value, "ka")] = [
        _rec(KA_IDX[CT[p]], KA_IDX[c]) for p, c in CRIB_SORTED
    ]

# Self-encrypting verification: CT[32]=PT[32]='S' -> Vigenere key[32]=0
_j32 = CPOS.index(32)
assert EXPECTED[("vigenere", "az")][_j32] == 0
assert EXPECTED[("vigenere", "ka")][_j32] == 0

# ── Constants ────────────────────────────────────────────────────────────────

VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]
ALPHS = ["az", "ka"]
IC_FLAG = 0.050  # Flag threshold for "different message" hypothesis

# ── Decrypt helpers ──────────────────────────────────────────────────────────


def decrypt_az(key: List[int], variant: CipherVariant) -> str:
    fn = DECRYPT_FN[variant]
    return "".join(chr(fn(ord(CT[i]) - 65, key[i]) + 65) for i in range(CT_LEN))


def decrypt_ka(key: List[int], variant: CipherVariant) -> str:
    fn = DECRYPT_FN[variant]
    return "".join(KA[fn(KA_IDX[CT[i]], key[i])] for i in range(CT_LEN))


def text_to_key(text: str, alph: str) -> List[int]:
    """Convert text to numeric key in given alphabet space."""
    if alph == "ka":
        return [KA_IDX[c] for c in text]
    return [ord(c) - 65 for c in text]


def keyword_to_key(keyword: str, length: int, alph: str) -> List[int]:
    """Repeat keyword to fill length, convert to key values."""
    kw_len = len(keyword)
    if alph == "ka":
        return [KA_IDX[keyword[i % kw_len]] for i in range(length)]
    return [ord(keyword[i % kw_len]) - 65 for i in range(length)]


# ── Keyword list builder ────────────────────────────────────────────────────


def build_keywords() -> List[str]:
    """Build keyword list from misspelling letters + thematic words."""
    kws: set[str] = set()

    # Named misspelling-derived keywords
    for w in ["EQUAL", "QUALE", "CLUE", "ACE", "EQUA", "ECQA"]:
        kws.add(w)

    # All permutations of {C,Q,A,E} (4! = 24)
    for p in permutations("CQAE"):
        kws.add("".join(p))

    # All permutations of {C,Q,U,A,E} (5! = 120)
    for p in permutations("CQUAE"):
        kws.add("".join(p))

    # Thematic keywords
    for w in [
        "ANTIPODES", "HIRSHHORN", "SMITHSONIAN", "WELTZEITUHR",
        "BERLIN", "KRYPTOS", "PALIMPSEST", "ABSCISSA",
        "SHADOW", "LIGHT", "CLOCK", "SANBORN", "SCHEIDT",
        "EGYPT", "WALL", "CARTER", "TUTANKHAMUN",
    ]:
        kws.add(w)

    return sorted(kws)


# ── Core evaluation ─────────────────────────────────────────────────────────


def new_stats() -> Dict[str, Any]:
    return {
        "tested": 0, "flagged": 0,
        "best_crib": 0, "best_crib_cfg": None,
        "best_ic": 0.0, "best_ic_cfg": None,
    }


def log_hit(record: dict) -> None:
    with open(RESULTS_FILE, "a") as f:
        f.write(json.dumps(record) + "\n")


def evaluate_config(
    key: List[int], variant: CipherVariant, alph: str,
    config: dict, stats: Dict[str, Any], scorer: Optional[NgramScorer],
) -> None:
    """Evaluate one config with dual-hypothesis scoring.

    Hypothesis 1 (same message): crib score > NOISE_FLOOR
    Hypothesis 2 (different message): IC > 0.050
    """
    stats["tested"] += 1

    # Fast crib check (24 comparisons, no decryption needed)
    exp = EXPECTED[(variant.value, alph)]
    crib = sum(key[CPOS[j]] == exp[j] for j in range(NC))

    # Decrypt + IC
    pt = decrypt_ka(key, variant) if alph == "ka" else decrypt_az(key, variant)
    ic_val = ic(pt)

    # Track best
    if crib > stats["best_crib"]:
        stats["best_crib"] = crib
        stats["best_crib_cfg"] = config.copy()
    if ic_val > stats["best_ic"]:
        stats["best_ic"] = ic_val
        stats["best_ic_cfg"] = config.copy()

    # Flag check — either hypothesis
    if crib <= NOISE_FLOOR and ic_val <= IC_FLAG:
        return

    # Full evaluation for flagged configs
    bean = verify_bean(key)
    sbd = score_candidate(pt, bean_result=bean, ngram_scorer=scorer)

    record = {
        "config": config,
        "plaintext": pt,
        "crib_score": crib,
        "ic": round(ic_val, 5),
        "ngram_per_char": round(sbd.ngram_per_char, 3) if sbd.ngram_per_char else None,
        "bean_pass": bean.passed,
        "score": sbd.to_dict(),
    }
    log_hit(record)
    stats["flagged"] += 1

    if crib > NOISE_FLOOR:
        print(f"    CRIB FLAG {crib}/24 IC={ic_val:.4f} | {config}")
    if ic_val > IC_FLAG:
        print(f"    IC FLAG {ic_val:.4f} crib={crib}/24 ngram={sbd.ngram_per_char:.2f}/char | {config}")


# ── Validation ───────────────────────────────────────────────────────────────


def validate_ka_pipeline() -> bool:
    """Validate KA decryption: K1 CT + keyword PALIMPSEST -> K1 PT."""
    key = keyword_to_key("PALIMPSEST", len(K1_CT), "ka")
    fn = DECRYPT_FN[CipherVariant.VIGENERE]
    pt = "".join(KA[fn(KA_IDX[K1_CT[i]], key[i])] for i in range(len(K1_CT)))
    ok = pt == K1_PT
    print(f"  KA pipeline (K1 CT + PALIMPSEST -> K1 PT): {'PASS' if ok else 'FAIL'}")
    if not ok:
        print(f"    Expected: {K1_PT}")
        print(f"    Got:      {pt}")
        for i in range(min(len(pt), len(K1_PT))):
            if pt[i] != K1_PT[i]:
                print(f"    First mismatch at pos {i}: got '{pt[i]}', expected '{K1_PT[i]}'")
                break
    return ok


def validate_grid_alignment() -> bool:
    """Verify K3 CT suffix -> K4 -> K1 CT prefix alignment in Antipodes."""
    # K3 ends with ...DOHW, then K4 starts with OBK...
    k3_tail_ok = BEFORE_P1.endswith("DOHW")
    # After K4, K1 CT starts with EMUFPHZL...
    k1_head_ok = AFTER_P1[:8] == "EMUFPHZL"
    ok = k3_tail_ok and k1_head_ok
    print(f"  Grid alignment (P1): K3 tail={'PASS' if k3_tail_ok else 'FAIL'}, "
          f"K1 head={'PASS' if k1_head_ok else 'FAIL'}")
    if not ok:
        print(f"    Before K4 ends: ...{BEFORE_P1[-10:]}")
        print(f"    After K4 starts: {AFTER_P1[:10]}...")
    return ok


def validate_ic_calibration() -> None:
    """Print IC reference values for calibration."""
    ic_k1 = ic(K1_PT)
    ic_ct = ic(CT)
    print(f"  IC calibration: K1 PT={ic_k1:.4f} (English), "
          f"K4 CT={ic_ct:.4f}, random={1/26:.4f}")


# ── Family A: Antipodes-adjacent CT running key ─────────────────────────────


def run_family_a(stats: Dict, scorer: Optional[NgramScorer]) -> None:
    """Sliding window running key from text surrounding K4 on the Antipodes."""
    sources = [
        ("before_P1", BEFORE_P1),
        ("after_P1", AFTER_P1),
        ("before_P2", BEFORE_P2),
        ("after_P2", AFTER_P2),
    ]

    for src_name, src_text in sources:
        for direction in ["forward", "reversed"]:
            text = src_text if direction == "forward" else src_text[::-1]
            max_off = len(text) - CT_LEN
            if max_off < 0:
                continue
            for off in range(max_off + 1):
                rk = text[off:off + CT_LEN]
                for var in VARIANTS:
                    for alph in ALPHS:
                        key = text_to_key(rk, alph)
                        config = {
                            "family": "A", "source": src_name,
                            "direction": direction, "offset": off,
                            "variant": var.value, "alph": alph,
                        }
                        evaluate_config(key, var, alph, config, stats, scorer)

        print(f"    {src_name}: {len(src_text)} chars, "
              f"tested={stats['tested']:,}, best_crib={stats['best_crib']}/24")


# ── Family B: Known-plaintext running key ────────────────────────────────────


def run_family_b(stats: Dict, scorer: Optional[NgramScorer]) -> None:
    """Running key from K1/K2/K3 known plaintexts."""
    sources = [
        ("K1_PT", K1_PT),
        ("K2_PT", K2_PT),
        ("K3_PT", K3_PT),
        ("K1K2_PT", K1_PT + K2_PT),
    ]

    for src_name, src_text in sources:
        for direction in ["forward", "reversed"]:
            text = src_text if direction == "forward" else src_text[::-1]
            max_off = len(text) - CT_LEN
            if max_off < 0:
                continue
            for off in range(max_off + 1):
                rk = text[off:off + CT_LEN]
                for var in VARIANTS:
                    for alph in ALPHS:
                        key = text_to_key(rk, alph)
                        config = {
                            "family": "B", "source": src_name,
                            "direction": direction, "offset": off,
                            "variant": var.value, "alph": alph,
                        }
                        evaluate_config(key, var, alph, config, stats, scorer)

        print(f"    {src_name}: {len(src_text)} chars, "
              f"tested={stats['tested']:,}, best_crib={stats['best_crib']}/24")


# ── Family C: Keyword-only ──────────────────────────────────────────────────


def run_family_c(
    keywords: List[str], stats: Dict, scorer: Optional[NgramScorer],
) -> None:
    """Repeating keyword decryption (misspelling-derived + thematic)."""
    for kw in keywords:
        for var in VARIANTS:
            for alph in ALPHS:
                key = keyword_to_key(kw, CT_LEN, alph)
                config = {
                    "family": "C", "keyword": kw,
                    "variant": var.value, "alph": alph,
                }
                evaluate_config(key, var, alph, config, stats, scorer)


# ── Family D: Keyword + running key ─────────────────────────────────────────


def run_family_d(
    keywords: List[str], stats: Dict, scorer: Optional[NgramScorer],
) -> None:
    """Two-layer: keyword + running key combined.

    combined_key[i] = (keyword_key[i] + running_key[i]) % 26
    Running keys: offset-0 adjacent text from each pass side.
    """
    # Build offset-0 running key sources (physically adjacent to K4)
    rk_sources: List[Tuple[str, str]] = []
    for label, before, after in [
        ("P1", BEFORE_P1, AFTER_P1),
        ("P2", BEFORE_P2, AFTER_P2),
    ]:
        if len(before) >= CT_LEN:
            rk_sources.append((f"before_{label}", before[-CT_LEN:]))
        if len(after) >= CT_LEN:
            rk_sources.append((f"after_{label}", after[:CT_LEN]))

    for kw in keywords:
        for rk_name, rk_text in rk_sources:
            for direction in ["forward", "reversed"]:
                text = rk_text if direction == "forward" else rk_text[::-1]
                for var in VARIANTS:
                    for alph in ALPHS:
                        kw_key = keyword_to_key(kw, CT_LEN, alph)
                        rk_key = text_to_key(text, alph)
                        key = [(kw_key[i] + rk_key[i]) % MOD
                               for i in range(CT_LEN)]
                        config = {
                            "family": "D", "keyword": kw,
                            "rk_source": rk_name, "direction": direction,
                            "variant": var.value, "alph": alph,
                        }
                        evaluate_config(key, var, alph, config, stats, scorer)


# ── Family E: Row-adjacent key ──────────────────────────────────────────────


def build_adjacent_key(
    k4_start: int, direction: str, alph: str,
) -> Optional[List[int]]:
    """Build key from grid-adjacent characters for each K4 position."""
    key: List[int] = []
    for i in range(CT_LEN):
        r, c = flat_to_grid(k4_start + i)
        if direction == "above":
            ch = grid_char(r - 1, c)
        elif direction == "below":
            ch = grid_char(r + 1, c)
        elif direction == "left":
            ch = grid_char(r, c - 1)
        else:  # right
            ch = grid_char(r, c + 1)

        if ch is None:
            return None  # Can't build complete key
        key.append(KA_IDX[ch] if alph == "ka" else ord(ch) - 65)
    return key


def run_family_e(stats: Dict, scorer: Optional[NgramScorer]) -> None:
    """Physical adjacency keys on the cylinder grid surface."""
    directions = ["above", "below", "left", "right"]
    for pass_label, k4_start in [("P1", K4_P1), ("P2", K4_P2)]:
        for d in directions:
            for var in VARIANTS:
                for alph in ALPHS:
                    key = build_adjacent_key(k4_start, d, alph)
                    if key is None:
                        continue
                    config = {
                        "family": "E", "pass": pass_label,
                        "direction": d,
                        "variant": var.value, "alph": alph,
                    }
                    evaluate_config(key, var, alph, config, stats, scorer)


# ── Main ─────────────────────────────────────────────────────────────────────


def main() -> None:
    t0 = time.time()
    print("=" * 70)
    print("Antipodes Key Engine")
    print("Running Key + Keyword Decryption through KA Tableau")
    print("=" * 70)

    # Setup output
    RESULTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    SUMMARY_FILE.parent.mkdir(parents=True, exist_ok=True)
    if RESULTS_FILE.exists():
        RESULTS_FILE.unlink()

    # Load quadgram scorer
    scorer: Optional[NgramScorer] = None
    if QUADGRAM_FILE.exists():
        scorer = NgramScorer.from_file(QUADGRAM_FILE)
        print(f"Quadgram scorer loaded ({QUADGRAM_FILE})")
    else:
        print(f"WARNING: {QUADGRAM_FILE} not found, ngram scoring disabled")

    # ── Validation ───────────────────────────────────────────────────────
    print("\n--- Validation ---")
    ka_ok = validate_ka_pipeline()
    grid_ok = validate_grid_alignment()
    validate_ic_calibration()
    print(f"  K4 pass 1 at flat pos {K4_P1}, pass 2 at {K4_P2}")
    print(f"  Before P1: {len(BEFORE_P1)} chars, After P1: {len(AFTER_P1)} chars")
    print(f"  Before P2: {len(BEFORE_P2)} chars, After P2: {len(AFTER_P2)} chars")

    if not ka_ok:
        print("\nFATAL: KA pipeline validation failed!")
        sys.exit(1)

    # Build keywords
    keywords = build_keywords()
    print(f"\nKeywords: {len(keywords)} unique")

    # ── Family A ─────────────────────────────────────────────────────────
    print("\n--- Family A: Antipodes-adjacent CT running key ---")
    stats_a = new_stats()
    run_family_a(stats_a, scorer)
    print(f"  Total: {stats_a['tested']:,} tested, {stats_a['flagged']} flagged, "
          f"best_crib={stats_a['best_crib']}/24, best_IC={stats_a['best_ic']:.4f}")

    # ── Family B ─────────────────────────────────────────────────────────
    print("\n--- Family B: Known-plaintext running key ---")
    stats_b = new_stats()
    run_family_b(stats_b, scorer)
    print(f"  Total: {stats_b['tested']:,} tested, {stats_b['flagged']} flagged, "
          f"best_crib={stats_b['best_crib']}/24, best_IC={stats_b['best_ic']:.4f}")

    # ── Family C ─────────────────────────────────────────────────────────
    print("\n--- Family C: Keyword-only ---")
    stats_c = new_stats()
    run_family_c(keywords, stats_c, scorer)
    print(f"  Total: {stats_c['tested']:,} tested, {stats_c['flagged']} flagged, "
          f"best_crib={stats_c['best_crib']}/24, best_IC={stats_c['best_ic']:.4f}")

    # ── Family D ─────────────────────────────────────────────────────────
    print("\n--- Family D: Keyword + Running key ---")
    stats_d = new_stats()
    run_family_d(keywords, stats_d, scorer)
    print(f"  Total: {stats_d['tested']:,} tested, {stats_d['flagged']} flagged, "
          f"best_crib={stats_d['best_crib']}/24, best_IC={stats_d['best_ic']:.4f}")

    # ── Family E ─────────────────────────────────────────────────────────
    print("\n--- Family E: Row-adjacent key ---")
    stats_e = new_stats()
    run_family_e(stats_e, scorer)
    print(f"  Total: {stats_e['tested']:,} tested, {stats_e['flagged']} flagged, "
          f"best_crib={stats_e['best_crib']}/24, best_IC={stats_e['best_ic']:.4f}")

    # ── Summary ──────────────────────────────────────────────────────────
    elapsed = round(time.time() - t0, 1)
    all_stats = {
        "A": stats_a, "B": stats_b, "C": stats_c,
        "D": stats_d, "E": stats_e,
    }
    total_tested = sum(s["tested"] for s in all_stats.values())
    total_flagged = sum(s["flagged"] for s in all_stats.values())
    best_crib = max(s["best_crib"] for s in all_stats.values())
    best_ic = max(s["best_ic"] for s in all_stats.values())

    summary = {
        "experiment": "antipodes_key_engine",
        "hypothesis": "Antipodes KA tableau as decryption device (KA-space, "
                      "misspelling keywords, dual-hypothesis scoring)",
        "families": {},
        "total_configs": total_tested,
        "total_flagged": total_flagged,
        "best_crib": best_crib,
        "best_ic": round(best_ic, 5),
        "noise_floor": NOISE_FLOOR,
        "ic_flag_threshold": IC_FLAG,
        "elapsed_s": elapsed,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }

    for k, s in all_stats.items():
        summary["families"][k] = {
            "tested": s["tested"],
            "flagged": s["flagged"],
            "best_crib": s["best_crib"],
            "best_crib_config": s["best_crib_cfg"],
            "best_ic": round(s["best_ic"], 5),
            "best_ic_config": s["best_ic_cfg"],
        }

    with open(SUMMARY_FILE, "w") as f:
        json.dump(summary, f, indent=2)

    print(f"\n{'=' * 70}")
    print("SUMMARY")
    print(f"{'=' * 70}")
    for k, s in all_stats.items():
        print(f"  Family {k}: {s['tested']:>7,} tested, {s['flagged']:>3} flagged, "
              f"best_crib={s['best_crib']}/24, best_IC={s['best_ic']:.4f}")
    print(f"  {'─' * 60}")
    print(f"  Total:  {total_tested:>7,} tested, {total_flagged:>3} flagged")
    print(f"  Best crib: {best_crib}/24, Best IC: {best_ic:.4f}")
    print(f"  Elapsed: {elapsed}s")
    print(f"  Results: {RESULTS_FILE}")
    print(f"  Summary: {SUMMARY_FILE}")

    if best_crib <= NOISE_FLOOR and best_ic <= IC_FLAG:
        print(f"\nVerdict: ALL NOISE — Antipodes key engine produced no signal.")
    else:
        print(f"\nVerdict: {total_flagged} flagged configs — investigate.")


if __name__ == "__main__":
    main()
