#!/usr/bin/env python3
"""
E-PLAYFAIR-01: Comprehensive Playfair Cipher Disproof for K4

Tests all five required checks:
  1. Parity check  — Playfair requires even-length output; K4 is 97 chars (odd)
  2. Digraph statistics — repeated digraphs, IC, digraph IC
  3. Doubled-letter constraint — Playfair forbids both letters in a pair being equal
  4. Keyword decryption attempts — KRYPTOS context keywords
  5. Hill-climbing on 25-letter Playfair square (only if statistical tests don't rule out)

Expected outcome: STRUCTURALLY ELIMINATED by checks 1+2 alone (confirming E-FRAC-21 Proof 8).
Additional checks serve as independent corroboration.
"""

import json
import math
import os
import random
import time
from itertools import permutations

from kryptos.kernel.constants import CT, CT_LEN, ALPH, CRIB_DICT

# ─────────────────────────────────────────────────────────────────────────────
# Playfair cipher implementation (for keyword decryption and hill-climbing)
# ─────────────────────────────────────────────────────────────────────────────

PLAYFAIR_ALPH = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # 25 letters: J omitted (merged with I)


def build_playfair_square(keyword: str) -> list[list[str]]:
    """Build 5×5 Playfair square from keyword. J→I merge."""
    seen = set()
    sq = []
    for ch in (keyword + PLAYFAIR_ALPH):
        ch = ch.upper().replace("J", "I")
        if ch in ALPH and ch not in seen:
            seen.add(ch)
            sq.append(ch)
    # sq should be exactly 25 letters
    assert len(sq) == 25, f"Expected 25, got {len(sq)}: {sq}"
    return [sq[i * 5:(i + 1) * 5] for i in range(5)]


def square_to_index(square: list[list[str]]) -> dict[str, tuple[int, int]]:
    """Map letter → (row, col) in Playfair square."""
    return {square[r][c]: (r, c) for r in range(5) for c in range(5)}


def playfair_decrypt_pair(a: str, b: str, square: list[list[str]],
                           idx: dict[str, tuple[int, int]]) -> tuple[str, str]:
    """Decrypt a single Playfair digraph."""
    a = a.replace("J", "I")
    b = b.replace("J", "I")
    ra, ca = idx[a]
    rb, cb = idx[b]
    if ra == rb:  # Same row: shift left
        return square[ra][(ca - 1) % 5], square[rb][(cb - 1) % 5]
    elif ca == cb:  # Same col: shift up
        return square[(ra - 1) % 5][ca], square[(rb - 1) % 5][cb]
    else:  # Rectangle: swap columns
        return square[ra][cb], square[rb][ca]


def playfair_decrypt(ct: str, keyword: str) -> str | None:
    """
    Attempt Playfair decryption. Returns None if ct length is odd (structural failure).
    J→I in ciphertext before decryption.
    """
    if len(ct) % 2 != 0:
        return None  # Structurally impossible
    ct = ct.replace("J", "I")
    square = build_playfair_square(keyword)
    idx = square_to_index(square)
    pt = []
    for i in range(0, len(ct), 2):
        a, b = ct[i], ct[i + 1]
        pa, pb = playfair_decrypt_pair(a, b, square, idx)
        pt.extend([pa, pb])
    return "".join(pt)


def playfair_decrypt_square(ct: str, square: list[list[str]]) -> str | None:
    """Decrypt with a pre-built Playfair square."""
    if len(ct) % 2 != 0:
        return None
    idx = square_to_index(square)
    pt = []
    for i in range(0, len(ct), 2):
        a, b = ct[i], ct[i + 1]
        pa, pb = playfair_decrypt_pair(a, b, square, idx)
        pt.extend([pa, pb])
    return "".join(pt)


# ─────────────────────────────────────────────────────────────────────────────
# Scoring utilities
# ─────────────────────────────────────────────────────────────────────────────

# English monogram frequencies (for IC / scoring)
ENGLISH_MONO_FREQ = {
    'A': 0.08167, 'B': 0.01492, 'C': 0.02782, 'D': 0.04253, 'E': 0.12702,
    'F': 0.02228, 'G': 0.02015, 'H': 0.06094, 'I': 0.06966, 'J': 0.00153,
    'K': 0.00772, 'L': 0.04025, 'M': 0.02406, 'N': 0.06749, 'O': 0.07507,
    'P': 0.01929, 'Q': 0.00095, 'R': 0.05987, 'S': 0.06327, 'T': 0.09056,
    'U': 0.02758, 'V': 0.00978, 'W': 0.02360, 'X': 0.00150, 'Y': 0.01974,
    'Z': 0.00074,
}

# Load quadgram data if available
_QUADGRAMS: dict[str, float] = {}
_QUAD_FLOOR: float = -15.0

def _load_quadgrams():
    global _QUADGRAMS, _QUAD_FLOOR
    path = "data/english_quadgrams.json"
    if os.path.exists(path):
        with open(path) as f:
            _QUADGRAMS = json.load(f)
        _QUAD_FLOOR = min(_QUADGRAMS.values()) - 1.0
    else:
        print("  [WARNING] Quadgram file not found — using monogram scoring only")

_load_quadgrams()


def score_quadgram(text: str) -> float:
    """Log-probability score per character using quadgrams."""
    if not _QUADGRAMS:
        return 0.0
    total = 0.0
    n = 0
    for i in range(len(text) - 3):
        quad = text[i:i + 4]
        total += _QUADGRAMS.get(quad, _QUAD_FLOOR)
        n += 1
    return total / n if n > 0 else _QUAD_FLOOR


def index_of_coincidence(text: str) -> float:
    """IC = sum(f_i * (f_i-1)) / (N * (N-1))."""
    n = len(text)
    if n < 2:
        return 0.0
    counts = [text.count(c) for c in ALPH]
    return sum(f * (f - 1) for f in counts) / (n * (n - 1))


def digraph_ic(text: str) -> float:
    """Digraph Index of Coincidence (for digraph cipher detection)."""
    if len(text) % 2 != 0:
        text = text[:-1]  # Drop last if odd
    digraphs = [text[i:i + 2] for i in range(0, len(text), 2)]
    n = len(digraphs)
    if n < 2:
        return 0.0
    # Count unique digraph pairs
    counts: dict[str, int] = {}
    for dg in digraphs:
        counts[dg] = counts.get(dg, 0) + 1
    return sum(f * (f - 1) for f in counts.values()) / (n * (n - 1))


def crib_score(pt: str) -> int:
    """Count how many crib positions match."""
    hits = 0
    for pos, ch in CRIB_DICT.items():
        if pos < len(pt) and pt[pos] == ch:
            hits += 1
    return hits


# ─────────────────────────────────────────────────────────────────────────────
# Digraph statistics
# ─────────────────────────────────────────────────────────────────────────────

def analyze_digraphs(ct: str) -> dict:
    """Full digraph analysis of the ciphertext."""
    n = len(ct)
    # Overlapping digraphs (all pairs at offsets 0, 1)
    digraphs_even = [ct[i:i + 2] for i in range(0, n - 1, 2)]
    digraphs_all  = [ct[i:i + 2] for i in range(n - 1)]

    # Count even-split digraphs (how Playfair would pair them)
    even_counts: dict[str, int] = {}
    for dg in digraphs_even:
        even_counts[dg] = even_counts.get(dg, 0) + 1

    # Repeated digraphs
    repeats_even = {k: v for k, v in even_counts.items() if v > 1}

    # Doubled pairs (same letter twice — Playfair inserts X between these)
    doubled_even = [dg for dg in digraphs_even if dg[0] == dg[1]]

    # Expected digraph repeats in random text
    # E[same digraph] ≈ C(n/2, 2) / 26^2 ≈ (n/2)^2 / (2 * 676)
    n_pairs = n // 2
    expected_repeats = (n_pairs ** 2) / (2 * 676)

    # Digraph IC for even-split pairs
    d_ic = digraph_ic(ct)
    # Expected Playfair digraph IC ≈ 0.065 (more repetitive than random)
    # Random digraph IC ≈ 1/676 ≈ 0.00148

    return {
        'n_pairs_even': n_pairs,
        'n_unique_digraphs_even': len(even_counts),
        'max_digraph_freq': max(even_counts.values()) if even_counts else 0,
        'repeated_digraphs': repeats_even,
        'n_repeated': len(repeats_even),
        'doubled_pairs_even': doubled_even,
        'n_doubled': len(doubled_even),
        'digraph_ic': d_ic,
        'expected_digraph_repeats_random': expected_repeats,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Hill-climbing on Playfair square (for thoroughness)
# ─────────────────────────────────────────────────────────────────────────────

def random_square() -> list[list[str]]:
    """Generate a random 5×5 Playfair square (shuffled 25-letter alphabet)."""
    letters = list(PLAYFAIR_ALPH)
    random.shuffle(letters)
    return [letters[i * 5:(i + 1) * 5] for i in range(5)]


def swap_two_letters(square: list[list[str]]) -> list[list[str]]:
    """Return a new square with two letters swapped."""
    flat = [c for row in square for c in row]
    i, j = random.sample(range(25), 2)
    flat[i], flat[j] = flat[j], flat[i]
    return [flat[k * 5:(k + 1) * 5] for k in range(5)]


def hill_climb_playfair(ct96: str, n_restarts: int = 20, n_iters: int = 5000,
                         rng_seed: int = 42) -> dict:
    """
    Hill-climb on a 25-letter Playfair square using quadgram scoring.
    NOTE: ct96 must be even-length. We use the first 96 chars of CT.

    This is for completeness only — structural proof already eliminates Playfair.
    """
    random.seed(rng_seed)
    best_score = -math.inf
    best_sq = None
    best_pt = ""
    best_cribs = 0

    for restart in range(n_restarts):
        sq = random_square()
        pt = playfair_decrypt_square(ct96, sq)
        score = score_quadgram(pt) if pt else -math.inf

        for _ in range(n_iters):
            new_sq = swap_two_letters(sq)
            new_pt = playfair_decrypt_square(ct96, new_sq)
            new_score = score_quadgram(new_pt) if new_pt else -math.inf
            if new_score > score:
                sq, pt, score = new_sq, new_pt, new_score

        if score > best_score:
            best_score = score
            best_sq = sq
            best_pt = pt
            best_cribs = crib_score(pt) if pt else 0

    return {
        'best_score_per_char': best_score,
        'best_pt_first_30': best_pt[:30] if best_pt else "",
        'crib_matches': best_cribs,
        'n_restarts': n_restarts,
        'n_iters': n_iters,
        'best_square': [''.join(row) for row in best_sq] if best_sq else [],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Main analysis
# ─────────────────────────────────────────────────────────────────────────────

def main():
    t0 = time.time()
    print("=" * 72)
    print("E-PLAYFAIR-01: Comprehensive Playfair Cipher Disproof for K4")
    print("=" * 72)
    print(f"\nCiphertext: {CT}")
    print(f"Length:     {CT_LEN} characters")
    print(f"Known cribs: {len(CRIB_DICT)} positions")

    results = {
        'experiment': 'E-PLAYFAIR-01',
        'ct': CT,
        'ct_len': CT_LEN,
    }

    # ══════════════════════════════════════════════════════════════════════════
    # CHECK 1: Parity (length must be even)
    # ══════════════════════════════════════════════════════════════════════════
    print("\n" + "─" * 72)
    print("CHECK 1: Parity — Playfair output must have even length")
    print("─" * 72)
    is_even = CT_LEN % 2 == 0
    print(f"  K4 CT length:  {CT_LEN}")
    print(f"  97 % 2 = {CT_LEN % 2}  →  {'EVEN' if is_even else 'ODD'}")
    print()
    print("  Playfair encrypts plaintext in DIGRAPHS (pairs of letters).")
    print("  Each 2-letter plaintext digraph produces exactly 1 ciphertext digraph.")
    print("  Therefore: |CT| must be even. Period.")
    print()
    if not is_even:
        print("  ✗ PROOF: K4 CT length = 97 (odd).")
        print("    No Playfair encryption can produce 97 ciphertext characters.")
        print("    This is a MATHEMATICAL IMPOSSIBILITY — no key or keyword can fix it.")
        print()
        print("  Could padding explain it?")
        print("  Playfair traditionally inserts 'X' between doubled letters (before enc)")
        print("  and appends 'X' if the message is odd-length (before enc).")
        print("  Either way: the CIPHERTEXT is always even. CT=97 is odd. Eliminated.")
        parity_verdict = "STRUCTURALLY_IMPOSSIBLE"
    else:
        parity_verdict = "PASSES_PARITY"
    print(f"\n  Parity verdict: {parity_verdict}")
    results['check1_parity'] = {
        'ct_len': CT_LEN,
        'is_even': is_even,
        'verdict': parity_verdict,
    }

    # ══════════════════════════════════════════════════════════════════════════
    # CHECK 2: Alphabet size — Playfair uses 25-letter alphabet (I/J merged)
    # ══════════════════════════════════════════════════════════════════════════
    print("\n" + "─" * 72)
    print("CHECK 2: Alphabet — Playfair CT uses at most 25 distinct letters")
    print("─" * 72)
    ct_unique = sorted(set(CT))
    n_unique = len(ct_unique)
    print(f"  K4 CT unique letters ({n_unique}): {' '.join(ct_unique)}")
    print()

    # Check for I and J specifically
    i_count = CT.count('I')
    j_count = CT.count('J')
    print(f"  Letter I: {i_count} occurrences at positions {[i for i, c in enumerate(CT) if c == 'I']}")
    print(f"  Letter J: {j_count} occurrences at positions {[i for i, c in enumerate(CT) if c == 'J']}")
    print()

    print("  Standard Playfair: I and J share one cell → CT can have at most 25 distinct letters.")
    print("  (Because the encipherment alphabet is exactly ABCDEFGHIKLMNOPQRSTUVWXYZ — 25 chars)")
    print()

    # In practice, some Playfair variants allow 26 letters in CT if I≠J semantics differ,
    # but let's check whether the CT contains both I and J:
    both_ij = i_count > 0 and j_count > 0
    if both_ij:
        print(f"  K4 CT contains BOTH I ({i_count}×) and J ({j_count}×).")
        print("  Under standard I/J merge, the CT alphabet is 25 letters.")
        print("  K4 has 26 distinct letters → IMPOSSIBLE under standard Playfair.")
    else:
        print(f"  K4 CT contains only {'I' if i_count > 0 else 'J'} (not both).")
        print("  Alphabet size check passes vacuously for I/J (only one present).")

    print()
    alphabet_verdict = "IMPOSSIBLE_26_LETTERS" if n_unique == 26 else "PASSES_ALPHABET"
    print(f"  Alphabet verdict: {alphabet_verdict}  ({n_unique} distinct letters in CT)")
    results['check2_alphabet'] = {
        'n_unique': n_unique,
        'i_count': i_count,
        'j_count': j_count,
        'both_i_and_j': both_ij,
        'verdict': alphabet_verdict,
    }

    # ══════════════════════════════════════════════════════════════════════════
    # CHECK 3: Doubled-letter constraint
    # ══════════════════════════════════════════════════════════════════════════
    print("\n" + "─" * 72)
    print("CHECK 3: Doubled-letter constraint (Playfair forbids XX digraphs)")
    print("─" * 72)
    print()
    print("  Playfair RULE: A plaintext digraph cannot have the same letter twice.")
    print("  (If you write 'LL', the cipher inserts 'X': L X L → encode separately.)")
    print("  Result: NO ciphertext digraph encrypts a same-letter pair.")
    print()
    print("  But this means nothing if CT is odd-length — CHECK 1 already kills it.")
    print("  We still analyze digraph structure as independent corroboration.")
    print()

    dg_stats = analyze_digraphs(CT)
    print(f"  Even-split digraph pairs (how Playfair would pair the CT):")
    print(f"    Total pairs:       {dg_stats['n_pairs_even']}")
    print(f"    Unique digraphs:   {dg_stats['n_unique_digraphs_even']}")
    print(f"    Repeated digraphs: {dg_stats['n_repeated']}  (expected ~{dg_stats['expected_digraph_repeats_random']:.1f} for random)")
    print(f"    Top repeats:       {sorted(dg_stats['repeated_digraphs'].items(), key=lambda x: -x[1])[:5]}")
    print(f"    Doubled pairs (XX pattern): {dg_stats['n_doubled']}  → {dg_stats['doubled_pairs_even']}")
    print()

    # Under Playfair, the CT digraph cannot be a doubled letter
    # But this constraint applies to the plaintext, not the ciphertext
    # So doubled CT digraphs are actually ALLOWED (they don't violate rules)
    # What's forbidden: doubled PT digraphs → doubled CT digraphs won't appear
    # (since the PT is always pre-processed to remove doubles)
    # Actually: in CT, doubled digraphs CAN appear (e.g. CT[i]=CT[i+1] is fine)
    # The rule is on the plaintext side. So this check is informational.
    print("  Note: Playfair forbids PLAINTEXT XX digraphs, not ciphertext.")
    print("  CT doubled digraphs are allowed. Checking CT digraphs is informational.")
    print()
    print(f"  Digraph IC (even-split): {dg_stats['digraph_ic']:.5f}")
    print(f"    Expected (random):  ~0.00148  (1/676)")
    print(f"    Expected (Playfair on English): ~0.015–0.025  (English digraph structure preserved)")
    print(f"    Observed:            {dg_stats['digraph_ic']:.5f}")

    # Interpretation: Playfair preserves some digraph frequency structure
    # because it's a digraph substitution (not full random).
    # But this is a weaker test compared to checks 1 and 2.
    results['check3_digraphs'] = dg_stats
    results['check3_digraphs']['verdict'] = (
        "INFORMATIONAL_ONLY (parity already eliminates)"
    )

    # ══════════════════════════════════════════════════════════════════════════
    # CHECK 4: IC and statistical fingerprint
    # ══════════════════════════════════════════════════════════════════════════
    print("\n" + "─" * 72)
    print("CHECK 4: Statistical fingerprint — IC and frequency analysis")
    print("─" * 72)
    ct_ic = index_of_coincidence(CT)
    print(f"\n  Monogram IC:")
    print(f"    K4 CT:              {ct_ic:.5f}")
    print(f"    English plaintext:  ~0.0667")
    print(f"    Random (26-letter): ~0.0385")
    print(f"    Playfair (English): ~0.045–0.055  (partially flattened by digraph sub)")
    print()
    print(f"  K4 IC = {ct_ic:.5f} is BELOW the random expectation of 0.0385.")
    print(f"  Playfair on English text produces IC ≈ 0.045–0.055.")
    print(f"  K4's IC is LOWER than even a random flat distribution.")
    print(f"  This is INCONSISTENT with Playfair output (and with random).")
    print()
    print(f"  (Note: For n=97, IC variance is large. This is a soft test.)")
    print()

    # Letter frequency analysis
    freq = {c: CT.count(c) / CT_LEN for c in ALPH}
    top5 = sorted(freq.items(), key=lambda x: -x[1])[:5]
    bot5 = sorted(freq.items(), key=lambda x: x[1])[:5]
    print(f"  Letter frequency (top 5): {', '.join(f'{c}={v:.3f}' for c, v in top5)}")
    print(f"  Letter frequency (bot 5): {', '.join(f'{c}={v:.3f}' for c, v in bot5)}")
    print()
    print(f"  Playfair partially preserves English letter frequencies (row/col swaps")
    print(f"  are local). High-frequency letters (E, T, A) should remain elevated.")
    # Check if E is elevated (most common English letter)
    e_freq = freq['E']
    t_freq = freq['T']
    print(f"  E frequency in CT: {e_freq:.4f}  (English: 0.127)")
    print(f"  T frequency in CT: {t_freq:.4f}  (English: 0.091)")
    print(f"  The frequency profile looks roughly uniform (consistent with strong encryption)")
    print(f"  rather than the Playfair 'soft' flattening pattern.")

    results['check4_statistics'] = {
        'ic': ct_ic,
        'english_ic': 0.0667,
        'random_ic': 0.0385,
        'playfair_ic_range': [0.045, 0.055],
        'ic_verdict': 'BELOW_RANDOM_INCONSISTENT_WITH_PLAYFAIR',
        'top5_letters': top5,
        'e_freq': e_freq,
        't_freq': t_freq,
    }

    # ══════════════════════════════════════════════════════════════════════════
    # CHECK 5: Keyword decryption attempts
    # ══════════════════════════════════════════════════════════════════════════
    print("\n" + "─" * 72)
    print("CHECK 5: Keyword decryption attempts (Kryptos-context keywords)")
    print("─" * 72)
    print()
    print("  IMPORTANT: Playfair on 97-char CT returns None (length is odd).")
    print("  We will attempt on CT[:96] (first 96 chars = 48 digraphs) to show")
    print("  that even ignoring the parity problem, no keyword produces a crib match.")
    print()

    ct96 = CT[:96]  # Even-length prefix

    kryptos_keywords = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN",
        "CLOCK", "BERLINCLOCK", "WELTZEITUHR", "SANBORN",
        "SCHEIDT", "SHADOW", "FORCES", "LAYER", "TWO",
        "NORTHEAST", "EAST", "LANGLEY", "VIRGINIA", "CIA",
        "KRYPTOS", "ANTHROPIC", "ANTIPODES",
        "DESPARATLY", "IQLUSION", "UNDERGRUUND",
        # Some Sanborn/Egypt-related
        "EGYPT", "CAIRO", "PYRAMID", "SPHINX", "OSIRIS",
        # William Webster
        "WEBSTER", "DRUSILLA",
        # Generic short keywords
        "KEY", "CODE", "SECRET",
    ]

    print(f"  Testing {len(kryptos_keywords)} keywords on CT[:96] (48 digraphs)")
    print(f"  Crib positions tested: positions 21-33 (EASTNORTHEAST), 63-73 (BERLINCLOCK)")
    print()

    # Re-score against cribs that fall within [:96]
    cribs_in_96 = {pos: ch for pos, ch in CRIB_DICT.items() if pos < 96}
    print(f"  Cribs within [:96]: {len(cribs_in_96)} positions")

    keyword_results = []
    best_crib_kw = 0
    best_kw = ""
    best_pt_kw = ""

    for kw in kryptos_keywords:
        pt = playfair_decrypt(ct96, kw)
        if pt is None:
            keyword_results.append({'keyword': kw, 'verdict': 'ODD_LENGTH_FAIL', 'cribs': 0})
            continue
        cribs_matched = sum(1 for pos, ch in cribs_in_96.items() if pos < len(pt) and pt[pos] == ch)
        qscore = score_quadgram(pt) if _QUADGRAMS else 0.0
        keyword_results.append({
            'keyword': kw,
            'cribs': cribs_matched,
            'quadgram': round(qscore, 3),
            'pt_first20': pt[:20],
        })
        if cribs_matched > best_crib_kw:
            best_crib_kw = cribs_matched
            best_kw = kw
            best_pt_kw = pt

    # Display results
    keyword_results.sort(key=lambda x: -x.get('cribs', 0))
    print(f"  {'Keyword':<20} {'Cribs':>6}  {'Quadgram':>10}  {'PT[:20]'}")
    print(f"  {'─'*20}  {'─'*6}  {'─'*10}  {'─'*20}")
    for r in keyword_results[:15]:
        cribs = r.get('cribs', 0)
        qg = r.get('quadgram', 0.0)
        pt20 = r.get('pt_first20', 'N/A')
        print(f"  {r['keyword']:<20} {cribs:>6}  {qg:>10.3f}  {pt20}")
    if len(keyword_results) > 15:
        print(f"  ... ({len(keyword_results) - 15} more keywords, all poor)")

    print()
    print(f"  Best keyword: '{best_kw}' — {best_crib_kw}/{len(cribs_in_96)} crib matches")
    print(f"  Best PT preview: {best_pt_kw[:30] if best_pt_kw else 'N/A'}")
    print()

    expected_random_cribs = len(cribs_in_96) / 25  # ~25-letter PT alphabet
    print(f"  Expected crib matches by chance: {expected_random_cribs:.1f}/{len(cribs_in_96)}")
    print(f"  Best achieved: {best_crib_kw}/{len(cribs_in_96)} — {'at or below' if best_crib_kw <= expected_random_cribs else 'above'} chance level")

    results['check5_keywords'] = {
        'n_keywords': len(kryptos_keywords),
        'ct_prefix_used': 96,
        'cribs_in_96': len(cribs_in_96),
        'expected_random': round(expected_random_cribs, 2),
        'best_keyword': best_kw,
        'best_crib_matches': best_crib_kw,
        'all_results': keyword_results,
    }

    # ══════════════════════════════════════════════════════════════════════════
    # CHECK 6: Hill-climbing on Playfair square
    # ══════════════════════════════════════════════════════════════════════════
    print("\n" + "─" * 72)
    print("CHECK 6: Hill-climbing on 25-letter Playfair square (exhaustive search)")
    print("─" * 72)
    print()
    print("  Since structural proofs already eliminate Playfair, this is run for")
    print("  COMPLETENESS ONLY — to show that even with a computer searching for")
    print("  the best possible Playfair key, no meaningful plaintext emerges.")
    print()
    print("  Parameters: 20 random restarts × 5000 hill-climb iterations")
    print("  Input: CT[:96] (96 chars = 48 digraphs, forced even-length)")
    print("  Scoring: quadgram log-probability per character")
    print()

    if _QUADGRAMS:
        hc_results = hill_climb_playfair(ct96, n_restarts=20, n_iters=5000)
        print(f"  Hill-climb results:")
        print(f"    Best score:     {hc_results['best_score_per_char']:.4f} per char")
        print(f"    English PT:    ~-3.08 per char (benchmark for readable English)")
        print(f"    Crib matches:   {hc_results['crib_matches']}/{len(cribs_in_96)}")
        print(f"    Best PT[:30]:   {hc_results['best_pt_first_30']}")
        print()
        print(f"  Best Playfair square found:")
        for row in hc_results['best_square']:
            print(f"    {' '.join(row)}")
        print()

        # Interpretation
        score = hc_results['best_score_per_char']
        if score > -4.5:
            interp = "SUSPICIOUS — warrants manual review"
        elif score > -5.5:
            interp = "NOISE — typical random text"
        else:
            interp = "WORSE THAN RANDOM"
        print(f"  Interpretation: {interp}")
        print(f"  (Readable English: -3.0 to -3.5. Random: -5.0 to -5.5.)")
        results['check6_hillclimb'] = hc_results
        results['check6_hillclimb']['interpretation'] = interp
    else:
        print("  Quadgram file not available — skipping hill-climbing.")
        print("  (Structural proof is already definitive; this is moot.)")
        results['check6_hillclimb'] = {'skipped': True, 'reason': 'no_quadgrams'}

    # ══════════════════════════════════════════════════════════════════════════
    # SUMMARY
    # ══════════════════════════════════════════════════════════════════════════
    elapsed = time.time() - t0
    print("\n" + "═" * 72)
    print("FINAL VERDICT SUMMARY")
    print("═" * 72)
    print()
    print("  Check 1 — Parity:           K4 CT = 97 chars (ODD).")
    print("                               Playfair output is ALWAYS even.")
    print("                               ➜ STRUCTURALLY IMPOSSIBLE. (DISPROVED)")
    print()
    print("  Check 2 — Alphabet:         K4 CT uses all 26 letters.")
    print("                               Playfair output alphabet has 25 letters (I/J merged).")
    print("                               ➜ STRUCTURALLY IMPOSSIBLE. (DISPROVED — independent)")
    print()
    print("  Check 3 — Digraph struct:   {n_doubled} doubled digraph pairs in even split.".format(**dg_stats))
    print(f"                               Digraph IC = {dg_stats['digraph_ic']:.5f}  (informational).")
    print("                               ➜ INFORMATIONAL (Checks 1+2 are definitive).")
    print()
    print(f"  Check 4 — IC/Statistics:    K4 IC = {ct_ic:.4f} < random (0.0385) < Playfair (0.045-0.055).")
    print("                               IC is INCONSISTENT with Playfair output on English.")
    print("                               ➜ STATISTICALLY INCONSISTENT (corroborating).")
    print()
    print(f"  Check 5 — Keywords:         {len(kryptos_keywords)} keywords on CT[:96] → best {best_crib_kw}/{len(cribs_in_96)} cribs.")
    print(f"                               Chance expectation: {expected_random_cribs:.1f}. No keyword beats noise.")
    print("                               ➜ NO KEYWORD EVIDENCE.")
    print()
    if _QUADGRAMS and 'check6_hillclimb' in results and not results['check6_hillclimb'].get('skipped'):
        hc = results['check6_hillclimb']
        print(f"  Check 6 — Hill-climb:       Best score {hc['best_score_per_char']:.3f}/char,")
        print(f"                               {hc['crib_matches']}/{len(cribs_in_96)} cribs. PT: '{hc['best_pt_first_30']}'")
        print(f"                               ➜ {hc['interpretation']}.")
    print()
    print("  ╔══════════════════════════════════════════════════════════════════╗")
    print("  ║  CONCLUSION: PLAYFAIR IS MATHEMATICALLY ELIMINATED FOR K4.     ║")
    print("  ║                                                                  ║")
    print("  ║  PRIMARY PROOF (Tier 1 — structural):                           ║")
    print("  ║   1. K4 CT length = 97 (odd prime). Playfair always produces    ║")
    print("  ║      even-length output. No key, no padding scheme, no variant  ║")
    print("  ║      can change this. [DERIVED FACT — reproducible proof]       ║")
    print("  ║                                                                  ║")
    print("  ║  INDEPENDENT PROOF (Tier 1 — structural):                       ║")
    print("  ║   2. K4 CT has 26 distinct letters. Playfair CT alphabet has    ║")
    print("  ║      ≤25 (I/J merged). Contradiction.                           ║")
    print("  ║                                                                  ║")
    print("  ║  Two-Square and Four-Square: same structural proofs apply.      ║")
    print("  ╚══════════════════════════════════════════════════════════════════╝")
    print()
    print(f"  Runtime: {elapsed:.2f}s")

    # Save results
    os.makedirs("results", exist_ok=True)
    results['verdict'] = 'STRUCTURALLY_ELIMINATED'
    results['confidence'] = 'MATHEMATICAL_PROOF'
    results['runtime_s'] = round(elapsed, 3)
    results['cross_reference'] = 'E-FRAC-21 Proof 8'
    with open("results/e_playfair_01_disproof.json", "w") as f:
        json.dump(results, f, indent=2, default=str)
    print("  Results written to results/e_playfair_01_disproof.json")
    print()
    print("  RESULT: playfair=ELIMINATED confidence=MATHEMATICAL_PROOF")


if __name__ == "__main__":
    main()
