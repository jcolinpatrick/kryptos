#!/usr/bin/env python3
"""
Cipher: exploratory/bespoke
Family: exploration
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-BESPOKE-09: 99-character CC insertion hypothesis.

Theory: K4's ciphertext is actually 99 characters, with "CC" (Checkpoint Charlie)
needing to be inserted. 99 = 9 × 11 = 3 × 3 × 11, giving:
  - Width-9: exactly 11 rows
  - Width-11: exactly 9 rows
  - Width-3: exactly 33 rows

Sanborn annotated "10.8 rows" → 97/9 = 10.78 ≈ 10.8. If K4 is ACTUALLY
99 chars, then 99/9 = 11 — "10.8" was the clue that 2 chars are missing!

CC = Checkpoint Charlie (Berlin Wall crossing, NATO phonetic C).
K4 already mentions BERLINCLOCK — Checkpoint Charlie is thematically perfect.
The CT has C at only 2 positions (82 and 94) — no CC digraph exists.

Phases:
  1. CC insertion + width-9 columnar with keyword orderings
  2. CC insertion + width-11 columnar with keyword orderings
  3. CC insertion + width-9 exhaustive for top positions
  4. CC at specific thematic positions (w9 + w11 + Vig/Beau)
  5. Single C insertion for width-7 and width-14
  6. Statistical context / false-positive analysis
"""
import itertools
import json
import os
import sys
import time
from collections import defaultdict

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, CRIB_DICT, CRIB_WORDS,
    N_CRIBS, KRYPTOS_ALPHABET,
)

# ── Helpers ──────────────────────────────────────────────────────────────

def keyword_to_col_order(keyword, width):
    """Convert a keyword to column reading order (tuple of ints).
    Handles repeated letters via positional tiebreak.
    Returns None if keyword is shorter than width.
    """
    kw = keyword[:width].upper()
    if len(kw) < width:
        return None
    indexed = [(ch, i) for i, ch in enumerate(kw)]
    ranked = sorted(indexed, key=lambda x: (x[0], x[1]))
    order = [0] * width
    for rank, (_, pos) in enumerate(ranked):
        order[pos] = rank
    return tuple(order)


def columnar_decrypt(ct, width, col_order):
    """Decrypt columnar transposition.

    Encryption: write PT row-by-row into grid of `width` columns,
    read columns in the order specified by col_order (col_order[rank] = col_idx).

    col_order is a RANKING: col_order[col_idx] = rank (the rank of that column).
    We read columns in rank order: rank 0 first, rank 1 second, etc.

    To decrypt: distribute CT characters into columns (by rank order),
    then read row-by-row.
    """
    n = len(ct)
    nrows = (n + width - 1) // width
    # Number of "long" columns (nrows chars) vs "short" (nrows-1 chars)
    n_long = n - (nrows - 1) * width
    if n % width == 0:
        n_long = width

    # Column lengths: first n_long columns (in GRID order) are long
    col_lens = [0] * width
    for col in range(width):
        col_lens[col] = nrows if col < n_long else nrows - 1

    # Distribute CT into columns by rank order
    cols = {}
    pos = 0
    for rank in range(width):
        # Find which column has this rank
        col_idx = list(col_order).index(rank)
        length = col_lens[col_idx]
        cols[col_idx] = ct[pos:pos + length]
        pos += length

    # Read row-by-row
    result = []
    for row in range(nrows):
        for col in range(width):
            if row < len(cols.get(col, '')):
                result.append(cols[col][row])
    return ''.join(result)


def quick_crib_score(pt, crib_dict=None):
    """Fast crib scoring."""
    if crib_dict is None:
        crib_dict = CRIB_DICT
    matches = 0
    for pos, ch in crib_dict.items():
        if pos < len(pt) and pt[pos] == ch:
            matches += 1
    return matches


def make_adjusted_crib_dict(insert_pos, n_inserted=2):
    """Adjust crib positions for characters inserted at insert_pos.

    If we INSERT characters into the CT before decryption, the resulting
    plaintext is longer than 97 chars. The cribs should still be at their
    original positions in the PLAINTEXT.

    Model: The ORIGINAL 99-char CT was transposed from a 99-char PT.
    2 chars were removed from the CT at position insert_pos to produce
    the 97-char sculpture text. The PT still has 99 chars, and the cribs
    are at the SAME positions (21-33, 63-73) in the 99-char PT.
    """
    return CRIB_DICT  # Cribs are at absolute PT positions, PT is 99 chars


def make_shifted_crib_dict(insert_pos, n_inserted=2):
    """Alternative model: cribs were defined on the 97-char text.
    If we insert chars, positions after insert_pos shift by n_inserted.

    Model: The sculpture CT IS the full CT. The "chart" had 99 chars because
    padding was added. The cribs refer to the 97-char plaintext. When we
    test the 99-char decryption, we need to figure out which 97 chars
    correspond to the original positions.
    """
    shifted = {}
    for pos, ch in CRIB_DICT.items():
        if pos < insert_pos:
            shifted[pos] = ch
        else:
            shifted[pos + n_inserted] = ch
    return shifted


def vig_decrypt_str(ct, key):
    """Vigenere decrypt with string key."""
    pt = []
    kw = [ALPH_IDX[c] for c in key.upper()]
    klen = len(kw)
    for i, c in enumerate(ct):
        ci = ALPH_IDX[c]
        ki = kw[i % klen]
        pt.append(ALPH[(ci - ki) % 26])
    return ''.join(pt)


def beau_decrypt_str(ct, key):
    """Beaufort decrypt with string key."""
    pt = []
    kw = [ALPH_IDX[c] for c in key.upper()]
    klen = len(kw)
    for i, c in enumerate(ct):
        ci = ALPH_IDX[c]
        ki = kw[i % klen]
        pt.append(ALPH[(ki - ci) % 26])
    return ''.join(pt)


def score_both_models(pt_full, insert_pos):
    """Score a 99-char PT under both crib models.

    Model A: Cribs at original positions (21-33, 63-73) in the 99-char PT.
    Model B: Cribs shifted — the 2 inserted chars push crib positions.
    Model C: Remove inserted chars from PT, score against original 97-char cribs.
    """
    # Model A: cribs at same absolute positions in 99-char PT
    sc_a = quick_crib_score(pt_full)

    # Model B: shifted cribs
    shifted_dict = make_shifted_crib_dict(insert_pos)
    sc_b = quick_crib_score(pt_full, shifted_dict)

    # Model C: remove 2 chars at insert_pos from PT, score as 97-char
    pt_97 = pt_full[:insert_pos] + pt_full[insert_pos + 2:]
    sc_c = quick_crib_score(pt_97)

    return max(sc_a, sc_b, sc_c), sc_a, sc_b, sc_c, pt_97


# ── Keyword orderings ────────────────────────────────────────────────────

def build_keyword_orderings(width):
    """Build keyword-derived column orderings for a given width."""
    orderings = {}

    keywords_for_order = {
        9: [
            ("KRYPTOSAB", "KRYPTOS+AB"),
            ("PALIMPSES", "PALIMPSEST[:9]"),
            ("CHECKPOIN", "CHECKPOINT[:9]"),
            ("BERLINCLO", "BERLINCLOCK[:9]"),
            ("ABSCISSAX", "ABSCISSA+X"),
            ("CHARLIEXX", "CHARLIE+XX"),
            ("STPWATCHX", "STOPWATCH rearranged"),  # won't work nicely
            ("STOPWATCH", "STOPWATCH"),
            ("HERBERTXX", "HERBERT+XX"),
            ("CARTERXXX", "CARTER+XXX"),
            ("SANBORNXX", "SANBORN+XX"),
            ("SCHEIDTXX", "SCHEIDT+XX"),
            ("ENIGMAXXX", "ENIGMA+XXX"),
            ("CLOCKXXXX", "CLOCK+XXXX"),
        ],
        11: [
            ("BERLINCLOCK", "BERLINCLOCK (perfect 11!)"),
            ("CHECKPOINTC", "CHECKPOINT+C"),
            ("PALIMPSESTX", "PALIMPSEST+X"),
            ("KRYPTOSABCD", "KRYPTOS+ABCD"),
            ("CHARLIEXXX", "CHARLIE+XXX"),   # only 10; skip
            ("EASTNORTHEA", "EASTNORTHEAST[:11]"),
            ("ABSCISSAXXX", "ABSCISSA+XXX"),
            ("MENGELEHREU", "MENGENLEHREUHR[:11]"),
            ("CHECKPOINT", "CHECKPOINT"),    # only 10; skip
            ("ALEXANDERPL", "ALEXANDERPLATZ[:11]"),
            ("SANBORNXXXX", "SANBORN+XXXX"),
            ("ENIGMAXXXXX", "ENIGMA+XXXXX"),
        ],
        7: [
            ("KRYPTOS", "KRYPTOS"),
            ("BERLINN", "BERLIN+N"),
            ("CHARLIE", "CHARLIE"),
            ("ABSCISS", "ABSCISSA[:7]"),
            ("CARTERX", "CARTER+X"),
            ("SANBORN", "SANBORN"),
            ("SCHEIDT", "SCHEIDT"),
            ("ENIGMAX", "ENIGMA+X"),
            ("HERBERT", "HERBERT"),
        ],
        14: [
            ("BERLINCLOCKKR", "BERLINCLOCK+KR"),   # only 13; too short
            ("BERLINCLOCKKRY", "BERLINCLOCK+KRY"),
            ("CHECKPOINTCCHA", "CHECKPOINT+CCHA"),
            ("PALIMPSESTXXXX", "PALIMPSEST+XXXX"),
            ("KRYPTOSABCDEFG", "KRYPTOS+ABCDEFG"),
        ],
    }

    if width not in keywords_for_order:
        return {}

    for kw, label in keywords_for_order[width]:
        order = keyword_to_col_order(kw, width)
        if order is not None:
            orderings[label] = order

    # Also add identity and reverse
    orderings["identity"] = tuple(range(width))
    orderings["reverse"] = tuple(range(width - 1, -1, -1))
    # Odds-then-evens, evens-then-odds
    evens = [i for i in range(width) if i % 2 == 0]
    odds = [i for i in range(width) if i % 2 == 1]
    if len(evens) + len(odds) == width:
        e_then_o = evens + odds
        o_then_e = odds + evens
        # Convert to ranking
        order_eto = [0] * width
        for rank, pos in enumerate(e_then_o):
            order_eto[pos] = rank
        order_ote = [0] * width
        for rank, pos in enumerate(o_then_e):
            order_ote[pos] = rank
        orderings["evens_then_odds"] = tuple(order_eto)
        orderings["odds_then_evens"] = tuple(order_ote)

    return orderings


# ── Substitution keywords ────────────────────────────────────────────────

SUB_KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "CHARLIE",
    "CHECKPOINT", "SANBORN", "SCHEIDT", "HERBERT", "CARTER",
    "ENIGMA", "STOPWATCH", "GOLD", "CLOCK", "SHADOW",
]


# ══════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════

print("=" * 72)
print("E-BESPOKE-09: 99-Character CC Insertion Hypothesis")
print("=" * 72)
print(f"CT length: {CT_LEN}")
print(f"CT: {CT}")
print(f"Cribs: {CRIB_WORDS}")
print()

all_results = []
global_best = 0
global_best_config = ""
t0 = time.time()

# Track per-phase stats
phase_stats = {}

def record_result(phase, score, config_str, pt_fragment, full_config=None):
    global global_best, global_best_config
    entry = {
        'phase': phase,
        'score': score,
        'config': config_str,
        'pt': pt_fragment[:80],
    }
    if full_config:
        entry.update(full_config)
    all_results.append(entry)
    if score > global_best:
        global_best = score
        global_best_config = config_str


# ══════════════════════════════════════════════════════════════════════════
# PHASE 1: CC insertion + width-9 columnar with keyword orderings
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "─" * 72)
print("PHASE 1: CC insertion at 98 positions + width-9 keyword orderings")
print("─" * 72)

w9_orderings = build_keyword_orderings(9)
print(f"  Width-9 keyword orderings: {len(w9_orderings)}")
for label, order in sorted(w9_orderings.items()):
    print(f"    {label}: {order}")

p1_best = 0
p1_count = 0
p1_position_scores = {}  # insert_pos -> best score (for Phase 3 selection)

for insert_pos in range(CT_LEN + 1):  # 0..97 = 98 positions
    extended = CT[:insert_pos] + "CC" + CT[insert_pos:]
    assert len(extended) == 99, f"Expected 99, got {len(extended)}"

    pos_best = 0
    for label, order in w9_orderings.items():
        # Transposition only (no substitution)
        pt_full = columnar_decrypt(extended, 9, order)
        sc, sc_a, sc_b, sc_c, pt_97 = score_both_models(pt_full, insert_pos)
        p1_count += 1

        if sc > pos_best:
            pos_best = sc
        if sc > p1_best:
            p1_best = sc
            cfg = f"CC@{insert_pos}/w9/{label}/order={list(order)}"
            print(f"  NEW BEST: {sc}/24 (A={sc_a},B={sc_b},C={sc_c}) — {cfg}")
            if sc >= 8:
                print(f"    PT99: {pt_full[:60]}")
                print(f"    PT97: {pt_97[:60]}")
                record_result(1, sc, cfg, pt_97, {
                    'insert_pos': insert_pos, 'order': list(order),
                    'label': label, 'sc_a': sc_a, 'sc_b': sc_b, 'sc_c': sc_c,
                })

        # Now add substitution layer
        for sub_kw in SUB_KEYWORDS:
            for variant, fn in [("vig", vig_decrypt_str), ("beau", beau_decrypt_str)]:
                pt_sub = fn(pt_full, sub_kw)
                sc_sub, sa, sb, sc_, pt97s = score_both_models(pt_sub, insert_pos)
                p1_count += 1
                if sc_sub > pos_best:
                    pos_best = sc_sub
                if sc_sub > p1_best:
                    p1_best = sc_sub
                    cfg = f"CC@{insert_pos}/w9/{label}+{variant}({sub_kw})"
                    print(f"  NEW BEST: {sc_sub}/24 (A={sa},B={sb},C={sc_}) — {cfg}")
                    if sc_sub >= 8:
                        print(f"    PT99: {pt_sub[:60]}")
                        print(f"    PT97: {pt97s[:60]}")
                        record_result(1, sc_sub, cfg, pt97s, {
                            'insert_pos': insert_pos, 'order': list(order),
                            'label': label, 'sub_kw': sub_kw, 'variant': variant,
                        })

    p1_position_scores[insert_pos] = pos_best

phase_stats[1] = {'configs': p1_count, 'best': p1_best}
print(f"\n  Phase 1 complete: {p1_count:,} configs, best {p1_best}/24")
print(f"  Time: {time.time() - t0:.1f}s")

# Show top insertion positions
sorted_positions = sorted(p1_position_scores.items(), key=lambda x: -x[1])
print(f"\n  Top 10 insertion positions by score:")
for pos, sc in sorted_positions[:10]:
    print(f"    CC@{pos}: {sc}/24")


# ══════════════════════════════════════════════════════════════════════════
# PHASE 2: CC insertion + width-11 columnar with keyword orderings
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "─" * 72)
print("PHASE 2: CC insertion at 98 positions + width-11 keyword orderings")
print("─" * 72)

w11_orderings = build_keyword_orderings(11)
print(f"  Width-11 keyword orderings: {len(w11_orderings)}")
for label, order in sorted(w11_orderings.items()):
    print(f"    {label}: {order}")

p2_best = 0
p2_count = 0
p2_position_scores = {}

for insert_pos in range(CT_LEN + 1):
    extended = CT[:insert_pos] + "CC" + CT[insert_pos:]
    assert len(extended) == 99

    pos_best = 0
    for label, order in w11_orderings.items():
        pt_full = columnar_decrypt(extended, 11, order)
        sc, sc_a, sc_b, sc_c, pt_97 = score_both_models(pt_full, insert_pos)
        p2_count += 1

        if sc > pos_best:
            pos_best = sc
        if sc > p2_best:
            p2_best = sc
            cfg = f"CC@{insert_pos}/w11/{label}/order={list(order)}"
            print(f"  NEW BEST: {sc}/24 (A={sc_a},B={sc_b},C={sc_c}) — {cfg}")
            if sc >= 8:
                print(f"    PT99: {pt_full[:60]}")
                print(f"    PT97: {pt_97[:60]}")
                record_result(2, sc, cfg, pt_97, {
                    'insert_pos': insert_pos, 'order': list(order), 'label': label,
                })

        # Substitution layer
        for sub_kw in SUB_KEYWORDS:
            for variant, fn in [("vig", vig_decrypt_str), ("beau", beau_decrypt_str)]:
                pt_sub = fn(pt_full, sub_kw)
                sc_sub, sa, sb, sc_, pt97s = score_both_models(pt_sub, insert_pos)
                p2_count += 1
                if sc_sub > pos_best:
                    pos_best = sc_sub
                if sc_sub > p2_best:
                    p2_best = sc_sub
                    cfg = f"CC@{insert_pos}/w11/{label}+{variant}({sub_kw})"
                    print(f"  NEW BEST: {sc_sub}/24 (A={sa},B={sb},C={sc_}) — {cfg}")
                    if sc_sub >= 8:
                        print(f"    PT99: {pt_sub[:60]}")
                        print(f"    PT97: {pt97s[:60]}")
                        record_result(2, sc_sub, cfg, pt97s, {
                            'insert_pos': insert_pos, 'order': list(order),
                            'label': label, 'sub_kw': sub_kw, 'variant': variant,
                        })

    p2_position_scores[insert_pos] = pos_best

phase_stats[2] = {'configs': p2_count, 'best': p2_best}
print(f"\n  Phase 2 complete: {p2_count:,} configs, best {p2_best}/24")
print(f"  Time: {time.time() - t0:.1f}s")


# ══════════════════════════════════════════════════════════════════════════
# PHASE 3: CC insertion + width-9 EXHAUSTIVE for top 5 positions
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "─" * 72)
print("PHASE 3: Width-9 EXHAUSTIVE orderings for top insertion positions")
print("─" * 72)

# Select top 5 insertion positions from Phase 1 (must have scored >= 4)
EXHAUSTIVE_THRESHOLD = 4
top_positions = [
    pos for pos, sc in sorted(p1_position_scores.items(), key=lambda x: -x[1])
    if sc >= EXHAUSTIVE_THRESHOLD
][:5]

if not top_positions:
    # Fall back to top 5 regardless of threshold
    top_positions = [pos for pos, _ in sorted_positions[:5]]

print(f"  Testing {len(top_positions)} insertion positions × 362,880 orderings")
print(f"  Positions: {top_positions}")

p3_best = 0
p3_count = 0

for insert_pos in top_positions:
    extended = CT[:insert_pos] + "CC" + CT[insert_pos:]
    pos_best = 0
    pos_t0 = time.time()

    for order in itertools.permutations(range(9)):
        pt_full = columnar_decrypt(extended, 9, list(order))

        # Score all three models
        sc, sc_a, sc_b, sc_c, pt_97 = score_both_models(pt_full, insert_pos)
        p3_count += 1

        if sc > pos_best:
            pos_best = sc
        if sc > p3_best:
            p3_best = sc
            cfg = f"CC@{insert_pos}/w9_exh/order={list(order)}"
            print(f"  NEW BEST: {sc}/24 (A={sc_a},B={sc_b},C={sc_c}) — {cfg}")
            if sc >= 8:
                print(f"    PT99: {pt_full[:60]}")
                print(f"    PT97: {pt_97[:60]}")
                record_result(3, sc, cfg, pt_97, {
                    'insert_pos': insert_pos, 'order': list(order),
                })

    pos_elapsed = time.time() - pos_t0
    print(f"    CC@{insert_pos}: best {pos_best}/24 (362,880 orderings in {pos_elapsed:.1f}s)")

phase_stats[3] = {'configs': p3_count, 'best': p3_best}
print(f"\n  Phase 3 complete: {p3_count:,} configs, best {p3_best}/24")
print(f"  Time: {time.time() - t0:.1f}s")


# ══════════════════════════════════════════════════════════════════════════
# PHASE 4: CC at specific thematic positions
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "─" * 72)
print("PHASE 4: CC at specific thematic positions + w9/w11 + Vig/Beau")
print("─" * 72)

THEMATIC_POSITIONS = [
    (0, "prepend"),
    (20, "T=20 ('T is your position')"),
    (21, "start of ENE crib"),
    (33, "end of ENE crib (between cribs)"),
    (34, "after ENE crib"),
    (48, "midpoint of gap between cribs"),
    (63, "start of BC crib (Checkpoint Charlie = Berlin landmark)"),
    (73, "end of BC crib"),
    (74, "after BC crib"),
    (82, "next to existing C at pos 82"),
    (94, "next to existing C at pos 94"),
    (97, "append"),
]

p4_best = 0
p4_count = 0

for insert_pos, reason in THEMATIC_POSITIONS:
    extended = CT[:insert_pos] + "CC" + CT[insert_pos:]
    assert len(extended) == 99
    print(f"\n  CC@{insert_pos} ({reason}):")

    pos_best = 0
    for width, orderings in [(9, w9_orderings), (11, w11_orderings)]:
        for label, order in orderings.items():
            pt_full = columnar_decrypt(extended, width, order)
            sc, sc_a, sc_b, sc_c, pt_97 = score_both_models(pt_full, insert_pos)
            p4_count += 1

            if sc > pos_best:
                pos_best = sc
            if sc > p4_best:
                p4_best = sc
                cfg = f"CC@{insert_pos}/w{width}/{label}"
                print(f"    NEW BEST: {sc}/24 — {cfg}")
                if sc >= 8:
                    print(f"      PT97: {pt_97[:60]}")
                    record_result(4, sc, cfg, pt_97)

            # Substitution layer
            for sub_kw in SUB_KEYWORDS:
                for variant, fn in [("vig", vig_decrypt_str), ("beau", beau_decrypt_str)]:
                    pt_sub = fn(pt_full, sub_kw)
                    sc_sub, sa, sb, sc_, pt97s = score_both_models(pt_sub, insert_pos)
                    p4_count += 1
                    if sc_sub > pos_best:
                        pos_best = sc_sub
                    if sc_sub > p4_best:
                        p4_best = sc_sub
                        cfg = f"CC@{insert_pos}/w{width}/{label}+{variant}({sub_kw})"
                        print(f"    NEW BEST: {sc_sub}/24 — {cfg}")
                        if sc_sub >= 8:
                            print(f"      PT97: {pt97s[:60]}")
                            record_result(4, sc_sub, cfg, pt97s)

    print(f"    CC@{insert_pos}: best {pos_best}/24")

phase_stats[4] = {'configs': p4_count, 'best': p4_best}
print(f"\n  Phase 4 complete: {p4_count:,} configs, best {p4_best}/24")
print(f"  Time: {time.time() - t0:.1f}s")


# ══════════════════════════════════════════════════════════════════════════
# PHASE 5: Single C insertion for width-7 (98 = 7 × 14) and width-14
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "─" * 72)
print("PHASE 5: Single C insertion → 98 chars (7 × 14)")
print("─" * 72)

w7_orderings = build_keyword_orderings(7)
w14_orderings = build_keyword_orderings(14)
print(f"  Width-7 orderings: {len(w7_orderings)}")
print(f"  Width-14 orderings: {len(w14_orderings)}")

p5_best = 0
p5_count = 0

for insert_pos in range(CT_LEN + 1):
    extended = CT[:insert_pos] + "C" + CT[insert_pos:]
    assert len(extended) == 98

    for width, orderings in [(7, w7_orderings), (14, w14_orderings)]:
        for label, order in orderings.items():
            pt_full = columnar_decrypt(extended, width, order)

            # Model A: cribs at absolute positions in 98-char PT
            sc_a = quick_crib_score(pt_full)
            # Model C: remove inserted char, score as 97-char
            pt_97 = pt_full[:insert_pos] + pt_full[insert_pos + 1:]
            sc_c = quick_crib_score(pt_97)
            # Shifted model
            shifted_dict = make_shifted_crib_dict(insert_pos, 1)
            sc_b = quick_crib_score(pt_full, shifted_dict)

            sc = max(sc_a, sc_b, sc_c)
            p5_count += 1

            if sc > p5_best:
                p5_best = sc
                cfg = f"C@{insert_pos}/w{width}/{label}"
                print(f"  NEW BEST: {sc}/24 (A={sc_a},B={sc_b},C={sc_c}) — {cfg}")
                if sc >= 8:
                    print(f"    PT97: {pt_97[:60]}")
                    record_result(5, sc, cfg, pt_97)

            # Substitution layer (only for promising configs)
            if sc >= 3:
                for sub_kw in SUB_KEYWORDS[:5]:  # top 5 keywords only
                    for variant, fn in [("vig", vig_decrypt_str), ("beau", beau_decrypt_str)]:
                        pt_sub = fn(pt_full, sub_kw)
                        sa2 = quick_crib_score(pt_sub)
                        pt97s = pt_sub[:insert_pos] + pt_sub[insert_pos + 1:]
                        sc2 = quick_crib_score(pt97s)
                        sd2 = quick_crib_score(pt_sub, shifted_dict)
                        sc_sub = max(sa2, sc2, sd2)
                        p5_count += 1
                        if sc_sub > p5_best:
                            p5_best = sc_sub
                            cfg = f"C@{insert_pos}/w{width}/{label}+{variant}({sub_kw})"
                            print(f"  NEW BEST: {sc_sub}/24 — {cfg}")
                            if sc_sub >= 8:
                                print(f"    PT97: {pt97s[:60]}")
                                record_result(5, sc_sub, cfg, pt97s)

phase_stats[5] = {'configs': p5_count, 'best': p5_best}
print(f"\n  Phase 5 complete: {p5_count:,} configs, best {p5_best}/24")
print(f"  Time: {time.time() - t0:.1f}s")


# ══════════════════════════════════════════════════════════════════════════
# PHASE 6: Statistical context
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "─" * 72)
print("PHASE 6: Statistical Context")
print("─" * 72)

# Count results by score threshold
score_dist = defaultdict(int)
for r in all_results:
    score_dist[r['score']] += 1

total_configs = sum(ps['configs'] for ps in phase_stats.values())
total_above_noise = len([r for r in all_results if r['score'] >= 7])
total_above_store = len([r for r in all_results if r['score'] >= 10])

print(f"\n  Total configurations tested: {total_configs:,}")
print(f"  Results >= 7/24 (above noise): {total_above_noise}")
print(f"  Results >= 10/24 (storable): {total_above_store}")

# Expected noise rates
# For width-9 with 99 chars: 11 exact rows. With random permutation
# and 24 crib positions in 99 positions, expected random = ~24 * (1/26) ≈ 0.92
# Actually it's more complex — each position has a 1/26 chance of matching
# any particular letter, so E[score] ≈ 24/26 ≈ 0.92 for a random substitution.
# For transposition-only, the letters are the same but rearranged.
# Expected crib match for random permutation of 97/99 chars is harder to compute.

print(f"\n  Score distribution:")
for sc in sorted(score_dist.keys(), reverse=True):
    print(f"    Score {sc}/24: {score_dist[sc]} configs")

print(f"\n  Phase-by-phase summary:")
for phase in sorted(phase_stats.keys()):
    ps = phase_stats[phase]
    print(f"    Phase {phase}: {ps['configs']:>10,} configs, best {ps['best']}/24")

# Compare with Phase 1 baseline (no insertion)
print(f"\n  Comparison: Testing w9 with NO insertion (97 chars)...")
p0_best = 0
p0_count = 0
for label, order in w9_orderings.items():
    pt = columnar_decrypt(CT, 9, order)
    sc = quick_crib_score(pt)
    p0_count += 1
    if sc > p0_best:
        p0_best = sc
        print(f"    w9/{label}: {sc}/24")

    for sub_kw in SUB_KEYWORDS:
        for variant, fn in [("vig", vig_decrypt_str), ("beau", beau_decrypt_str)]:
            pt_sub = fn(pt, sub_kw)
            sc_sub = quick_crib_score(pt_sub)
            p0_count += 1
            if sc_sub > p0_best:
                p0_best = sc_sub
                print(f"    w9/{label}+{variant}({sub_kw}): {sc_sub}/24")

print(f"  Baseline (no insertion): {p0_count} configs, best {p0_best}/24")
print(f"  CC insertion improvement over baseline: {max(p1_best, p2_best) - p0_best}")


# ══════════════════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ══════════════════════════════════════════════════════════════════════════
elapsed = time.time() - t0
print(f"\n{'=' * 72}")
print(f"E-BESPOKE-09: FINAL SUMMARY")
print(f"{'=' * 72}")
print(f"Total time: {elapsed:.1f}s")
print(f"Total configs: {total_configs:,}")
print(f"Global best: {global_best}/24")
print(f"Best config: {global_best_config}")

if global_best <= 6:
    classification = "NOISE"
elif global_best <= 9:
    classification = "NOISE (borderline)"
elif global_best <= 17:
    classification = "STORE"
elif global_best <= 23:
    classification = "SIGNAL — INVESTIGATE!"
else:
    classification = "BREAKTHROUGH!"

print(f"Classification: {classification}")

# Print all results >= 8
notable = [r for r in all_results if r['score'] >= 8]
if notable:
    print(f"\nAll results >= 8/24:")
    for r in sorted(notable, key=lambda x: -x['score']):
        print(f"  {r['score']}/24 | Phase {r['phase']} | {r['config']}")
        print(f"    PT: {r['pt']}")
else:
    print(f"\nNo results >= 8/24")

# Save artifact
os.makedirs('results', exist_ok=True)
artifact = {
    'experiment': 'E-BESPOKE-09',
    'description': '99-character CC insertion hypothesis (Checkpoint Charlie)',
    'elapsed_seconds': elapsed,
    'total_configs': total_configs,
    'global_best': global_best,
    'global_best_config': global_best_config,
    'classification': classification,
    'phase_stats': phase_stats,
    'notable_results': notable,
    'all_results_above_noise': [r for r in all_results if r['score'] >= 7],
    'p1_top_positions': sorted_positions[:20],
}
with open('results/e_bespoke_09_99chars_cc.json', 'w') as f:
    json.dump(artifact, f, indent=2, default=str)

print(f"\nArtifact: results/e_bespoke_09_99chars_cc.json")
print(f"{'=' * 72}")
