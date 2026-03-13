#!/usr/bin/env python3
"""
Comprehensive Four-Square / digraphic cipher attack on K4.

Cipher:  Four-Square variants (5×5, 2×13, 26-letter)
Family:  substitution
Status:  active
Keyspace: Multiple variants tested
Last run: never
Best score: N/A

Tests:
1. Terminal null removed (pos 96), 96 chars = 48 digraphs
2. Each of 97 positions as removable null
3. Both 25-letter (I/J merge) and 26-letter systems
4. Both digraph parities (start=0 and start=1)
5. BERLINCLOCK and KRYPTOS as keyword seeds for cipher squares
6. Digraphic IC scoring
"""

import json, math, random, sys, time
from pathlib import Path
from collections import Counter

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from kryptos.kernel.constants import CT, CRIB_DICT

# ── Alphabets ───────────────────────────────────────────────────────────────
ALPHA25 = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # I/J merged
ALPHA26 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def merge_ij(ch):
    return 'I' if ch == 'J' else ch

# ── Load quadgrams ──────────────────────────────────────────────────────────
QG_PATH = Path(__file__).resolve().parents[2] / "data" / "english_quadgrams.json"
with open(QG_PATH) as f:
    _raw_qg = json.load(f)
QG_FLOOR = min(_raw_qg.values()) - 1.0

def quadgram_score(text):
    return sum(_raw_qg.get(text[i:i+4], QG_FLOOR) for i in range(len(text)-3))

def quadgram_per_char(text):
    n = len(text) - 3
    return quadgram_score(text) / n if n > 0 else QG_FLOOR

# ── Grid operations ────────────────────────────────────────────────────────
def make_grid(letters, rows, cols):
    """Make a rows×cols grid from a string of letters."""
    assert len(letters) == rows * cols, f"Expected {rows*cols} letters, got {len(letters)}"
    return [list(letters[i*cols:(i+1)*cols]) for i in range(rows)]

def make_lookup(grid, rows, cols):
    return {grid[r][c]: (r, c) for r in range(rows) for c in range(cols)}

def keyword_square(keyword, alphabet):
    """Generate keyword-mixed alphabet."""
    seen = set()
    result = []
    for ch in keyword.upper():
        if ch in alphabet and ch not in seen:
            result.append(ch)
            seen.add(ch)
    for ch in alphabet:
        if ch not in seen:
            result.append(ch)
            seen.add(ch)
    return ''.join(result)

# ── Four-Square decrypt (generic grid size) ────────────────────────────────
def four_square_decrypt_generic(ct_text, p1, p2, c1, c2, rows, cols, start=0):
    """Decrypt using Four-Square with arbitrary grid dimensions."""
    c1_lk = make_lookup(c1, rows, cols)
    c2_lk = make_lookup(c2, rows, cols)

    pt = []
    i = start
    while i + 1 < len(ct_text):
        ct1, ct2 = ct_text[i], ct_text[i+1]
        if ct1 not in c1_lk or ct2 not in c2_lk:
            pt.append('?')
            pt.append('?')
            i += 2
            continue
        r1, j1 = c1_lk[ct1]
        r2, j2 = c2_lk[ct2]
        pt.append(p1[r1][j2])
        pt.append(p2[r2][j1])
        i += 2

    if i < len(ct_text):
        pt.append(ct_text[i])

    return ''.join(pt)

# ── Crib scoring ───────────────────────────────────────────────────────────
def crib_score(plaintext, crib_dict=CRIB_DICT, use_merge=True):
    """Count crib matches. Handles both 25 and 26 letter systems."""
    matches = 0
    for pos, expected in crib_dict.items():
        if pos < len(plaintext):
            actual = plaintext[pos]
            if use_merge:
                if merge_ij(actual) == merge_ij(expected):
                    matches += 1
            else:
                if actual == expected:
                    matches += 1
    return matches

# ── Simulated Annealing (generic) ──────────────────────────────────────────
def sa_generic(ct_text, rows, cols, alphabet, start=0,
               keywords=None, n_restarts=30, steps=40000,
               crib_weight=30.0, crib_dict=CRIB_DICT):
    """
    SA for generic grid Four-Square.

    keywords: optional dict mapping grid index (0=p1, 1=c1, 2=c2, 3=p2)
              to keyword string for initialization
    """
    n_letters = rows * cols
    assert len(alphabet) == n_letters
    use_merge = (n_letters == 25)

    if use_merge:
        ct = ''.join(merge_ij(ch) for ch in ct_text)
    else:
        ct = ct_text

    best_global = (-float('inf'), "", None, 0)

    for restart in range(n_restarts):
        # Initialize grids
        grids = []
        for g_idx in range(4):
            if keywords and g_idx in keywords:
                grids.append(keyword_square(keywords[g_idx], alphabet))
            else:
                letters = list(alphabet)
                random.shuffle(letters)
                grids.append(''.join(letters))

        p1 = make_grid(grids[0], rows, cols)
        c1 = make_grid(grids[1], rows, cols)
        c2 = make_grid(grids[2], rows, cols)
        p2 = make_grid(grids[3], rows, cols)

        pt = four_square_decrypt_generic(ct, p1, p2, c1, c2, rows, cols, start)
        qg = quadgram_score(pt)
        cs = crib_score(pt, crib_dict, use_merge)
        current_score = qg + cs * crib_weight

        best_score = current_score
        best_grids = list(grids)
        best_cs = cs
        best_pt = pt

        for step in range(steps):
            t = 1.5 * (0.005 / 1.5) ** (step / max(steps-1, 1))

            grid_idx = random.randint(0, 3)
            new_grids = list(grids)
            # Swap two letters in chosen grid
            lst = list(grids[grid_idx])
            i, j = random.sample(range(n_letters), 2)
            lst[i], lst[j] = lst[j], lst[i]
            new_grids[grid_idx] = ''.join(lst)

            np1 = make_grid(new_grids[0], rows, cols)
            nc1 = make_grid(new_grids[1], rows, cols)
            nc2 = make_grid(new_grids[2], rows, cols)
            np2 = make_grid(new_grids[3], rows, cols)

            npt = four_square_decrypt_generic(ct, np1, np2, nc1, nc2, rows, cols, start)
            nqg = quadgram_score(npt)
            ncs = crib_score(npt, crib_dict, use_merge)
            new_score = nqg + ncs * crib_weight

            delta = new_score - current_score
            if delta > 0 or random.random() < math.exp(delta / t):
                grids = new_grids
                current_score = new_score
                pt = npt
                cs = ncs

                if new_score > best_score:
                    best_score = new_score
                    best_grids = list(new_grids)
                    best_cs = ncs
                    best_pt = npt

        if best_cs > best_global[3] or (best_cs == best_global[3] and quadgram_per_char(best_pt) > quadgram_per_char(best_global[1])):
            best_global = (best_score, best_pt, best_grids, best_cs)

    return best_global

# ── Main test suite ────────────────────────────────────────────────────────
def run_tests():
    print("=" * 70)
    print("COMPREHENSIVE FOUR-SQUARE ATTACK ON K4")
    print("=" * 70)
    print(f"CT: {CT}")
    print(f"CT len: {len(CT)}")
    print()

    results = []

    # ═══════════════════════════════════════════════════════════════════
    # TEST 1: 5×5 Four-Square with keyword seeds
    # ═══════════════════════════════════════════════════════════════════
    print("\n" + "="*70)
    print("TEST 1: 5×5 Four-Square with keyword seeds (96 chars, start=0)")
    print("="*70)

    ct96 = CT[:96]
    keyword_configs = [
        ({1: "BERLINCLOCK", 2: "KRYPTOS"}, "c1=BERLINCLOCK, c2=KRYPTOS"),
        ({1: "KRYPTOS", 2: "BERLINCLOCK"}, "c1=KRYPTOS, c2=BERLINCLOCK"),
        ({1: "BERLINCLOCK", 2: "BERLINCLOCK"}, "c1=c2=BERLINCLOCK"),
        ({0: "KRYPTOS", 3: "KRYPTOS"}, "p1=p2=KRYPTOS"),
        ({0: "BERLINCLOCK", 3: "BERLINCLOCK"}, "p1=p2=BERLINCLOCK"),
        ({0: "KRYPTOS", 1: "BERLINCLOCK", 2: "BERLINCLOCK", 3: "KRYPTOS"},
         "p1=p2=KRYPTOS, c1=c2=BERLINCLOCK"),
        ({1: "KOMPASS", 2: "DEFECTOR"}, "c1=KOMPASS, c2=DEFECTOR"),
        ({}, "all random (control)"),
    ]

    random.seed(42)
    for kw_dict, desc in keyword_configs:
        score, pt, grids, cs = sa_generic(
            ct96, 5, 5, ALPHA25, start=0,
            keywords=kw_dict, n_restarts=15, steps=30000, crib_weight=30.0
        )
        qg = quadgram_per_char(pt)
        print(f"  {desc}")
        print(f"    crib={cs}/24 qg={qg:.3f} | {pt[:50]}...")
        results.append((cs, qg, desc, pt))

    # ═══════════════════════════════════════════════════════════════════
    # TEST 2: 2×13 Four-Square (26-letter, no I/J merge)
    # ═══════════════════════════════════════════════════════════════════
    print("\n" + "="*70)
    print("TEST 2: 2×13 Four-Square (26-letter, no I/J merge)")
    print("="*70)

    random.seed(123)
    for start in [0, 1]:
        for kw_dict, desc in [
            ({1: "BERLINCLOCK", 2: "KRYPTOS"}, f"c1=BERLINCLOCK c2=KRYPTOS start={start}"),
            ({}, f"all random start={start}"),
        ]:
            score, pt, grids, cs = sa_generic(
                ct96, 2, 13, ALPHA26, start=start,
                keywords=kw_dict, n_restarts=15, steps=30000,
                crib_weight=30.0, crib_dict=CRIB_DICT
            )
            qg = quadgram_per_char(pt)
            print(f"  {desc}")
            print(f"    crib={cs}/24 qg={qg:.3f} | {pt[:50]}...")
            results.append((cs, qg, f"2x13: {desc}", pt))

    # ═══════════════════════════════════════════════════════════════════
    # TEST 3: Null at each of 97 positions, then 5×5 on remaining 96
    # ═══════════════════════════════════════════════════════════════════
    print("\n" + "="*70)
    print("TEST 3: Remove each position as null, check digraphic properties")
    print("="*70)

    def digraphic_ic(text, start=0):
        digraphs = [text[i:i+2] for i in range(start, len(text)-1, 2)]
        n = len(digraphs)
        freq = Counter(digraphs)
        num = sum(f*(f-1) for f in freq.values())
        den = n*(n-1)
        return (num/den*625) if den > 0 else 0

    best_null_positions = []
    for null_pos in range(97):
        # Remove this position
        remaining = CT[:null_pos] + CT[null_pos+1:]
        assert len(remaining) == 96

        # Check digraphic IC at both parities
        for start in [0, 1]:
            rm = ''.join(merge_ij(ch) for ch in remaining)
            dic = digraphic_ic(rm, start)

            # Adjust crib positions (positions after null_pos shift down by 1)
            shifted_cribs = {}
            for pos, ch in CRIB_DICT.items():
                new_pos = pos if pos < null_pos else pos - 1
                shifted_cribs[new_pos] = ch

            if dic > 2.5:
                best_null_positions.append((dic, null_pos, start, remaining, shifted_cribs))

    best_null_positions.sort(reverse=True)
    print(f"  Positions with digraphic IC × 625 > 2.5: {len(best_null_positions)}")

    for dic, null_pos, start, remaining, shifted_cribs in best_null_positions[:10]:
        print(f"  null={null_pos:2d} (char={CT[null_pos]}) start={start}: dic={dic:.2f}")

    # Run SA on top candidates
    if best_null_positions:
        print(f"\n  Running SA on top 5 null positions...")
        random.seed(456)
        for dic, null_pos, start, remaining, shifted_cribs in best_null_positions[:5]:
            score, pt, grids, cs = sa_generic(
                remaining, 5, 5, ALPHA25, start=start,
                keywords={1: "BERLINCLOCK"}, n_restarts=10, steps=25000,
                crib_weight=30.0, crib_dict=shifted_cribs
            )
            qg = quadgram_per_char(pt)
            print(f"  null={null_pos} ('{CT[null_pos]}') start={start}: crib={cs}/24 qg={qg:.3f} dic={dic:.2f}")
            print(f"    {pt[:50]}...")
            results.append((cs, qg, f"null@{null_pos} start={start}", pt))

    # ═══════════════════════════════════════════════════════════════════
    # TEST 4: Start=1 with 97 chars (48 digraphs + first char solo)
    # ═══════════════════════════════════════════════════════════════════
    print("\n" + "="*70)
    print("TEST 4: Start=1 parity (97 chars)")
    print("="*70)

    random.seed(789)
    score, pt, grids, cs = sa_generic(
        CT, 5, 5, ALPHA25, start=1,
        keywords={1: "BERLINCLOCK", 2: "KRYPTOS"},
        n_restarts=15, steps=30000, crib_weight=30.0
    )
    qg = quadgram_per_char(pt)
    print(f"  5×5 start=1: crib={cs}/24 qg={qg:.3f}")
    print(f"    {pt[:60]}...")
    results.append((cs, qg, "5x5 start=1", pt))

    # ═══════════════════════════════════════════════════════════════════
    # SUMMARY
    # ═══════════════════════════════════════════════════════════════════
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    results.sort(key=lambda x: (-x[0], -x[1]))
    for cs, qg, desc, pt in results[:15]:
        print(f"  crib={cs:2d}/24 qg={qg:+.3f} | {desc}")
        if cs >= 20:
            print(f"         {pt[:60]}...")

if __name__ == "__main__":
    t0 = time.time()
    run_tests()
    print(f"\nTotal elapsed: {time.time()-t0:.1f}s")
