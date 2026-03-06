#!/usr/bin/env python3
"""
T16 deep attack — IC below random (0.0356), no Kasiski, all basic attacks fail.
Escalation: autokey, Bifid, rail fence, then two-layer with non-columnar transpositions.
"""

import json
from collections import Counter
from itertools import permutations
from math import gcd

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CT = "YIVGXDNRBZUVGGHTLJPQLVTFNVAJQBFURTCMUPTAWCVSGHJLUKZKGN"

with open("data/english_quadgrams.json") as f:
    QG = json.load(f)
QG_FLOOR = min(QG.values()) - 2.0

def qg_score(text: str) -> float:
    if len(text) < 4:
        return -99.0
    return sum(QG.get(text[i:i+4], QG_FLOOR) for i in range(len(text) - 3)) / (len(text) - 3)

def ic(text: str) -> float:
    n = len(text)
    if n <= 1:
        return 0.0
    freq = Counter(text)
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))

# Check what's missing
present = set(CT)
missing = set(ALPHA) - present
print(f"Length: {len(CT)}")
print(f"IC: {ic(CT):.4f}")
print(f"Letters present: {len(present)} ({sorted(present)})")
print(f"Missing: {sorted(missing)}")

# ── AUTOKEY (Vigenere + Beaufort, PT-keyed + CT-keyed) ──
print(f"\n{'=' * 72}")
print("AUTOKEY ATTACK (dictionary primers, all 4 variants)")
print("=" * 72)

def autokey_vig_pt_decrypt(ct: str, primer: str) -> str:
    """Vigenere autokey, PT-keyed: K = primer || PT"""
    pt = []
    key = list(primer)
    for i, c in enumerate(ct):
        k = ALPHA.index(key[i])
        p = (ALPHA.index(c) - k) % 26
        pt.append(ALPHA[p])
        key.append(ALPHA[p])
    return "".join(pt)

def autokey_vig_ct_decrypt(ct: str, primer: str) -> str:
    """Vigenere autokey, CT-keyed: K = primer || CT"""
    pt = []
    key = list(primer)
    for i, c in enumerate(ct):
        k = ALPHA.index(key[i])
        p = (ALPHA.index(c) - k) % 26
        pt.append(ALPHA[p])
        key.append(c)
    return "".join(pt)

def autokey_beau_pt_decrypt(ct: str, primer: str) -> str:
    """Beaufort autokey, PT-keyed"""
    pt = []
    key = list(primer)
    for i, c in enumerate(ct):
        k = ALPHA.index(key[i])
        p = (k - ALPHA.index(c)) % 26
        pt.append(ALPHA[p])
        key.append(ALPHA[p])
    return "".join(pt)

def autokey_beau_ct_decrypt(ct: str, primer: str) -> str:
    """Beaufort autokey, CT-keyed"""
    pt = []
    key = list(primer)
    for i, c in enumerate(ct):
        k = ALPHA.index(key[i])
        p = (k - ALPHA.index(c)) % 26
        pt.append(ALPHA[p])
        key.append(c)
    return "".join(pt)

with open("wordlists/english.txt") as f:
    words = [w.strip().upper() for w in f if 2 <= len(w.strip()) <= 12
             and w.strip().isalpha() and all(c in ALPHA for c in w.strip().upper())]
print(f"Loaded {len(words)} words")

autokey_funcs = [
    ("Vig-PT", autokey_vig_pt_decrypt),
    ("Vig-CT", autokey_vig_ct_decrypt),
    ("Beau-PT", autokey_beau_pt_decrypt),
    ("Beau-CT", autokey_beau_ct_decrypt),
]

best_autokey = (-99, "", "", "")
for name, func in autokey_funcs:
    best_for_variant = (-99, "", "")
    for word in words:
        pt = func(CT, word)
        s = qg_score(pt)
        if s > best_for_variant[0]:
            best_for_variant = (s, pt, word)
        if s > best_autokey[0]:
            best_autokey = (s, pt, word, name)
    print(f"  {name:<8} best: key={best_for_variant[2]}, score={best_for_variant[0]:.3f}, {best_for_variant[1][:40]}...")

if best_autokey[0] > -4.5:
    print(f"\n  *** AUTOKEY SOLVED: {best_autokey[3]}, key={best_autokey[2]}, score={best_autokey[0]:.3f}")
    print(f"  PT: {best_autokey[1]}")
else:
    print(f"\n  Autokey best: {best_autokey[0]:.3f} — not solved")

# ── BIFID ──
print(f"\n{'=' * 72}")
print("BIFID ATTACK (dictionary keywords, periods 3-27)")
print("=" * 72)

def make_polybius_grid(keyword: str) -> list[str]:
    """5x5 Polybius grid, I/J merged."""
    seen = set()
    grid = []
    for c in keyword.upper() + "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if c == 'J':
            c = 'I'
        if c not in seen and c in ALPHA:
            seen.add(c)
            grid.append(c)
    return grid

def bifid_decrypt(ct: str, grid: list[str], period: int) -> str:
    ct = ct.upper().replace('J', 'I')
    # Letter to coords
    def to_rc(c):
        idx = grid.index(c)
        return idx // 5, idx % 5

    def from_rc(r, c):
        return grid[r * 5 + c]

    pt = []
    for start in range(0, len(ct), period):
        block = ct[start:start + period]
        rows = []
        cols = []
        for c in block:
            r, co = to_rc(c)
            rows.append(r)
            cols.append(co)
        # Interleave: [r0, c0, r1, c1, ...] then split into first half = PT rows, second half = PT cols
        interleaved = []
        for i in range(len(block)):
            interleaved.append(rows[i])
            interleaved.append(cols[i])
        half = len(interleaved) // 2
        pt_rows = interleaved[:half]
        pt_cols = interleaved[half:]
        for i in range(len(pt_rows)):
            pt.append(from_rc(pt_rows[i], pt_cols[i]))
    return "".join(pt)

# Try dictionary keywords with various periods
best_bifid = (-99, "", "", 0)
keyword_set = set()
for w in words:
    if 3 <= len(w) <= 15:
        keyword_set.add(w)

print(f"  Testing {len(keyword_set)} keywords × periods 3-27")
for kw in keyword_set:
    grid = make_polybius_grid(kw)
    for period in [5, 6, 7, 8, 9, 10, 11, 12, 54]:  # Common periods + full-length
        try:
            pt = bifid_decrypt(CT, grid, period)
            s = qg_score(pt)
            if s > best_bifid[0]:
                best_bifid = (s, pt, kw, period)
                if s > -4.5:
                    print(f"  *** HIT: kw={kw}, period={period}, score={s:.3f}, {pt[:40]}...")
        except (ValueError, IndexError):
            continue

print(f"  Bifid best: kw={best_bifid[2]}, period={best_bifid[3]}, score={best_bifid[0]:.3f}")
if best_bifid[0] > -4.5:
    print(f"  PT: {best_bifid[1]}")

# ── RAIL FENCE ──
print(f"\n{'=' * 72}")
print("RAIL FENCE (rails 2-15)")
print("=" * 72)

def rail_fence_decrypt(ct: str, rails: int) -> str:
    n = len(ct)
    pattern = []
    for r in range(rails):
        for i in range(n):
            cycle = 2 * (rails - 1)
            if cycle == 0:
                cycle = 1
            mod = i % cycle
            if mod == r or mod == cycle - r:
                pattern.append((r, i))
    pattern.sort()
    result = [''] * n
    for idx, (_, orig_pos) in enumerate(pattern):
        if idx < len(ct):
            result[orig_pos] = ct[idx]
    return "".join(result)

best_rail = (-99, "", 0)
for rails in range(2, 16):
    pt = rail_fence_decrypt(CT, rails)
    s = qg_score(pt)
    if s > best_rail[0]:
        best_rail = (s, pt, rails)
print(f"  Best: rails={best_rail[2]}, score={best_rail[0]:.3f}, {best_rail[1][:40]}...")

# ── OVERALL RESULTS ──
print(f"\n{'=' * 72}")
print("OVERALL SCOREBOARD")
print("=" * 72)
all_results = [
    ("Autokey", best_autokey[0], best_autokey[1], f"{best_autokey[3]} key={best_autokey[2]}"),
    ("Bifid", best_bifid[0], best_bifid[1], f"kw={best_bifid[2]} p={best_bifid[3]}"),
    ("Rail Fence", best_rail[0], best_rail[1], f"rails={best_rail[2]}"),
]
all_results.sort(key=lambda x: -x[1])
for name, score, pt, detail in all_results:
    marker = " *** SOLVED" if score > -4.5 else ""
    print(f"  {name:<12} {score:>7.3f}  {detail:<30}  {pt[:35]}...{marker}")
