#!/usr/bin/env python3
"""
VIC Cipher Model: Straddling Checkerboard + Columnar Transposition attack on K4.

Cipher:  Straddling Checkerboard + Columnar Transposition (VIC-style)
Family:  substitution
Status:  active
Keyspace: prefix_sets × columnar_widths × permutations
Last run: never
Best score: N/A

Two-system model matching Scheidt's background:
  PT(73) → straddling checkerboard encode → intermediate(97) → columnar trans → CT(97)

73 PT chars → 49 monomes (1 CT char each) + 24 dinomes (2 CT chars each) = 97 CT chars.
Need ≥4 "prefix" letters (combined CT freq ≥ 24) since max single-letter freq = 8.

Attack: pattern-match crib repetition signatures (EASTNORTHEAST + BERLINCLOCK)
in the decoded 73-token sequence, without needing the actual checkerboard table.

Two sub-models:
  A) CT → undo trans(97) → intermediate → decode → PT(73)
  B) CT → decode → transposed(73) → undo trans(73) → PT(73)
"""

import sys, time, math
from pathlib import Path
from itertools import permutations, combinations
from collections import Counter

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from kryptos.kernel.constants import CT

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# ── Crib Patterns ────────────────────────────────────────────────────────────
# EASTNORTHEAST: positions with same letter
#   E(0,9) A(1,10) S(2,11) T(3,7,12) N(4) O(5) R(6) H(8)
# BERLINCLOCK: L(3,7) C(6,9), rest unique
#   B(0) E(1) R(2) L(3,7) I(4) N(5) C(6,9) O(8) K(10)
# Cross-constraints (shared letters): E(ENE:0,BC:1) N(ENE:4,BC:5) O(ENE:5,BC:8) R(ENE:6,BC:2)
ENE_LEN = 13
BC_LEN = 11


def check_ene(tokens, p):
    """Check EASTNORTHEAST repetition pattern at position p."""
    t = tokens
    # Equality checks
    if t[p] != t[p+9]: return False      # E
    if t[p+1] != t[p+10]: return False    # A
    if t[p+2] != t[p+11]: return False    # S
    if t[p+3] != t[p+7]: return False     # T
    if t[p+3] != t[p+12]: return False    # T
    # 8 groups must all be distinct
    vals = {t[p], t[p+1], t[p+2], t[p+3], t[p+4], t[p+5], t[p+6], t[p+8]}
    return len(vals) == 8


def check_bc(tokens, q):
    """Check BERLINCLOCK repetition pattern at position q."""
    t = tokens
    if t[q+3] != t[q+7]: return False     # L
    if t[q+6] != t[q+9]: return False     # C
    # 9 groups must all be distinct
    vals = {t[q], t[q+1], t[q+2], t[q+3], t[q+4], t[q+5], t[q+6], t[q+8], t[q+10]}
    return len(vals) == 9


def check_cross(tokens, p, q):
    """Cross-crib constraints + 13 distinct token values."""
    t = tokens
    # Shared letters must have same token
    if t[p] != t[q+1]: return False       # E
    if t[p+4] != t[q+5]: return False     # N
    if t[p+5] != t[q+8]: return False     # O
    if t[p+6] != t[q+2]: return False     # R
    # All 13 crib letters must have distinct tokens
    # ENE unique: E,A,S,T,N,O,R,H  +  BC unique: B,L,I,C,K
    all_toks = {
        t[p], t[p+1], t[p+2], t[p+3], t[p+4], t[p+5], t[p+6], t[p+8],  # 8 ENE
        t[q], t[q+3], t[q+4], t[q+6], t[q+10]                            # 5 BC-only
    }
    return len(all_toks) == 13


def find_crib_patterns(tokens):
    """Find all (p, q) with both crib patterns + cross-constraints."""
    n = len(tokens)
    hits = []
    # First find ENE matches (rare — most positions fail first equality)
    ene_matches = []
    max_p = n - ENE_LEN
    for p in range(max_p + 1):
        if check_ene(tokens, p):
            ene_matches.append(p)
    if not ene_matches:
        return hits
    # For each ENE match, check BC + cross
    max_q = n - BC_LEN
    for p in ene_matches:
        for q in range(max_q + 1):
            if check_bc(tokens, q) and check_cross(tokens, p, q):
                hits.append((p, q))
    return hits


# ── Parsing & Transposition ──────────────────────────────────────────────────

def parse_cb(text, prefix_set):
    """Parse text with prefix_set → list of tokens (str, length 1 or 2)."""
    tokens = []
    i = 0
    n = len(text)
    while i < n:
        if text[i] in prefix_set:
            if i + 1 < n:
                tokens.append(text[i:i+2])
                i += 2
            else:
                tokens.append(text[i])
                i += 1
        else:
            tokens.append(text[i])
            i += 1
    return tokens


def count_tokens(text, prefix_set):
    """Count tokens without building list (fast)."""
    count = 0
    i = 0
    n = len(text)
    while i < n:
        if text[i] in prefix_set:
            i += 2
        else:
            i += 1
        count += 1
    return count


def columnar_undo(seq, width, perm):
    """Undo columnar transposition. Works on strings or lists.
    perm[i] = column index read i-th from CT."""
    n = len(seq)
    nrows = -(-n // width)
    rem = n % width
    col_lens = [nrows if c < rem else nrows - 1 for c in range(width)] if rem else [nrows] * width

    is_str = isinstance(seq, str)
    cols = [None] * width
    pos = 0
    for ci in perm:
        cl = col_lens[ci]
        cols[ci] = seq[pos:pos+cl]
        pos += cl

    if is_str:
        result = []
        for r in range(nrows):
            for c in range(width):
                if r < len(cols[c]):
                    result.append(cols[c][r])
        return ''.join(result)
    else:
        result = []
        for r in range(nrows):
            for c in range(width):
                if r < len(cols[c]):
                    result.append(cols[c][r])
        return result


def decode_hit(tokens, p, q):
    """Extract partial checkerboard table from a hit."""
    table = {}
    for i, ch in enumerate("EASTNORTHEAST"):
        tok = tokens[p + i]
        if ch in table:
            assert table[ch] == tok, f"Inconsistency: {ch}→{table[ch]} vs {tok}"
        else:
            table[ch] = tok
    for i, ch in enumerate("BERLINCLOCK"):
        tok = tokens[q + i]
        if ch in table:
            assert table[ch] == tok, f"Inconsistency: {ch}→{table[ch]} vs {tok}"
        else:
            table[ch] = tok
    return table


# ── Main ─────────────────────────────────────────────────────────────────────

def run():
    ct = CT
    ct_freq = Counter(ct)
    all_hits = []

    print("=" * 70)
    print("VIC CIPHER MODEL: STRADDLING CHECKERBOARD + COLUMNAR TRANSPOSITION")
    print("=" * 70)
    print(f"CT: {ct}")
    print(f"CT length: {len(ct)}")
    print()

    # ── Phase 0: Enumerate valid prefix sets ─────────────────────────────
    print("Phase 0: Enumerating prefix sets (combined CT freq >= 24)")
    valid_by_size = {}
    for size in range(4, 11):
        sets = []
        for combo in combinations(ALPHA, size):
            f = sum(ct_freq.get(c, 0) for c in combo)
            if f >= 24:
                sets.append((combo, f))
        valid_by_size[size] = sets
        print(f"  Size {size}: {len(sets):,} valid prefix sets")
    print()

    t0 = time.time()
    configs_total = 0

    # ══════════════════════════════════════════════════════════════════════
    # MODEL B: CT → decode → transposed(73) → undo trans → PT(73)
    # Parse CT once per prefix set, then try transpositions on token list
    # ══════════════════════════════════════════════════════════════════════
    print("=" * 70)
    print("MODEL B: CT → decode → transposed(73) → undo trans(73) → PT(73)")
    print("=" * 70)

    # Find prefix sets giving 73 tokens from CT parse
    b_valid = []
    for size in range(4, 11):
        count_73 = 0
        for combo, freq in valid_by_size[size]:
            ps = set(combo)
            tc = count_tokens(ct, ps)
            if tc == 73:
                tokens = parse_cb(ct, ps)
                b_valid.append((combo, tokens, size))
                count_73 += 1
        if count_73 > 0:
            print(f"  Size {size}: {count_73} prefix sets give 73 tokens from CT")
    print(f"  Total: {len(b_valid)} prefix sets for Model B")

    # Identity transposition (no trans)
    print("\n  Testing identity transposition (no trans)...")
    id_hits = 0
    for combo, tokens, size in b_valid:
        hits = find_crib_patterns(tokens)
        for p, q in hits:
            id_hits += 1
            table = decode_hit(tokens, p, q)
            inv = {v: k for k, v in table.items()}
            decoded = ''.join(inv.get(tok, '?') for tok in tokens)
            print(f"  *** HIT: prefix={combo} ENE@{p} BC@{q}")
            print(f"      Partial PT: {decoded}")
            all_hits.append(('B', 'id', combo, None, p, q, tokens))
    print(f"  Identity: {id_hits} hits")

    # With columnar transposition
    # Tight limits to keep runtime ~5 minutes:
    # size 5: w5-8 (61 sets), size 6: w5-7 (2972), size 7: w5 (34K), size 8+: identity only
    width_limits = {4: 8, 5: 8, 6: 7, 7: 5, 8: 0, 9: 0, 10: 0}

    for width in range(5, 9):
        # Filter prefix sets applicable to this width
        applicable = [(c, t, s) for c, t, s in b_valid if width <= width_limits.get(s, 0)]
        if not applicable:
            continue

        perms = list(permutations(range(width)))
        total = len(perms) * len(applicable)
        print(f"\n  Width {width}: {len(perms)} perms × {len(applicable)} prefix sets = {total:,} configs")

        w_hits = 0
        w_configs = 0
        t_w = time.time()
        for combo, tokens, size in applicable:
            for perm in perms:
                w_configs += 1
                configs_total += 1
                untrans = columnar_undo(tokens, width, perm)
                hits = find_crib_patterns(untrans)
                for p, q in hits:
                    w_hits += 1
                    table = decode_hit(untrans, p, q)
                    inv = {v: k for k, v in table.items()}
                    decoded = ''.join(inv.get(tok, '?') for tok in untrans)
                    print(f"  *** HIT: prefix={combo} w={width} perm={perm} ENE@{p} BC@{q}")
                    print(f"      Partial PT: {decoded}")
                    all_hits.append(('B', width, combo, perm, p, q, untrans))

            if w_configs % 100000 == 0:
                print(f"    ... {w_configs:,}/{total:,} ({time.time()-t_w:.1f}s)", flush=True)

        print(f"    → {w_hits} hits ({w_configs:,} configs, {time.time()-t_w:.1f}s)")

    print(f"\n  Model B total: {configs_total:,} configs, {len(all_hits)} hits, {time.time()-t0:.1f}s")

    # ══════════════════════════════════════════════════════════════════════
    # MODEL A: CT → undo trans(97) → intermediate → decode → PT(73)
    # Undo transposition on 97-char CT, then parse intermediate
    # ══════════════════════════════════════════════════════════════════════
    print()
    print("=" * 70)
    print("MODEL A: CT → undo trans(97) → intermediate(97) → decode → PT(73)")
    print("=" * 70)

    # For Model A, organize by width. For each permutation, compute intermediate
    # once, then test all prefix sets.
    # Limit: size 4 → widths 5-8, size 5 → widths 5-7, size 6 → width 5-6
    a_width_limits = {4: 8, 5: 7, 6: 6}
    a_configs = 0
    a_hits = 0
    t_a = time.time()

    for width in range(5, 9):
        # Collect applicable prefix sets for this width
        applicable = []
        for size in range(4, 7):  # only sizes 4-6 for model A
            if width <= a_width_limits.get(size, 5):
                applicable.extend(valid_by_size[size])
        if not applicable:
            continue

        perms_list = list(permutations(range(width)))
        total = len(perms_list) * len(applicable)
        print(f"\n  Width {width}: {len(perms_list)} perms × {len(applicable)} prefix sets = {total:,} configs")

        w_hits = 0
        w_configs = 0
        w_73_count = 0
        t_w = time.time()

        for perm in perms_list:
            intermediate = columnar_undo(ct, width, perm)

            for combo, freq in applicable:
                ps = set(combo)
                w_configs += 1
                a_configs += 1

                tc = count_tokens(intermediate, ps)
                if tc != 73:
                    continue
                w_73_count += 1

                tokens = parse_cb(intermediate, ps)
                hits = find_crib_patterns(tokens)
                for p, q in hits:
                    w_hits += 1
                    a_hits += 1
                    table = decode_hit(tokens, p, q)
                    inv = {v: k for k, v in table.items()}
                    decoded = ''.join(inv.get(tok, '?') for tok in tokens)
                    print(f"  *** HIT: prefix={combo} w={width} perm={perm} ENE@{p} BC@{q}")
                    print(f"      Partial PT: {decoded}")
                    all_hits.append(('A', width, combo, perm, p, q, tokens))

            if w_configs % 500000 == 0 and w_configs > 0:
                elapsed = time.time() - t_w
                rate = w_configs / elapsed if elapsed > 0 else 0
                print(f"    ... {w_configs:,}/{total:,} ({w_73_count} with 73 tokens, "
                      f"{w_hits} hits, {elapsed:.1f}s, {rate:.0f}/s)", flush=True)

        elapsed = time.time() - t_w
        print(f"    → {w_hits} hits ({w_configs:,} tested, {w_73_count} had 73 tokens, {elapsed:.1f}s)")

    print(f"\n  Model A total: {a_configs:,} configs, {a_hits} hits, {time.time()-t_a:.1f}s")

    # ══════════════════════════════════════════════════════════════════════
    # SUMMARY
    # ══════════════════════════════════════════════════════════════════════
    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    total = configs_total + a_configs
    print(f"Total configs tested: {total:,}")
    print(f"Total hits: {len(all_hits)}")
    print(f"Total elapsed: {time.time()-t0:.1f}s")

    if all_hits:
        print("\nHIT DETAILS:")
        for hit in all_hits:
            model, width, prefix, perm, p, q, tokens = hit
            print(f"\n  Model {model}, width={width}, prefix={prefix}")
            print(f"  Perm: {perm}")
            print(f"  ENE at token pos {p}, BC at token pos {q}")
            table = decode_hit(tokens, p, q)
            print(f"  Checkerboard (13/26): {table}")
            inv = {v: k for k, v in table.items()}
            decoded = ''.join(inv.get(tok, '?') for tok in tokens)
            print(f"  Partial PT: {decoded}")
    else:
        print("\nNo hits. VIC model (straddling checkerboard + columnar trans) with")
        print("prefix sizes 4-10 and columnar widths 5-8: ELIMINATED for tested configs.")
        print("Remaining: wider transpositions, non-columnar transposition, or")
        print("non-standard variable-length codes.")


if __name__ == "__main__":
    run()
