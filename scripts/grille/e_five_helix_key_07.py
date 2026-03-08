#!/usr/bin/env python3
"""FIVE as helix start position: helical reading from cylinder = running key.

Cipher: helical running key from tableau/cipher cylinder
Family: grille
Status: active
Keyspace: ~2M configs
Last run: never
Best score: n/a

HYPOTHESIS (Colin, 2026-03-07): FIVE at the Code Room cylinder seam
indicates a STARTING POSITION. Read a helical string from that position
on the tableau cylinder (or cipher cylinder). That string IS the running
key for decrypting K4 via Vigenere/Beaufort.

Interpretations of "five" as start position:
  A) Column 5 (0-indexed) — the 6th column
  B) Position of F in FIVE on the seam — col 28 on single panel
  C) 5 chars from the seam in either direction
  D) Row 5
  E) The 5th cell from various reference points
  F) ALL start positions (exhaustive), with pitch=5 as the special parameter

The helix is read from the TABLEAU cylinder (Code Room = tableau as cylinder)
and used as a running key to decrypt K4.
"""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, MOD
from kryptos.kernel.transforms.vigenere import decrypt_text, CipherVariant
from kryptos.kernel.scoring.free_crib import score_free_fast

KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {c: i for i, c in enumerate(KA)}

# === BUILD BOTH CYLINDERS ===

# --- Tableau cylinder (28×31, Code Room) ---
TAB_H, TAB_W = 28, 31

def build_tableau():
    """Build the 28×31 Kryptos tableau (header + 26 KA rows + footer)."""
    grid = []
    # Row 0: header = ABCDEFGHIJKLMNOPQRSTUVWXYZABCD (30 chars at cols 1-30)
    # With key column blank at col 0. For cylinder, col 0 = L (fills blank)
    header = "LABCDEFGHIJKLMNOPQRSTUVWXYZABCD"
    grid.append(header)
    # Rows 1-26: key column (A-Z) + KA shifted rows
    for r in range(26):
        key_char = ALPH[r]  # A through Z
        row = key_char
        for c in range(30):
            ka_idx = (r + c) % 26
            row += KA[ka_idx]
        grid.append(row)
    # Row 27: footer = ABCDEFGHIJKLMNOPQRSTUVWXYZABCD (30 chars)
    footer = " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD"
    grid.append(footer)
    assert all(len(row) == 31 for row in grid), f"Row lengths: {[len(r) for r in grid]}"
    return grid

tab_grid = build_tableau()

# --- Cipher cylinder (28×31) ---
K1_CT = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"
K2_CT = (
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKKDQMCPFQZDQMMIAGPFXHQRLG"
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNAQZGZLECGYUXUEENJTBJLBQCRTBJDFHRR"
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTIHHDDDUVHDWKBFUFPWNTDFIYCUQZERE"
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDXFLGGTEZFKZBSFDQVGOGIPUFXHHDRKF"
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE"
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKPDQUMEBEDMHDAFMJGZNUPLGEWJLLAETG"
)
K3_CT = (
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLLNOHSNOSMRWXMNE"
    "TPRNGATIHNRARPESLNNELEBLPIIACAEWMTWNDITEENRAHCTENEUDRETNHAEOE"
    "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWENATAMATEGYEERLB"
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTIBSEDDNIAAHTTMSTEWPIEROAGRIEWFEB"
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORITRKLMLEHAGTDHARDPNEOHMGFMFEUHE"
    "ECDMRIPFEIMEHNLSSTTRTVDOHW"
)
FULL_CIPHER = K1_CT + "?" + K2_CT + "?" + K3_CT + "?" + CT
assert len(FULL_CIPHER) == 868

cip_grid = []
for r in range(TAB_H):
    cip_grid.append(FULL_CIPHER[r*TAB_W:(r+1)*TAB_W])

# K4 position in flat cipher
K4_START = 771  # position in 868-char sequence

VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]
THRESHOLD = 7

results = []
total = 0

def helix_reading(grid, height, width, start_r, start_c, pitch, direction=1):
    """Read a helix from grid. Returns string of all chars visited.

    pitch: rows advanced per full revolution (per width columns)
    direction: +1 = left-to-right, -1 = right-to-left
    """
    chars = []
    visited = set()
    r, c = start_r, start_c

    for _ in range(height * width):
        if (r, c) in visited:
            # Find next unvisited
            found = False
            for try_c in range(width):
                for try_r in range(height):
                    if (try_r, try_c) not in visited:
                        r, c = try_r, try_c
                        found = True
                        break
                if found:
                    break
            if not found:
                break

        visited.add((r, c))
        ch = grid[r][c]
        if ch != ' ':
            chars.append(ch)

        c = (c + direction) % width
        if (direction == 1 and c == start_c) or (direction == -1 and c == start_c):
            r = (r + pitch) % height

    return ''.join(chars)


def helix_reading_continuous(grid, height, width, start_r, start_c, row_step):
    """Continuous helix: each column step also advances row by row_step/width.

    Equivalent to: at each step, c += 1, fractional_r += row_step/width.
    Since gcd(28,31)=1, this visits all cells for coprime steps.
    """
    chars = []
    visited = set()

    for step in range(height * width):
        r = (start_r + (step * row_step) // width) % height
        c = (start_c + step) % width

        if (r, c) not in visited:
            visited.add((r, c))
            ch = grid[r][c]
            if ch != ' ':
                chars.append(ch)

    return ''.join(chars)


def extract_key_for_k4(helix_str, k4_offset=0):
    """Extract 97 chars from helix string starting at k4_offset."""
    key_str = helix_str[k4_offset:k4_offset + CT_LEN]
    if len(key_str) < CT_LEN:
        # Wrap around
        key_str += helix_str[:CT_LEN - len(key_str)]
    return key_str


def try_running_key(key_str, label):
    """Use key_str as running key to decrypt K4."""
    global total
    key_nums = []
    for ch in key_str[:CT_LEN]:
        if ch == '?' or ch == ' ':
            key_nums.append(0)
        else:
            key_nums.append(ALPH_IDX[ch])

    for variant in VARIANTS:
        pt = decrypt_text(CT, key_nums, variant)
        sc = score_free_fast(pt)
        if sc > THRESHOLD:
            results.append((sc, label, variant.value, pt[:60]))
            print(f"  ** SCORE {sc}: {label} ({variant.value}): {pt[:60]}")
        total += 1


# ================================================================
# PHASE 1: Tableau helix as running key — all pitches, FIVE-related starts
# ================================================================
print("=" * 78)
print("  PHASE 1: Tableau helix running key — FIVE-related start positions")
print("=" * 78)
print()

# FIVE-related start positions on 28×31 grid
five_starts = [
    (0, 5, "col5"),           # Column 5
    (5, 0, "row5"),           # Row 5
    (5, 5, "r5c5"),           # (5,5)
    (0, 28, "F_of_FIVE"),     # Position of F in the FIVE seam on cipher grid
    (0, 29, "I_of_FIVE"),
    (0, 30, "V_of_FIVE"),
    (14, 0, "E_of_FIVE_K3"),  # E at start of K3 (bottom half)
    (0, 0, "origin"),
    (14, 0, "center_split"),
    (0, 4, "five_0idx"),      # 0-indexed position 4 = 5th char
    (4, 0, "row4_0idx"),
    (24, 27, "k4_start"),     # Where K4 starts on cipher grid
]

phase1_total = 0
for start_r, start_c, start_name in five_starts:
    for pitch in range(1, TAB_H):
        for direction in [1, -1]:
            helix = helix_reading(tab_grid, TAB_H, TAB_W, start_r, start_c, pitch, direction)

            # Use helix as running key at various offsets
            for k4_off in [0, K4_START % len(helix), 5, len(helix) - CT_LEN]:
                key = extract_key_for_k4(helix, k4_off)
                dir_str = "fwd" if direction == 1 else "rev"
                try_running_key(key, f"tab_helix_{start_name}_p{pitch}_{dir_str}_off{k4_off}")
                phase1_total += 1

    # Also test continuous helix
    for row_step in range(1, TAB_H):
        helix = helix_reading_continuous(tab_grid, TAB_H, TAB_W, start_r, start_c, row_step)
        for k4_off in [0, K4_START % max(1, len(helix)), 5]:
            key = extract_key_for_k4(helix, k4_off)
            try_running_key(key, f"tab_conthelix_{start_name}_rs{row_step}_off{k4_off}")
            phase1_total += 1

print(f"  Phase 1: {phase1_total} configs ({total} total)")

# ================================================================
# PHASE 2: Cipher helix as running key (cipher cylinder self-keying)
# ================================================================
print()
print("=" * 78)
print("  PHASE 2: Cipher cylinder helix as running key")
print("=" * 78)
print()

phase2_start = total
for start_r, start_c, start_name in five_starts:
    for pitch in range(1, TAB_H):
        for direction in [1, -1]:
            helix = helix_reading(cip_grid, TAB_H, TAB_W, start_r, start_c, pitch, direction)

            for k4_off in [0, K4_START % len(helix), 5]:
                key = extract_key_for_k4(helix, k4_off)
                dir_str = "fwd" if direction == 1 else "rev"
                try_running_key(key, f"cip_helix_{start_name}_p{pitch}_{dir_str}_off{k4_off}")

print(f"  Phase 2: {total - phase2_start} configs")

# ================================================================
# PHASE 3: Pitch=5 exhaustive (all start positions)
# ================================================================
print()
print("=" * 78)
print("  PHASE 3: Pitch=5 — ALL start positions on tableau")
print("=" * 78)
print()

phase3_start = total
for start_r in range(TAB_H):
    for start_c in range(TAB_W):
        for direction in [1, -1]:
            helix = helix_reading(tab_grid, TAB_H, TAB_W, start_r, start_c, 5, direction)

            for k4_off in [0, K4_START % len(helix), 5]:
                key = extract_key_for_k4(helix, k4_off)
                dir_str = "fwd" if direction == 1 else "rev"
                try_running_key(key, f"tab_p5_{start_r}_{start_c}_{dir_str}_off{k4_off}")

        # Continuous helix with row_step=5
        helix = helix_reading_continuous(tab_grid, TAB_H, TAB_W, start_r, start_c, 5)
        for k4_off in [0, K4_START % max(1, len(helix)), 5]:
            key = extract_key_for_k4(helix, k4_off)
            try_running_key(key, f"tab_cont5_{start_r}_{start_c}_off{k4_off}")

    if (start_r + 1) % 7 == 0:
        print(f"  ... row {start_r+1}/{TAB_H}, {total - phase3_start} configs")

print(f"  Phase 3: {total - phase3_start} configs")

# ================================================================
# PHASE 4: Pitch=5 exhaustive on CIPHER cylinder
# ================================================================
print()
print("=" * 78)
print("  PHASE 4: Pitch=5 — ALL start positions on cipher cylinder")
print("=" * 78)
print()

phase4_start = total
for start_r in range(TAB_H):
    for start_c in range(TAB_W):
        for direction in [1, -1]:
            helix = helix_reading(cip_grid, TAB_H, TAB_W, start_r, start_c, 5, direction)

            for k4_off in [0, K4_START % len(helix), 5]:
                key = extract_key_for_k4(helix, k4_off)
                dir_str = "fwd" if direction == 1 else "rev"
                try_running_key(key, f"cip_p5_{start_r}_{start_c}_{dir_str}_off{k4_off}")

    if (start_r + 1) % 7 == 0:
        print(f"  ... row {start_r+1}/{TAB_H}, {total - phase4_start} configs")

print(f"  Phase 4: {total - phase4_start} configs")

# ================================================================
# PHASE 5: ALL pitches, ALL starts on tableau (exhaustive)
# ================================================================
print()
print("=" * 78)
print("  PHASE 5: ALL pitches × ALL starts on tableau (running key)")
print("=" * 78)
print()

phase5_start = total
for pitch in range(1, TAB_H):
    for start_r in range(TAB_H):
        for start_c in range(TAB_W):
            helix = helix_reading(tab_grid, TAB_H, TAB_W, start_r, start_c, pitch, 1)

            # Key at offset 0 (from helix start) and at K4's linear position
            for k4_off in [0, K4_START % len(helix)]:
                key = extract_key_for_k4(helix, k4_off)
                try_running_key(key, f"tab_full_p{pitch}_{start_r}_{start_c}_off{k4_off}")

    print(f"  pitch {pitch}/{TAB_H-1}, {total - phase5_start} configs, {total} total")

print(f"  Phase 5: {total - phase5_start} configs")

# ================================================================
# PHASE 6: Two-panel tableau helix (14×62 cylinder)
# ================================================================
print()
print("=" * 78)
print("  PHASE 6: Two-panel tableau (14×62) — pitch=5 and FIVE-starts")
print("=" * 78)
print()

# Build 14×62 tableau cylinder (top half beside bottom half)
tab_top = [tab_grid[r] for r in range(14)]
tab_bot = [tab_grid[r] for r in range(14, 28)]
tab_2panel = [tab_top[r] + tab_bot[r] for r in range(14)]

phase6_start = total
for pitch in [1, 2, 3, 5, 7, 9, 11, 13]:
    for start_r in range(14):
        for start_c in range(62):
            helix = helix_reading(tab_2panel, 14, 62, start_r, start_c, pitch, 1)

            key = extract_key_for_k4(helix, 0)
            try_running_key(key, f"tab2p_p{pitch}_{start_r}_{start_c}")

    print(f"  pitch {pitch}, {total - phase6_start} configs")

print(f"  Phase 6: {total - phase6_start} configs")

# ================================================================
# PHASE 7: Cipher two-panel helix as key
# ================================================================
print()
print("=" * 78)
print("  PHASE 7: Two-panel cipher (14×62) — helix as running key")
print("=" * 78)
print()

# Build 14×62 cipher cylinder
top_half = K1_CT + "?" + K2_CT + "?"
bottom_half = K3_CT + "?" + CT
cip_top = [top_half[r*31:(r+1)*31] for r in range(14)]
cip_bot = [bottom_half[r*31:(r+1)*31] for r in range(14)]
cip_2panel = [cip_top[r] + cip_bot[r] for r in range(14)]

phase7_start = total
for pitch in [1, 2, 3, 5, 7, 9, 11, 13]:
    for start_r in range(14):
        for start_c in range(62):
            helix = helix_reading(cip_2panel, 14, 62, start_r, start_c, pitch, 1)

            key = extract_key_for_k4(helix, 0)
            try_running_key(key, f"cip2p_p{pitch}_{start_r}_{start_c}")

    print(f"  pitch {pitch}, {total - phase7_start} configs")

print(f"  Phase 7: {total - phase7_start} configs")

# ================================================================
# SUMMARY
# ================================================================
print()
print("=" * 78)
print(f"  TOTAL: {total} configurations tested")
print("=" * 78)

if results:
    results.sort(reverse=True)
    print(f"\n{len(results)} results above threshold {THRESHOLD}:")
    for sc, label, var, pt in results[:30]:
        print(f"  SCORE {sc:2d}: {label} ({var}): {pt}")
else:
    print("\nNo results above threshold.")

print("\nDONE")
