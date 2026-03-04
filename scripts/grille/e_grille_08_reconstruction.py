#!/usr/bin/env python3
"""
Cipher: Cardan grille
Family: grille
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-GRILLE-08: Reconstruct YAR Cardan grille extraction from exact ciphertext layout.

Uses the exact ciphertext line breaks as provided by Colin, overlaid on the
KA Vigenère tableau. Y/A/R positions in the ciphertext are holes; tableau
characters at those positions are extracted.
"""
import sys
sys.path.insert(0, 'src')

from kryptos.kernel.constants import CT as K4_CT

# ── Exact ciphertext layout (28 rows, as carved on the sculpture) ──────────
CT_ROWS = [
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJ",      # Row 1 (32)
    "YQTQUXQBQVYUVLLTREVJYQTMKYRDMFD",        # Row 2 (31)
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCE",         # Row 3 (31)
    "GGWHKK?DQMCPFQZDQMMIAGPFXHQRLG",         # Row 4 (30)
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA",         # Row 5 (31)
    "QZGZLECGYUXUEENJTBJLBQCRTBJDFHRR",       # Row 6 (32)
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTI",         # Row 7 (31)
    "HHDDDUVH?DWKBFUFPWNTDFIYCUQZERE",        # Row 8 (31)
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDX",        # Row 9 (32)
    "FLGGTEZ?FKZBSFDQVGOGIPUFXHHDRKF",        # Row 10 (31)
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQ",          # Row 11 (30)
    "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE",         # Row 12 (31)
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP",         # Row 13 (31)
    "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG",         # Row 14 (31)
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIA",        # Row 15 (32)
    "CHTNREYULDSLLSLLNOHSNOSMRWXMNE",          # Row 16 (30)
    "TPRNGATIHNRARPESLNNELEBLPIIACAE",          # Row 17 (31)
    "WMTWNDITEENRAHCTENEUDRETNHAEOE",           # Row 18 (30)
    "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCR",        # Row 19 (32)
    "EIFTBRSPAMHHEWENATAMATEGYEERLB",           # Row 20 (30)
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTI",         # Row 21 (32)
    "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB",          # Row 22 (31)
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORIT",       # Row 23 (33)
    "RKLMLEHAGTDHARDPNEOHMGFMFEUHE",            # Row 24 (29)
    "ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR",         # Row 25 (31)
    "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO",          # Row 26 (31)
    "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP",          # Row 27 (31)
    "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR",         # Row 28 (31)
]

# ── KA alphabet ────────────────────────────────────────────────────────────
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
assert len(KA) == 26
assert len(set(KA)) == 26  # all 26 letters present

# ── Exact tableau as provided by Colin (28 rows) ─────────────────────────
# Each row includes the label character in position 0, then the alphabet content.
# Header/footer rows have space as label. Variable row lengths match the sculpture.
TABLEAU_ROWS = [
    " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",                # Row 1: header (31)
    "AKRYPTOSABCDEFGHIJLMNQUVWXZKRYP",                # Row 2: A (31)
    "BRYPTOSABCDEFGHIJLMNQUVWXZKRYPT",                # Row 3: B (31)
    "CYPTOSABCDEFGHIJLMNQUVWXZKRYPTO",                # Row 4: C (31)
    "DPTOSABCDEFGHIJLMNQUVWXZKRYPTOS",                # Row 5: D (31)
    "ETOSABCDEFGHIJLMNQUVWXZKRYPTOSA",                # Row 6: E (31)
    "FOSABCDEFGHIJLMNQUVWXZKRYPTOSAB",                # Row 7: F (31)
    "GSABCDEFGHIJLMNQUVWXZKRYPTOSABC",                # Row 8: G (31)
    "HABCDEFGHIJLMNQUVWXZKRYPTOSABCD",                # Row 9: H (31)
    "IBCDEFGHIJLMNQUVWXZKRYPTOSABCDE",                # Row 10: I (31)
    "JCDEFGHIJLMNQUVWXZKRYPTOSABCDEF",                # Row 11: J (31)
    "KDEFGHIJLMNQUVWXZKRYPTOSABCDEFG",                # Row 12: K (31)
    "LEFGHIJLMNQUVWXZKRYPTOSABCDEFGH",                # Row 13: L (31)
    "MFGHIJLMNQUVWXZKRYPTOSABCDEFGHI",                # Row 14: M (31)
    "NGHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",               # Row 15: N (32)
    "OHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",                # Row 16: O (31)
    "PIJLMNQUVWXZKRYPTOSABCDEFGHIJLM",                # Row 17: P (31)
    "QJLMNQUVWXZKRYPTOSABCDEFGHIJLMN",                # Row 18: Q (31)
    "RLMNQUVWXZKRYPTOSABCDEFGHIJLMNQ",                # Row 19: R (31)
    "SMNQUVWXZKRYPTOSABCDEFGHIJLMNQU",                # Row 20: S (31)
    "TNQUVWXZKRYPTOSABCDEFGHIJLMNQUV",                # Row 21: T (31)
    "UQUVWXZKRYPTOSABCDEFGHIJLMNQUVW",                # Row 22: U (31)
    "VUVWXZKRYPTOSABCDEFGHIJLMNQUVWXT",               # Row 23: V (32)
    "WVWXZKRYPTOSABCDEFGHIJLMNQUVWXZ",                # Row 24: W (31)
    "XWXZKRYPTOSABCDEFGHIJLMNQUVWXZK",                # Row 25: X (31)
    "YXZKRYPTOSABCDEFGHIJLMNQUVWXZKR",                # Row 26: Y (31)
    "ZZKRYPTOSABCDEFGHIJLMNQUVWXZKRY",                # Row 27: Z (31)
    " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",                # Row 28: footer (31)
]

def get_tableau_char(row_idx, col_idx_0):
    """Get tableau character at (1-indexed row, 0-indexed col)."""
    tab_row = TABLEAU_ROWS[row_idx - 1]
    if col_idx_0 < len(tab_row):
        return tab_row[col_idx_0]
    else:
        # Column extends beyond tableau row — use cyclic extension
        body_idx = row_idx - 2
        if row_idx == 1 or row_idx == 28:
            return "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[(col_idx_0 - 1) % 26]
        else:
            return KA[(body_idx + (col_idx_0 - 1)) % 26]


# ── Grille mask letters ───────────────────────────────────────────────────
MASK_LETTERS = {'Y', 'A', 'R'}

# ── Extract ───────────────────────────────────────────────────────────────
print("=" * 70)
print("E-GRILLE-08: YAR Cardan Grille Reconstruction")
print("=" * 70)

# Print row lengths
total_chars = 0
for i, row in enumerate(CT_ROWS):
    total_chars += len(row)
print(f"\nTotal ciphertext characters: {total_chars}")
print(f"Number of rows: {len(CT_ROWS)}")
print(f"Row lengths: {[len(r) for r in CT_ROWS]}")

# Count Y, A, R in ciphertext
yar_count = sum(1 for row in CT_ROWS for ch in row if ch in MASK_LETTERS)
print(f"\nTotal Y/A/R in ciphertext: {yar_count}")
y_count = sum(1 for row in CT_ROWS for ch in row if ch == 'Y')
a_count = sum(1 for row in CT_ROWS for ch in row if ch == 'A')
r_count = sum(1 for row in CT_ROWS for ch in row if ch == 'R')
print(f"  Y: {y_count}, A: {a_count}, R: {r_count}")

# Extract through the grille
extracted = []
extraction_details = []

for row_idx_0, ct_row in enumerate(CT_ROWS):
    row_idx = row_idx_0 + 1  # 1-indexed

    for col_idx_0, ct_char in enumerate(ct_row):
        col_idx = col_idx_0 + 1  # 1-indexed
        if ct_char in MASK_LETTERS:
            tab_char = get_tableau_char(row_idx, col_idx_0)
            extracted.append(tab_char)
            extraction_details.append({
                'row': row_idx,
                'col': col_idx,
                'ct_char': ct_char,
                'tab_char': tab_char,
                'mask': ct_char,
            })

extracted_str = ''.join(extracted)

print(f"\n{'─' * 70}")
print(f"EXTRACTED CT (no correction): {len(extracted_str)} characters")
print(f"{'─' * 70}")
print(extracted_str)

# ── Compare with user's CT ────────────────────────────────────────────────
USER_CT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
print(f"\nUser's CT ({len(USER_CT)} chars):")
print(USER_CT)

print(f"\n{'─' * 70}")
print("CHARACTER-BY-CHARACTER COMPARISON")
print(f"{'─' * 70}")

min_len = min(len(extracted_str), len(USER_CT))
matches = 0
mismatches = []
for i in range(min_len):
    if extracted_str[i] == USER_CT[i]:
        matches += 1
    else:
        mismatches.append((i, extracted_str[i], USER_CT[i]))

print(f"Length match: {len(extracted_str)} vs {len(USER_CT)}")
print(f"Character matches: {matches}/{min_len} ({100*matches/min_len:.1f}%)")
print(f"Mismatches: {len(mismatches)}")

if mismatches:
    print(f"\nFirst 20 mismatches:")
    for pos, got, expected in mismatches[:20]:
        detail = extraction_details[pos] if pos < len(extraction_details) else None
        loc = f"(row {detail['row']}, col {detail['col']}, mask={detail['mask']})" if detail else ""
        print(f"  pos {pos:3d}: got '{got}' expected '{expected}' {loc}")

# Extra/missing chars
if len(extracted_str) != len(USER_CT):
    print(f"\nLength difference: {len(extracted_str) - len(USER_CT)} chars")

# ── Detailed extraction table ─────────────────────────────────────────────
print(f"\n{'─' * 70}")
print("FULL EXTRACTION TABLE (first 30 chars)")
print(f"{'─' * 70}")
print(f"{'Pos':>4} {'Row':>4} {'Col':>4} {'CT':>4} {'Tab':>4} {'User':>5}")
for i, d in enumerate(extraction_details[:30]):
    user_ch = USER_CT[i] if i < len(USER_CT) else '?'
    match = '✓' if d['tab_char'] == user_ch else '✗'
    print(f"{i:4d} {d['row']:4d} {d['col']:4d} {d['ct_char']:>4} {d['tab_char']:>4} {user_ch:>5} {match}")

# ── Y/A/R breakdown ──────────────────────────────────────────────────────
print(f"\n{'─' * 70}")
print("EXTRACTION BY MASK LETTER")
print(f"{'─' * 70}")
y_chars = ''.join(d['tab_char'] for d in extraction_details if d['mask'] == 'Y')
a_chars = ''.join(d['tab_char'] for d in extraction_details if d['mask'] == 'A')
r_chars = ''.join(d['tab_char'] for d in extraction_details if d['mask'] == 'R')
print(f"Y-holes ({len(y_chars):3d} chars): {y_chars}")
print(f"A-holes ({len(a_chars):3d} chars): {a_chars}")
print(f"R-holes ({len(r_chars):3d} chars): {r_chars}")
print(f"Total: {len(y_chars) + len(a_chars) + len(r_chars)}")

# ── Per-row extraction summary ────────────────────────────────────────────
print(f"\n{'─' * 70}")
print("PER-ROW EXTRACTION")
print(f"{'─' * 70}")
row_groups = {}
for d in extraction_details:
    row_groups.setdefault(d['row'], []).append(d)

for row in sorted(row_groups.keys()):
    details = row_groups[row]
    chars = ''.join(d['tab_char'] for d in details)
    cols = [d['col'] for d in details]
    masks = [d['mask'] for d in details]
    print(f"  Row {row:2d}: {chars:30s} (cols {cols}, masks {masks})")

# ── Identify the UNDERGRUUND correction position ─────────────────────────
print(f"\n{'─' * 70}")
print("UNDERGRUUND CORRECTION ANALYSIS")
print(f"{'─' * 70}")

# Find all R positions in the ciphertext that, if changed to E, would remove a hole
# and look for the UNDERGRUUND area (K3 text)
# K3 encrypted text starts around row 15 based on position counting
# Let's find positions where changing R→E removes exactly one hole

r_positions = [(d['row'], d['col'], d['tab_char']) for d in extraction_details if d['mask'] == 'R']
print(f"\nAll R-hole positions ({len(r_positions)} total):")
for row, col, tab in r_positions:
    ct_row_text = CT_ROWS[row - 1]
    print(f"  Row {row:2d} Col {col:2d} → tableau '{tab}' (CT context: ...{ct_row_text[max(0,col-4):col+3]}...)")

# ── Check ? positions ─────────────────────────────────────────────────────
print(f"\n{'─' * 70}")
print("? CHARACTER POSITIONS")
print(f"{'─' * 70}")
for row_idx_0, ct_row in enumerate(CT_ROWS):
    for col_idx_0, ch in enumerate(ct_row):
        if ch == '?':
            row_idx = row_idx_0 + 1
            col_idx = col_idx_0 + 1
            tab_char = get_tableau_char(row_idx, col_idx_0)
            print(f"  Row {row_idx:2d} Col {col_idx:2d}: CT='?', Tableau='{tab_char}'")
            # What if ? is actually A, Y, or R?
            print(f"    If ?=A or Y or R: would extract '{tab_char}'")

# ── Final summary ─────────────────────────────────────────────────────────
print(f"\n{'=' * 70}")
print("SUMMARY")
print(f"{'=' * 70}")
print(f"Extracted length: {len(extracted_str)}")
print(f"User CT length:   {len(USER_CT)}")
print(f"Match rate:       {matches}/{min_len} ({100*matches/min_len:.1f}%)")
print(f"Y-holes: {len(y_chars)}, A-holes: {len(a_chars)}, R-holes: {len(r_chars)}")

if extracted_str.upper() == USER_CT.upper():
    print("\n*** PERFECT MATCH — extraction verified! ***")
elif matches >= min_len * 0.95:
    print(f"\n*** NEAR MATCH ({100*matches/min_len:.1f}%) — minor discrepancies ***")
else:
    print(f"\n*** SIGNIFICANT MISMATCH — alignment or method differs ***")
    print("Possible causes:")
    print("  1. ? characters may be specific letters (A/Y/R) on the sculpture")
    print("  2. UNDERGRUUND correction changes one position")
    print("  3. Tableau row labels or wrapping differs from model")
    print("  4. Some rows have different lengths than parsed")
