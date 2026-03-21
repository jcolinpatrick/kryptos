#!/usr/bin/env python3
"""Test German and thematic non-English texts as running keys for K4.

The Gutenberg sweep tests ~60K English texts. This script targets:
1. German texts (Berlin/DDR/Cold War theme — BERLINCLOCK crib)
2. Specific intelligence/tradecraft documents
3. Latin texts (Carter's archaeology theme)
4. French texts (le Carré, NATO context)

Key insight: source text[21:34] = JLJODEGKUKKKL and source[63:74] = OCGGBGOKTRU
These are the LITERAL characters that must appear at those positions in the source.
"""
import sys, math, urllib.request, urllib.error, re, json
from pathlib import Path
sys.path.insert(0, 'src')
from kryptos.kernel.constants import CT, CRIB_WORDS

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Load quadgrams
with open("data/english_quadgrams.json") as f:
    QG = json.load(f)
QG_FLOOR = min(QG.values()) - 2.0

def score_text(text):
    n = len(text) - 3
    if n <= 0: return QG_FLOOR
    return sum(QG.get(text[i:i+4], QG_FLOOR) for i in range(n)) / n

# Build crib key
crib_key = {}
for (start, word) in CRIB_WORDS:
    for j, ch in enumerate(word):
        pos = start + j
        key_val = (AZ.index(ch) + AZ.index(CT[pos])) % 26
        crib_key[pos] = key_val
crib_positions = sorted(crib_key.keys())

def test_running_key(source, label, alpha=AZ, min_signal=8, verbose=True):
    """Test source as running key. Returns (best_score, best_offset, n_signals)."""
    src = source.upper()
    src_clean = ''.join(c for c in src if c in alpha)

    if len(src_clean) < max(crib_positions) + 1:
        print(f"  {label}: too short ({len(src_clean)} usable chars)")
        return -99, -1, 0

    best = -99
    best_off = -1
    signals = []

    for off in range(len(src_clean) - max(crib_positions)):
        score = 0
        for pos, expected in crib_key.items():
            idx = pos + off
            if idx >= len(src_clean): break
            if alpha.index(src_clean[idx]) == expected:
                score += 1
        if score > best:
            best = score
            best_off = off
        if score >= min_signal:
            signals.append((score, off))

    if verbose:
        if best >= 6 or signals:
            # Show details of best match
            src_slice = src_clean[best_off+21:best_off+34]
            print(f"  {label}: best={best}/24 at off={best_off} "
                  f"src[{21+best_off}:{34+best_off}]='{src_slice}'")
            if signals:
                print(f"    *** {len(signals)} offsets ≥ {min_signal}: {signals[:5]}")
            # Show full decryption at best offset
            pt = ''.join(AZ[(alpha.index(src_clean[pos+best_off]) - AZ.index(CT[pos])) % 26]
                          for pos in range(min(97, len(src_clean)-best_off)))
            print(f"    PT[21:40]={pt[21:40]}")
        else:
            print(f"  {label}: best={best}/24 (noise)")
    return best, best_off, len(signals)

# German Gutenberg project texts (try to fetch from Gutenberg)
GERMAN_GUTENBERG = [
    ("Berlin Alexanderplatz (Döblin)", 14379),
    ("Der Tunnel (Kellermann)", 6516),
    ("Faust I (Goethe)", 2229),
    ("Faust II (Goethe)", 30483),
    ("Der Process (Kafka)", 7849),
    ("Das Schloss (Kafka)", 7848),
    ("Buddenbrooks (Mann)", 901),
    ("Der Zauberberg (Mann)", 11319),
    ("Der Untertan (Heinrich Mann)", 12279),
    ("Im Westen nichts Neues (Remarque)", 32564),
    ("Deutschland ein Wintermärchen (Heine)", 4485),
    ("Nathan der Weise (Lessing)", 4032),
    ("Wilhelm Tell (Schiller)", 6788),
    ("Die Leiden des jungen Werthers (Goethe)", 2407),
]

LATIN_GUTENBERG = [
    ("Caesar's Gallic Wars", 10657),
    ("Cicero's De Officiis", 7804),
    ("Virgil's Aeneid", 228),
]

FRENCH_GUTENBERG = [
    ("Les Misérables (Hugo)", 135),
    ("Le Comte de Monte-Cristo (Dumas)", 17989),
]

# Also try some specific thematic texts
THEMATIC_TEXTS = {
    "K4_sample": "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR",
    "KRYPTOS_keyword": "KRYPTOSABCDEFGHIJLMNQUVWXZKRYPTOSABCDEFGHIJLMNQUVWXZKRYPTOSABCDEFGHIJLMNQUVWXZKRYPTOSABCDE",
    "NDYAHR_extended": "NDYAHRNDYAHRNDYAHRNDYAHRNDYAHRNDYAHRNDYAHRNDYAHRNDYAHRNDYAHRNDYAHRNDYAHRNDYAHRNDYAHR",
    "BERLINCLOCK_reversed": "KCOLCNILREBKCOLCNILREBKCOLCNILREBKCOLCNILREBKCOLCNILREBKCOLCNILREBKCOLCNILREB",
    "EASTNORTHEAST_key": "EASTNORTHEASTBERLINCLOCK" * 5,  # cribs as running key
    "ALPHABET_ZA": "ZYXWVUTSRQPONMLKJIHGFEDCBAZYXWVUTSRQPONMLKJIHGFEDCBAZYXWVUTSRQPONMLKJIHGFEDCBA",
}

print("=== German/Foreign Language Running Key Test ===\n")

print("--- Thematic texts (hardcoded) ---")
for label, text in THEMATIC_TEXTS.items():
    test_running_key(text, label)

print()
print("--- Gutenberg downloads (German, Latin, French) ---")

def fetch_gutenberg(num, label):
    """Try to fetch Gutenberg text."""
    urls = [
        f"https://www.gutenberg.org/cache/epub/{num}/pg{num}.txt",
        f"https://www.gutenberg.org/files/{num}/{num}.txt",
        f"https://www.gutenberg.org/files/{num}/{num}-0.txt",
    ]
    for url in urls:
        try:
            with urllib.request.urlopen(url, timeout=10) as r:
                raw = r.read().decode('utf-8', errors='replace')
            # Strip Project Gutenberg header/footer
            raw = re.sub(r'\*\*\* START.*?\*\*\*', '', raw, flags=re.DOTALL)
            raw = re.sub(r'\*\*\* END.*', '', raw, flags=re.DOTALL)
            return raw.strip()
        except Exception:
            continue
    return None

for label, num in GERMAN_GUTENBERG + LATIN_GUTENBERG + FRENCH_GUTENBERG:
    text = fetch_gutenberg(num, label)
    if text:
        test_running_key(text, f"Gutenberg #{num} ({label})")
    else:
        print(f"  Gutenberg #{num} ({label}): FETCH FAILED")

print()
print("=== Summary ===")
print("Any result ≥8/24 would be a notable signal.")
print("Threshold for serious investigation: ≥12/24 (Model A) or ≥18/24 (Model B)")
