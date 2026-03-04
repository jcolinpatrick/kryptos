#!/usr/bin/env python3
"""
Cipher: statistical analysis
Family: statistical
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-FREQ-EQUIV-01: Test statistical significance of lower-half frequency equivalences.

The lower half of the cipher panel (K3+K4, 433 chars) has six frequency equivalence
classes covering 14 letters:
  {J,V,X}=3, {K,Y}=9, {B,C,P,U}=11, {M,W}=13, {D,L}=20, {I,N}=25

This experiment tests whether this level of structure is statistically unlikely
under a null model of English plaintext encrypted with standard polyalphabetic ciphers.
"""

import random
import string
from collections import Counter
from pathlib import Path

# === CONSTANTS ===

# The actual lower-half text (K3 + ? + K4, 14 rows of width 31)
LOWER_HALF = (
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAI"
    "ACHTNREYULDSLLSLLNOHSNOSMRWXMNE"
    "TPRNGATIHNRARPESLNNELEBLPIIACAE"
    "WMTWNDITEENRAHCTENEUDRETNHAEOE"
    "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCR"
    "EIFTBRSPAMHHEWENATAMATEGYEERLB"
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTI"
    "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB"
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORIT"
    "RKLMLEHAGTDHARDPNEOHMGFMFEUHE"
    "ECDMRIPFEIMEHNLSSTTRTVDOHW"
    # ? removed, then K4:
    "OBKR"
    "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO"
    "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP"
    "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
)

# English text source for null model
# Load wordlist for generating pseudo-English
WORDLIST_PATH = Path(__file__).resolve().parent.parent / "wordlists" / "english.txt"

def load_words():
    """Load common English words."""
    if WORDLIST_PATH.exists():
        words = []
        with open(WORDLIST_PATH) as f:
            for line in f:
                w = line.strip().upper()
                if 3 <= len(w) <= 12 and w.isalpha():
                    words.append(w)
        return words
    else:
        # Fallback: use a simple frequency-based generator
        return None

def generate_english_text(length, words):
    """Generate pseudo-English text of given length from word list."""
    if words is None:
        # Fallback: weighted random from English letter frequencies
        freqs = "ETAOINSHRDLCUMWFGYPBVKJXQZ"
        weights = [12.7,9.1,8.2,7.5,7.0,6.7,6.3,6.1,6.0,4.3,4.0,2.8,2.8,2.4,2.4,2.2,2.0,2.0,1.9,1.5,1.0,0.8,0.15,0.15,0.10,0.07]
        total = sum(weights)
        weights = [w/total for w in weights]
        return ''.join(random.choices(freqs, weights=weights, k=length))

    text = []
    while len(text) < length:
        word = random.choice(words)
        text.extend(list(word))
    return ''.join(text[:length])

def vigenere_encrypt(plaintext, key):
    """Encrypt with Vigenère (standard A-Z)."""
    ct = []
    for i, ch in enumerate(plaintext):
        if ch.isalpha():
            p = ord(ch.upper()) - 65
            k = ord(key[i % len(key)].upper()) - 65
            ct.append(chr((p + k) % 26 + 65))
        else:
            ct.append(ch)
    return ''.join(ct)

def random_key(period):
    """Generate random alphabetic key of given period."""
    return ''.join(random.choices(string.ascii_uppercase, k=period))

def count_frequency_ties(text):
    """Count frequency equivalence classes (ties of 2+) in text.

    Returns:
        n_classes: number of equivalence classes with 2+ members
        max_width: size of largest class
        n_tied_letters: total letters involved in ties
        tied_letters_by_freq: dict of freq -> set of letters
    """
    text = ''.join(c for c in text.upper() if c.isalpha())
    freq = Counter(text)

    # Group letters by frequency
    freq_groups = {}
    for ch, f in freq.items():
        if f not in freq_groups:
            freq_groups[f] = set()
        freq_groups[f].add(ch)

    # Also count letters NOT in text (freq=0) as a group
    all_letters = set(string.ascii_uppercase)
    missing = all_letters - set(freq.keys())
    if len(missing) >= 2:
        freq_groups[0] = missing

    # Filter to groups with 2+ members (exclude freq=0 for cleaner analysis)
    tied = {f: letters for f, letters in freq_groups.items() if len(letters) >= 2 and f > 0}

    n_classes = len(tied)
    max_width = max((len(letters) for letters in tied.values()), default=0)
    n_tied_letters = sum(len(letters) for letters in tied.values())

    return n_classes, max_width, n_tied_letters, tied

# === MAIN EXPERIMENT ===

print("=" * 75)
print("E-FREQ-EQUIV-01: Lower-Half Frequency Equivalence Significance Test")
print("=" * 75)

# Part 1: Measure K4's lower half
print("\n--- PART 1: Observed equivalence structure ---")

# Clean lower half (letters only)
lower_clean = ''.join(c for c in LOWER_HALF if c.isalpha())
print(f"Lower half: {len(lower_clean)} characters")

n_cls, max_w, n_tied, tied_groups = count_frequency_ties(lower_clean)
print(f"Equivalence classes (freq > 0, size >= 2): {n_cls}")
print(f"Max class width: {max_w}")
print(f"Total tied letters: {n_tied}")
print(f"Tied letters / 26: {n_tied/26:.1%}")
print("\nDetail:")
for f in sorted(tied_groups.keys()):
    letters = sorted(tied_groups[f])
    print(f"  Freq {f:>3}: {{{', '.join(letters)}}} (width {len(letters)})")

# Composite score: n_classes * max_width (rewards both many ties and wide ties)
observed_score = n_cls * max_w + n_tied
print(f"\nComposite score (n_classes × max_width + n_tied): {observed_score}")

# Part 2: Monte Carlo null distribution
print("\n--- PART 2: Monte Carlo Null Distribution ---")

words = load_words()
print(f"Wordlist loaded: {len(words) if words else 'fallback mode'} words")

n_trials = 10000
periods = list(range(3, 13))  # periods 3-12

mc_n_classes = []
mc_max_width = []
mc_n_tied = []
mc_scores = []

random.seed(42)

for trial in range(n_trials):
    # Generate pseudo-English plaintext
    pt = generate_english_text(len(lower_clean), words)

    # Encrypt with random Vigenère key
    period = random.choice(periods)
    key = random_key(period)
    ct = vigenere_encrypt(pt, key)

    # Measure frequency ties
    nc, mw, nt, _ = count_frequency_ties(ct)
    mc_n_classes.append(nc)
    mc_max_width.append(mw)
    mc_n_tied.append(nt)
    mc_scores.append(nc * mw + nt)

# Sort for percentile calculation
mc_n_classes.sort()
mc_max_width.sort()
mc_n_tied.sort()
mc_scores.sort()

def percentile(observed, distribution):
    rank = sum(1 for x in distribution if x <= observed) / len(distribution)
    return rank

print(f"\n{n_trials} trials: English plaintext + Vigenère (periods 3-12)")
print(f"\n{'Metric':>20} {'Observed':>10} {'Mean':>10} {'95th':>10} {'99th':>10} {'Pctile':>10}")
print("-" * 70)

for name, obs, dist in [
    ("n_classes", n_cls, mc_n_classes),
    ("max_width", max_w, mc_max_width),
    ("n_tied_letters", n_tied, mc_n_tied),
    ("composite_score", observed_score, mc_scores),
]:
    mean = sum(dist) / len(dist)
    p95 = dist[int(0.95 * len(dist))]
    p99 = dist[int(0.99 * len(dist))]
    pct = percentile(obs, dist)
    sig = ""
    if pct > 0.99:
        sig = " *** p<0.01"
    elif pct > 0.95:
        sig = " ** p<0.05"
    print(f"{name:>20} {obs:>10} {mean:>10.1f} {p95:>10} {p99:>10} {pct*100:>9.1f}%{sig}")

# Part 3: Breakdown by cipher type
print("\n--- PART 3: Null distribution by period ---")
print(f"\n{'Period':>8} {'Mean classes':>14} {'Mean tied':>12} {'Mean score':>12}")
print("-" * 50)

random.seed(42)
for period in periods:
    scores_p = []
    classes_p = []
    tied_p = []
    for _ in range(1000):
        pt = generate_english_text(len(lower_clean), words)
        key = random_key(period)
        ct = vigenere_encrypt(pt, key)
        nc, mw, nt, _ = count_frequency_ties(ct)
        classes_p.append(nc)
        tied_p.append(nt)
        scores_p.append(nc * mw + nt)
    print(f"{period:>8} {sum(classes_p)/len(classes_p):>14.1f} "
          f"{sum(tied_p)/len(tied_p):>12.1f} {sum(scores_p)/len(scores_p):>12.1f}")

print(f"\nObserved: classes={n_cls}, tied={n_tied}, score={observed_score}")

# Part 4: What about the FULL panel?
print("\n\n--- PART 4: Full panel equivalence structure (for comparison) ---")

# Full panel = upper + lower
UPPER_HALF = (
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJ"
    "YQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCE"
    "GGWHKKDQMCPFQZDQMMIAGPFXHQRLG"  # ? removed
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA"
    "QZGZLECGYUXUEENJTBJLBQCRTBJDFHRR"
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTI"
    "HHDDDUVHDWKBFUFPWNTDFIYCUQZERE"   # ? removed
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDX"
    "FLGGTEZFKZBSFDQVGOGIPUFXHHDRKF"    # squeezed ? removed
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQ"
    "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE"
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP"
    "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG"
)

full_panel = ''.join(c for c in (UPPER_HALF + LOWER_HALF) if c.isalpha())
n_cls_full, max_w_full, n_tied_full, tied_full = count_frequency_ties(full_panel)
print(f"Full panel ({len(full_panel)} chars):")
print(f"  Classes: {n_cls_full}, Max width: {max_w_full}, Tied letters: {n_tied_full}")
for f in sorted(tied_full.keys()):
    letters = sorted(tied_full[f])
    print(f"  Freq {f:>3}: {{{', '.join(letters)}}} (width {len(letters)})")

upper_clean = ''.join(c for c in UPPER_HALF if c.isalpha())
n_cls_upper, max_w_upper, n_tied_upper, tied_upper = count_frequency_ties(upper_clean)
print(f"\nUpper half ({len(upper_clean)} chars):")
print(f"  Classes: {n_cls_upper}, Max width: {max_w_upper}, Tied letters: {n_tied_upper}")
for f in sorted(tied_upper.keys()):
    letters = sorted(tied_upper[f])
    print(f"  Freq {f:>3}: {{{', '.join(letters)}}} (width {len(letters)})")

print("\n\n--- EXPERIMENT COMPLETE ---")
